/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/os/renv.h>

#include <rlib/rmem.h>
#include <stdlib.h>

#if defined (R_OS_WIN32)
#include <rlib/charset/runicode.h>
#include <rlib/concurrency/rthreads.h>
#include <rlib/data/rhashfuncs.h>
#include <rlib/data/rhashtable.h>
#include <rlib/rstr.h>
#endif
#if defined (HAVE_WINDOWS_H)
#include <windows.h>
#endif

#if defined (R_OS_WIN32)
/* r_getenv must hand back a pointer with getenv lifetime: owned by the
 * environment, stable for the process, and -- crucially -- not invalidated by
 * a lookup of a *different* variable, because callers cache it (r_fs_get_tmp_dir
 * stashes r_getenv ("TEMP") for the process lifetime). The Win32 value is UTF-16
 * and must be converted to UTF-8, so cache the conversion process-globally keyed
 * by name: a name maps to its latest UTF-8 value, and that pointer stays valid
 * until the variable's value actually changes (mirroring getenv, which is only
 * allowed to overwrite on a re-query of the same name). */
static RMutex       g__r_getenv_mutex;
static RHashTable * g__r_getenv_cache;
static ROnce        g__r_getenv_once = R_ONCE_INIT;

static rpointer
r_getenv_cache_init (rpointer data)
{
  (void) data;
  r_mutex_init (&g__r_getenv_mutex);
  g__r_getenv_cache = r_hash_table_new_full (r_str_hash, r_str_equal,
      r_free, r_free);
  return NULL;
}
#endif

const rchar *
r_getenv (const rchar * key)
{
  if (R_UNLIKELY (key == NULL)) return NULL;

#if defined (R_OS_WIN32)
  {
    runichar2 * wkey, * wval;
    rchar * val;
    const rchar * ret;
    DWORD need, got;

    if ((wkey = r_utf8_to_utf16_dup (key, -1, NULL, NULL, NULL)) == NULL)
      return NULL;

    /* Size the value (code units incl. NUL); 0 means unset. */
    if ((need = GetEnvironmentVariableW (wkey, NULL, 0)) == 0) {
      r_free (wkey);
      return NULL;
    }

    wval = r_mem_new_n (runichar2, need);
    got = GetEnvironmentVariableW (wkey, wval, need);
    r_free (wkey);
    /* got == 0: removed under us; got >= need: grew under us. */
    if (got == 0 || got >= need) {
      r_free (wval);
      return NULL;
    }

    val = r_utf16_to_utf8_dup (wval, got, NULL, NULL, NULL);
    r_free (wval);
    if (R_UNLIKELY (val == NULL))
      return NULL;

    r_call_once (&g__r_getenv_once, r_getenv_cache_init, NULL);
    r_mutex_lock (&g__r_getenv_mutex);
    ret = r_hash_table_lookup (g__r_getenv_cache, key);
    if (ret != NULL && r_str_equals (ret, val)) {
      r_free (val);          /* unchanged: keep the already-cached pointer */
    } else {
      r_hash_table_insert (g__r_getenv_cache, r_strdup (key), val);
      ret = val;
    }
    r_mutex_unlock (&g__r_getenv_mutex);
    return ret;
  }
#else
  return getenv (key);
#endif
}

rboolean
r_setenv (const rchar * key, const rchar * val, rboolean always)
{
  if (R_UNLIKELY (key == NULL || val == NULL)) return FALSE;

#if defined (R_OS_WIN32)
  {
    runichar2 * wkey, * wval;
    rboolean ret;

    if ((wkey = r_utf8_to_utf16_dup (key, -1, NULL, NULL, NULL)) == NULL)
      return FALSE;

    /* always == FALSE: keep an existing value but still report success. */
    if (!always && GetEnvironmentVariableW (wkey, NULL, 0) != 0) {
      r_free (wkey);
      return TRUE;
    }

    if ((wval = r_utf8_to_utf16_dup (val, -1, NULL, NULL, NULL)) == NULL) {
      r_free (wkey);
      return FALSE;
    }

    ret = SetEnvironmentVariableW (wkey, wval) != 0;
    r_free (wval);
    r_free (wkey);
    return ret;
  }
#else
  return setenv (key, val, always) == 0;
#endif
}

rboolean
r_unsetenv (const rchar * key)
{
  if (R_UNLIKELY (key == NULL)) return FALSE;

#if defined (R_OS_WIN32)
  {
    runichar2 * wkey;
    rboolean ret;

    if ((wkey = r_utf8_to_utf16_dup (key, -1, NULL, NULL, NULL)) == NULL)
      return FALSE;

    ret = SetEnvironmentVariableW (wkey, NULL) != 0;
    r_free (wkey);
    return ret;
  }
#else
  return unsetenv (key) == 0;
#endif
}
