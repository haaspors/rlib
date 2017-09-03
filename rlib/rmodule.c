/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rlib-private.h"
#include <rlib/rmodule.h>

#define R_LOG_CAT_DEFAULT &rlib_logcat

#if defined (R_OS_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

RMODULE
r_module_open (const rchar * path, rboolean lazy, RModuleError * err)
{
  HMODULE mod;

  (void) lazy;

  if (err != NULL)
    *err = R_MODULE_ERROR_OK;

  if (!GetModuleHandleExA (0, path, &mod)) {
    if ((mod = LoadLibraryEx (path, NULL, 0)) == NULL) {
      if (err != NULL)
        *err = R_MODULE_ERROR_NOT_FOUND;
    }
  }

  return (RMODULE)mod;
}
rpointer
r_module_lookup (RMODULE mod, const rchar * sym)
{
  return GetProcAddress (mod, sym);
}
void
r_module_close (RMODULE mod)
{
  FreeLibrary (mod);
}
#elif defined (HAVE_DLFCN_H)
#include <dlfcn.h>

RMODULE
r_module_open (const rchar * path, rboolean lazy, RModuleError * err)
{
  RMODULE mod;

  if ((mod = dlopen (path, lazy ? RTLD_LAZY : RTLD_NOW)) == NULL) {
    if (err != NULL)
      *err = R_MODULE_ERROR_NOT_FOUND;
  }

  return mod;
}
rpointer
r_module_lookup (RMODULE mod, const rchar * sym)
{
  return dlsym (mod, sym);
}
void
r_module_close (RMODULE mod)
{
  dlclose (mod);
}
#else
rboolean
r_module_open (const rchar * path, rboolean lazy, RModuleError * err)
{
  (void) path;
  (void) lazy;
  (void) err;
  return FALSE;
}
rpointer
r_module_lookup (RMODULE mod, const rchar * sym)
{
  (void) mod;
  (void) sym;
  return NULL;
}
void r_module_close (RMODULE mod)
{
  (void) mod;
}
#endif

