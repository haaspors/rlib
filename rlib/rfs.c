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
#include <rlib/rfs.h>
#include <rlib/rstr.h>
#include <rlib/rthreads.h>
#ifdef R_OS_WIN32
#include <rlib/runicode.h>
#include <windows.h>
#else
#include <unistd.h>
#include <errno.h>
#endif

rchar *
r_fs_path_basename (const rchar * file)
{
  rsize idxbeg, idxend;

  if (R_UNLIKELY (file == NULL))
    return NULL;
  if (R_UNLIKELY (file[0] == 0))
    return r_strdup (".");

  idxend = r_strlen (file) - 1;
  while (idxend > 0 && R_IS_DIR_SEP (file[idxend])) idxend--;
  if (idxend == 0)
    return r_strdup (".");
  idxbeg = idxend;
  while (idxbeg > 0 && !R_IS_DIR_SEP (file[idxbeg-1])) idxbeg--;

  return r_strndup (&file[idxbeg], idxend - idxbeg + 1);
}

rchar *
r_fs_path_dirname (const rchar * file)
{
  rsize idx;

  if (R_UNLIKELY (file == NULL))
    return NULL;
  if (R_UNLIKELY (file[0] == 0))
    return r_strdup (".");

  idx = r_strlen (file) - 1;
  while (idx > 0 && R_IS_DIR_SEP (file[idx])) idx--;
  while (idx > 0 && !R_IS_DIR_SEP (file[idx])) idx--;
  if (idx == 0)
    return r_strdup (R_IS_DIR_SEP (file[0]) ? R_DIR_SEP_STR : ".");

  return r_strndup (file, idx);
}

rchar *
r_fs_path_build (const rchar * first, ...)
{
  rchar * ret;
  va_list args;

  va_start (args, first);
  ret = r_fs_path_buildv (first, args);
  va_end (args);

  return ret;
}

static void
r_fs_path_strip_dirsep (rpointer data, rpointer user)
{
  rchar * str = data;
  rsize end;

  if (R_UNLIKELY (str == NULL || *str == 0))
    return;

  end = r_strlen (str) - 1;
  while (end > 0 && R_IS_DIR_SEP (str[end]))
    str[end--] = 0;

  /* user == first entry, which may have a leading dirsep! */
  if (data != user) {
    rsize beg = 0;

    while (beg < end && R_IS_DIR_SEP (str[beg])) beg++;
    if (beg > 0)
      r_memmove (str, &str[beg], end - beg + 2);
  }
}

rchar *
r_fs_path_buildv (const rchar * first, va_list args)
{
  rchar * ret;
  rchar ** strv;

  if (R_UNLIKELY (first == NULL))
    return NULL;

  strv = r_strv_newv (first, args);
  r_strv_foreach (strv, r_fs_path_strip_dirsep, strv[0]);
  ret = r_strv_join (strv, R_DIR_SEP_STR);
  r_strv_free (strv);

  return ret;
}

rchar *
r_fs_path_build_strv (rchar * const * strv)
{
  rchar * ret;
  rchar ** cpy = r_strv_copy (strv);
  r_strv_foreach (cpy, r_fs_path_strip_dirsep, strv[0]);

  ret = r_strv_join (cpy, R_DIR_SEP_STR);
  r_strv_free (cpy);

  return ret;
}

static const rchar *
r_fs_find_tmp_dir (void)
{
  const rchar * ret;

  if ((ret = getenv ("TEMP")) != NULL)        return ret;
  if ((ret = getenv ("TMP")) != NULL)         return ret;
  if ((ret = getenv ("TMPDIR")) != NULL)      return ret;
#ifdef R_OS_WIN32
  if ((ret = getenv ("USERPROFILE")) != NULL) return ret;
#endif

  return "/tmp";
}

const rchar *
r_fs_get_tmp_dir (void)
{
  static ROnce tmpdironce = R_ONCE_INIT;
  return r_call_once (&tmpdironce, (RThreadFunc)r_fs_find_tmp_dir, NULL);
}

rchar *
r_fs_get_cur_dir (void)
{
  rchar * ret = NULL;

#ifdef R_OS_WIN32
  runichar2 dummy[2], * curdir;
  int len = GetCurrentDirectoryW (2, dummy);

  curdir = r_mem_new_n (runichar2, len);
  if (GetCurrentDirectoryW (len, curdir) == len - 1)
    ret = r_utf16_to_utf8 (curdir, -1, NULL, NULL, NULL);
  r_free (curdir);
#else
  rsize maxlen = 1024;
  rchar * curdir, * tmp;

  do {
    curdir = r_mem_new_n (rchar, maxlen);
    *curdir = 0;

    if ((tmp = getcwd (curdir, maxlen - 1)) != NULL) {
      ret = r_strdup (tmp);
      r_free (curdir);
      break;
    }

    r_free (curdir);
    maxlen *= 2;
  } while (errno == ERANGE && maxlen < RINT16_MAX);
#endif

  return ret;
}

