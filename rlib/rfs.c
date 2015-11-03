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
#include <string.h>

rchar *
r_fs_path_basename (const rchar * file)
{
  rsize idxbeg, idxend;

  if (R_UNLIKELY (file == NULL))
    return NULL;
  if (R_UNLIKELY (file[0] == 0))
    return r_strdup (".");

  idxend = strlen (file) - 1;
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

  idx = strlen (file) - 1;
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

rchar *
r_fs_path_buildv (const rchar * first, va_list args)
{
  rchar * ret;
  rchar ** strv;

  if (R_UNLIKELY (first == NULL))
    return NULL;

  strv = r_strv_newv (first, args);
  ret = r_fs_path_build_strv (strv);
  r_strv_free (strv);

  return ret;
}

rchar *
r_fs_path_build_strv (rchar * const * strv)
{
  return r_strv_join (strv, R_DIR_SEP_STR);
}

