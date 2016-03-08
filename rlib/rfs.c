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
#include <rlib/rrand.h>
#include <rlib/rthreads.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined (R_OS_WIN32)
#include <rlib/runicode.h>
#include <windows.h>
#elif defined (R_OS_UNIX)
#include <unistd.h>
#include <errno.h>
#endif

#define RFS_PATH_RAND_MAX_TRIES    1024

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

rchar *
r_fs_path_new_tmpname_full (const rchar * dir,
    const rchar * prefix, const rchar * suffix)
{
  static const rchar candidates[] =
    "0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static const rsize cands = sizeof (candidates) - 1;
  rchar * name, * file, * r = r_alloca (7);
  RPrng * prng = r_rand_prng_new ();
  int tries = 0;

  if (dir == NULL) dir = r_fs_get_tmp_dir ();
  if (prefix == NULL) prefix = "";
  if (suffix == NULL) suffix = "";

  r[6] = 0;
  file = NULL;

  do {
    int i;
    for (i = 0; i < 6; i++)
      r[i] = candidates[r_prng_get_u64 (prng) % cands];

    r_free (file);
    name = r_strprintf ("%s%s%s", prefix, r, suffix);
    file = r_fs_path_build (dir, name, NULL);
    r_free (name);
  } while (r_fs_test_exists (file) && ++tries < RFS_PATH_RAND_MAX_TRIES);

  r_prng_unref (prng);
  return file;
}

static const rchar *
r_fs_find_tmp_dir (void)
{
#ifdef RLIB_HAVE_FILES
  const rchar * ret;

  if ((ret = getenv ("TEMP")) != NULL)        return ret;
  if ((ret = getenv ("TMP")) != NULL)         return ret;
  if ((ret = getenv ("TMPDIR")) != NULL)      return ret;
#ifdef R_OS_WIN32
  if ((ret = getenv ("USERPROFILE")) != NULL) return ret;
#endif

  return "/tmp";
#else
  return NULL;
#endif
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

#ifdef RLIB_HAVE_FILES
#if defined (R_OS_WIN32)
  runichar2 dummy[2], * curdir;
  int len = GetCurrentDirectoryW (2, dummy);

  curdir = r_mem_new_n (runichar2, len);
  if (GetCurrentDirectoryW (len, curdir) == len - 1)
    ret = r_utf16_to_utf8 (curdir, -1, NULL, NULL, NULL);
  r_free (curdir);
#elif defined (R_OS_UNIX)
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
#else
#error "OS not supported"
#endif
#endif

  return ret;
}

rssize
r_fs_get_filesize (const rchar * path)
{
  rssize ret;
#ifdef R_OS_WIN32
  runichar2 * upath;

  if ((upath = r_utf8_to_utf16 (path, -1, NULL, NULL, NULL)) != NULL) {
    struct __stat64 s;
    if (_wstat64 (upath, &s) == 0) {
      ret = s.st_size;
    } else {
      ret = -1;
    }
  } else {
    ret = -1;
  }
#else
  struct stat s;
  if (stat (path, &s) == 0) {
    ret = s.st_size;
  } else {
    ret = -1;
  }
#endif
  return ret;
}

#ifdef R_OS_WIN32
static DWORD
r_fs_get_file_attributes (const rchar * path)
{
  DWORD ret;
  runichar2 * upath;

  if ((upath = r_utf8_to_utf16 (path, -1, NULL, NULL, NULL)) != NULL) {
    ret = GetFileAttributesW (upath);
    r_free (upath);
  } else {
    ret = INVALID_FILE_ATTRIBUTES;
  }

  return ret;
}

static DWORD
r_fs_get_file_access (const rchar * path, DWORD req)
{
  DWORD ret = 0;
  runichar2 * upath;

  if ((upath = r_utf8_to_utf16 (path, -1, NULL, NULL, NULL)) != NULL) {
    DWORD len = 0;
    HANDLE token = NULL;

    if (OpenProcessToken (GetCurrentProcess (),
          TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_QUERY | STANDARD_RIGHTS_READ,
          &token)) {
      HANDLE impToken = NULL;
      if (DuplicateToken (token, SecurityImpersonation, &impToken)) {
        PSECURITY_DESCRIPTOR secdesc;

        GetFileSecurityW (upath,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            NULL, len, &len);
        if (len > 0 && (secdesc = r_malloc (len)) != NULL) {
          if (GetFileSecurityW (upath,
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                secdesc, len, &len)) {
            GENERIC_MAPPING mapping = { 0xFFFFFFFF };
            PRIVILEGE_SET privset = { 0 };
            DWORD privsetlen = sizeof (PRIVILEGE_SET);
            BOOL result = FALSE;
            DWORD granted = 0;

            mapping.GenericRead = FILE_GENERIC_READ;
            mapping.GenericWrite = FILE_GENERIC_WRITE;
            mapping.GenericExecute = FILE_GENERIC_EXECUTE;
            mapping.GenericAll = FILE_ALL_ACCESS;

            MapGenericMask (&req, &mapping);
            if (AccessCheck (secdesc, impToken, req, &mapping, &privset, &privsetlen,
                &granted, &result) && result)
              ret = granted;
          }

          r_free (secdesc);
        }

        CloseHandle (impToken);
      }

      CloseHandle (token);
    }

    r_free (upath);
  }

  return ret;
}
#endif

rboolean
r_fs_test_exists (const rchar * path)
{
#if defined (R_OS_WIN32)
  return r_fs_get_file_attributes (path) != INVALID_FILE_ATTRIBUTES;
#elif defined (R_OS_UNIX)
  return access (path, F_OK) == 0;
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_test_is_directory (const rchar * path)
{
#if defined (R_OS_WIN32)
  DWORD a = r_fs_get_file_attributes (path);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#elif defined (R_OS_UNIX)
  struct stat s;
  return (stat (path, &s) == 0) && S_ISDIR (s.st_mode);
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_test_is_regular (const rchar * path)
{
#if defined (R_OS_WIN32)
  DWORD a = r_fs_get_file_attributes (path);
  return (a & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)) == 0;
#elif defined (R_OS_UNIX)
  struct stat s;
  return (stat (path, &s) == 0) && S_ISREG (s.st_mode);
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_test_is_device (const rchar * path)
{
#if defined (R_OS_WIN32)
  DWORD a = r_fs_get_file_attributes (path);
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DEVICE);
#elif defined (R_OS_UNIX)
  struct stat s;
  return (stat (path, &s) == 0) && (S_ISCHR (s.st_mode) || S_ISBLK (s.st_mode));
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_test_is_symlink (const rchar * path)
{
#if defined (R_OS_WIN32)
  /* FIXME: Symlinks on windows? */
  (void) path;
  return FALSE;
#elif defined (R_OS_UNIX)
  struct stat s;
  return (lstat (path, &s) == 0) && S_ISLNK (s.st_mode);
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_test_read_access (const rchar * path)
{
#if defined (R_OS_WIN32)
  return r_fs_get_file_access (path, GENERIC_READ) != 0;
#elif defined (R_OS_UNIX)
  return access (path, R_OK) == 0;
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_test_write_access (const rchar * path)
{
#if defined (R_OS_WIN32)
  return r_fs_get_file_access (path, GENERIC_WRITE) != 0;
#elif defined (R_OS_UNIX)
  return access (path, W_OK) == 0;
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_test_exec_access (const rchar * path)
{
#if defined (R_OS_WIN32)
  return r_fs_get_file_access (path, GENERIC_EXECUTE) != 0;
#elif defined (R_OS_UNIX)
  return access (path, X_OK) == 0;
#else
  (void) path;
  return FALSE;
#endif
}

rboolean
r_fs_mkdir (const rchar * path, int mode)
{
#if defined (R_OS_WIN32)
  rboolean ret;
  runichar2 * upath;

  (void) mode;

  if ((upath = r_utf8_to_utf16 (path, -1, NULL, NULL, NULL)) != NULL) {
    ret = _wmkdir (upath) == 0;
    r_free (upath);
  } else {
    ret = FALSE;
  }

  return ret;
#elif defined (R_OS_UNIX)
  return mkdir (path, mode) == 0;
#else
  (void) path;
  (void) mode;
  return FALSE;
#endif
}

rboolean
r_fs_mkdir_full (const rchar * path, int mode)
{
  rchar * parent;
  rboolean ret;

  if (R_UNLIKELY (path == NULL))
    return FALSE;
  if ((path[0] == '.' || R_IS_DIR_SEP (path[0])) && path[1] == 0)
    return TRUE;
  if (r_fs_test_is_directory (path))
    return TRUE;

  parent = r_fs_path_dirname (path);
  ret = r_fs_mkdir_full (parent, mode);
  r_free (parent);

  return ret ? r_fs_mkdir (path, mode) : FALSE;
}

