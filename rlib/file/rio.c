/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/file/rfile-private.h>
#include <rlib/file/rio.h>

#include <rlib/file/rfs.h>
#include <rlib/rmem.h>
#ifdef R_OS_WIN32
#include <rlib/charset/runicode.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <errno.h>

#if defined (R_OS_UNIX)
static int
r_file_permission_get_open_mode (const RFilePermission * perm)
{
  int ret;

  if (perm != NULL) {
    ret = (perm->user & 7) << 6 | (perm->group & 7) << 3 | (perm->others & 7) << 0;
  } else {
    ret = 0644;
  }

  return ret;
}
#endif

RIOHandle
r_io_open_file (const rchar * file, RFileOpenMode mode, RFileAccess access,
    RFileShareMode share, RFileFlags flags, const RFilePermission * perm)
{
  RIOHandle ret = R_IO_HANDLE_INVALID;
  if (R_UNLIKELY (file == NULL || *file == 0))
    return ret;

#ifdef RLIB_HAVE_FILES
#if defined (R_OS_WIN32)
  wchar_t * utf16file = r_utf8_to_utf16_dup (file, -1, NULL, NULL, NULL);
  DWORD a = 0, f = 0;

  if (access & R_FILE_READ)
    a |= GENERIC_READ;
  if (access & R_FILE_WRITE)
    a |= GENERIC_WRITE;
  if (access & R_FILE_EXECUTE)
    a |= FILE_EXECUTE;

  if (flags & R_FILE_FLAG_NONBLOCK)
    f |= FILE_FLAG_OVERLAPPED;
  /*if (flags & R_FILE_FLAG_CLOEXEC);*/
  if (flags & R_FILE_FLAG_TEMPORARY)
    f |= FILE_ATTRIBUTE_TEMPORARY;
  if (flags & R_FILE_FLAG_NO_CACHE)
    f |= FILE_FLAG_WRITE_THROUGH;

  ret = CreateFileW (utf16file, a, (DWORD)share, NULL, (DWORD)mode, f, NULL);
  r_free (utf16file);
#elif defined (R_OS_UNIX)
  int f, m;

  switch (mode) {
    case R_FILE_CREATE_NEW:
      f = O_CREAT | O_EXCL;
      break;
    case R_FILE_CREATE_ALWAYS:
      f = O_CREAT | O_TRUNC;
      break;
    case R_FILE_OPEN_EXISTING:
      f = 0;
      break;
    case R_FILE_OPEN_ALWAYS:
      f = O_CREAT;
      break;
    case R_FILE_TRUNCATE_EXISTING:
      f = O_TRUNC;
      break;
    default:
      return R_IO_HANDLE_INVALID;
  }

  if ((access & R_FILE_RDWR) == R_FILE_RDWR)
    f |= O_RDWR;
  else if (access & R_FILE_WRITE)
    f |= O_WRONLY;
  else
    f |= O_RDONLY;

  (void) share;

  if (flags & R_FILE_FLAG_NONBLOCK)
    f |= O_NONBLOCK;
  if (flags & R_FILE_FLAG_CLOEXEC)
    f |= O_CLOEXEC;
  /*if (flags & R_FILE_FLAG_TEMPORARY)*/
    /*f |= O_;*/
  if (flags & R_FILE_FLAG_DIRECTORY)
    f |= O_DIRECTORY;
#ifdef O_DIRECT
  if (flags & R_FILE_FLAG_NO_CACHE)
    f |= O_DIRECT;
#endif

  if (f & O_CREAT)
    m = r_file_permission_get_open_mode (perm);
  else
    m = 0;

  do {
    ret = open (file, f, m);
  } while (R_UNLIKELY (ret < 0 && errno == EINTR));
#endif
#else
  (void) mode;
  (void) access;
  (void) share;
  (void) flags;
#endif

  return ret;
}

RIOHandle
r_io_open_tmp_full (const rchar * dir, const rchar * fileprefix, RFileAccess access,
    RFileShareMode share, RFileFlags flags, const RFilePermission * perm, rchar ** path)
{
  rchar * file;
  RIOHandle ret;

  flags |= R_FILE_FLAG_TEMPORARY;
  if ((file = r_fs_path_new_tmpname_full (dir, fileprefix, "")) != NULL) {
    ret = r_io_open_file (file, R_FILE_CREATE_NEW, access, share, flags, perm);
    if (ret != R_IO_HANDLE_INVALID && path != NULL)
      *path = file;
    else
      r_free (file);
  } else {
    ret = R_IO_HANDLE_INVALID;
  }

  return ret;
}

rboolean
r_io_truncate (RIOHandle handle, rsize size)
{
#if defined (R_OS_WIN32)
  LARGE_INTEGER pos;
  pos.QuadPart = size;
  return SetFilePointerEx (handle, pos, NULL, FILE_BEGIN) && SetEndOfFile (handle);
#elif defined (R_OS_UNIX)
  return ftruncate (handle, size) == 0;
#else
  (void) handle;
  (void) size;
  return FALSE;
#endif
}

roffset
r_io_seek (RIOHandle handle, roffset offset, RSeekMode mode)
{
  roffset ret;
#if defined (R_OS_WIN32)
  LARGE_INTEGER pos;
  LARGE_INTEGER out;
  pos.QuadPart = offset;
  if (SetFilePointerEx (handle, pos, &out, r_file_seek_mode_to_method (mode))) {
    ret = out.QuadPart;
  } else {
    ret = -1;
  }
#elif defined (HAVE_LSEEK64)
  ret = (roffset)lseek64 (handle, offset, r_file_seek_mode_to_whence (mode));
#elif defined (HAVE_LSEEK)
  ret = (roffset)lseek (handle, (off_t)offset, r_file_seek_mode_to_whence (mode));
#else
  (void) handle;
  (void) offset;
  (void) mode;
  ret = -1;
#endif

  return ret;
}


ruint64
r_io_filesize (RIOHandle handle)
{
  ruint64 ret = 0;

#if defined (R_OS_WIN32)
  GetFileSizeEx (handle, &ret);
#elif defined (HAVE_FSTAT)
  struct stat st;
  if (fstat (handle, &st) == 0)
    ret = (ruint64)st.st_size;
#else
  roffset res, cur;
  cur = r_io_seek (handle, 0, R_SEEK_MODE_CUR);
  if ((res = r_io_seek (handle, 0, R_SEEK_MODE_END)) >= 0)
    ret = (ruint64)res;
  r_io_seek (handle, cur, R_SEEK_MODE_SET)
#endif

  return ret;
}

