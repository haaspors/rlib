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
#define _LARGEFILE64_SOURCE
#include <rlib/rfd.h>
#include <rlib/rfs.h>
#include <rlib/rstr.h>
#if defined (R_OS_WIN32)
#include <rlib/runicode.h>
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#elif defined (R_OS_UNIX)
#include <unistd.h>
#endif
#include <errno.h>

#if defined (__APPLE__) && defined (__MACH__)
#define lseek64 lseek
#endif

int
r_fd_open (const rchar * file, int flags, int mode)
{
  int fd = -1;
  if (R_UNLIKELY (file == NULL || *file == 0))
    return fd;

#ifdef R_OS_WIN32
  wchar_t * utf16file = r_utf8_to_utf16 (file, -1, NULL, NULL, NULL);
  fd = _wopen (utf16file, flags, mode);
  r_free (utf16file);
#else
  do {
    fd = open (file, flags, mode);
  } while (R_UNLIKELY (fd == -1 && errno == EINTR));
#endif

  return fd;
}

int
r_fd_open_tmp (const rchar * dir, const rchar * pre, rchar ** path)
{
  return r_fd_open_tmp_full (dir, pre, O_WRONLY, 0600, path);
}

int
r_fd_open_tmp_full (const rchar * dir, const rchar * fileprefix,
    int flags, int mode, rchar ** path)
{
  rchar * file;
  int fd = -1;

  if ((file = r_fs_path_new_tmpname_full (dir, fileprefix, "")) != NULL) {
    fd = r_fd_open (file, flags | O_CREAT | O_EXCL, mode);

    if (path != NULL && fd >= 0)
      *path = file;
    else
      r_free (file);
  }

  return fd;
}

rboolean
r_fd_close (int fd)
{
  int res;
#ifdef R_OS_WIN32
  res = _close (fd);
#else
  res = close (fd);
#endif
  return res == 0;
}

rssize
r_fd_write (int fd, rconstpointer buf, rsize size)
{
  rssize res;
#ifdef R_OS_WIN32
  res = (rssize)_write (fd, buf, (unsigned int)size);
#else
  res = write (fd, buf, size);
#endif
  return res;
}

rssize
r_fd_read (int fd, rpointer buf, rsize size)
{
  rssize res;
#ifdef R_OS_WIN32
  res = (rssize)_read (fd, buf, (unsigned int)size);
#else
  res = read (fd, buf, size);
#endif
  return res;
}

rssize
r_fd_tell (int fd)
{
  rssize res;
#ifdef R_OS_WIN32
  res = (rssize)_telli64 (fd);
#else
  res = lseek64 (fd, 0, SEEK_CUR);
#endif
  return res;
}

rssize
r_fd_seek (int fd, rssize offset, int mode)
{
  rssize res;
#ifdef R_OS_WIN32
  res = (rssize)_lseeki64 (fd, (__int64)offset, mode);
#else
  res = lseek64 (fd, offset, mode);
#endif
  return res;
}

rboolean
r_fd_truncate (int fd, rsize size)
{
  int res;
#ifdef R_OS_WIN32
  res = (int)_chsize_s (fd, (__int64)size);
#else
  res = ftruncate (fd, size);
#endif

  return res == 0;
}

#ifdef R_OS_WIN32
static int
fsync (int fd)
{
  HANDLE h = (HANDLE) _get_osfhandle (fd);

  if (h != INVALID_HANDLE_VALUE) {
    if (FlushFileBuffers (h)) {
      return 0;
    } else {
      switch (GetLastError ()) {
        case ERROR_ACCESS_DENIED: /* This is OK */
          return 0;
        case ERROR_INVALID_HANDLE:
          errno = EINVAL;
          break;
        default:
          errno = EIO;
        }
    }
  } else {
    errno = EBADF;
  }

  return -1;
}
#endif

rboolean
r_fd_flush (int fd)
{
  return fsync (fd) == 0;
}

