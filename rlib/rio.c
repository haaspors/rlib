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
#include <rlib/rio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if defined (R_OS_WIN32)
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#endif

#include <errno.h>

rboolean
r_io_close (RIOHandle handle)
{
#if defined (R_OS_WIN32)
  return CloseHandle (handle);
#elif defined (R_OS_UNIX)
  return close (handle) == 0;
#else
  (void) handle;
  return FALSE;
#endif
}

rssize
r_io_write (RIOHandle handle, rconstpointer buf, rsize size)
{
#if defined (R_OS_WIN32)
  DWORD in = (DWORD)size, out = 0;
  if (WriteFile (handle, buf, in, &out, NULL))
    return out;
  return -1;
#elif defined (R_OS_UNIX)
  return write (handle, buf, size);
#else
  (void) handle;
  (void) buf;
  (void) size;
  return -1;
#endif
}

rssize
r_io_read (RIOHandle handle, rpointer buf, rsize size)
{
#if defined (R_OS_WIN32)
  DWORD in = (DWORD)size, out = 0;
  if (ReadFile (handle, buf, in, &out, NULL))
    return out;
  return -1;
#elif defined (R_OS_UNIX)
  return read (handle, buf, size);
#else
  (void) handle;
  (void) buf;
  (void) size;
  return -1;
#endif
}

rboolean
r_io_flush (RIOHandle handle)
{
#if defined (R_OS_WIN32)
  return FlushFileBuffers (handle);
#else
  return fsync (handle) == 0;
#endif
}

#ifdef R_OS_UNIX
rboolean
r_io_unix_set_nonblocking (RIOHandle handle, rboolean set)
{
  int res;

#ifdef HAVE_IOCTL
  do {
    res = ioctl (handle, FIONBIO, &set);
  } while (res < 0 && errno == EINTR);
  if (res == 0)
    return TRUE;
#endif

#ifdef HAVE_FCNTL
  do {
    res = fcntl (handle, F_GETFL);
  } while (res < 0 && errno == EINTR);

  if (!!(res & O_NONBLOCK) != !!set)
    return 0;

  if (set)
    res |= O_NONBLOCK;
  else
    res &= ~O_NONBLOCK;

  do {
    res = fcntl (handle, F_SETFL, res);
  } while (res < 0 && errno == EINTR);
  if (res == 0)
    return TRUE;
#endif

  return FALSE;
}
#endif

#ifdef R_OS_UNIX
rboolean
r_io_unix_set_cloexec (RIOHandle handle, rboolean set)
{
  int res;

#ifdef HAVE_IOCTL
  do {
    res = ioctl (handle, set ? FIOCLEX : FIONCLEX);
  } while (res < 0 && errno == EINTR);
  if (res == 0)
    return TRUE;
#endif

#ifdef HAVE_FCNTL
  do {
    res = fcntl (handle, F_GETFL);
  } while (res < 0 && errno == EINTR);

  if (!!(res & FD_CLOEXEC) != !!set)
    return 0;

  if (set)
    res |= FD_CLOEXEC;
  else
    res &= ~FD_CLOEXEC;

  do {
    res = fcntl (handle, F_SETFL, res);
  } while (res < 0 && errno == EINTR);
  if (res == 0)
    return TRUE;
#endif

  return FALSE;
}
#endif

