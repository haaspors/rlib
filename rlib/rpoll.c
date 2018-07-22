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
#include <rlib/rpoll.h>

#include <rlib/rtime.h>

#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef R_OS_WIN32
#define STRICT
#define WIN32_LEAN_AND_MEAN 1
#include <windows.h>
#endif

#if defined (HAVE_POLL)
int
r_poll (RPoll * handles, ruint count, RClockTime timeout)
{
  return poll ((struct pollfd *)handles, count, timeout == R_CLOCK_TIME_INFINITE ? -1 : R_TIME_AS_MSECONDS (timeout));
}
#elif defined (R_OS_WIN32)
int
r_poll (RPoll * handles, ruint count, RClockTime timeout)
{
  int ret;
  HANDLE win32_handles[MAXIMUM_WAIT_OBJECTS];
  ruint i;
  DWORD t, res;

  if (R_UNLIKELY (count > MAXIMUM_WAIT_OBJECTS)) {
    errno = E2BIG;
    return -1;
  }

  for (i = 0; i < count; i++)
    win32_handles[i] = handles[i].handle;

  for (ret = 0, i = 0, t = (timeout == R_CLOCK_TIME_INFINITE) ? INFINITE : (DWORD)R_TIME_AS_MSECONDS (timeout);
      i < count && (res = WaitForMultipleObjectsEx(count - i, &win32_handles[i], FALSE, t, TRUE)) < (count - i);
      ret++, i++, t = 0) {
    i += res;
    handles[i].revents = handles[i].events;
  }

  if (res == WAIT_FAILED) {
    switch (GetLastError ()) {
      case ERROR_INVALID_HANDLE:
        errno = EINVAL;
        break;
      /* FIXME: Add more error codes? */
      default:
        errno = EIO;
      }
    return -1;
  }

  return ret;
}
#elif defined (HAVE_SELECT)
int
r_poll (RPoll * handles, ruint count, RClockTime timeout)
{
  ruint i;
  fd_set rset, wset, xset;
  struct timeval tv;
  int ret, maxfd = 0;

  FD_ZERO (&rset);
  FD_ZERO (&wset);
  FD_ZERO (&xset);

  for (i = 0; i < count; i++) {
    if (handles[i].handle >= 0) {
      if (handles[i].events & R_IO_IN)
        FD_SET (handles[i].handle, &rset);
      if (handles[i].events & R_IO_OUT)
        FD_SET (handles[i].handle, &wset);
      if (handles[i].events & R_IO_PRI)
        FD_SET (handles[i].handle, &xset);
      if (handles[i].handle > maxfd && (handles[i].events & (R_IO_IN|R_IO_OUT|R_IO_PRI)))
        maxfd = handles[i].handle;
    }
  }

  R_TIME_TO_TIMEVAL (timeout, tv);
  if ((ret = select (maxfd + 1, &rset, &wset, &xset, timeout == R_CLOCK_TIME_INFINITE ? NULL : &tv)) > 0) {
    for (i = 0; i < count; i++) {
      handles[i].revents = 0;
      if (handles[i].handle >= 0) {
        if (FD_ISSET (handles[i].handle, &rset))
          handles[i].revents |= R_IO_IN;
        if (FD_ISSET (handles[i].handle, &wset))
          handles[i].revents |= R_IO_OUT;
        if (FD_ISSET (handles[i].handle, &xset))
          handles[i].revents |= R_IO_PRI;
      }
    }
  }

  return ret;
}
#else
#error Need either 'poll' or 'select'
#endif

