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

#include <rlib/rassert.h>
#include <rlib/rmem.h>
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
#include <errno.h>

#define R_POLL_SET_MIN_INCREASE     64

#if defined (HAVE_PPOLL)
int
r_poll (RPoll * handles, ruint count, RClockTime timeout)
{
  int ret;
  struct timespec ts, * pts;

  if (timeout != R_CLOCK_TIME_INFINITE) {
    R_TIME_TO_TIMESPEC (timeout, ts);
    pts = &ts;
  } else {
    pts = NULL;
  }

  do {
    ret = ppoll ((struct pollfd *)handles, count, pts, NULL);
  } while (ret < 0 && errno == EINTR);

  return ret;
}
#elif defined (HAVE_POLL)
int
r_poll (RPoll * handles, ruint count, RClockTime timeout)
{
  int ret, t;

  if (timeout == R_CLOCK_TIME_INFINITE) {
    t = -1;
  } else if (timeout != 0) {
    t = R_TIME_AS_MSECONDS (timeout) + 1;
  } else {
    t = 0;
  }

  do {
    ret = poll ((struct pollfd *)handles, count, t);
  } while (ret < 0 && errno == EINTR);

  return ret;
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

  if (timeout == R_CLOCK_TIME_INFINITE) {
    t = INFINITE;
  } else if (timeout != 0) {
    t = R_TIME_AS_MSECONDS (timeout) + 1;
  } else {
    t = 0;
  }

  for (i = 0; i < count; i++)
    win32_handles[i] = handles[i].handle;

  for (ret = 0, i = 0; i < count; ret++, i++, t = 0) {
    res = WaitForMultipleObjectsEx (count - i, &win32_handles[i], FALSE, t, TRUE);

    if (res < (WAIT_OBJECT_0 + count - i)) {
      i += res;
      handles[i].revents = handles[i].events;
    } else if (res == WAIT_FAILED) {
      DWORD dw;
      LPVOID lpMsgBuf;

      switch ((dw = GetLastError ())) {
      case ERROR_INVALID_HANDLE:
        errno = EINVAL;
        break;
      /* FIXME: Add more error codes? */
      default:
        errno = EIO;
      }

      FormatMessageA (FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
          NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR) &lpMsgBuf, 0, NULL);
      R_LOG_CAT_ERROR (R_LOG_CAT_ASSERT, "WaitForMultipleObjectsEx error '%s'", lpMsgBuf);
      LocalFree (lpMsgBuf);
      return -1;
    } else if (res == WAIT_TIMEOUT) {
      break;
    } else if (res == WAIT_IO_COMPLETION) {
      // FIXME: WAIT_IO_COMPLETION
      r_assert_not_reached ();
    } else {
      // FIXME: What to do when we get WAIT_ABANDONED_0
      r_assert_not_reached ();
    }
  }

  return ret;
}
#elif defined (HAVE_SELECT)
static inline int
r_select (int nfds, fd_set * r, fd_set * w, fd_set * e, struct timeval * t)
{
  int ret;

  do {
    ret = select (nfds, r, w, e, t);
  } while (ret < 0 && errno == EINTR);

  return ret;
}

int
r_poll (RPoll * handles, ruint count, RClockTime timeout)
{
  ruint i;
  fd_set rset, wset, xset;
  struct timeval tv, * ptv;
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

  if (timeout != R_CLOCK_TIME_INFINITE) {
    R_TIME_TO_TIMEVAL (timeout, tv);
    ptv = &tv;
  } else {
    ptv = NULL;
  }

  if ((ret = r_select (maxfd + 1, &rset, &wset, &xset, ptv)) > 0) {
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

void
r_poll_set_init (RPollSet * ps, ruint alloc)
{
  ps->handle_user = r_hash_table_new (NULL, NULL);
  ps->handle_idx = r_hash_table_new (NULL, NULL);
  ps->count = 0;
  ps->alloc = MAX (alloc, R_POLL_SET_MIN_INCREASE);
  ps->handles = r_mem_new0_n (RPoll, ps->alloc);
}

void
r_poll_set_clear (RPollSet * ps)
{
  r_free (ps->handles);
  r_hash_table_unref (ps->handle_idx);
  r_hash_table_unref (ps->handle_user);

  r_memclear (ps, sizeof (RPollSet));
}

int
r_poll_set_find (RPollSet * ps, RIOHandle handle)
{
  rpointer val;

  if (ps != NULL && r_hash_table_lookup_full (ps->handle_idx,
        RIO_HANDLE_TO_POINTER (handle), NULL, &val) == R_HASH_TABLE_OK)
    return RPOINTER_TO_UINT (val);

  return RUINT_MAX;
}

rpointer
r_poll_set_get_user (RPollSet * ps, RIOHandle handle)
{
  if (R_UNLIKELY (ps == NULL)) return NULL;

  return r_hash_table_lookup (ps->handle_user, RIO_HANDLE_TO_POINTER (handle));
}

static void
r_poll_set_update (RPollSet * ps, ruint idx, RIOHandle handle, rushort events, rpointer user)
{
  r_hash_table_insert (ps->handle_user, RIO_HANDLE_TO_POINTER (handle), user);
  r_hash_table_insert (ps->handle_idx, RIO_HANDLE_TO_POINTER (handle),
      RUINT_TO_POINTER (idx));

  ps->handles[idx].handle = handle;
  ps->handles[idx].events = events;
  ps->handles[idx].revents = 0;
}

int
r_poll_set_add (RPollSet * ps, RIOHandle handle, rushort events, rpointer user)
{
  ruint idx;

  if (R_UNLIKELY (ps == NULL)) return -1;
  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return -1;

  if (ps->alloc < ps->count) {
    do {
      ps->alloc += R_POLL_SET_MIN_INCREASE;
    } while (ps->alloc < ps->count);
    ps->handles = r_realloc (ps->handles, sizeof (RPoll) * ps->alloc);
    if (R_UNLIKELY (ps->handles == NULL)) {
      /* FIXME: Error out properly */
      return -1;
    }
  }

  idx = ps->count++;
  r_poll_set_update (ps, idx, handle, events, user);
  return (int)idx;
}

static rboolean
r_poll_set_remove_idx (RPollSet * ps, int idx)
{
  rpointer key, user;

  if (R_UNLIKELY (idx < 0)) return FALSE;
  if (R_UNLIKELY ((ruint)idx >= ps->count)) return FALSE;

  key = RIO_HANDLE_TO_POINTER (ps->handles[idx].handle);
  if (r_hash_table_remove_full (ps->handle_user, key, NULL, &user) == R_HASH_TABLE_OK) {
    r_hash_table_remove (ps->handle_idx, key);

    if ((ruint)idx < --ps->count) {
      RPoll * last = &ps->handles[ps->count];
      rpointer last_user;

      if (r_hash_table_lookup_full (ps->handle_user, RIO_HANDLE_TO_POINTER (last->handle),
            NULL, &last_user) == R_HASH_TABLE_OK)
        r_poll_set_update (ps, (ruint)idx, last->handle, last->events, last_user);
      else
        return FALSE;
    }

    return TRUE;
  }

  return FALSE;
}

rboolean
r_poll_set_remove (RPollSet * ps, RIOHandle handle)
{
  if (R_UNLIKELY (ps == NULL)) return FALSE;
  return r_poll_set_remove_idx (ps, r_poll_set_find (ps, handle));
}

