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
#if defined (HAVE_WINDOWS_H)
#include <winsock2.h>
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
/* Cap on how long the Win32 wait actually blocks. WSAEventSelect records a
 * network event with WSAEnumNetworkEvents but does not always *signal* the
 * event object the wait blocks on (FD_CLOSE in particular is edge-triggered).
 * Capping the wait turns an indefinite block into a periodic re-check: every
 * wake -- including a timeout -- re-runs WSAEnumNetworkEvents and so picks up
 * any recorded-but-unsignalled readiness within the cap rather than sleeping
 * through it. */
#define R_POLL_WIN32_MAX_WAIT_MS    1000

/* Map the requested R_IO_* readiness to the FD_* network events a socket is
 * associated with through WSAEventSelect. FD_CLOSE is folded into readability
 * so a peer reset / EOF wakes the read watcher (recv then reports the error). */
static long
r_poll_win32_fd_events (rushort events)
{
  long ret = 0;

  if (events & R_IO_IN)  ret |= FD_READ | FD_ACCEPT | FD_CLOSE;
  if (events & R_IO_OUT) ret |= FD_WRITE | FD_CONNECT;
  if (events & R_IO_PRI) ret |= FD_OOB;

  return ret;
}

int
r_poll (RPoll * handles, ruint count, RClockTime timeout)
{
  HANDLE waits[MAXIMUM_WAIT_OBJECTS];
  ruint i;
  int ret = 0;
  DWORD t, res;

  if (R_UNLIKELY (count > MAXIMUM_WAIT_OBJECTS)) {
    errno = E2BIG;
    return -1;
  }
  if (R_UNLIKELY (count == 0))
    return 0;

  if (timeout == 0)
    t = 0;
  else if (timeout == R_CLOCK_TIME_INFINITE)
    t = R_POLL_WIN32_MAX_WAIT_MS;
  else
    t = (DWORD) MIN (R_TIME_AS_MSECONDS (timeout) + 1, R_POLL_WIN32_MAX_WAIT_MS);

  /* Wait on the per-socket WSAEVENT (socket readiness) or, for a non-socket
   * handle such as the loop wakeup, on the handle itself. WSAEVENTs stay valid
   * even after their socket is closed, so a closed-but-not-yet-pruned socket
   * can no longer fail the whole wait the way a bare socket handle did. */
  for (i = 0; i < count; i++) {
    handles[i].revents = 0;
    waits[i] = (handles[i].wsaevent != NULL) ?
        (HANDLE)handles[i].wsaevent : (HANDLE)handles[i].handle;
  }

  res = WaitForMultipleObjectsEx ((DWORD)count, waits, FALSE, t, FALSE);
  /* Read actual readiness from every entry for every result: a normal wake, a
   * WAIT_TIMEOUT (re-enumerate to pick up an event recorded but not signalled,
   * see the cap above), or WAIT_FAILED (a single bad bare handle -- a socket
   * whose arming fell back to a direct wait, closed before it was pruned --
   * fails the whole call; the probe below skips it and the loop prunes it next
   * turn instead of stalling). */
  (void) res;

  for (i = 0; i < count; i++) {
    if (handles[i].wsaevent != NULL) {
      WSANETWORKEVENTS ne;
      rushort rev = 0;

      if (WSAEnumNetworkEvents ((SOCKET)(ruintptr)handles[i].handle,
            (WSAEVENT)handles[i].wsaevent, &ne) != 0)
        continue;   /* e.g. WSAENOTSOCK: a socket closed but not yet pruned */

      if (ne.lNetworkEvents & (FD_READ | FD_ACCEPT | FD_CLOSE)) rev |= R_IO_IN;
      if (ne.lNetworkEvents & FD_OOB)                           rev |= R_IO_PRI;
      if (ne.lNetworkEvents & (FD_WRITE | FD_CONNECT))          rev |= R_IO_OUT;
      /* A failed connect / abortive close surfaces as an error condition; the
       * loop watches WRITABLE for connect and READABLE for recv. */
      if ((ne.lNetworkEvents & FD_CONNECT) && ne.iErrorCode[FD_CONNECT_BIT] != 0)
        rev |= R_IO_ERR | R_IO_OUT;
      if ((ne.lNetworkEvents & FD_CLOSE) && ne.iErrorCode[FD_CLOSE_BIT] != 0)
        rev |= R_IO_ERR | R_IO_IN;

      if (rev != 0) {
        handles[i].revents = rev;
        ret++;
      }
    } else if (WaitForSingleObject ((HANDLE)handles[i].handle, 0) == WAIT_OBJECT_0) {
      handles[i].revents = handles[i].events;
      ret++;
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

#ifdef R_OS_WIN32
/* Associate a socket entry with a fresh WSAEVENT so r_poll can wait on its
 * readiness. A handle that is not a socket (the loop wakeup event) keeps
 * wsaevent == NULL and is waited on directly. */
static void
r_poll_entry_arm (RPoll * p)
{
  WSAEVENT ev;

  p->wsaevent = NULL;
  if ((ev = WSACreateEvent ()) == WSA_INVALID_EVENT)
    return;

  /* A non-socket handle (the loop wakeup) fails with WSAENOTSOCK and keeps
   * wsaevent == NULL, so it is waited on directly. */
  if (WSAEventSelect ((SOCKET)(ruintptr)p->handle, ev,
        r_poll_win32_fd_events (p->events)) == 0)
    p->wsaevent = ev;
  else
    WSACloseEvent (ev);
}

/* Re-issue the WSAEventSelect association after the watched events changed. */
static void
r_poll_entry_rearm (RPoll * p)
{
  if (p->wsaevent != NULL)
    WSAEventSelect ((SOCKET)(ruintptr)p->handle, (WSAEVENT)p->wsaevent,
        r_poll_win32_fd_events (p->events));
}

static void
r_poll_entry_disarm (RPoll * p)
{
  if (p->wsaevent != NULL) {
    WSAEventSelect ((SOCKET)(ruintptr)p->handle, NULL, 0);
    WSACloseEvent ((WSAEVENT)p->wsaevent);
    p->wsaevent = NULL;
  }
}

#define R_POLL_ENTRY_ARM(p)         r_poll_entry_arm (p)
#define R_POLL_ENTRY_REARM(p)       r_poll_entry_rearm (p)
#define R_POLL_ENTRY_DISARM(p)      r_poll_entry_disarm (p)
#define R_POLL_ENTRY_TAKE(dst, src) R_STMT_START {                            \
    (dst)->wsaevent = (src)->wsaevent; (src)->wsaevent = NULL;                \
  } R_STMT_END
#else
#define R_POLL_ENTRY_ARM(p)         R_STMT_START { } R_STMT_END
#define R_POLL_ENTRY_REARM(p)       R_STMT_START { } R_STMT_END
#define R_POLL_ENTRY_DISARM(p)      R_STMT_START { } R_STMT_END
#define R_POLL_ENTRY_TAKE(dst, src) R_STMT_START { } R_STMT_END
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
#ifdef R_OS_WIN32
  ruint i;
  for (i = 0; i < ps->count; i++)
    R_POLL_ENTRY_DISARM (&ps->handles[i]);
#endif

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

  if (ps->count >= ps->alloc) {
    do {
      ps->alloc += R_POLL_SET_MIN_INCREASE;
    } while (ps->count >= ps->alloc);
    ps->handles = r_realloc (ps->handles, sizeof (RPoll) * ps->alloc);
    if (R_UNLIKELY (ps->handles == NULL)) {
      /* FIXME: Error out properly */
      return -1;
    }
  }

  idx = ps->count++;
  r_poll_set_update (ps, idx, handle, events, user);
  R_POLL_ENTRY_ARM (&ps->handles[idx]);
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
    R_POLL_ENTRY_DISARM (&ps->handles[idx]);

    if ((ruint)idx < --ps->count) {
      RPoll * last = &ps->handles[ps->count];
      rpointer last_user;

      if (r_hash_table_lookup_full (ps->handle_user, RIO_HANDLE_TO_POINTER (last->handle),
            NULL, &last_user) == R_HASH_TABLE_OK) {
        r_poll_set_update (ps, (ruint)idx, last->handle, last->events, last_user);
        /* Carry the moved entry's WSAEVENT to its new slot (update only
         * rewrites the poll fields, not the association). */
        R_POLL_ENTRY_TAKE (&ps->handles[idx], last);
      } else {
        return FALSE;
      }
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

rboolean
r_poll_set_modify (RPollSet * ps, RIOHandle handle, rushort events)
{
  int idx;

  if (R_UNLIKELY (ps == NULL)) return FALSE;
  if ((idx = r_poll_set_find (ps, handle)) < 0)
    return FALSE;

  ps->handles[idx].events = events;
  R_POLL_ENTRY_REARM (&ps->handles[idx]);
  return TRUE;
}

