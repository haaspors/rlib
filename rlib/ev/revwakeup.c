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
#include "rev-private.h"
#include <rlib/ev/revwakeup.h>
#include <rlib/os/renv.h>    /* DIAG #310: r_getenv gate, revert before merge */
#include <rlib/os/rtty.h>    /* DIAG #310: r_printerr, revert before merge */

#include <rlib/rio.h>

#if defined (R_OS_WIN32)
#include <winsock2.h>   /* before windows.h: winsock select()/socketpair wakeup */
#endif
#if defined (HAVE_WINDOWS_H)
#include <windows.h>
#endif
#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#define R_LOG_CAT_DEFAULT &revlogcat

#if defined (R_OS_WIN32)
/* Windows winsock select() waits on sockets only, so the loop wakeup cannot be
 * an event handle -- it must be a connected socket pair (a self-pipe). Windows
 * has no socketpair(), so emulate one over the loopback interface: bind+listen
 * an ephemeral port, connect a second socket to it, accept the peer. The
 * connect completes against the loopback listener without an interleaved
 * accept, so this is safe on a single thread. @rd is the readable wait end,
 * @wr the end signalled to wake the loop; both are left non-blocking. */
static rboolean
r_ev_wakeup_win_socketpair (SOCKET * rd, SOCKET * wr)
{
  SOCKET listener = INVALID_SOCKET, c = INVALID_SOCKET, a = INVALID_SOCKET;
  struct sockaddr_in addr;
  int addrlen = (int) sizeof (addr);
  u_long nb = 1;

  if ((listener = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    goto fail;

  r_memclear (&addr, sizeof (addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (listener, (struct sockaddr *)&addr, sizeof (addr)) != 0) goto fail;
  if (getsockname (listener, (struct sockaddr *)&addr, &addrlen) != 0) goto fail;
  if (listen (listener, 1) != 0) goto fail;

  if ((c = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    goto fail;
  if (connect (c, (struct sockaddr *)&addr, addrlen) != 0) goto fail;
  if ((a = accept (listener, NULL, NULL)) == INVALID_SOCKET) goto fail;

  closesocket (listener);
  ioctlsocket (a, FIONBIO, &nb);
  ioctlsocket (c, FIONBIO, &nb);
  *rd = a;
  *wr = c;
  /* DIAG #310: log the pair so the wakeup's readable fd can be matched against
   * the r_poll fd-set trace. Revert before merge. */
  if (r_getenv ("DIAG310_POLL") != NULL)
    r_printerr ("DIAG310: wakeup_pair rd=%p wr=%p port=%u\n",
        (void *) (ruintptr) a, (void *) (ruintptr) c,
        (unsigned) ntohs (addr.sin_port));
  return TRUE;

fail:
  if (listener != INVALID_SOCKET) closesocket (listener);
  if (c != INVALID_SOCKET) closesocket (c);
  if (a != INVALID_SOCKET) closesocket (a);
  return FALSE;
}
#endif

static void
r_ev_wakeup_free (REvWakeup * wakeup)
{
  r_ev_wakeup_clear (wakeup);
  r_free (wakeup);
}

REvWakeup *
r_ev_wakeup_new (REvLoop * loop)
{
  REvWakeup * ret;

  if ((ret = r_mem_new (REvWakeup)) != NULL)
    r_ev_wakeup_init (ret, loop, (RDestroyNotify)r_ev_wakeup_free);

  return ret;
}

void
r_ev_wakeup_init (REvWakeup * wakeup, REvLoop * loop, RDestroyNotify notify)
{
  RIOHandle handle;

#if defined (R_OS_WIN32)
    SOCKET rd, wr;
    if (!r_ev_wakeup_win_socketpair (&rd, &wr)) {
      R_LOG_ERROR ("Failed to create wakeup socketpair for loop %p", loop);
      abort ();
    }
    handle = (RIOHandle)(ruintptr) rd;            /* readable wait end */
    wakeup->signal_handle = (RIOHandle)(ruintptr) wr;  /* signalled to wake */
    /* Both ends are sockets; closed with closesocket in r_ev_wakeup_clear. */
    wakeup->close_handle = R_IO_HANDLE_INVALID;
#elif defined (HAVE_EVENTFD)
    wakeup->signal_handle = handle = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
    wakeup->close_handle = R_IO_HANDLE_INVALID;
#elif defined (HAVE_PIPE2)
    int pipefd[2];
    if (pipe2 (pipefd, O_CLOEXEC | O_NONBLOCK) != 0) {
      R_LOG_ERROR ("Failed to initialize pipe for loop %p", loop);
      abort ();
    }
    handle = pipefd[0];
    wakeup->signal_handle = pipefd[1];
    wakeup->close_handle = pipefd[1];
#elif defined (HAVE_PIPE)
    int pipefd[2];
    if (pipe (pipefd) != 0) {
      R_LOG_ERROR ("Failed to initialize pipe for loop %p", loop);
      abort ();
    }
    handle = pipefd[0];
    wakeup->signal_handle = pipefd[1];
    wakeup->close_handle = pipefd[1];
#ifdef R_OS_UNIX
    r_io_unix_set_cloexec (pipefd[0], TRUE);
    r_io_unix_set_cloexec (pipefd[1], TRUE);
#endif
#else
#error No wakeup mechanism available?
#endif
  r_ev_io_init ((REvIO *)wakeup, loop, handle, notify);
}

void
r_ev_wakeup_clear (REvWakeup * wakeup)
{
#if defined (R_OS_WIN32)
  /* Both ends are sockets: closesocket, not r_io_close (CloseHandle). The
   * readable end (evio.handle) is otherwise never closed -- r_ev_io_clear does
   * not touch the handle. */
  if (wakeup->evio.handle != R_IO_HANDLE_INVALID)
    closesocket ((SOCKET)(ruintptr) wakeup->evio.handle);
  if (wakeup->signal_handle != R_IO_HANDLE_INVALID)
    closesocket ((SOCKET)(ruintptr) wakeup->signal_handle);
#else
  if (wakeup->close_handle != R_IO_HANDLE_INVALID)
    r_io_close (wakeup->close_handle);
#endif
  r_ev_io_clear ((REvIO *)wakeup);
}

void
r_ev_wakeup_read (REvWakeup * wakeup)
{
#if defined (R_OS_WIN32)
  char buf[64];
  int r;
  do {
    r = recv ((SOCKET)(ruintptr) wakeup->evio.handle, buf, sizeof (buf), 0);
  } while (r > 0);
#else
  int r;
  ruint64 buf;
  do {
    r = r_io_read (wakeup->evio.handle, &buf, sizeof (ruint64));
  } while (r >= 0 || errno == EINTR);
#endif
}

rboolean
r_ev_wakeup_signal (REvWakeup * wakeup)
{
#if defined (R_OS_WIN32)
  char b = 1;
  return send ((SOCKET)(ruintptr) wakeup->signal_handle, &b, 1, 0) == 1;
#else
  ruint64 buf = 1;
  return r_io_write (wakeup->signal_handle, &buf, sizeof (ruint64)) == sizeof (ruint64);
#endif
}

