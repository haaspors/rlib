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

#include <rlib/rio.h>

#if defined (R_OS_WIN32)
#define WIN32_LEAN_AND_MEAN 1
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
    wakeup->signal_handle = handle = CreateEvent (NULL, TRUE, FALSE, NULL);
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
  if (wakeup->close_handle != R_IO_HANDLE_INVALID)
    r_io_close (wakeup->close_handle);
  r_ev_io_clear ((REvIO *)wakeup);
}

void
r_ev_wakeup_read (REvWakeup * wakeup)
{
#if defined (R_OS_WIN32)
  ResetEvent ((HANDLE) wakeup->signal_handle);
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
  return SetEvent ((HANDLE) wakeup->signal_handle);
#else
  ruint64 buf = 1;
  return r_io_write (wakeup->signal_handle, &buf, sizeof (ruint64)) == sizeof (ruint64);
#endif
}

