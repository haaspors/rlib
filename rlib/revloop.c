/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rlib-private.h"
#include <rlib/revloop.h>

#include <rlib/ratomic.h>
#include <rlib/rlist.h>
#include <rlib/rmem.h>
#include <rlib/rqueue.h>

#include <sys/types.h>
#include <string.h>
#ifdef R_OS_UNIX
#include <unistd.h>
#endif
#ifdef HAVE_KQUEUE
#include <sys/event.h>
#endif
#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <errno.h>

R_LOG_CATEGORY_DEFINE_STATIC (evloopcat, "revloop", "RLib EvLoop", R_CLR_BG_YELLOW);
#define R_LOG_CAT_DEFAULT &evloopcat

void
r_ev_loop_init (void)
{
  r_log_category_register (&evloopcat);
}

void
r_ev_loop_deinit (void)
{
}

static raptr g__r_ev_loop_default; /* (REvLoop *) */

typedef struct {
  REvIOEvents events;
  REvIOCB io_cb;
  rpointer data;
  RDestroyNotify notify;
} REvIOCtx;

typedef struct {
  REvIOFunc close_cb;
  rpointer data;
  RDestroyNotify notify;
} REvIOCloseCtx;

struct _REvIO {
  RRef ref;

  REvLoop * loop;
  RList * alnk; /* If NULL -> inactive, else -> link in REvLoop::active queue */
  RList * chglnk; /* If not NULL -> changing link in REvLoop::chg queue */
  REvIOCloseCtx close_ctx;

  REvHandle handle;
  REvIOCtx current;
  REvIOCtx pending;
};

#define R_EV_IO_IS_ACTIVE(evio) ((evio->alnk) != NULL)
#define R_EV_IO_IS_CHANGING(evio) ((evio->chglnk) != NULL)

#define r_ev_io_ctx_init(ctx, e, cb, d, n)                                    \
  R_STMT_START {                                                              \
    (ctx)->events = e;                                                        \
    (ctx)->io_cb = cb;                                                        \
    (ctx)->data = d;                                                          \
    (ctx)->notify = n;                                                        \
  } R_STMT_END
#define r_ev_io_ctx_clear(ctx)                                                \
  R_STMT_START {                                                              \
    if ((ctx)->notify != NULL) (ctx)->notify ((ctx)->data);                   \
    r_memset (ctx, 0, sizeof (REvIOCtx));                                     \
  } R_STMT_END
#define r_ev_io_invoke_cb(evio, events)                                       \
  R_STMT_START {                                                              \
    (evio)->current.io_cb ((evio)->current.data, events, evio);               \
  } R_STMT_END


struct _REvLoop {
  RRef ref;

  rboolean stop_request;
  RClockTime ts;
  RClock * clock;

  /* For various callbacks */
  RCBQueue acbs;
  RCBQueue bcbs;
  RCBRList * prepare;
  RCBRList * idle;

  /* For IO events */
  REvHandle evhandle;
  RQueue active;
  RQueue chg;
};

#define R_EV_LOOP_MAX_EVENTS 1024

static void
r_ev_loop_free (REvLoop * loop)
{
  REvLoop * prev = loop;
  r_atomic_ptr_cmp_xchg_strong (&g__r_ev_loop_default, &prev, NULL);

  r_queue_clear (&loop->chg, NULL);
  r_queue_clear (&loop->active, NULL);
  r_cbrlist_destroy (loop->prepare);  loop->prepare = NULL;
  r_cbrlist_destroy (loop->idle);     loop->idle = NULL;
  r_cbqueue_clear (&loop->acbs);
  r_cbqueue_clear (&loop->bcbs);

  r_clock_unref (loop->clock); loop->clock = NULL;

  if (loop->evhandle != R_EV_HANDLE_INVALID) {
    r_ev_handle_close (loop->evhandle);
    loop->evhandle = R_EV_HANDLE_INVALID;
  }

  r_free (loop);
}

static void
r_ev_loop_setup (REvLoop * loop, RClock * clock)
{
  loop->stop_request = FALSE;
  r_cbqueue_init (&loop->bcbs);
  r_cbqueue_init (&loop->acbs);
  loop->prepare = loop->idle = NULL;
  r_queue_init (&loop->active);
  r_queue_init (&loop->chg);

  loop->clock = clock != NULL ? r_clock_ref (clock) : r_system_clock_get ();
  loop->ts = r_clock_get_time (loop->clock);

#if defined (R_OS_WIN32)
#elif defined (HAVE_EPOLL)
  loop->evhandle = epoll_create1 (0);
#elif defined (HAVE_KQUEUE)
  loop->evhandle = kqueue ();
#endif
}

REvLoop *
r_ev_loop_new_full (RClock * clock)
{
  REvLoop * loop;

  if ((loop = r_mem_new (REvLoop)) != NULL) {
    REvLoop * prev = NULL;
    r_ref_init (loop, r_ev_loop_free);
    r_ev_loop_setup (loop, clock);

    r_atomic_ptr_cmp_xchg_strong (&g__r_ev_loop_default, &prev, loop);
  }

  return loop;
}

REvLoop *
r_ev_loop_default (void)
{
  return r_atomic_ptr_load (&g__r_ev_loop_default);
}

static inline void
r_ev_loop_prepare (REvLoop * loop)
{
  loop->prepare = r_cbrlist_call (loop->prepare);
}

static inline void
r_ev_loop_idle (REvLoop * loop)
{
  loop->idle = r_cbrlist_call (loop->idle);
}

static void
r_ev_loop_update_timers (REvLoop * loop)
{
  r_clock_process_entries (loop->clock, &loop->ts);
}

static void
r_ev_loop_invoke_bcbs (REvLoop * loop)
{
  RCBList * lst;

  while ((lst = r_cbqueue_pop (&loop->bcbs)) != NULL) {
    lst->cb (lst->data, lst->user);
    r_cblist_free1 (lst);
  }
}

static void
r_ev_loop_invoke_acbs (REvLoop * loop)
{
  RCBList * lst;

  while ((lst = r_cbqueue_pop (&loop->acbs)) != NULL) {
    lst->cb (lst->data, lst->user);
    r_cblist_free1 (lst);
  }
}

static RClockTime
r_ev_loop_next_deadline (REvLoop * loop, REvLoopRunMode mode)
{
  if (mode == R_EV_LOOP_RUN_NOWAIT) return loop->ts;
  if (loop->stop_request) return loop->ts;
  if (loop->idle != NULL) return loop->ts;
  if (r_cbqueue_size (&loop->acbs) > 0) return loop->ts;
  if (r_clock_timeout_count (loop->clock) == 0 && r_queue_size (&loop->active) == 0) return loop->ts;

  return r_clock_first_timeout (loop->clock);
}

static int
r_ev_loop_io_wait (REvLoop * loop, RClockTime deadline)
{
  REvIO * evio;
  RClockTime timeout;
  int ret, i;

#if defined (R_OS_WIN32)
  (void) loop;
  (void) deadline;
  (void) timeout;
  (void) evio;
  (void) i;

  /* TODO: Implement win32 backend */
  ret = -1;
  goto beach;
#elif defined (HAVE_EPOLL)
  struct epoll_event events[R_EV_LOOP_MAX_EVENTS], * ev = events;

  while ((evio = r_queue_pop (&loop->chg)) != NULL) {
    int op;

    if (R_UNLIKELY (evio->handle == R_EV_HANDLE_INVALID))
      continue;

    R_LOG_DEBUG ("loop %p changes evio "R_EV_IO_FORMAT, loop, R_EV_IO_ARGS (evio));

    ev->data.ptr = evio;
    ev->events = EPOLLET;
    if (evio->pending.events & R_EV_IO_READABLE) ev->events |= EPOLLIN;
    if (evio->pending.events & R_EV_IO_WRITABLE) ev->events |= EPOLLOUT;
    if (evio->pending.events & R_EV_IO_HANGUP)   ev->events |= EPOLLRDHUP;
    op = (evio->current.events == 0) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;
    if (epoll_ctl (loop->evhandle, op, evio->handle, ev) == 0) {
      r_ev_io_ctx_clear (&evio->current);
      r_memcpy (&evio->current, &evio->pending, sizeof (REvIOCtx));
    } else {
      R_LOG_ERROR ("epoll_ctl for loop %p failed %d: \"%s\" with operation %d for fd: %d",
          loop, errno, strerror (errno), op, evio->handle);

      r_ev_io_ctx_clear (&evio->pending);
      if (errno == EPERM)
        r_ev_io_invoke_cb (evio, R_EV_IO_ERROR);
      else
        abort ();
    }

    r_memset (&evio->pending, 0, sizeof (REvIOCtx));
  }

  if (R_CLOCK_TIME_IS_VALID (deadline) && deadline >= loop->ts)
    timeout = deadline - loop->ts;
  else
    timeout = R_CLOCK_TIME_NONE;

  R_LOG_DEBUG ("loop %p WAIT for %"R_TIME_FORMAT, loop, R_TIME_ARGS (timeout));
  do {
    int tms = -1;
    if (R_CLOCK_TIME_IS_VALID (timeout))
      tms = MAX (R_TIME_AS_MSECONDS (timeout), 1);
    R_LOG_TRACE ("executing epoll_wait for loop %p with timeout %d", loop, tms);
    ret = epoll_wait (loop->evhandle, events, R_N_ELEMENTS (events), tms);
  } while (ret < 0 && errno == EINTR);

  if (ret < 0) {
    R_LOG_ERROR ("epoll_wait for loop %p failed with error %d", loop, ret);
    goto beach;
  }

  R_LOG_DEBUG ("epoll_wait for loop %p with %d events", loop, ret);
  for (i = 0; i < ret; i++) {
    REvIOEvents rev = 0;
    ev = &events[i];
    evio = ev->data.ptr;

    if (ev->events & EPOLLERR)  rev |= R_EV_IO_ERROR;
    if (ev->events & EPOLLHUP)  rev |= R_EV_IO_HANGUP;
    if (ev->events & EPOLLIN)   rev |= R_EV_IO_READABLE;
    if (ev->events & EPOLLOUT)  rev |= R_EV_IO_WRITABLE;

    if (R_LIKELY (rev != 0))
      r_ev_io_invoke_cb (evio, rev);
  }
#elif defined (HAVE_KQUEUE)
  struct kevent events[R_EV_LOOP_MAX_EVENTS], * ev;
  struct timespec spec = { 0, 0 };
  int nev = 0;

  while ((evio = r_queue_pop (&loop->chg)) != NULL) {
    if (R_UNLIKELY (evio->handle == R_EV_HANDLE_INVALID))
      continue;

    R_LOG_DEBUG ("loop %p changes evio "R_EV_IO_FORMAT, loop, R_EV_IO_ARGS (evio));

    if (evio->pending.events & R_EV_IO_READABLE && !(evio->current.events & R_EV_IO_READABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, evio);
    else if (evio->current.events & R_EV_IO_READABLE && !(evio->pending.events & R_EV_IO_READABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_READ, EV_DELETE, 0, 0, evio);
    if (evio->pending.events & R_EV_IO_WRITABLE && !(evio->current.events & R_EV_IO_WRITABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, evio);
    else if (evio->current.events & R_EV_IO_WRITABLE && !(evio->pending.events & R_EV_IO_WRITABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_READ, EV_DELETE, 0, 0, evio);

    r_ev_io_ctx_clear (&evio->current);
    r_memcpy (&evio->current, &evio->pending, sizeof (REvIOCtx));
    r_memset (&evio->pending, 0, sizeof (REvIOCtx));

    if (R_UNLIKELY (nev > (R_EV_LOOP_MAX_EVENTS - 4))) {
      if (kevent (loop->evhandle, events, nev, NULL, 0, NULL) != 0) {
        R_LOG_ERROR ("kevent for loop %p failed %d: \"%s\" with %d changes",
            loop, errno, strerror (errno), nev);
        abort ();
      }
      nev = 0;
    }
  }

  if (R_CLOCK_TIME_IS_VALID (deadline) && deadline >= loop->ts)
    R_TIME_TO_TIMESPEC ((timeout = deadline - loop->ts), spec);
  else
    timeout = R_CLOCK_TIME_NONE;

  R_LOG_DEBUG ("loop %p WAIT for %"R_TIME_FORMAT, loop, R_TIME_ARGS (timeout));
  do {
    R_LOG_TRACE ("executing kevent for loop %p with changelst of %d events", loop, nev);
    ret = kevent (loop->evhandle, events, nev, events, R_N_ELEMENTS (events),
        R_CLOCK_TIME_IS_VALID (deadline) ? &spec : NULL);
  } while (ret < 0 && errno == EINTR);

  if (ret < 0) {
    R_LOG_ERROR ("kevent for loop %p failed with error %d", loop, ret);
    goto beach;
  }

  R_LOG_DEBUG ("kevent for loop %p with eventlst of %d events", loop, ret);
  for (i = 0; i < ret; i++) {
    REvIOEvents rev = 0;
    ev = &events[i];
    evio = ev->udata;

    if (ev->flags & EV_ERROR)
      rev |= R_EV_IO_ERROR;
    if ((ev->flags & EV_EOF) && (evio->current.events & R_EV_IO_HANGUP))
      rev |= R_EV_IO_HANGUP;

    switch (ev->filter) {
      case EVFILT_READ:
        R_LOG_DEBUG ("evio "R_EV_IO_FORMAT" gives READ"
            " flags: 0x%"RINT16_MODIFIER"x fflags: 0x%"RINT32_MODIFIER"x",
            R_EV_IO_ARGS (evio), ev->flags, ev->fflags);
        rev |= R_EV_IO_READABLE;
        break;
      case EVFILT_WRITE:
        R_LOG_DEBUG ("evio "R_EV_IO_FORMAT" gives WRITE"
            " flags: 0x%"RINT16_MODIFIER"x fflags: 0x%"RINT32_MODIFIER"x",
            R_EV_IO_ARGS (evio), ev->flags, ev->fflags);
        rev |= R_EV_IO_WRITABLE;
        break;
      default:
        R_LOG_DEBUG ("evio "R_EV_IO_FORMAT" gives filter: %"RINT16_FMT
            " flags: 0x%"RINT16_MODIFIER"x fflags: 0x%"RINT32_MODIFIER"x",
            R_EV_IO_ARGS (evio), ev->filter, ev->flags, ev->fflags);
        if (rev == 0)
          continue;
    }

    r_ev_io_invoke_cb (evio, rev);
  }
#endif
beach:

  return ret;
}

static ruint
r_ev_loop_outstanding_events (REvLoop * loop)
{
  return r_cbrlist_len (loop->idle) +
    r_cbqueue_size (&loop->bcbs) +
    r_cbqueue_size (&loop->acbs) +
    r_clock_timeout_count (loop->clock) +
    r_queue_size (&loop->active);
}

ruint
r_ev_loop_run (REvLoop * loop, REvLoopRunMode mode)
{
  ruint ret;
  RClockTime deadline;
  int res = 0;

  R_LOG_DEBUG ("EvLoop %p mode %d", loop, mode);

  ret = r_ev_loop_outstanding_events (loop);
  while (!loop->stop_request && ret != 0 && res >= 0) {
    r_ev_loop_prepare (loop);
    r_ev_loop_update_timers (loop);

    r_ev_loop_invoke_bcbs (loop);
    deadline = r_ev_loop_next_deadline (loop, mode);
    if ((res = r_ev_loop_io_wait (loop, deadline)) == 0)
      r_ev_loop_idle (loop);
    r_ev_loop_invoke_acbs (loop);

    r_ev_loop_update_timers (loop);

    ret = r_ev_loop_outstanding_events (loop);
    if (mode != R_EV_LOOP_RUN_LOOP)
      break;
  }

  return ret;
}

void
r_ev_loop_stop (REvLoop * loop)
{
  R_LOG_DEBUG ("EvLoop %p requesting stop", loop);
  loop->stop_request = TRUE;
}

rboolean
r_ev_loop_add_prepare (REvLoop * loop, REvFuncReturn prepare_cb,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (loop == NULL)) return FALSE;
  if (R_UNLIKELY (prepare_cb == NULL)) return FALSE;

  loop->prepare = r_cbrlist_prepend_full (loop->prepare, (RFuncReturn)prepare_cb,
      data, datanotify, loop, NULL);

  return TRUE;
}

rboolean
r_ev_loop_add_idle (REvLoop * loop, REvFuncReturn idle_cb,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (loop == NULL)) return FALSE;
  if (R_UNLIKELY (idle_cb == NULL)) return FALSE;

  loop->idle = r_cbrlist_prepend_full (loop->idle, (RFuncReturn)idle_cb,
      data, datanotify, loop, NULL);

  return TRUE;
}

rboolean
r_ev_loop_add_callback (REvLoop * loop, rboolean pri,
    REvFunc cb, rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (loop == NULL)) return FALSE;
  if (R_UNLIKELY (cb == NULL)) return FALSE;

  r_cbqueue_push (pri ? &loop->bcbs : &loop->acbs,
      (RFunc)cb, data, datanotify, loop, NULL);
  return TRUE;
}

rboolean
r_ev_loop_add_callback_at (REvLoop * loop, RClockEntry ** timer,
    RClockTime deadline, REvFunc cb, rpointer data, RDestroyNotify datanotify)
{
  RClockEntry * entry;
  if (R_UNLIKELY (loop == NULL)) return FALSE;
  entry = r_clock_add_timeout_callback (loop->clock,
      deadline, (RFunc)cb, data, datanotify, loop, NULL);
  if (timer != NULL)
    *timer = entry;
  else if (entry != NULL)
    r_clock_entry_unref (entry);
  return entry != NULL;
}

rboolean
r_ev_loop_add_callback_later (REvLoop * loop, RClockEntry ** timer,
    RClockTimeDiff delay, REvFunc cb, rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (loop == NULL)) return FALSE;
  return r_ev_loop_add_callback_at (loop, timer, loop->ts + delay,
      cb, data, datanotify);
}

rboolean
r_ev_loop_cancel_timer (REvLoop * loop, RClockEntry * timer)
{
  if (R_UNLIKELY (loop == NULL)) return FALSE;
  return r_clock_cancel_entry (loop->clock, timer);
}

static void
r_ev_io_free (REvIO * evio)
{
  if (R_UNLIKELY (R_EV_IO_IS_ACTIVE (evio))) {
    R_LOG_ERROR ("REvIO instance "R_EV_IO_FORMAT" still active when freeing",
        R_EV_IO_ARGS (evio));
    r_queue_remove_link (&evio->loop->active, evio->alnk);
    if (R_EV_IO_IS_CHANGING (evio))
      r_queue_remove_link (&evio->loop->chg, evio->chglnk);

    evio->alnk = evio->chglnk = NULL;
  }

  r_ev_io_ctx_clear (&evio->pending);
  r_ev_io_ctx_clear (&evio->current);

  r_ev_loop_unref (evio->loop);
  r_free (evio);
}

REvIO *
r_ev_loop_init_handle (REvLoop * loop, REvHandle handle)
{
  REvIO * ret;

  if ((ret = r_mem_new0 (REvIO)) != NULL) {
    r_ref_init (ret, r_ev_io_free);

    ret->loop = r_ev_loop_ref (loop);
    ret->handle = handle;

#ifdef R_OS_UNIX
    r_ev_handle_set_nonblocking (handle, TRUE);
#endif
  }

  return ret;
}

rboolean
r_ev_io_start (REvIO * evio, REvIOEvents events, REvIOCB io_cb,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (evio == NULL)) return FALSE;
  if (R_UNLIKELY (events == 0)) return FALSE;
  if (R_UNLIKELY (io_cb == NULL)) return FALSE;
  if (R_UNLIKELY (evio->loop->stop_request)) return FALSE;

  r_ev_io_ctx_clear (&evio->pending);
  r_ev_io_ctx_init (&evio->pending, events, io_cb, data, datanotify);
  evio->chglnk = r_queue_push (&evio->loop->chg, evio);

  if (!R_EV_IO_IS_ACTIVE (evio))
    evio->alnk = r_queue_push (&evio->loop->active, evio);

  return R_EV_IO_IS_ACTIVE (evio);
}

rboolean
r_ev_io_stop (REvIO * evio)
{
  if (R_UNLIKELY (evio == NULL)) return FALSE;

  if (R_EV_IO_IS_ACTIVE (evio)) {
    r_queue_remove_link (&evio->loop->active, evio->alnk);
    evio->alnk = NULL;

    r_ev_io_ctx_clear (&evio->pending);
    evio->chglnk = r_queue_push (&evio->loop->chg, evio);
    return R_EV_IO_IS_CHANGING (evio);
  }

  return TRUE;
}

rboolean
r_ev_io_close (REvIO * evio, REvIOFunc close_cb,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (evio == NULL)) return FALSE;
  if (R_UNLIKELY (evio->close_ctx.close_cb != NULL)) return FALSE;

  if (evio->handle != R_EV_HANDLE_INVALID) {
    r_ev_handle_close (evio->handle);
    evio->handle = R_EV_HANDLE_INVALID;
  }

  if (R_EV_IO_IS_ACTIVE (evio)) {
    if (!r_ev_io_stop (evio))
      return FALSE;

    r_cbqueue_push (&evio->loop->acbs, (RFunc)close_cb,
        data, datanotify, r_ev_io_ref (evio), r_ev_io_unref);
  } else {
    if (close_cb != NULL)
      close_cb (data, evio);

    if (datanotify != NULL)
      datanotify (data);
  }

  return TRUE;
}

rboolean
r_ev_handle_close (REvHandle handle)
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

#ifdef R_OS_UNIX
rboolean
r_ev_handle_set_nonblocking (REvHandle handle, rboolean set)
{
  int res;

#ifdef HAVE_IOCTL
  do {
    res = ioctl (handle, FIONBIO, &set);
  } while (res < 0 && errno != EINTR);
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

rboolean
r_ev_handle_set_cloexec (REvHandle handle, rboolean set)
{
  int res;

#ifdef HAVE_IOCTL
  do {
    res = ioctl (handle, set ? FIOCLEX : FIONCLEX);
  } while (res < 0 && errno != EINTR);
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

