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
#include "../rlib-private.h"
#include "rev-private.h"

#include <rlib/ratomic.h>
#include <rlib/rmem.h>
#include <rlib/rthreads.h>

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
#ifdef HAVE_SYS_EVENTFD_H
#include <sys/eventfd.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <errno.h>

R_LOG_CATEGORY_DEFINE_STATIC (evloopcat, "revloop", "RLib EvLoop", R_CLR_BG_CYAN | R_CLR_FG_RED | R_CLR_FMT_BOLD);
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

static rboolean
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

#ifdef HAVE_EPOLL
static void r_ev_loop_eventfd_io_cb (rpointer data, REvIOEvents events, REvIO * evio);
#endif


struct _REvLoop {
  RRef ref;

  rboolean stop_request;
  RClockTime ts;
  RClock * clock;

  RTaskQueue * tq;
  rauint tqitems;
  RCBQueue dcbs;
  RMutex done_mutex;
#ifdef HAVE_EPOLL
  REvIO evio_wakeup;
#ifdef HAVE_EVENTFD
  int evfd;
#else
  int pipefd[2];
#endif
#endif

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

  r_clock_unref (loop->clock);    loop->clock = NULL;
  r_task_queue_unref (loop->tq);  loop->tq = NULL;
  r_mutex_lock (&loop->done_mutex);
  r_cbqueue_clear (&loop->dcbs);
  r_mutex_unlock (&loop->done_mutex);
  r_mutex_clear (&loop->done_mutex);

#ifdef HAVE_EPOLL
#ifdef HAVE_EVENTFD
    r_ev_handle_close (loop->evfd);
#else
    r_ev_handle_close (loop->pipefd[0]);
    r_ev_handle_close (loop->pipefd[1]);
#endif
    r_cbqueue_clear (&loop->evio_wakeup.iocbq);
#endif

  if (loop->evhandle != R_EV_HANDLE_INVALID) {
    r_ev_handle_close (loop->evhandle);
    loop->evhandle = R_EV_HANDLE_INVALID;
  }

  r_free (loop);
}

static void
r_ev_loop_setup (REvLoop * loop, RClock * clock, RTaskQueue * tq)
{
  loop->stop_request = FALSE;
  r_cbqueue_init (&loop->dcbs);
  r_cbqueue_init (&loop->bcbs);
  r_cbqueue_init (&loop->acbs);
  loop->prepare = loop->idle = NULL;
  r_queue_init (&loop->active);
  r_queue_init (&loop->chg);

  loop->clock = clock != NULL ? r_clock_ref (clock) : r_system_clock_get ();
  loop->ts = r_clock_get_time (loop->clock);

  loop->tq = tq != NULL ? r_task_queue_ref (tq) :
    r_task_queue_new_simple (R_EV_LOOP_DEFAULT_TASK_THREADS);
  r_atomic_uint_store (&loop->tqitems, 0);
  r_mutex_init (&loop->done_mutex);

#if defined (R_OS_WIN32)
#elif defined (HAVE_EPOLL)
  if ((loop->evhandle = epoll_create1 (0)) != R_EV_HANDLE_INVALID) {
    struct epoll_event ev;
    REvHandle fd;

#ifdef HAVE_EVENTFD
    fd = loop->evfd = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);
#else
    if (pipe (loop->pipefd) != 0) {
      R_LOG_ERROR ("Failed to initialize pipe for loop %p", loop);
      abort ();
    }
    fd = loop->pipefd[1];
#endif

    r_ref_init (&loop->evio_wakeup.ref, NULL);
    loop->evio_wakeup.loop = loop;
    loop->evio_wakeup.alnk = loop->evio_wakeup.chglnk = NULL;
    loop->evio_wakeup.handle = fd;
    loop->evio_wakeup.events = R_EV_IO_READABLE;
    r_cbqueue_init (&loop->evio_wakeup.iocbq);
    r_cbqueue_push (&loop->evio_wakeup.iocbq,
        (RFunc)r_ev_loop_eventfd_io_cb, loop, NULL, NULL, NULL);

    ev.data.ptr = &loop->evio_wakeup;
    ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl (loop->evhandle, EPOLL_CTL_ADD, fd, &ev) != 0) {
      R_LOG_ERROR ("Failed to add tq event fd %d for loop %p",
          ev.data.fd, loop);
      abort ();
    }
  }
#elif defined (HAVE_KQUEUE)
  if ((loop->evhandle = kqueue ()) != R_EV_HANDLE_INVALID) {
    struct kevent ev;
    EV_SET (&ev, 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent (loop->evhandle, &ev, 1, NULL, 0, NULL) != 0) {
      R_LOG_ERROR ("Failed to initialize EVFILT_USER for loop %p", loop);
      abort ();
    }
  }
#endif
}

REvLoop *
r_ev_loop_new_full (RClock * clock, RTaskQueue * tq)
{
  REvLoop * loop;

  if ((loop = r_mem_new (REvLoop)) != NULL) {
    REvLoop * prev = NULL;
    r_ref_init (loop, r_ev_loop_free);
    r_ev_loop_setup (loop, clock, tq);

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
r_ev_loop_move_done_callbacks (REvLoop * loop)
{
  r_mutex_lock (&loop->done_mutex);
  R_LOG_TRACE ("loop %p - Move callbacks: %"RUINT64_FMT,
      loop, r_cbqueue_size (&loop->dcbs));
  r_cbqueue_merge (&loop->acbs, &loop->dcbs);
  r_mutex_unlock (&loop->done_mutex);
}

static RClockTime
r_ev_loop_next_deadline (REvLoop * loop, REvLoopRunMode mode)
{
  if (mode == R_EV_LOOP_RUN_NOWAIT) return loop->ts;
  if (loop->stop_request) return loop->ts;
  if (loop->idle != NULL) return loop->ts;
  if (r_cbqueue_size (&loop->acbs) > 0) return loop->ts;
  if (r_clock_timeout_count (loop->clock) == 0 &&
      r_queue_size (&loop->active) == 0 &&
      r_atomic_uint_load (&loop->tqitems) == 0)
    return loop->ts;

  return r_clock_first_timeout (loop->clock);
}

static inline REvIOEvents
r_ev_io_get_iocbq_events (REvIO * evio)
{
  REvIOEvents ret = 0;
  RCBList * it;

  for (it = evio->iocbq.head; it != NULL; it = it->next)
    ret |= RPOINTER_TO_UINT (it->user);

  return ret;
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

  /* FIXME: clear->pop! which makes us able to move stuff back on the queue */
  while ((evio = r_queue_pop (&loop->chg)) != NULL) {
    REvIOEvents pending = 0;
    int op;

    if (R_UNLIKELY (evio->handle == R_EV_HANDLE_INVALID))
      continue;

    pending = evio->events | r_ev_io_get_iocbq_events (evio);
    R_LOG_DEBUG ("loop %p changes evio "R_EV_IO_FORMAT" %4x->%x",
        loop, R_EV_IO_ARGS (evio), evio->events, pending);

    ev->data.ptr = evio;
    ev->events = EPOLLET;
    if (pending & R_EV_IO_READABLE) ev->events |= EPOLLIN;
    if (pending & R_EV_IO_WRITABLE) ev->events |= EPOLLOUT;
    if (pending & R_EV_IO_HANGUP)   ev->events |= EPOLLRDHUP;
    op = (evio->events == 0) ? EPOLL_CTL_ADD : EPOLL_CTL_MOD;

    if (epoll_ctl (loop->evhandle, op, evio->handle, ev) == 0) {
      evio->events = pending;
      evio->chglnk = NULL;
    } else {
      R_LOG_ERROR ("epoll_ctl for loop %p failed %d: \"%s\" with operation %d for fd: %d",
          loop, errno, strerror (errno), op, evio->handle);

      if (errno == EPERM)
        r_ev_io_invoke_iocb (evio, R_EV_IO_ERROR);
      else
        abort ();
      evio->chglnk = NULL; /*r_queue_push (&evio->loop->chg, evio)*/
    }
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
      r_ev_io_invoke_iocb (evio, rev);
  }
#elif defined (HAVE_KQUEUE)
  struct kevent events[R_EV_LOOP_MAX_EVENTS], * ev;
  struct timespec spec = { 0, 0 };
  int nev = 0;
  REvIOEvents pending;

  while ((evio = r_queue_pop (&loop->chg)) != NULL) {
    if (R_UNLIKELY (evio->handle == R_EV_HANDLE_INVALID))
      continue;

    pending = evio->events | r_ev_io_get_iocbq_events (evio);
    R_LOG_DEBUG ("loop %p changes evio "R_EV_IO_FORMAT" %4x->%x",
        loop, R_EV_IO_ARGS (evio), evio->events, pending);

    if (pending & R_EV_IO_READABLE && !(evio->events & R_EV_IO_READABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, evio);
    else if (evio->events & R_EV_IO_READABLE && !(pending & R_EV_IO_READABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_READ, EV_DELETE, 0, 0, evio);
    if (pending & R_EV_IO_WRITABLE && !(evio->events & R_EV_IO_WRITABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, evio);
    else if (evio->events & R_EV_IO_WRITABLE && !(pending & R_EV_IO_WRITABLE))
      EV_SET (&events[nev++], evio->handle, EVFILT_READ, EV_DELETE, 0, 0, evio);

    evio->events = pending;
    evio->chglnk = NULL;

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

    if (ev->flags & EV_ERROR)
      rev |= R_EV_IO_ERROR;
    if ((evio = ev->udata) != NULL) {
      if ((ev->flags & EV_EOF) && (evio->events & R_EV_IO_HANGUP))
        rev |= R_EV_IO_HANGUP;
    }

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
      case EVFILT_USER:
        R_LOG_DEBUG ("USER flags: 0x%"RINT16_MODIFIER"x fflags: 0x%"RINT32_MODIFIER"x",
            ev->flags, ev->fflags);
        r_ev_loop_move_done_callbacks (loop);
        continue;
      default:
        R_LOG_DEBUG ("evio "R_EV_IO_FORMAT" gives filter: %"RINT16_FMT
            " flags: 0x%"RINT16_MODIFIER"x fflags: 0x%"RINT32_MODIFIER"x",
            R_EV_IO_ARGS (evio), ev->filter, ev->flags, ev->fflags);
        if (rev == 0)
          continue;
    }

    r_ev_io_invoke_iocb (evio, rev);
  }
#endif
beach:

  return ret;
}

static ruint
r_ev_loop_outstanding_events (REvLoop * loop)
{
  return r_cbrlist_len (loop->idle) +
    r_cbqueue_size (&loop->acbs) +
    r_cbqueue_size (&loop->bcbs) +
    loop->tqitems +
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

    r_ev_loop_move_done_callbacks (loop);

    r_cbqueue_call_pop (&loop->bcbs);
    deadline = r_ev_loop_next_deadline (loop, mode);
    if ((res = r_ev_loop_io_wait (loop, deadline)) == 0)
      r_ev_loop_idle (loop);
    r_cbqueue_call_pop (&loop->acbs);

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

#ifdef HAVE_EPOLL
static void
r_ev_loop_eventfd_io_cb (rpointer data, REvIOEvents events, REvIO * evio)
{
  REvLoop * loop = data;
  REvHandle fd = evio->handle;

  if (events & R_EV_IO_ERROR) {
    R_LOG_ERROR ("Wakeup evio "R_EV_IO_FORMAT" received error event for loop %p",
        R_EV_IO_ARGS (evio), loop);
  }

  if (events & R_EV_IO_READABLE) {
    int r;
    ruint64 buf;
    while (TRUE) {
      do {
        r = read (fd, &buf, sizeof (ruint64));
      } while (r == sizeof (ruint64));

      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      } else if (errno != EINTR) {
        R_LOG_ERROR ("Read from wakeup eventfd failed, errno: %d for loop %p",
            errno, loop);
        abort ();
      }
    }

    r_ev_loop_move_done_callbacks (loop);
  }
}
#endif

static void
r_ev_loop_wakeup (REvLoop * loop)
{
#if defined (R_OS_WIN32)
  R_LOG_DEBUG ("loop %p wakeup!", loop);
#elif defined (HAVE_EPOLL)
  ruint64 buf = r_atomic_uint_load (&loop->tqitems);
  int res;
#ifdef HAVE_EVENTFD
  int fd = loop->evfd;
#else
  int fd = loop->pipefd[1];
#endif
  R_LOG_DEBUG ("loop %p wakeup!", loop);
  if ((res = write (fd, &buf, sizeof (ruint64))) != sizeof (ruint64)) {
    R_LOG_ERROR ("Write failed (res %d) to event fd %d for loop %p",
        res, fd, loop);
  }
#elif defined (HAVE_KQUEUE)
  struct kevent ev;
  int res;

  EV_SET (&ev, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  res = kevent (loop->evhandle, &ev, 1, NULL, 0, NULL);
  R_LOG_DEBUG ("loop %p wakeup! res %d", loop, res);
#endif
}

typedef struct {
  REvLoop * loop;
  RTaskFunc task;
  REvFunc done;
  rpointer data;
  RDestroyNotify datanotify;
} REvLoopTaskCtx;

static void
r_ev_loop_task_done (rpointer data, rpointer user)
{
  REvLoopTaskCtx * ctx = data;
  (void) user;

  /* This is a barrier, so after this barrier - task_proxy is done and
   * the loop is unrefed!*/
  r_mutex_lock (&ctx->loop->done_mutex);
  r_mutex_unlock (&ctx->loop->done_mutex);

  R_LOG_TRACE ("loop %p task done: %p", ctx->loop, ctx->done);

  if (ctx->done != NULL)
    ctx->done (ctx->data, ctx->loop);

  if (ctx->datanotify != NULL)
    ctx->datanotify (ctx->data);

  r_atomic_uint_fetch_sub (&ctx->loop->tqitems, 1);
}

static void
r_ev_loop_task_proxy (rpointer data, RTaskQueue * q, RTask * t)
{
  REvLoopTaskCtx * ctx = data;
  rboolean wakeup;

  ctx->task (ctx->data, q, t);

  r_mutex_lock (&ctx->loop->done_mutex);
  wakeup = r_cbqueue_is_empty (&ctx->loop->dcbs);
  R_LOG_TRACE ("loop %p push r_ev_loop_task_done", ctx->loop);
  r_cbqueue_push (&ctx->loop->dcbs, r_ev_loop_task_done,
      ctx, NULL, r_task_ref (t), r_task_unref);

  if (wakeup)
    r_ev_loop_wakeup (ctx->loop);
  r_ev_loop_unref (ctx->loop);
  r_mutex_unlock (&ctx->loop->done_mutex);
}

RTask *
r_ev_loop_add_task (REvLoop * loop, RTaskFunc task, REvFunc done,
    rpointer data, RDestroyNotify datanotify)
{
  RTask * ret;
  REvLoopTaskCtx * ctx;

  if (R_UNLIKELY (loop == NULL)) return NULL;

  if ((ctx = r_mem_new (REvLoopTaskCtx)) != NULL) {
    ctx->loop = r_ev_loop_ref (loop);
    ctx->task = task;
    ctx->done = done;
    ctx->data = data;
    ctx->datanotify = datanotify;
    if ((ret = r_task_queue_add (loop->tq, r_ev_loop_task_proxy, ctx, r_free)) != NULL) {
      r_atomic_uint_fetch_add (&loop->tqitems, 1);
    } else {
      r_free (ctx);
    }
  } else {
    ret = NULL;
  }

  return ret;
}

void
r_ev_io_clear (REvIO * evio)
{
  if (R_UNLIKELY (R_EV_IO_IS_ACTIVE (evio))) {
    R_LOG_ERROR ("REvIO instance "R_EV_IO_FORMAT" still active when freeing",
        R_EV_IO_ARGS (evio));
    r_queue_remove_link (&evio->loop->active, evio->alnk);
    if (R_EV_IO_IS_CHANGING (evio))
      r_queue_remove_link (&evio->loop->chg, evio->chglnk);

    evio->alnk = evio->chglnk = NULL;
  }

  r_cbqueue_clear (&evio->iocbq);

  r_ev_loop_unref (evio->loop);
}

void
r_ev_io_init (REvIO * evio, REvLoop * loop, REvHandle handle, RDestroyNotify notify)
{
  r_ref_init (evio, notify);

  evio->loop = r_ev_loop_ref (loop);
  evio->handle = handle;

#ifdef R_OS_UNIX
  if (handle != R_EV_HANDLE_INVALID)
    r_fd_unix_set_nonblocking (handle, TRUE);
#endif
}

static void
r_ev_io_free (REvIO * evio)
{
  r_ev_io_clear (evio);
  r_free (evio);
}

REvIO *
r_ev_loop_init_handle (REvLoop * loop, REvHandle handle)
{
  REvIO * ret;

  if ((ret = r_mem_new0 (REvIO)) != NULL)
    r_ev_io_init (ret, loop, handle, (RDestroyNotify)r_ev_io_free);

  return ret;
}

rpointer
r_ev_io_start (REvIO * evio, REvIOEvents events, REvIOCB io_cb,
    rpointer data, RDestroyNotify datanotify)
{
  rpointer ret;

  if (R_UNLIKELY (evio == NULL)) return FALSE;
  if (R_UNLIKELY (events == 0)) return FALSE;
  if (R_UNLIKELY (io_cb == NULL)) return FALSE;
  if (R_UNLIKELY (evio->loop->stop_request)) return FALSE;

  ret = r_cbqueue_push (&evio->iocbq, (RFunc)io_cb, data, datanotify,
      RUINT_TO_POINTER (events), NULL);
  if (!R_EV_IO_IS_CHANGING (evio) && (evio->events & events) != events)
    evio->chglnk = r_queue_push (&evio->loop->chg, evio);

  if (!R_EV_IO_IS_ACTIVE (evio))
    evio->alnk = r_queue_push (&evio->loop->active, evio);

  return ret;
}

rboolean
r_ev_io_stop (REvIO * evio, rpointer ctx)
{
  if (R_UNLIKELY (evio == NULL)) return FALSE;
  if (R_UNLIKELY (ctx == NULL)) return FALSE;

  r_cbqueue_remove_link (&evio->iocbq, ctx);

  if (R_EV_IO_IS_ACTIVE (evio)) {
    REvIOEvents events;

    if ((events = r_ev_io_get_iocbq_events (evio)) == 0) {
      r_queue_remove_link (&evio->loop->active, evio->alnk);
      evio->alnk = NULL;
    }

    if (!R_EV_IO_IS_CHANGING (evio) && evio->events != events)
      evio->chglnk = r_queue_push (&evio->loop->chg, evio);
  }

  return TRUE;
}

rboolean
r_ev_io_close (REvIO * evio, REvIOFunc close_cb,
    rpointer data, RDestroyNotify datanotify)
{
  if (R_UNLIKELY (evio == NULL)) return FALSE;

  if (evio->handle != R_EV_HANDLE_INVALID) {
    r_ev_handle_close (evio->handle);
    evio->handle = R_EV_HANDLE_INVALID;
  }

  if (R_EV_IO_IS_ACTIVE (evio)) {
    r_queue_remove_link (&evio->loop->active, evio->alnk);
    if (R_EV_IO_IS_CHANGING (evio))
      r_queue_remove_link (&evio->loop->chg, evio->chglnk);
    evio->alnk = evio->chglnk = NULL;
  }

  r_cbqueue_push (&evio->loop->acbs, (RFunc)close_cb,
      data, datanotify, r_ev_io_ref (evio), r_ev_io_unref);

  return TRUE;
}

