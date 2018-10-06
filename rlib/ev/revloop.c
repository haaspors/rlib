/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include <rlib/rassert.h>
#include <rlib/ratomic.h>
#include <rlib/rio.h>
#include <rlib/rmem.h>
#include <rlib/rpoll.h>
#include <rlib/rthreads.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_EVENT_H
#include <sys/event.h>
#endif
#ifdef HAVE_SYS_EPOLL_H
#include <sys/epoll.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

/* TODO: Add strerror to rstr? */
#include <errno.h>
#include <string.h>


/* Setup MACROS to select evloop backend! */
#if defined (HAVE_KQUEUE)
#define USE_KQUEUE  1
#elif defined (HAVE_EPOLL_CTL)
#define USE_EPOLL   1
#define USE_WAKEUP  1
#else
#define USE_RPOLL   1
#define USE_WAKEUP  1
#endif


R_LOG_CATEGORY_DEFINE (revlogcat, "ev", "RLib EvLoop",
    R_CLR_BG_CYAN | R_CLR_FG_RED | R_CLR_FMT_BOLD);
#define R_LOG_CAT_DEFAULT &revlogcat

void
r_ev_loop_init (void)
{
  r_log_category_register (&revlogcat);
}

void
r_ev_loop_deinit (void)
{
}

static raptr g__r_ev_loop_default; /* (REvLoop *) */
static RTss  g__r_ev_loop_tss = R_TSS_INIT (NULL);

#ifdef USE_WAKEUP
static void r_ev_loop_wakeup_cb (rpointer data, REvIOEvents events, REvIO * evio);
#endif


struct _REvLoop {
  RRef ref;

  rsize iterations;
  rsize idle_count;

  rboolean stop_request;
  RClockTime ts;
  RClock * clock;

  RTaskQueue * tq;
  rauint tqitems;
  RCBQueue dcbs;
  RMutex done_mutex;

  /* Wakeup handle for backends not supporting it natively */
#ifdef USE_WAKEUP
  REvWakeup evio_wakeup;
#endif

  /* For various callbacks */
  RCBQueue acbs;
  RCBQueue bcbs;
  RCBRList * prepare;
  RCBRList * idle;

  /* For IO events */
  RIOHandle handle;
#ifdef USE_RPOLL
  RPollSet pollset;
#endif
  RQueue active;
  RQueue chg;
};

static void
r_ev_loop_free (REvLoop * loop)
{
  REvLoop * prev = loop;
  r_atomic_ptr_cmp_xchg_strong (&g__r_ev_loop_default, &prev, NULL);

#ifdef USE_RPOLL
  r_poll_set_clear (&loop->pollset);
#endif

#ifdef USE_WAKEUP
  r_ev_wakeup_clear (&loop->evio_wakeup);
#endif

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

  if (loop->handle != R_IO_HANDLE_INVALID) {
    r_io_close (loop->handle);
    loop->handle = R_IO_HANDLE_INVALID;
  }

  r_free (loop);
}

static void
r_ev_loop_setup (REvLoop * loop, RClock * clock, RTaskQueue * tq)
{
  loop->iterations = loop->idle_count = 0;
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
    r_task_queue_new (1, R_EV_LOOP_DEFAULT_TASK_THREADS);
  r_atomic_uint_store (&loop->tqitems, 0);
  r_mutex_init (&loop->done_mutex);

#ifdef USE_WAKEUP
  r_ev_wakeup_init (&loop->evio_wakeup, loop, NULL);
  /* Mark the wakeup source internal */
  loop->evio_wakeup.evio.flags |= R_EV_IO_INTERNAL;
  r_ev_loop_unref (loop);
  if (R_UNLIKELY (r_ev_io_start (&loop->evio_wakeup.evio, R_EV_IO_READABLE,
        r_ev_loop_wakeup_cb, loop, NULL) == NULL)) {
    R_LOG_ERROR ("Failed to add wakeup for loop %p", loop);
  }
#endif

#if defined (USE_KQUEUE)
  if ((loop->handle = kqueue ()) != R_IO_HANDLE_INVALID) {
    struct kevent ev;
    EV_SET (&ev, 1, EVFILT_USER, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent (loop->handle, &ev, 1, NULL, 0, NULL) != 0) {
      R_LOG_ERROR ("Failed to initialize EVFILT_USER for loop %p", loop);
      abort ();
    }
  }
#elif defined (USE_EPOLL)
 loop->handle = epoll_create1 (0);
#elif defined (USE_RPOLL)
  loop->handle = R_IO_HANDLE_INVALID;
  r_poll_set_init (&loop->pollset, 0);
#else
  loop->handle = R_IO_HANDLE_INVALID;
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

REvLoop *
r_ev_loop_current (void)
{
  return r_tss_get (&g__r_ev_loop_tss);
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
  R_LOG_TRACE ("loop %p - Move callbacks: %"RSIZE_FMT,
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

#if defined (USE_KQUEUE)
static int
r_ev_loop_io_wait (REvLoop * loop, RClockTime deadline)
{
  REvIO * evio;
  int ret, i;

  struct kevent events[R_EV_LOOP_MAX_EVENTS], * ev;
  struct timespec spec = { 0, 0 }, * pspec;
  int nev = 0;
  REvIOEvents pending;

  while ((evio = r_queue_pop (&loop->chg)) != NULL) {
    evio->chglnk = NULL;
    if (R_UNLIKELY (evio->handle == R_IO_HANDLE_INVALID))
      continue;
    if (R_UNLIKELY (R_EV_IO_IS_CLOSED (evio))) {
      evio->handle = R_IO_HANDLE_INVALID;
      continue;
    }

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

    if ((evio->events = pending) != 0)
      evio->flags |= R_EV_IO_ADDED;
    else
      evio->flags &= ~R_EV_IO_ADDED;

    if (R_UNLIKELY (nev > (R_EV_LOOP_MAX_EVENTS - 4))) {
      if (kevent (loop->handle, events, nev, NULL, 0, NULL) != 0) {
        R_LOG_ERROR ("kevent for loop %p failed %d: \"%s\" with %d changes",
            loop, errno, strerror (errno), nev);
        abort ();
      }
      nev = 0;
    }
  }

  if (deadline != R_CLOCK_TIME_INFINITE) {
    R_TIME_TO_TIMESPEC (deadline - loop->ts, spec);
    pspec = &spec;
  } else {
    pspec = NULL;
  }

  do {
    R_LOG_TRACE ("executing kevent for loop %p with changelst of %d events", loop, nev);
    ret = kevent (loop->handle, events, nev, events, R_N_ELEMENTS (events), pspec);
  } while (ret < 0 && errno == EINTR);

  if (ret >= 0) {
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
  } else {
    R_LOG_ERROR ("kevent for loop %p failed with error %d", loop, ret);
  }

  return ret;
}
#elif defined (USE_EPOLL)
static int
r_ev_loop_io_wait (REvLoop * loop, RClockTime deadline)
{
  REvIO * evio;
  int ret, i, tms;

  struct epoll_event events[R_EV_LOOP_MAX_EVENTS], * ev = events;

  /* FIXME: clear->pop! which makes us able to move stuff back on the queue */
  while ((evio = r_queue_pop (&loop->chg)) != NULL) {
    REvIOEvents pending = 0;
    int op;

    evio->chglnk = NULL;
    if (R_UNLIKELY (evio->handle == R_IO_HANDLE_INVALID))
      continue;
    if (R_UNLIKELY (evio->flags & R_EV_IO_CLOSED)) {
      evio->handle = R_IO_HANDLE_INVALID;
      continue;
    }

    pending = evio->events | r_ev_io_get_iocbq_events (evio);
    if (R_UNLIKELY (evio->events == pending))
      continue;
    R_LOG_DEBUG ("loop %p changes evio "R_EV_IO_FORMAT" %4x->%x",
        loop, R_EV_IO_ARGS (evio), evio->events, pending);

    ev->data.ptr = evio;
    ev->events = EPOLLET;
    if (pending & R_EV_IO_READABLE) ev->events |= EPOLLIN;
    if (pending & R_EV_IO_WRITABLE) ev->events |= EPOLLOUT;
    if (pending & R_EV_IO_HANGUP)   ev->events |= EPOLLRDHUP;

    if (R_EV_IO_IS_ADDED (evio))
      op = (pending == 0) ? EPOLL_CTL_DEL : EPOLL_CTL_MOD;
    else if (pending == 0)
      continue;
    else
      op = EPOLL_CTL_ADD;

    if (epoll_ctl (loop->handle, op, evio->handle, ev) == 0) {
      evio->events = pending;
      switch (op) {
      case EPOLL_CTL_ADD:
        evio->flags |= R_EV_IO_ADDED;
        break;
      case EPOLL_CTL_DEL:
        evio->flags &= ~R_EV_IO_ADDED;
        break;
      }
    } else {
      R_LOG_ERROR ("epoll_ctl for loop %p failed %d: \"%s\" with operation %d for fd: %d",
          loop, errno, strerror (errno), op, evio->handle);

      if (errno == EPERM)
        r_ev_io_invoke_iocb (evio, R_EV_IO_ERROR);
      else
        abort ();
      /*evio->chglnk = r_queue_push (&evio->loop->chg, evio)*/
    }
  }

  if (deadline != R_CLOCK_TIME_INFINITE)
    tms = R_TIME_AS_MSECONDS (deadline - loop->ts) + 1;
  else
    tms = -1;

  do {
    R_LOG_TRACE ("executing epoll_wait for loop %p with timeout %d", loop, tms);
    ret = epoll_wait (loop->handle, events, R_N_ELEMENTS (events), tms);
  } while (ret < 0 && errno == EINTR);

  if (ret >= 0) {
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
  } else {
    R_LOG_ERROR ("epoll_wait for loop %p failed with error %d", loop, ret);
  }

  return ret;
}
#elif defined (USE_RPOLL)
static int
r_ev_loop_io_wait (REvLoop * loop, RClockTime deadline)
{
  REvIO * evio;
  RClockTime timeout;
  int ret;
  ruint i;

  while ((evio = r_queue_pop (&loop->chg)) != NULL) {
    REvIOEvents pending;

    evio->chglnk = NULL;
    if (R_UNLIKELY (evio->handle == R_IO_HANDLE_INVALID))
      continue;
    if (R_UNLIKELY (R_EV_IO_IS_CLOSED (evio))) {
      if (R_EV_IO_IS_ADDED (evio)) {
        R_LOG_DEBUG ("loop %p closed evio "R_EV_IO_FORMAT, loop, R_EV_IO_ARGS (evio));
        r_poll_set_remove (&loop->pollset, evio->handle);
        evio->flags &= ~R_EV_IO_ADDED;
      }
      evio->handle = R_IO_HANDLE_INVALID;
      continue;
    }

    pending = evio->events | r_ev_io_get_iocbq_events (evio);
    if (R_UNLIKELY (evio->events == pending))
      continue;
    R_LOG_DEBUG ("loop %p changes evio "R_EV_IO_FORMAT" %4x->%x",
        loop, R_EV_IO_ARGS (evio), evio->events, pending);

    if ((evio->events = pending) != 0) {
      rushort events = 0;

      if (pending & R_EV_IO_ERROR)    events |= R_IO_ERR;
      if (pending & R_EV_IO_READABLE) events |= R_IO_IN;
      if (pending & R_EV_IO_WRITABLE) events |= R_IO_OUT;
      if (pending & R_EV_IO_HANGUP)   events |= R_IO_HUP;

      if (!R_EV_IO_IS_ADDED (evio)) {
        if (r_poll_set_add (&loop->pollset, evio->handle, events, evio) >= 0) {
          evio->flags |= R_EV_IO_ADDED;
        } else {
          R_LOG_ERROR ("Couldn't add %"R_IO_HANDLE_FMT" evio "R_EV_IO_FORMAT" to pollset",
              evio->handle, R_EV_IO_ARGS (evio));
        }
      } else {
        int idx;
        if ((idx = r_poll_set_find (&loop->pollset, evio->handle)) >= 0) {
          loop->pollset.handles[idx].events = events;
        } else {
          R_LOG_ERROR ("Couldn't update events on evio "R_EV_IO_FORMAT,
              R_EV_IO_ARGS (evio));
        }
      }
    } else if (R_EV_IO_IS_ADDED (evio)) {
      if (r_poll_set_remove (&loop->pollset, evio->handle)) {
        evio->flags &= ~R_EV_IO_ADDED;
      } else {
        R_LOG_ERROR ("Couldn't remove fd: %"R_IO_HANDLE_FMT" evio "R_EV_IO_FORMAT,
            evio->handle, R_EV_IO_ARGS (evio));
      }
    }
  }

  if (deadline != R_CLOCK_TIME_INFINITE)
    timeout = deadline - loop->ts;
  else
    timeout = R_CLOCK_TIME_INFINITE;

  ret = r_poll (loop->pollset.handles, loop->pollset.count, timeout);
  if (ret >= 0) {
    int processed = 0;
    R_LOG_DEBUG ("r_poll for loop %p with %d events", loop, ret);
    for (i = 0; i < loop->pollset.count && processed < ret; i++) {
      REvIOEvents rev = 0;
      evio = r_poll_set_get_user (&loop->pollset, loop->pollset.handles[i].handle);
      r_assert_cmpptr (evio, !=, NULL);

      if (loop->pollset.handles[i].revents & R_IO_ERR)  rev |= R_EV_IO_ERROR;
      if (loop->pollset.handles[i].revents & R_IO_HUP)  rev |= R_EV_IO_HANGUP;
      if (loop->pollset.handles[i].revents & R_IO_IN)   rev |= R_EV_IO_READABLE;
      if (loop->pollset.handles[i].revents & R_IO_OUT)  rev |= R_EV_IO_WRITABLE;
      loop->pollset.handles[i].revents = 0;

      R_LOG_INFO ("r_poll for loop %p handle %"R_IO_HANDLE_FMT" evio: "R_EV_IO_FORMAT" - %u",
          loop, loop->pollset.handles[i].handle, R_EV_IO_ARGS (evio), (ruint)rev);
      if (R_LIKELY (rev != 0)) {
        processed++;
        r_ev_io_invoke_iocb (evio, rev);
      }
    }
  } else {
    R_LOG_ERROR ("r_poll for loop %p failed with error %d", loop, ret);
  }

  return ret;
}
#else
/* TODO: Implement win32 backend */
static int
r_ev_loop_io_wait (REvLoop * loop, RClockTime deadline)
{
  int ret = -1;

  (void) loop;
  (void) deadline;

  return ret;
}
#endif

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
  if (R_UNLIKELY (r_tss_get (&g__r_ev_loop_tss) != NULL)) {
    R_LOG_ERROR ("Nested event loops not really supported %p ---> %p",
        loop, r_tss_get (&g__r_ev_loop_tss));
  }

  r_tss_set (&g__r_ev_loop_tss, loop);
  ret = r_ev_loop_outstanding_events (loop);
  while (!loop->stop_request && ret != 0 && res >= 0) {
    r_ev_loop_prepare (loop);
    r_ev_loop_update_timers (loop);

    r_ev_loop_move_done_callbacks (loop);

    r_cbqueue_call_pop (&loop->bcbs);
    deadline = r_ev_loop_next_deadline (loop, mode);
    r_assert_cmpuint (deadline, >=, loop->ts);
    R_LOG_TRACE ("loop %p: now %"R_TIME_FORMAT" WAIT until %"R_TIME_FORMAT,
        loop, R_TIME_ARGS (loop->ts), R_TIME_ARGS (deadline));
    if ((res = r_ev_loop_io_wait (loop, deadline)) == 0) {
      r_ev_loop_idle (loop);
      loop->idle_count++;
    }
    r_cbqueue_call_pop (&loop->acbs);

    r_ev_loop_update_timers (loop);
    loop->iterations++;

    ret = r_ev_loop_outstanding_events (loop);
    if (mode != R_EV_LOOP_RUN_LOOP)
      break;
  }
  r_tss_set (&g__r_ev_loop_tss, NULL);

  return ret;
}

void
r_ev_loop_stop (REvLoop * loop)
{
  R_LOG_DEBUG ("EvLoop %p requesting stop", loop);
  loop->stop_request = TRUE;
}

rsize
r_ev_loop_get_iterations (const REvLoop * loop)
{
  return loop->iterations;
}

rsize
r_ev_loop_get_idle_count (const REvLoop * loop)
{
  return loop->idle_count;
}

ruint
r_ev_loop_task_group_count (REvLoop * loop)
{
  return r_task_queue_group_count (loop->tq);
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

void
r_ev_loop_add_cb_after (REvLoop * loop, RFunc func,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  r_cbqueue_push (&loop->acbs, func, data, datanotify, user, usernotify);
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

#ifdef USE_WAKEUP
static void
r_ev_loop_wakeup_cb (rpointer data, REvIOEvents events, REvIO * evio)
{
  REvLoop * loop = data;

  if (events & R_EV_IO_ERROR) {
    R_LOG_ERROR ("Wakeup evio "R_EV_IO_FORMAT" received error event for loop %p",
        R_EV_IO_ARGS (evio), loop);
  }

  if (events & R_EV_IO_READABLE) {
    r_ev_wakeup_read (&loop->evio_wakeup);

#if !defined (R_OS_WIN32)
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      R_LOG_ERROR ("Read from wakeup eventfd failed, errno: %d for loop %p",
          errno, loop);
      abort ();
    }
#endif

    r_ev_loop_move_done_callbacks (loop);
  }
}
#endif

static void
r_ev_loop_wakeup (REvLoop * loop)
{
#if defined (USE_KQUEUE)
  struct kevent ev;
  int res;

  EV_SET (&ev, 1, EVFILT_USER, 0, NOTE_TRIGGER, 0, NULL);
  res = kevent (loop->handle, &ev, 1, NULL, 0, NULL);
  R_LOG_DEBUG ("loop %p wakeup! res %d", loop, res);
#elif defined (USE_WAKEUP)
  if (r_ev_wakeup_signal (&loop->evio_wakeup))
    R_LOG_DEBUG ("loop %p wakeup!", loop);
  else
    R_LOG_ERROR ("Wakeup signalling failed for loop %p", loop);
#else
#error No wakeup mechanism
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
r_ev_loop_add_task_full (REvLoop * loop, ruint taskgroup,
    RTaskFunc task, REvFunc done, rpointer data, RDestroyNotify datanotify, ...)
{
  RTask * ret;
  va_list args;

  va_start (args, datanotify);
  ret = r_ev_loop_add_task_full_v (loop, taskgroup, task, done, data, datanotify, args);
  va_end (args);

  return ret;
}

RTask *
r_ev_loop_add_task_full_v (REvLoop * loop, ruint taskgroup,
    RTaskFunc task, REvFunc done, rpointer data, RDestroyNotify datanotify,
    va_list args)
{
  RTask * ret;
  REvLoopTaskCtx * ctx;

  if (R_UNLIKELY (loop == NULL)) return NULL;

  if (done == NULL) {
    ret = r_task_queue_add_full_v (loop->tq, taskgroup,
        task, data, datanotify, args);
  } else if ((ctx = r_mem_new (REvLoopTaskCtx)) != NULL) {
    ctx->loop = r_ev_loop_ref (loop);
    ctx->task = task;
    ctx->done = done;
    ctx->data = data;
    ctx->datanotify = datanotify;
    if ((ret = r_task_queue_add_full_v (loop->tq, taskgroup,
            r_ev_loop_task_proxy, ctx, r_free, args)) != NULL) {
      r_atomic_uint_fetch_add (&loop->tqitems, 1);
    } else {
      r_ev_loop_unref (loop);
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
  }

  if (evio->usernotify != NULL)
    evio->usernotify (evio->user);

  if (R_EV_IO_IS_CHANGING (evio))
    r_queue_remove_link (&evio->loop->chg, evio->chglnk);
  evio->alnk = evio->chglnk = NULL;

  r_cbqueue_clear (&evio->iocbq);

  if (evio->loop != NULL)
    r_ev_loop_unref (evio->loop);
}

rboolean
r_ev_io_validate_taskgroup (REvIO * evio, ruint taskgroup)
{
  return (taskgroup == RUINT_MAX) ||
    (taskgroup < r_task_queue_group_count (evio->loop->tq));
}

void
r_ev_io_init (REvIO * evio, REvLoop * loop, RIOHandle handle, RDestroyNotify notify)
{
  r_ref_init (evio, notify);

  if (loop != NULL)
    r_ev_loop_ref (loop);
  evio->loop = loop;
  evio->alnk = evio->chglnk = NULL;
  evio->handle = handle;
  evio->events = 0;
  evio->flags = R_EV_IO_FLAGS_NONE;
  r_cbqueue_init (&evio->iocbq);
  evio->user = NULL;
  evio->usernotify = NULL;

#ifdef R_OS_UNIX
  if (handle != R_IO_HANDLE_INVALID)
    r_io_unix_set_nonblocking (handle, TRUE);
#endif
}

static void
r_ev_io_free (REvIO * evio)
{
  r_ev_io_clear (evio);
  r_free (evio);
}

REvIO *
r_ev_io_new (REvLoop * loop, RIOHandle handle)
{
  REvIO * ret;

  if (R_UNLIKELY (loop == NULL)) return NULL;
  if (R_UNLIKELY (handle == R_IO_HANDLE_INVALID)) return NULL;

  if ((ret = r_mem_new0 (REvIO)) != NULL)
    r_ev_io_init (ret, loop, handle, (RDestroyNotify)r_ev_io_free);

  return ret;
}

void
r_ev_io_set_user (REvIO * evio, rpointer user, RDestroyNotify notify)
{
  if (evio->usernotify != NULL)
    evio->usernotify (evio->user);
  evio->user = user;
  evio->usernotify = notify;
}

rpointer
r_ev_io_get_user (REvIO * evio)
{
  return evio->user;
}

rpointer
r_ev_io_start (REvIO * evio, REvIOEvents events, REvIOCB io_cb,
    rpointer data, RDestroyNotify datanotify)
{
  rpointer ret;

  if (R_UNLIKELY (evio == NULL)) return NULL;
  if (R_UNLIKELY (evio->handle == R_IO_HANDLE_INVALID)) return NULL;
  if (R_UNLIKELY (events == 0)) return NULL;
  if (R_UNLIKELY (io_cb == NULL)) return NULL;
  if (R_UNLIKELY (evio->loop->stop_request)) return NULL;

  R_LOG_TRACE ("loop %p start evio "R_EV_IO_FORMAT" %4x + %x",
      evio->loop, R_EV_IO_ARGS (evio), evio->events, events);
  ret = r_cbqueue_push (&evio->iocbq, (RFunc)io_cb, data, datanotify,
      RUINT_TO_POINTER (events), NULL);
  if (!R_EV_IO_IS_CHANGING (evio) && (evio->events & events) != events)
    evio->chglnk = r_queue_push (&evio->loop->chg, evio);

  if (!R_EV_IO_IS_ACTIVE (evio) && !R_EV_IO_IS_INTERNAL (evio))
    evio->alnk = r_queue_push (&evio->loop->active, evio);

  return ret;
}

rboolean
r_ev_io_stop (REvIO * evio, rpointer ctx)
{
  if (R_UNLIKELY (evio == NULL)) return FALSE;
  if (R_UNLIKELY (ctx == NULL)) return FALSE;

  R_LOG_TRACE ("loop %p stop evio "R_EV_IO_FORMAT" %4x - %x",
      evio->loop, R_EV_IO_ARGS (evio), evio->events, RPOINTER_TO_UINT (((RCBList *)ctx)->user));
  r_cbqueue_remove_link (&evio->iocbq, ctx);

  if (R_EV_IO_IS_ACTIVE (evio) || R_EV_IO_IS_INTERNAL (evio)) {
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

  R_LOG_TRACE ("loop %p evio "R_EV_IO_FORMAT, evio->loop, R_EV_IO_ARGS (evio));

  if (evio->handle != R_IO_HANDLE_INVALID && !R_EV_IO_IS_CLOSED (evio)) {
    r_io_close (evio->handle);
    evio->flags |= R_EV_IO_CLOSED;
  }

  if (R_EV_IO_IS_ACTIVE (evio)) {
    r_queue_remove_link (&evio->loop->active, evio->alnk);
    evio->alnk = NULL;
  }

  if (R_EV_IO_IS_ACTIVE (evio) || R_EV_IO_IS_INTERNAL (evio)) {
    if (!R_EV_IO_IS_CHANGING (evio))
      evio->chglnk = r_queue_push (&evio->loop->chg, evio);
  }

  r_cbqueue_push (&evio->loop->acbs, (RFunc)close_cb,
      data, datanotify, r_ev_io_ref (evio), r_ev_io_unref);

  return TRUE;
}

