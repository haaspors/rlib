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
#ifndef __R_EV_LOOP_H__
#define __R_EV_LOOP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/ev/revloop.h
 * @brief The event loop: run modes, timers, idle / prepare / callback
 * hooks and task-queue integration.
 */

#include <rlib/ev/revio.h>

#include <rlib/rclock.h>
#include <rlib/rref.h>
#include <rlib/concurrency/rtaskqueue.h>

#include <stdarg.h>

/**
 * @defgroup r_evloop Event loop (REvLoop)
 * @ingroup r_ev
 *
 * @brief The core loop object: drive it with @ref r_ev_loop_run, and
 * schedule timers, idle / prepare hooks, immediate callbacks and
 * off-thread tasks on it.
 *
 * An @ref REvLoop owns an @ref RClock (for timers) and optionally an
 * @ref RTaskQueue (for offloading work via @ref r_ev_loop_add_task).
 * I/O sources (@ref r_evio, @ref r_evtcp, @ref r_evudp,
 * @ref r_evresolve, @ref r_evwakeup) register against it and fire
 * their callbacks on the loop thread, so callbacks must not block —
 * push long-running work to a task group instead.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief How far @ref r_ev_loop_run advances before returning. */
typedef enum {
  R_EV_LOOP_RUN_LOOP,   /**< Run until the loop is stopped. */
  R_EV_LOOP_RUN_ONCE,   /**< Block for and process one round of events. */
  R_EV_LOOP_RUN_NOWAIT, /**< Process ready events without blocking. */
} REvLoopRunMode;

/** @brief Opaque, refcounted event loop. */
typedef struct REvLoop REvLoop;
/** @brief Loop callback. */
typedef void (*REvFunc) (rpointer data, REvLoop * loop);
/** @brief Loop callback returning whether it should remain registered. */
typedef rboolean (*REvFuncReturn) (rpointer data, REvLoop * loop);

/** @brief Create a loop with a default clock and no task queue. */
#define r_ev_loop_new() r_ev_loop_new_full (NULL, NULL)
/** @brief Create a loop with an explicit @p clock and task queue @p tq (either may be @c NULL). */
R_API REvLoop * r_ev_loop_new_full (RClock * clock, RTaskQueue * tq) R_ATTR_MALLOC;
/** @brief Return the process-wide default loop, creating it on first use. */
R_API REvLoop * r_ev_loop_default (void);
/** @brief Return the loop running on the calling thread, or @c NULL. */
R_API REvLoop * r_ev_loop_current (void);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_ev_loop_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_ev_loop_unref r_ref_unref

/**
 * @brief Run the loop in @p mode.
 * @return Number of events / callbacks processed.
 */
R_API ruint r_ev_loop_run (REvLoop * loop, REvLoopRunMode mode);
/** @brief Ask a running loop to stop (it returns from @ref r_ev_loop_run). */
R_API void r_ev_loop_stop (REvLoop * loop);

/** @brief Total iterations the loop has run. */
R_API rsize r_ev_loop_get_iterations (const REvLoop * loop);
/** @brief Number of registered idle callbacks. */
R_API rsize r_ev_loop_get_idle_count (const REvLoop * loop);

/** @brief Number of task groups in the loop's task queue. */
R_API ruint r_ev_loop_task_group_count (REvLoop * loop);

/** @brief Run @p prepare_cb before each poll; returns whether to stay registered. */
R_API rboolean r_ev_loop_add_prepare (REvLoop * loop, REvFuncReturn prepare_cb,
    rpointer data, RDestroyNotify datanotify);
/** @brief Run @p idle_cb when the loop is otherwise idle; returns whether to stay registered. */
R_API rboolean r_ev_loop_add_idle (REvLoop * loop, REvFuncReturn idle_cb,
    rpointer data, RDestroyNotify datanotify);
/**
 * @brief Queue a one-shot callback to run on the next loop iteration;
 * @p pri @c TRUE runs it ahead of non-priority callbacks.
 */
R_API rboolean r_ev_loop_add_callback (REvLoop * loop, rboolean pri,
    REvFunc cb, rpointer data, RDestroyNotify datanotify);

/**
 * @brief Schedule @p cb to fire at absolute time @p deadline; the
 * optional @p entry out-pointer receives a cancellable timer handle.
 */
R_API rboolean r_ev_loop_add_callback_at (REvLoop * loop, RClockEntry ** entry,
    RClockTime deadline, REvFunc cb, rpointer data, RDestroyNotify datanotify);
/** @brief Schedule @p cb to fire after @p delay from now. */
R_API rboolean r_ev_loop_add_callback_later (REvLoop * loop, RClockEntry ** entry,
    RClockTimeDiff delay, REvFunc cb, rpointer data, RDestroyNotify datanotify);
/** @brief Cancel a timer entry from @ref r_ev_loop_add_callback_at / @ref r_ev_loop_add_callback_later. */
R_API rboolean r_ev_loop_cancel_timer (REvLoop * loop, RClockEntry * entry);

/** @brief Queue a task on any group, with @p done fired on the loop thread when it completes. */
#define r_ev_loop_add_task(loop, task, done, data, datanotify)                \
  r_ev_loop_add_task_full (loop, RUINT_MAX, task, done, data, datanotify, NULL)
/** @brief @ref r_ev_loop_add_task pinned to a specific task @p group. */
#define r_ev_loop_add_task_with_taskgroup(loop, group, task, done, data, datanotify)  \
  r_ev_loop_add_task_full (loop, group, task, done, data, datanotify, NULL)
/**
 * @brief Queue @p task on @p taskgroup; @p done runs on the loop
 * thread once it finishes. Trailing args are @c RTask dependencies
 * (@c NULL-terminated).
 */
R_API RTask * r_ev_loop_add_task_full (REvLoop * loop, ruint taskgroup,
    RTaskFunc task, REvFunc done, rpointer data, RDestroyNotify datanotify,
    ...) R_ATTR_NULL_TERMINATED;
/** @brief @c va_list variant of @ref r_ev_loop_add_task_full. */
R_API RTask * r_ev_loop_add_task_full_v (REvLoop * loop, ruint taskgroup,
    RTaskFunc task, REvFunc done, rpointer data, RDestroyNotify datanotify,
    va_list args);

/** @brief Convenience: create an @ref REvIO watcher for @p handle on @p loop. */
static inline REvIO * r_ev_loop_create_ev_io (REvLoop * loop, RIOHandle handle)
{ return r_ev_io_new (loop, handle); }

R_END_DECLS

/** @} */

#endif /* __R_EV_LOOP_H__ */

