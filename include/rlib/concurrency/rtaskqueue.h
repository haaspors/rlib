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
#ifndef __R_TASK_QUEUE_H__
#define __R_TASK_QUEUE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/concurrency/rtaskqueue.h
 * @brief Multi-group, multi-thread task queue with dependencies,
 * cancellation and NUMA-aware worker placement.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rbitset.h>

#include <stdarg.h>

R_BEGIN_DECLS

/**
 * @defgroup r_taskqueue Task queue (RTaskQueue)
 * @ingroup r_concurrency
 *
 * @brief Deferred-work queue: callers enqueue @ref RTask objects
 * with optional dependencies, worker threads owned by the queue
 * pick them up and run them to completion.
 *
 * A queue is partitioned into one or more @e groups, each backed by
 * a set of worker threads. @ref r_task_queue_add_task_with_group
 * (or the @ref r_task_queue_add_full convenience) pins the task to a
 * specific group; @c RUINT_MAX means "any group". Workers can be
 * pinned to individual CPUs or NUMA nodes via the
 * @c _pin_on_* constructors for cache locality.
 *
 * Each task is refcounted and one-shot. Tasks may declare
 * dependencies on other tasks; the queue only dispatches a task
 * once every dep has finished. @ref r_task_cancel removes a task
 * from the queue (optionally waiting if it has already started),
 * @ref r_task_wait blocks until completion.
 *
 * @{
 */

/** @brief Opaque, refcounted task handle. */
typedef struct RTask RTask;
/** @brief Opaque, refcounted task-queue handle. */
typedef struct RTaskQueue RTaskQueue;
/**
 * @brief Task entry-point signature.
 *
 * @param data  Opaque payload supplied at task creation.
 * @param queue Queue dispatching this task.
 * @param task  The task being run (useful for spawning continuations).
 */
typedef void (*RTaskFunc) (rpointer data, RTaskQueue * queue, RTask * task);

/** @brief Take a reference on a task (alias for @ref r_ref_ref). */
#define r_task_ref    r_ref_ref
/** @brief Drop a reference on a task (alias for @ref r_ref_unref). */
#define r_task_unref  r_ref_unref
/**
 * @brief Add one or more dependencies to a task that has not yet run.
 *
 * The variadic argument list is a @c NULL-terminated sequence of
 * additional @ref RTask pointers; @p dep is required, the rest are
 * optional. @p task will not be dispatched until every listed
 * dependency has finished (cancelled deps also satisfy the wait).
 *
 * @return @c TRUE if all deps were attached, @c FALSE if @p task
 *         had already been dispatched.
 */
R_API rboolean r_task_add_dep (RTask * task, RTask * dep, ...) R_ATTR_NULL_TERMINATED;
/** @brief @c va_list variant of @ref r_task_add_dep. */
R_API rboolean r_task_add_dep_v (RTask * task, RTask * dep, va_list args);
/**
 * @brief Cancel a pending or running task.
 *
 * @param task            Task to cancel.
 * @param wait_if_running If @c TRUE and the task has already started,
 *                        block until it returns. If @c FALSE, return
 *                        immediately leaving the task to finish on
 *                        its own.
 * @return @c TRUE if the task was cancelled before running, @c FALSE
 *         if it had already started.
 */
R_API rboolean r_task_cancel (RTask * task, rboolean wait_if_running);
/**
 * @brief Block until @p task has finished (cancelled tasks count as
 * finished).
 * @return @c TRUE on a successful wait, @c FALSE if @p task is invalid.
 */
R_API rboolean r_task_wait (RTask * task);

/**
 * @brief Create a queue with @p groups worker groups, each containing
 * @p threads_per_group worker threads.
 *
 * No affinity hints are applied; threads run wherever the OS schedules
 * them. Use one of the @c _pin_on_* constructors for NUMA-aware pinning.
 */
R_API RTaskQueue * r_task_queue_new (ruint groups, ruint threads_per_group) R_ATTR_MALLOC;
/**
 * @brief One group per NUMA node selected by @p nodeset, each with
 * @p threads_per_group workers pinned to that node's CPUs.
 */
R_API RTaskQueue * r_task_queue_new_pin_and_group_on_numa_node (const RBitset * nodeset, ruint threads_per_group) R_ATTR_MALLOC;
/**
 * @brief One worker per CPU on the selected NUMA nodes, grouped per
 * NUMA node.
 */
R_API RTaskQueue * r_task_queue_new_pin_on_cpu_group_numa_node (const RBitset * nodeset) R_ATTR_MALLOC;
/**
 * @brief One worker per CPU in @p cpuset; workers are partitioned
 * evenly across @p groups groups.
 */
R_API RTaskQueue * r_task_queue_new_pin_on_each_cpu (const RBitset * cpuset, ruint groups) R_ATTR_MALLOC;
/**
 * @brief One worker per CPU in @p cpuset, grouped by the NUMA node
 * each CPU belongs to.
 */
R_API RTaskQueue * r_task_queue_new_pin_on_each_cpu_group_numa_node (const RBitset * cpuset) R_ATTR_MALLOC;
/** @brief Take a reference on the queue (alias for @ref r_ref_ref). */
#define r_task_queue_ref    r_ref_ref
/** @brief Drop a reference on the queue (alias for @ref r_ref_unref). */
#define r_task_queue_unref  r_ref_unref
/**
 * @brief Return the queue owning the calling thread, or @c NULL if
 * the calling thread is not a queue worker.
 */
R_API RTaskQueue * r_task_queue_current (void);

/**
 * @brief Allocate a task bound to @p queue without dispatching it.
 *
 * Useful when the task needs dependencies (see @ref r_task_add_dep)
 * attached before it goes live. Use @ref r_task_queue_add_task to
 * dispatch.
 *
 * @param queue      Queue the task will run on.
 * @param func       Task entry point.
 * @param data       Payload forwarded to @p func.
 * @param datanotify Destructor called on @p data when the task is
 *                   freed; may be @c NULL.
 */
R_API RTask * r_task_queue_allocate (RTaskQueue * queue, RTaskFunc func,
    rpointer data, RDestroyNotify datanotify);
/**
 * @brief Dispatch a pre-allocated task to any worker group.
 *
 * Convenience wrapper that passes @c RUINT_MAX as the group.
 */
#define r_task_queue_add_task(queue, task)                                    \
  r_task_queue_add_task_with_group (queue, task, RUINT_MAX)
/**
 * @brief Dispatch a pre-allocated task to a specific group.
 *
 * @param queue Queue the task is bound to.
 * @param task  Task to dispatch.
 * @param group Group index, or @c RUINT_MAX to let the queue pick.
 * @return @c TRUE on success, @c FALSE if the group is invalid or
 *         the task has already been dispatched.
 */
R_API rboolean r_task_queue_add_task_with_group (RTaskQueue * queue,
    RTask * task, ruint group);

/**
 * @brief Allocate-and-dispatch a task in one call, no dependencies.
 *
 * Convenience wrapper around @ref r_task_queue_add_full with
 * @c RUINT_MAX group and no deps.
 */
#define r_task_queue_add(queue, func, data, datanotify)                       \
  r_task_queue_add_full (queue, RUINT_MAX, func, data, datanotify, NULL)
/**
 * @brief Allocate-and-dispatch a task with group and dependencies.
 *
 * @param queue       Queue the task will run on.
 * @param group       Group index, or @c RUINT_MAX for "any group".
 * @param func        Task entry point.
 * @param data        Payload forwarded to @p func.
 * @param datanotify  Destructor for @p data; may be @c NULL.
 * @param ...         @c NULL-terminated list of @ref RTask dependencies.
 * @return Refcounted handle to the newly-queued task.
 */
R_API RTask * r_task_queue_add_full (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, RDestroyNotify datanotify,
    ...) R_ATTR_NULL_TERMINATED R_ATTR_WARN_UNUSED_RESULT;
/** @brief @c va_list variant of @ref r_task_queue_add_full. */
R_API RTask * r_task_queue_add_full_v (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, RDestroyNotify datanotify,
    va_list args) R_ATTR_WARN_UNUSED_RESULT;

/** @brief Number of tasks currently queued but not yet running. */
R_API rsize r_task_queue_queued_tasks (const RTaskQueue * queue);
/** @brief Number of worker groups in @p queue. */
R_API ruint r_task_queue_group_count (const RTaskQueue * queue);
/** @brief Total number of worker threads across all groups. */
R_API ruint r_task_queue_thread_count (const RTaskQueue * queue);

R_END_DECLS

/** @} */

#endif /* __R_TASK_QUEUE_H__ */

