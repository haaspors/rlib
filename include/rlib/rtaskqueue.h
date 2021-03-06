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

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rbitset.h>

#include <stdarg.h>

R_BEGIN_DECLS

typedef struct _RTask RTask;
typedef struct _RTaskQueue RTaskQueue;
typedef void (*RTaskFunc) (rpointer data, RTaskQueue * queue, RTask * task);

#define r_task_ref    r_ref_ref
#define r_task_unref  r_ref_unref
R_API rboolean r_task_add_dep (RTask * task, RTask * dep, ...) R_ATTR_NULL_TERMINATED;
R_API rboolean r_task_add_dep_v (RTask * task, RTask * dep, va_list args);
R_API rboolean r_task_cancel (RTask * task, rboolean wait_if_running);
R_API rboolean r_task_wait (RTask * task);

R_API RTaskQueue * r_task_queue_new (ruint groups, ruint threads_per_group) R_ATTR_MALLOC;
R_API RTaskQueue * r_task_queue_new_pin_and_group_on_numa_node (const RBitset * nodeset, ruint threads_per_group) R_ATTR_MALLOC;
R_API RTaskQueue * r_task_queue_new_pin_on_cpu_group_numa_node (const RBitset * nodeset) R_ATTR_MALLOC;
R_API RTaskQueue * r_task_queue_new_pin_on_each_cpu (const RBitset * cpuset, ruint groups) R_ATTR_MALLOC;
R_API RTaskQueue * r_task_queue_new_pin_on_each_cpu_group_numa_node (const RBitset * cpuset) R_ATTR_MALLOC;
#define r_task_queue_ref    r_ref_ref
#define r_task_queue_unref  r_ref_unref
R_API RTaskQueue * r_task_queue_current (void);

R_API RTask * r_task_queue_allocate (RTaskQueue * queue, RTaskFunc func,
    rpointer data, RDestroyNotify datanotify);
#define r_task_queue_add_task(queue, task)                                    \
  r_task_queue_add_task_with_group (queue, task, RUINT_MAX)
R_API rboolean r_task_queue_add_task_with_group (RTaskQueue * queue,
    RTask * task, ruint group);

#define r_task_queue_add(queue, func, data, datanotify)                       \
  r_task_queue_add_full (queue, RUINT_MAX, func, data, datanotify, NULL)
R_API RTask * r_task_queue_add_full (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, RDestroyNotify datanotify,
    ...) R_ATTR_NULL_TERMINATED R_ATTR_WARN_UNUSED_RESULT;
R_API RTask * r_task_queue_add_full_v (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, RDestroyNotify datanotify,
    va_list args) R_ATTR_WARN_UNUSED_RESULT;

R_API rsize r_task_queue_queued_tasks (const RTaskQueue * queue);
R_API ruint r_task_queue_group_count (const RTaskQueue * queue);
R_API ruint r_task_queue_thread_count (const RTaskQueue * queue);

R_END_DECLS

#endif /* __R_TASK_QUEUE_H__ */

