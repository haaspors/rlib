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
#include <rlib/rtaskqueue.h>

#include <rlib/data/rlist.h>
#include <rlib/data/rqueue.h>

#include <rlib/os/rsys.h>

#include <rlib/rlog.h>
#include <rlib/rthreadpool.h>

R_LOG_CATEGORY_DEFINE_STATIC (tqcat, "taskqueue", "RLib TaskQueue",
    R_CLR_BG_BLUE);
#define R_LOG_CAT_DEFAULT &tqcat

static RTss  g__r_task_queue_tss = R_TSS_INIT (NULL);

typedef enum {
  R_TASK_NONE     = 0x00,
  R_TASK_QUEUED   = 0x01,
  R_TASK_RUNNING  = 0x02,
  R_TASK_DONE     = 0xf0,
  R_TASK_CANCELED = 0xf1,
} RTaskState;

struct _RTask {
  RRef ref;
  RTaskState state;

  RTaskQueue * queue;
  ruint group;
  RTaskFunc func;
  rpointer data;
  RDestroyNotify datanotify;

  RSList * dep;
};

typedef struct {
  RQueue *  q;
  rboolean  running;
  RCond     cond;
  RMutex    mutex;
  ruint     threads;
} RTQCtx;

struct _RTaskQueue {
  RRef ref;

  RThreadPool * pool;
  RDestroyNotify stop;

  RCond   wait_cond;
  RMutex  wait_mutex;

  ruint ctxcount;
  RTQCtx * ctx;
};


void
r_task_queue_init (void)
{
  r_log_category_register (&tqcat);
}


static rpointer r_task_queue_loop (rpointer data, rpointer spec);

rboolean
r_task_add_dep (RTask * task, RTask * dep, ...)
{
  rboolean ret;
  va_list args;

  va_start (args, dep);
  ret = r_task_add_dep_v (task, dep, args);
  va_end (args);

  return ret;
}

rboolean
r_task_add_dep_v (RTask * task, RTask * dep, va_list args)
{
  for (; dep != NULL; dep = va_arg (args, RTask *)) {
    if (R_UNLIKELY (dep->state < R_TASK_QUEUED))
      return FALSE;
    task->dep = r_slist_prepend (task->dep, r_task_ref (dep));
  }

  return TRUE;
}

rboolean
r_task_cancel (RTask * task, rboolean wait_if_running)
{
  RTQCtx * ctx;
  rboolean ret;

  if (R_UNLIKELY (task == NULL || task->queue == NULL)) return FALSE;

  ctx = &task->queue->ctx[task->group];

  r_mutex_lock (&(ctx)->mutex);
  if ((ret = (task->state >= R_TASK_QUEUED))) {
    if (wait_if_running && r_task_queue_current () == NULL &&
        task->state == R_TASK_RUNNING) {
      r_mutex_unlock (&(ctx)->mutex);
      r_task_wait (task);
      r_mutex_lock (&(ctx)->mutex);
    }
    if (task->state < R_TASK_DONE) {
      r_mutex_lock (&task->queue->wait_mutex);
      task->state = R_TASK_CANCELED;
      r_cond_broadcast (&task->queue->wait_cond);
      r_mutex_unlock (&task->queue->wait_mutex);
    }
  }
  r_mutex_unlock (&(ctx)->mutex);

  return ret;
}

rboolean
r_task_wait (RTask * task)
{
  if (R_UNLIKELY (task == NULL || task->queue == NULL)) return FALSE;
  if (R_UNLIKELY (r_task_queue_current () != NULL)) {
    R_LOG_ERROR ("Do NOT wait for a task (%p) from a task callback!", task);
    abort ();
    return FALSE;
  }

  r_mutex_lock (&task->queue->wait_mutex);
  while (task->state < R_TASK_DONE)
    r_cond_wait (&task->queue->wait_cond, &task->queue->wait_mutex);
  r_mutex_unlock (&task->queue->wait_mutex);

  return TRUE;
}

static void
r_task_queue_free (RTaskQueue * queue)
{
  if (queue != NULL) {
    ruint i;

    for (i = 0; i < queue->ctxcount; i++) {
      r_mutex_lock (&queue->ctx[i].mutex);
      R_LOG_TRACE ("TQ: %p [%p] - stop", queue, &queue->ctx[i]);
      queue->ctx[i].running = FALSE;
      r_cond_broadcast (&queue->ctx[i].cond);
      r_mutex_unlock (&queue->ctx[i].mutex);
    }

    r_thread_pool_join (queue->pool);
    r_thread_pool_unref (queue->pool);

    for (i = 0; i < queue->ctxcount; i++) {
      r_queue_free (queue->ctx[i].q, r_task_unref);
      r_cond_clear (&queue->ctx[i].cond);
      r_mutex_clear (&queue->ctx[i].mutex);
    }

    r_cond_clear (&queue->wait_cond);
    r_mutex_clear (&queue->wait_mutex);

    r_free (queue->ctx);
    r_free (queue);
  }
}

static RTaskQueue *
r_task_queue_alloc (rsize ctxcount)
{
  RTaskQueue * ret;

  if ((ret = r_mem_new0 (RTaskQueue)) != NULL) {
    ruint i;
    r_ref_init (ret, r_task_queue_free);

    r_mutex_init (&ret->wait_mutex);
    r_cond_init (&ret->wait_cond);

    ret->ctxcount = ctxcount;
    ret->ctx = r_mem_new_n (RTQCtx, ctxcount);

    for (i = 0; i < ctxcount; i++) {
      ret->ctx[i].q = r_queue_new ();
      ret->ctx[i].running = TRUE;
      ret->ctx[i].threads = 0;
      r_mutex_init (&ret->ctx[i].mutex);
      r_cond_init (&ret->ctx[i].cond);
    }

    ret->pool = r_thread_pool_new ("taskqueue", r_task_queue_loop, ret);
  }

  return ret;
}


RTaskQueue *
r_task_queue_new_simple (ruint threads)
{
  RTaskQueue * ret;

  if (R_UNLIKELY (threads == 0)) return NULL;

  if ((ret = r_task_queue_alloc (1)) != NULL) {
    R_LOG_DEBUG ("New simple task queue: %p, %u threads", ret, threads);
    while (threads--)
      r_thread_pool_start_thread (ret->pool, NULL, NULL, ret->ctx);
  }

  return ret;
}

RTaskQueue *
r_task_queue_new_thread_per_group (ruint groups)
{
  RTaskQueue * ret;

  if (R_UNLIKELY (groups == 0)) return NULL;

  if ((ret = r_task_queue_alloc (groups)) != NULL) {
    ruint i;
    for (i = 0; i < groups; i++)
      r_thread_pool_start_thread (ret->pool, NULL, NULL, &ret->ctx[i]);
  }

  return ret;
}

RTaskQueue *
r_task_queue_new_per_numa_simple (ruint thrpernode)
{
  RSysTopology * topo;
  RTaskQueue * ret = NULL;
  RBitset * cpuset;

  if (!r_bitset_init_stack (cpuset, r_sys_cpuset_max ()))
    return NULL;

  if ((topo = r_sys_topology_discover ()) != NULL) {
    rsize i, nodes = r_sys_topology_node_count (topo);
    if ((ret = r_task_queue_alloc (nodes)) != NULL) {
      for (i = 0; i < nodes; i++) {
        RSysNode * node;

        if ((node = r_sys_topology_node (topo, i)) != NULL) {
          r_bitset_clear (cpuset);
          if (r_sys_topology_node_cpuset (node, cpuset) &&
              r_bitset_popcount (cpuset) > 0) {
            ruint j;
            for (j = 0; j < thrpernode; j++)
              r_thread_pool_start_thread (ret->pool, NULL, cpuset, &ret->ctx[i]);
          }
          r_sys_node_unref (node);
        }
      }
    }

    r_sys_topology_unref (topo);
  }

  return ret;
}

RTaskQueue *
r_task_queue_new_per_numa_each_cpu (void)
{
  RSysTopology * topo;
  RTaskQueue * ret = NULL;
  RBitset * cpuset;

  if (!r_bitset_init_stack (cpuset, r_sys_cpuset_max ()))
    return NULL;

  if ((topo = r_sys_topology_discover ()) != NULL) {
    rsize i, nodes = r_sys_topology_node_count (topo);
    if ((ret = r_task_queue_alloc (nodes)) != NULL) {
      for (i = 0; i < nodes; i++) {
        RSysNode * node;

        if ((node = r_sys_topology_node (topo, i)) != NULL) {
          r_bitset_clear (cpuset);
          if (r_sys_topology_node_cpuset (node, cpuset) &&
              r_bitset_popcount (cpuset) > 0) {
            r_thread_pool_start_thread_on_each_cpu (ret->pool, cpuset,
                &ret->ctx[i]);
          }
          r_sys_node_unref (node);
        }
      }
    }

    r_sys_topology_unref (topo);
  }

  return ret;
}

RTaskQueue *
r_task_queue_new_per_numa_each_cpu_with_cpuset (const RBitset * cpuset)
{
  RSysTopology * topo;
  RTaskQueue * ret = NULL;
  RBitset * ncpuset;

  if (cpuset == NULL)
    return r_task_queue_new_per_numa_each_cpu ();

  if (!r_bitset_init_stack (ncpuset, r_sys_cpuset_max ()))
    return NULL;

  if ((topo = r_sys_topology_discover ()) != NULL) {
    rsize i, nodes = r_sys_topology_node_count (topo);
    if ((ret = r_task_queue_alloc (nodes)) != NULL) {
      for (i = 0; i < nodes; i++) {
        RSysNode * node;

        if ((node = r_sys_topology_node (topo, i)) != NULL) {
          r_bitset_clear (ncpuset);
          if (r_sys_topology_node_cpuset (node, ncpuset) &&
              r_bitset_or (ncpuset, ncpuset, cpuset) &&
              r_bitset_popcount (ncpuset) > 0) {
            r_thread_pool_start_thread_on_each_cpu (ret->pool, ncpuset,
                &ret->ctx[i]);
          }
          r_sys_node_unref (node);
        }
      }
    }

    r_sys_topology_unref (topo);
  }

  return ret;
}

RTaskQueue *
r_task_queue_new_per_cpu_simple (ruint cpupergroup)
{
  RTaskQueue * ret = NULL;
  ruint i, g, cpus = r_sys_cpu_logical_count ();

  if (R_UNLIKELY (cpupergroup == 0)) return NULL;
  g = (cpus + cpupergroup - 1) / cpupergroup;
  if (R_UNLIKELY (g == 0)) g = 1;

  if ((ret = r_task_queue_alloc (g)) != NULL) {
    for (i = 0; i < cpus; i++)
      r_thread_pool_start_thread_on_cpu (ret->pool, i, &ret->ctx[i / cpupergroup]);
  }

  return ret;
}

RTaskQueue *
r_task_queue_current (void)
{
  return r_tss_get (&g__r_task_queue_tss);
}

static void
r_task_free (RTask * task)
{
  if (R_LIKELY (task != NULL)) {
    if (task->datanotify != NULL)
      task->datanotify (task->data);
    r_slist_destroy_full (task->dep, r_task_unref);
    r_free (task);
  }
}

RTask *
r_task_queue_allocate (RTaskQueue * queue, RTaskFunc func,
    rpointer data, RDestroyNotify datanotify)
{
  RTask * ret;

  /* FIXME: Add taskpool to avoid to many malloc/free ? */
  if ((ret = r_mem_new0 (RTask)) != NULL) {
    r_ref_init (ret, r_task_free);

    ret->queue = queue;
    ret->func = func;
    ret->data = data;
    ret->datanotify = datanotify;
  }

  return ret;
}

rboolean
r_task_queue_add_task_with_group (RTaskQueue * queue,
    RTask * task, ruint group)
{
  RTQCtx * ctx;

  if (R_UNLIKELY (queue == NULL)) return FALSE;
  if (R_UNLIKELY (task == NULL)) return FALSE;
  if (R_UNLIKELY (task->queue != queue)) return FALSE;
  if (group == RUINT_MAX) group = 0;
  else if (R_UNLIKELY (group >= queue->ctxcount)) return FALSE;

  ctx = &queue->ctx[group];
  r_mutex_lock (&ctx->mutex);
  if (ctx->threads > 0)
    R_LOG_DEBUG ("TQ: %p [%u] - push task %p", queue, group, task);
  else
    R_LOG_WARNING ("TQ: %p [%u] - push task %p (no threads)", queue, group, task);
  task->group = group;
  task->state = R_TASK_QUEUED;
  r_queue_push (ctx->q, r_task_ref (task));
  r_cond_signal (&ctx->cond);
  r_mutex_unlock (&ctx->mutex);

  return TRUE;
}

RTask *
r_task_queue_add_full (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, RDestroyNotify datanotify, ...)
{
  RTask * ret;
  va_list args;

  va_start (args, datanotify);
  ret = r_task_queue_add_full_v (queue, group, func, data, datanotify, args);
  va_end (args);

  return ret;
}

RTask *
r_task_queue_add_full_v (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, RDestroyNotify datanotify, va_list args)
{
  RTask * ret = NULL;

  if ((ret = r_task_queue_allocate (queue, func, data, datanotify)) != NULL) {
    RTask * dep = va_arg (args, RTask *);
    if (!r_task_add_dep_v (ret, dep, args) ||
        !r_task_queue_add_task_with_group (queue, ret, group)) {
      r_task_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

static RTask *
r_task_queue_ctx_pop_locked (RTQCtx * ctx)
{
  RTask * t, * dep;

  /* FIXME: Traverse the queue internally to pick the first task with all
   * deps satisfied ?? */
  if ((t = r_queue_peek (ctx->q)) != NULL) {
    RSList * it;
    for (it = t->dep; it != NULL; it = r_slist_next (it)) {
      dep = r_slist_data (it);
      if (dep->state < R_TASK_DONE)
        return NULL;
    }

    return r_queue_pop (ctx->q);
  }

  return NULL;
}

static rpointer
r_task_queue_loop (rpointer common, rpointer spec)
{
  RTaskQueue * queue = common;
  RTQCtx * ctx = spec;
  RTask * task;

  if (R_UNLIKELY (r_tss_get (&g__r_task_queue_tss) != NULL)) {
    R_LOG_ERROR ("Nested task queue???? %p ---> %p",
        queue, r_tss_get (&g__r_task_queue_tss));
    abort ();
  }

  R_LOG_DEBUG ("TQ: %p - start thread for ctx %p", queue, ctx);
  r_tss_set (&g__r_task_queue_tss, queue);
  r_mutex_lock (&(ctx)->mutex);
  ctx->threads++;
  while (ctx->running) {
    if (R_LIKELY ((task = r_task_queue_ctx_pop_locked (ctx)) != NULL)) {
      RSList * dep = task->dep;
      task->dep = NULL;
      if (task->state == R_TASK_QUEUED) {
        task->state = R_TASK_RUNNING;
        r_mutex_unlock (&(ctx)->mutex);
        {
          r_slist_destroy_full (dep, r_task_unref);
          R_LOG_TRACE ("TQ: %p [%p] - process task %p", queue, ctx, task);
          task->func (task->data, queue, task);
        }
        r_mutex_lock (&(ctx)->mutex);
        r_mutex_lock (&queue->wait_mutex);
        task->state = R_TASK_DONE;
        r_cond_broadcast (&queue->wait_cond);
        r_mutex_unlock (&queue->wait_mutex);
      } else {
        R_LOG_DEBUG ("TQ: %p [%p] - process task %p - not queued 0x%.2x",
            queue, ctx, task, task->state);
        if (dep != NULL) {
          r_mutex_unlock (&(ctx)->mutex);
          r_slist_destroy_full (dep, r_task_unref);
          r_mutex_lock (&(ctx)->mutex);
        }
      }
      r_task_unref (task);
    } else {
      R_LOG_TRACE ("TQ: %p [%p] - wait", queue, ctx);
      r_cond_wait (&(ctx)->cond, &(ctx)->mutex);
    }
  }
  ctx->threads--;
  r_mutex_unlock (&(ctx)->mutex);
  r_tss_set (&g__r_task_queue_tss, NULL);
  R_LOG_DEBUG ("TQ: %p - end thread for ctx %p", queue, ctx);

  return NULL;
}

rsize
r_task_queue_queued_tasks (const RTaskQueue * queue)
{
  ruint i;
  rsize ret = 0;

  for (i = 0; i < queue->ctxcount; i++)
    ret += r_queue_size (queue->ctx[i].q);

  return ret;
}

ruint
r_task_queue_group_count (const RTaskQueue * queue)
{
  return queue->ctxcount;
}

ruint
r_task_queue_thread_count (const RTaskQueue * queue)
{
  return r_thread_pool_running_threads (queue->pool);
}

