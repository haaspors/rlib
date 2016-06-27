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

#include <rlib/rlist.h>
#include <rlib/rlog.h>
#include <rlib/rqueue.h>
#include <rlib/rthreadpool.h>

#define R_LOG_CAT_DEFAULT &tqcat
R_LOG_CATEGORY_DEFINE_STATIC (tqcat, "rtaskqueue", "RLib TaskQueue", R_CLR_BG_BLUE);

struct _RTask {
  RRef ref;

  RTaskQueue * queue;
  ruint group;
  RTaskFunc func;
  rpointer data;

  RSList * dep;

  rboolean queued, ran;
};

typedef struct {
  RQueue *  q;
  rboolean  running;
  RCond     cond;
  RMutex    mutex;
} RTQCtx;

struct _RTaskQueue {
  RRef ref;

  RThreadPool * pool;
  RDestroyNotify stop;

  ruint ctxcount;
  RTQCtx * ctx;
};


void
r_task_queue_init (void)
{
  r_log_category_register (&tqcat);
}


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
    if (R_UNLIKELY (!dep->queued))
      return FALSE;
    task->dep = r_slist_prepend (task->dep, r_task_ref (dep));
  }

  return TRUE;
}

static rpointer r_task_queue_loop (rpointer data, rpointer spec);
static void r_task_queue_stop (RTaskQueue * queue);

static void
r_task_queue_free (RTaskQueue * queue)
{
  if (queue != NULL) {
    ruint i;
    r_task_queue_stop (queue);
    r_thread_pool_unref (queue->pool);
    for (i = 0; i < queue->ctxcount; i++) {
      r_queue_free (queue->ctx[i].q, r_task_unref);
      r_cond_clear (&queue->ctx[i].cond);
      r_mutex_clear (&queue->ctx[i].mutex);
    }
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

    ret->ctxcount = ctxcount;
    ret->ctx = r_mem_new_n (RTQCtx, ctxcount);

    for (i = 0; i < ctxcount; i++) {
      ret->ctx[i].q = r_queue_new ();
      ret->ctx[i].running = TRUE;
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

static void
r_task_free (RTask * task)
{
  if (R_LIKELY (task != NULL)) {
    r_slist_destroy_full (task->dep, r_task_unref);
    r_free (task);
  }
}

RTask *
r_task_queue_allocate (RTaskQueue * queue, RTaskFunc func, rpointer data)
{
  RTask * ret;

  /* FIXME: Add pool of tasks to queue */
  if ((ret = r_mem_new0 (RTask)) != NULL) {
    r_ref_init (ret, r_task_free);

    ret->queue = queue;
    ret->func = func;
    ret->data = data;
  }

  return ret;
}

rboolean
r_task_queue_add_task_with_group (RTaskQueue * queue,
    RTask * task, ruint group)
{
  if (R_UNLIKELY (queue == NULL)) return FALSE;
  if (R_UNLIKELY (task == NULL)) return FALSE;
  if (group == RUINT_MAX) group = 0;
  else if (R_UNLIKELY (group >= queue->ctxcount)) return FALSE;

  r_mutex_lock (&queue->ctx[group].mutex);
  R_LOG_DEBUG ("TQ: %p [%u] - push task %p", queue, group, task);
  task->group = group;
  task->queued = TRUE;
  r_queue_push (queue->ctx[group].q, r_task_ref (task));
  r_cond_broadcast (&queue->ctx[group].cond);
  r_mutex_unlock (&queue->ctx[group].mutex);

  return TRUE;
}

RTask *
r_task_queue_add_full (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, ...)
{
  RTask * ret;
  va_list args;

  va_start (args, data);
  ret = r_task_queue_add_full_v (queue, group, func, data, args);
  va_end (args);

  return ret;
}

RTask *
r_task_queue_add_full_v (RTaskQueue * queue, ruint group,
    RTaskFunc func, rpointer data, va_list args)
{
  RTask * ret = NULL;

  if ((ret = r_task_queue_allocate (queue, func, data)) != NULL) {
    RTask * dep = va_arg (args, RTask *);
    if (!r_task_add_dep_v (ret, dep, args) ||
        !r_task_queue_add_task_with_group (queue, ret, group)) {
      r_task_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}


static void
r_task_queue_stop (RTaskQueue * queue)
{
  ruint i;
  for (i = 0; i < queue->ctxcount; i++) {
    r_mutex_lock (&queue->ctx[i].mutex);
    R_LOG_TRACE ("TQ: %p [%p] - stop", queue, &queue->ctx[i]);
    queue->ctx[i].running = FALSE;
    r_cond_broadcast (&queue->ctx[i].cond);
    r_mutex_unlock (&queue->ctx[i].mutex);
  }

  r_thread_pool_join (queue->pool);
}

static rboolean
r_task_queue_ctx_should_pop_locked (RTQCtx * ctx)
{
  RTask * t, * dep;

  if ((t = r_queue_peek (ctx->q)) != NULL) {
    RSList * it;
    for (it = t->dep; it != NULL; it = r_slist_next (it)) {
      dep = r_slist_data (it);
      if (!dep->ran)
        return FALSE;
    }

    return TRUE;
  }

  return FALSE;
}

static rpointer
r_task_queue_loop (rpointer common, rpointer spec)
{
  RTaskQueue * queue = common;
  RTQCtx * ctx = spec;
  RTask * task;

  R_LOG_DEBUG ("TQ: %p - start thread for ctx %p", queue, ctx);
  r_mutex_lock (&(ctx)->mutex);
  while (ctx->running) {
    if (R_LIKELY ((task = r_queue_pop (ctx->q)) != NULL)) {
      r_mutex_unlock (&(ctx)->mutex);
      R_LOG_TRACE ("TQ: %p [%p] - process task %p", queue, ctx, task);
      task->func (task->data, queue, task);
      task->ran = TRUE;
      r_task_unref (task);
      r_mutex_lock (&(ctx)->mutex);
    }
    if (R_UNLIKELY (!ctx->running))
      break;
    if (!r_task_queue_ctx_should_pop_locked (ctx)) {
      R_LOG_TRACE ("TQ: %p [%p] - wait", queue, ctx);
      r_cond_wait (&(ctx)->cond, &(ctx)->mutex);
    }
  }
  r_mutex_unlock (&(ctx)->mutex);
  R_LOG_DEBUG ("TQ: %p - end thread for ctx %p", queue, ctx);

  return NULL;
}

