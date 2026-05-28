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
#ifndef __R_QUEUE_H__
#define __R_QUEUE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_queue Queues
 * @ingroup r_data
 *
 * @brief Three queue implementations for different access patterns:
 * a list-backed FIFO, a callback queue keyed on @ref RFuncCallbackCtx,
 * and a refcounted circular ring buffer with bounded capacity.
 *
 * @c RQueue is a typedef alias for @ref RQueueList - the most common
 * choice when nothing else applies. @c RCBQueue is the deferred-work
 * counterpart that wraps each entry in an @ref RFuncCallbackCtx so
 * the queue can both store and later invoke the work. @c RQueueRing
 * is for bounded producer/consumer scenarios where an upper bound
 * on the queue depth is known at construction time.
 *
 * @{
 */

/**
 * @file rlib/data/rqueue.h
 * @brief FIFO queue (list-backed), callback queue, and bounded
 * ring-buffer queue.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rlist.h>

R_BEGIN_DECLS

/* RQueue is really just RQueueList */
/** @brief Alias: @c RQueue is the list-backed queue type. */
#define RQueue              RQueueList
/** @brief Static initialiser for an empty @c RQueue. */
#define R_QUEUE_INIT        R_QUEUE_LIST_INIT
/** @brief Allocate a heap-backed empty queue. */
#define r_queue_new         r_queue_list_new
/** @brief Free a heap-backed queue, calling @p notify on each remaining item. */
#define r_queue_free        r_queue_list_free
/** @brief Initialise a stack-allocated queue to empty. */
#define r_queue_init        r_queue_list_init
/** @brief Remove all items from @p q, calling @p notify on each. */
#define r_queue_clear       r_queue_list_clear
/** @brief Push @p item onto the tail; returns the new node. */
#define r_queue_push        r_queue_list_push
/** @brief Pop the head item; returns the item or @c NULL when empty. */
#define r_queue_pop         r_queue_list_pop
/** @brief Peek at the head item without removing it. */
#define r_queue_peek        r_queue_list_peek
/** @brief Remove an arbitrary node from @p q. */
#define r_queue_remove_link r_queue_list_remove_link
/** @brief Number of items currently in @p q. */
#define r_queue_size        r_queue_list_size
/** @brief @c TRUE iff @p q has no items. */
#define r_queue_is_empty    r_queue_list_is_empty


/** @name List-backed queue (RQueueList)
 *  @{ */

/**
 * @brief List-backed FIFO / deque.
 *
 * @c head and @c tail are doubly-linked @c RList nodes;
 * @ref r_queue_list_push appends in O(1) and
 * @ref r_queue_list_pop removes from the head in O(1).
 */
typedef struct {
  RList * head;                 /**< Head node. */
  RList * tail;                 /**< Tail node. */
  rsize size;                   /**< Number of items currently in the queue. */
} RQueueList;

/** @brief Static initialiser for an empty @ref RQueueList. */
#define R_QUEUE_LIST_INIT { NULL, NULL, 0 }
/** @brief Heap-allocate an empty @ref RQueueList. */
static inline RQueueList * r_queue_list_new (void) R_ATTR_MALLOC;
/** @brief Initialise a stack-allocated @ref RQueueList. */
static inline void        r_queue_list_init (RQueueList * q);
/** @brief Free a heap-allocated queue, calling @p notify on each item. */
static inline void        r_queue_list_free (RQueueList * q, RDestroyNotify notify);
/** @brief Drop every item from @p q, calling @p notify on each. */
static inline void        r_queue_list_clear (RQueueList * q, RDestroyNotify notify);
/** @brief Append @p item to the tail; returns the new list node. */
static inline RList *     r_queue_list_push (RQueueList * q, rpointer item);
/** @brief Remove and return the head item, or @c NULL when empty. */
static inline rpointer    r_queue_list_pop (RQueueList * q);
/** @brief Peek at the head item without removing it. */
static inline rpointer    r_queue_list_peek (const RQueueList * q);
/** @brief Remove an arbitrary @p link from @p q. */
static inline void        r_queue_list_remove_link (RQueueList * q, RList * link);
/** @brief Item count. */
#define r_queue_list_size(q)      (q)->size
/** @brief @c TRUE iff @p q has no items. */
#define r_queue_list_is_empty(q)  ((q)->size == 0)

/** @} */

/** @name Callback queue (RCBQueue)
 *
 * FIFO of @ref RFuncCallbackCtx entries. Used for deferred-work
 * patterns where a producer enqueues callbacks and a consumer
 * fires them later (event loops, idle dispatch, etc.).
 *  @{ */

/** @brief List-backed queue of @ref RFuncCallbackCtx entries. */
typedef struct {
  RCBList * head;               /**< Head node. */
  RCBList * tail;                /**< Tail node. */
  rsize size;                    /**< Number of pending callbacks. */
} RCBQueue;

/** @brief Heap-allocate an empty @ref RCBQueue. */
static inline RCBQueue *  r_cbqueue_new (void) R_ATTR_MALLOC;
/** @brief Initialise a stack-allocated @ref RCBQueue. */
static inline void        r_cbqueue_init (RCBQueue * q);
/** @brief Free a heap-allocated callback queue; runs each callback's destroy notifiers. */
static inline void        r_cbqueue_free (RCBQueue * q);
/** @brief Drop all callbacks, running destroy notifiers. */
static inline void        r_cbqueue_clear (RCBQueue * q);
/** @brief Append a callback to the tail; returns the new node. */
static inline RCBList *   r_cbqueue_push (RCBQueue * q, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify);
/** @brief Detach and return the head node; caller is responsible for invoking / freeing. */
static inline RCBList *   r_cbqueue_pop (RCBQueue * q);
/** @brief Peek at the head node. */
static inline RCBList *   r_cbqueue_peek (const RCBQueue * q);
/** @brief Remove an arbitrary @p link from @p q. */
static inline void        r_cbqueue_remove_link (RCBQueue * q, RCBList * link);
/** @brief Invoke every callback currently queued; returns the number called. */
static inline rsize       r_cbqueue_call (RCBQueue * q);
/**
 * @brief Atomically detach + invoke + drop the queue's callbacks.
 *
 * Useful for one-shot dispatch where the queue isn't reused
 * afterwards.
 */
static inline rsize       r_cbqueue_call_pop (RCBQueue * q);
/** @brief Concatenate @p src onto @p dst; @p src ends up empty. */
static inline void        r_cbqueue_merge (RCBQueue * dst, RCBQueue * src);
/** @brief Number of callbacks currently queued. */
#define r_cbqueue_size(q)      (q)->size
/** @brief @c TRUE iff no callbacks are queued. */
#define r_cbqueue_is_empty(q)  ((q)->size == 0)


/** @} */

/** @name Ring-buffer queue (RQueueRing)
 *
 * Bounded, refcounted FIFO backed by a power-of-two ring buffer.
 * Insert / remove are O(1) and contend over a single producer /
 * consumer index pair; the capacity is fixed at construction. Use
 * when the queue depth has a known upper bound and allocating per
 * push would dominate the cost.
 *  @{ */

/** @brief Opaque, refcounted ring-buffer queue. */
typedef struct RQueueRing RQueueRing;
/** @brief Construct a ring queue with capacity @p size (rounded up to a power of 2). */
R_API RQueueRing * r_queue_ring_new (rsize size) R_ATTR_MALLOC;
/** @brief Increment the queue's refcount. */
#define r_queue_ring_ref    r_ref_ref
/** @brief Decrement the queue's refcount; frees when it reaches zero. */
#define r_queue_ring_unref  r_ref_unref

/** @brief Drop every item, calling @p notify on each. */
R_API void      r_queue_ring_clear (RQueueRing * q, RDestroyNotify notify);
/**
 * @brief Push @p item onto the tail.
 *
 * @return @c FALSE if the ring is full.
 */
R_API rboolean  r_queue_ring_push (RQueueRing * q, rpointer item) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Remove and return the head item, or @c NULL when empty. */
R_API rpointer  r_queue_ring_pop (RQueueRing * q);
/** @brief Peek at the head item without removing it. */
R_API rpointer  r_queue_ring_peek (RQueueRing * q);
/** @brief Number of items currently in @p q. */
R_API rsize     r_queue_ring_size (RQueueRing * q);
/** @brief @c TRUE iff @p q has no items. */
R_API rboolean  r_queue_ring_is_empty (RQueueRing * q);

/** @} */




/******************************************************************************/
/* Queue / Deque / Queue implemented with a list                              */
/******************************************************************************/
static inline RQueueList * r_queue_list_new (void)
{
  return r_mem_new0 (RQueueList);
}
static inline void r_queue_list_init (RQueueList * q)
{
  r_memset (q, 0, sizeof (RQueueList));
}
static inline void r_queue_list_free (RQueueList * q, RDestroyNotify notify)
{
  if (q != NULL) {
    r_queue_list_clear (q, notify);
    r_free (q);
  }
}
static inline void r_queue_list_clear (RQueueList * q, RDestroyNotify notify)
{
  RList * head = q->head;
  r_memset (q, 0, sizeof (RQueueList));
  r_list_destroy_full (head, notify);
}
static inline RList * r_queue_list_push (RQueueList * q, rpointer item)
{
  RList * ret = r_list_alloc_copy (item);
  if (q->size++ > 0) {
    ret->prev = q->tail;
    q->tail->next = ret;
    q->tail = ret;
  } else {
    q->head = q->tail = ret;
  }

  return ret;
}
static inline rpointer r_queue_list_pop (RQueueList * q)
{
  rpointer ret;
  RList * it;

  if ((it = q->head) != NULL) {
    if ((q->head = it->next) != NULL)
      q->head->prev = NULL;
    else
      q->tail = NULL;
    ret = it->data;
    r_list_free1 (it);

    q->size--;
  } else {
    ret = NULL;
  }

  return ret;
}
static inline rpointer r_queue_list_peek (const RQueueList * q)
{
  return q->head != NULL ? q->head->data : NULL;
}
static inline void r_queue_list_remove_link (RQueueList * q, RList * link)
{
  if (link == q->tail)
    q->tail = q->tail->prev;
  q->head = r_list_destroy_link (q->head, link);
  q->size--;
}

static inline RCBQueue *  r_cbqueue_new (void)
{
  return r_mem_new0 (RCBQueue);
}
static inline void r_cbqueue_init (RCBQueue * q)
{
  r_memset (q, 0, sizeof (RCBQueue));
}
static inline void r_cbqueue_free (RCBQueue * q)
{
  if (q != NULL) {
    r_cbqueue_clear (q);
    r_free (q);
  }
}
static inline void r_cbqueue_clear (RCBQueue * q)
{
  RCBList * head = q->head;
  r_memset (q, 0, sizeof (RCBQueue));
  r_cblist_destroy (head);
}
static inline RCBList * r_cbqueue_push (RCBQueue * q, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify)
{
  RCBList * n = r_cblist_alloc_full (cb, data, datanotify, user, usernotify);
  if (q->size++ > 0) {
    n->prev = q->tail;
    q->tail->next = n;
    q->tail = n;
  } else {
    q->tail = q->head = n;
  }

  return n;
}
static inline RCBList * r_cbqueue_pop (RCBQueue * q)
{
  RCBList * ret;

  if ((ret = q->head) != NULL) {
    if ((q->head = ret->next) != NULL)
      q->head->prev = NULL;
    else
      q->tail = NULL;
    ret->prev = NULL;

    q->size--;
  } else {
    ret = NULL;
  }

  return ret;
}
static inline RCBList * r_cbqueue_peek (const RCBQueue * q)
{
  return q->head;
}
static inline void r_cbqueue_remove_link (RCBQueue * q, RCBList * link)
{
  if (link == q->tail)
    q->tail = q->tail->prev;
  q->head = r_cblist_destroy_link (q->head, link);
  q->size--;
}
static inline rsize r_cbqueue_call (RCBQueue * q)
{
  return r_cblist_call (q->head);
}

static inline rsize r_cbqueue_call_pop (RCBQueue * q)
{
  rsize ret;
  RCBList * lst = q->head;
  r_memset (q, 0, sizeof (RCBQueue));
  ret = r_cblist_call (lst);
  r_cblist_destroy (lst);
  return ret;
}
static inline void r_cbqueue_merge (RCBQueue * dst, RCBQueue * src)
{
  if (dst->size > 0 && src->size > 0) {
    dst->size += src->size;

    dst->tail->next = src->head;
    src->head->prev = dst->tail;
    dst->tail = src->tail;
  } else if (dst->size == 0) {
    r_memcpy (dst, src, sizeof (RCBQueue));
  }

  r_memset (src, 0, sizeof (RCBQueue));
}

R_END_DECLS

/** @} */

#endif /* __R_QUEUE_H__ */

