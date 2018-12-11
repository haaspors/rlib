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

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rlist.h>

R_BEGIN_DECLS

/* RQueue is really just RQueueList */
#define RQueue              RQueueList
#define R_QUEUE_INIT        R_QUEUE_LIST_INIT
#define r_queue_new         r_queue_list_new
#define r_queue_free        r_queue_list_free
#define r_queue_init        r_queue_list_init
#define r_queue_clear       r_queue_list_clear
#define r_queue_push        r_queue_list_push
#define r_queue_pop         r_queue_list_pop
#define r_queue_peek        r_queue_list_peek
#define r_queue_remove_link r_queue_list_remove_link
#define r_queue_size        r_queue_list_size
#define r_queue_is_empty    r_queue_list_is_empty


/******************************************************************************/
/* Queue / Deque / Queue implemented with a list                              */
/******************************************************************************/
typedef struct {
  RList * head, * tail;
  rsize size;
} RQueueList;

#define R_QUEUE_LIST_INIT { NULL, NULL, 0 }
static inline RQueueList * r_queue_list_new (void) R_ATTR_MALLOC;
static inline void        r_queue_list_init (RQueueList * q);
static inline void        r_queue_list_free (RQueueList * q, RDestroyNotify notify);
static inline void        r_queue_list_clear (RQueueList * q, RDestroyNotify notify);
static inline RList *     r_queue_list_push (RQueueList * q, rpointer item);
static inline rpointer    r_queue_list_pop (RQueueList * q);
static inline rpointer    r_queue_list_peek (const RQueueList * q);
static inline void        r_queue_list_remove_link (RQueueList * q, RList * link);
#define r_queue_list_size(q)      (q)->size
#define r_queue_list_is_empty(q)  ((q)->size == 0)

/******************************************************************************/
/* CBQueue / Callback Queue implemented with a list                            */
/******************************************************************************/
typedef struct {
  RCBList * head, * tail;
  rsize size;
} RCBQueue;

#define R_QUEUE_LIST_INIT { NULL, NULL, 0 }
static inline RCBQueue *  r_cbqueue_new (void) R_ATTR_MALLOC;
static inline void        r_cbqueue_init (RCBQueue * q);
static inline void        r_cbqueue_free (RCBQueue * q);
static inline void        r_cbqueue_clear (RCBQueue * q);
static inline RCBList *   r_cbqueue_push (RCBQueue * q, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify);
static inline RCBList *   r_cbqueue_pop (RCBQueue * q);
static inline RCBList *   r_cbqueue_peek (const RCBQueue * q);
static inline void        r_cbqueue_remove_link (RCBQueue * q, RCBList * link);
static inline rsize       r_cbqueue_call (RCBQueue * q);
static inline rsize       r_cbqueue_call_pop (RCBQueue * q);
static inline void        r_cbqueue_merge (RCBQueue * dst, RCBQueue * src);
#define r_cbqueue_size(q)      (q)->size
#define r_cbqueue_is_empty(q)  ((q)->size == 0)


/******************************************************************************/
/* Queue implemented with a circular ring buffer                              */
/******************************************************************************/
typedef struct _RQueueRing RQueueRing;
R_API RQueueRing * r_queue_ring_new (rsize size) R_ATTR_MALLOC;
#define r_queue_ring_ref    r_ref_ref
#define r_queue_ring_unref  r_ref_unref

R_API void      r_queue_ring_clear (RQueueRing * q, RDestroyNotify notify);
R_API rboolean  r_queue_ring_push (RQueueRing * q, rpointer item) R_ATTR_WARN_UNUSED_RESULT;
R_API rpointer  r_queue_ring_pop (RQueueRing * q);
R_API rpointer  r_queue_ring_peek (RQueueRing * q);
R_API rsize     r_queue_ring_size (RQueueRing * q);
R_API rboolean  r_queue_ring_is_empty (RQueueRing * q);




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

#endif /* __R_QUEUE_H__ */

