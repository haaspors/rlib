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
#ifndef __R_EV_PRIV_H__
#define __R_EV_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rev-private.h should only be used internally in rlib!"
#endif

#include <rlib/ev/revloop.h>
#include <rlib/ev/revwakeup.h>

#include <rlib/data/rlist.h>
#include <rlib/data/rqueue.h>
#include <rlib/os/rsys.h>

#include <rlib/rlog.h>

R_BEGIN_DECLS

R_API_HIDDEN R_LOG_CATEGORY_DEFINE_EXTERN (revlogcat);

#define R_EV_LOOP_MAX_EVENTS              1024
#define R_EV_LOOP_DEFAULT_TASK_THREADS    r_sys_cpu_physical_count ()

R_API_HIDDEN void r_ev_loop_add_cb_after (REvLoop * loop, RFunc func,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify);

typedef enum {
  R_EV_IO_FLAGS_NONE  = 0,
  R_EV_IO_ADDED       = (1 << 0),
  R_EV_IO_INTERNAL    = (1 << 1),
  R_EV_IO_CLOSED      = (1 << 2),
} REvIOFlag;
typedef ruint32 REvIOFlags;

typedef struct REvIOCBNode REvIOCBNode;
struct REvIOCBNode {
  REvIOCBNode * next;
  REvIOCBNode * prev;
  REvIOCB cb;
  rpointer data;
  RDestroyNotify datanotify;
  REvIOEvents events;
};

typedef struct {
  REvIOCBNode * head;
  REvIOCBNode * tail;
  rsize size;
} REvIOCBQueue;

static inline REvIOCBNode * r_ev_iocb_queue_push (REvIOCBQueue * q,
    REvIOCB cb, rpointer data, RDestroyNotify datanotify, REvIOEvents events)
{
  REvIOCBNode * n = r_mem_new (REvIOCBNode);
  n->cb = cb;
  n->data = data;
  n->datanotify = datanotify;
  n->events = events;
  n->next = NULL;
  n->prev = q->tail;
  if (q->tail != NULL)
    q->tail->next = n;
  else
    q->head = n;
  q->tail = n;
  q->size++;
  return n;
}

static inline void r_ev_iocb_queue_remove (REvIOCBQueue * q, REvIOCBNode * n)
{
  if (n->prev != NULL)
    n->prev->next = n->next;
  else
    q->head = n->next;
  if (n->next != NULL)
    n->next->prev = n->prev;
  else
    q->tail = n->prev;
  q->size--;
  if (n->datanotify != NULL)
    n->datanotify (n->data);
  r_free (n);
}

static inline void r_ev_iocb_queue_clear (REvIOCBQueue * q)
{
  REvIOCBNode * n;
  while ((n = q->head) != NULL) {
    q->head = n->next;
    if (n->datanotify != NULL)
      n->datanotify (n->data);
    r_free (n);
  }
  q->tail = NULL;
  q->size = 0;
}

struct REvIO {
  RRef ref;

  REvLoop * loop;
  RList * alnk; /* If NULL -> inactive, else -> link in REvLoop::active queue */
  RList * chglnk; /* If not NULL -> changing link in REvLoop::chg queue */

  RIOHandle handle;
  REvIOEvents events;
  REvIOFlags flags;
  REvIOCBQueue iocbq;

  rpointer user;
  RDestroyNotify usernotify;
};

#define R_EV_IO_FORMAT        "%p [%"R_IO_HANDLE_FMT"]"
#define R_EV_IO_ARGS(evio)    evio, (evio != NULL ? ((REvIO *)evio)->handle : R_IO_HANDLE_INVALID)

#define R_EV_IO_IS_INTERNAL(evio)   (evio->flags & R_EV_IO_INTERNAL)
#define R_EV_IO_IS_CLOSED(evio)     (evio->flags & R_EV_IO_CLOSED)
#define R_EV_IO_IS_ADDED(evio)      (evio->flags & R_EV_IO_ADDED)
#define R_EV_IO_IS_ACTIVE(evio)     ((evio->alnk) != NULL)
#define R_EV_IO_IS_CHANGING(evio)   ((evio->chglnk) != NULL)

R_API_HIDDEN void r_ev_io_init (REvIO * evio, REvLoop * loop, RIOHandle handle,
    RDestroyNotify notify);
R_API_HIDDEN void r_ev_io_clear (REvIO * evio);
R_API_HIDDEN rboolean r_ev_io_validate_taskgroup (REvIO * evio, ruint taskgroup);

#define r_ev_io_invoke_iocb(evio, events)                                     \
  R_STMT_START {                                                              \
    REvIOCBNode * it;                                                         \
    for (it = evio->iocbq.head; it != NULL; it = it->next)                    \
      it->cb (it->data, events, evio);                                        \
  } R_STMT_END


struct REvWakeup {
  REvIO evio;
  RIOHandle close_handle;
  RIOHandle signal_handle;
};

R_API_HIDDEN void r_ev_wakeup_init (REvWakeup * wakeup, REvLoop * loop, RDestroyNotify notify);
R_API_HIDDEN void r_ev_wakeup_clear (REvWakeup * wakeup);
R_API_HIDDEN void r_ev_wakeup_read (REvWakeup * wakeup);

R_END_DECLS

#endif /* __R_EV_PRIV_H__ */

