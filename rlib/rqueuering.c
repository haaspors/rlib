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
#include <rlib/rqueue.h>

struct _RQueueRing {
  RRef ref;

  rpointer * buffer;
  ruint sizep1;

  rsize head, tail;
};

static void
r_queue_ring_free (RQueueRing * q)
{
  if (R_LIKELY (q != NULL)) {
    r_free (q->buffer);
    r_free (q);
  }
}

RQueueRing *
r_queue_ring_new (rsize size)
{
  RQueueRing * ret;

  if (R_UNLIKELY (size == 0)) return NULL;
  if (R_UNLIKELY (size >= RSIZE_MAX / RLIB_SIZEOF_VOID_P)) return NULL;

  if ((ret = r_mem_new (RQueueRing)) != NULL) {
    r_ref_init (ret, r_queue_ring_free);

    ret->sizep1 = size + 1;
    ret->head = ret->tail = 0;

    if (R_UNLIKELY ((ret->buffer = r_mem_new_n (rpointer, ret->sizep1)) == NULL)) {
      r_queue_ring_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

void
r_queue_ring_clear (RQueueRing * q, RDestroyNotify notify)
{
  if (notify != NULL)
    while (!r_queue_ring_is_empty (q)) notify (r_queue_ring_pop (q));
  else
    q->head = q->tail = 0;
}

rboolean
r_queue_ring_push (RQueueRing * q, rpointer item)
{
  rboolean ret;
  if ((ret = (r_queue_ring_size (q) < q->sizep1 - 1))) {
    q->tail %= q->sizep1;
    q->buffer[q->tail++] = item;
  }

  return ret;
}

rpointer
r_queue_ring_pop (RQueueRing * q)
{
  if (q->tail == q->head)
    return NULL;
  q->head %= q->sizep1;
  return q->buffer[q->head++];
}

rpointer
r_queue_ring_peek (RQueueRing * q)
{
  return (q->tail == q->head) ? NULL : q->buffer[q->head % q->sizep1];
}

rsize
r_queue_ring_size (RQueueRing * q)
{
  if (q->tail >= q->head)
    return q->tail - q->head;
  else
    return q->sizep1 - (q->head - q->tail);
}

rboolean
r_queue_ring_is_empty (RQueueRing * q)
{
  return q->tail == q->head;
}


