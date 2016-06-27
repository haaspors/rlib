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

#include <rlib/ratomic.h>

struct _RQueueRingLF {
  RRef ref;

  rpointer * buffer;
  ruint size;

  raptr ht; /* head and tail */
};

static void
r_queue_ring_lf_free (RQueueRingLF * q)
{
  if (R_LIKELY (q != NULL)) {
    r_free (q->buffer);
    r_free (q);
  }
}

#define HT_SHIFT          (RLIB_SIZEOF_SIZE_T * 4)
#define HT_LOWER          (RSIZE_MAX >> HT_SHIFT)
#define HT_UPPER          (RSIZE_MAX << HT_SHIFT)
#define HT_TAIL(ptr)      (RPOINTER_TO_SIZE (ptr) & HT_LOWER)
#define HT_HEAD(ptr)      ((RPOINTER_TO_SIZE (ptr) >> HT_SHIFT) & HT_LOWER)
#define HT_TAIL_INC(ptr)  (((HT_TAIL (ptr) + 1) & HT_LOWER) | (RPOINTER_TO_SIZE (ptr) & HT_UPPER))
#define HT_HEAD_INC(ptr)  (((HT_HEAD (ptr) + 1) << HT_SHIFT) | (RPOINTER_TO_SIZE (ptr) & HT_LOWER))

RQueueRingLF *
r_queue_ring_lf_new (rsize size)
{
  RQueueRingLF * ret;

  if (R_UNLIKELY (size > (RSIZE_MAX / 2))) return NULL;

  if ((ret = r_mem_new (RQueueRingLF)) != NULL) {
    r_ref_init (ret, r_queue_ring_lf_free);

    ret->size = size;
    ret->buffer = r_mem_new_n (rpointer, size);

    r_atomic_ptr_store (&ret->ht, NULL);
  }

  return ret;
}

void
r_queue_ring_lf_clear (RQueueRingLF * q, RDestroyNotify notify)
{
  if (notify != NULL)
    while (q->size > 0) notify (r_queue_ring_lf_pop (q));
  else
    r_atomic_ptr_store (&q->ht, NULL);
}

rboolean
r_queue_ring_lf_push (RQueueRingLF * q, rpointer item)
{
  rpointer new, old = r_atomic_ptr_load (&q->ht);

  do {
    if (R_UNLIKELY (HT_TAIL (old) - HT_HEAD (old) > q->size))
      return FALSE;

    new = RSIZE_TO_POINTER (HT_TAIL_INC (old));
  } while (!r_atomic_ptr_cmp_xchg_weak (&q->ht, &old, new));

  q->buffer[HT_TAIL (old) % q->size] = item;

  /* TODO: Update dirtymap */

  return TRUE;
}

rpointer
r_queue_ring_lf_pop (RQueueRingLF * q)
{
  rpointer new, old = r_atomic_ptr_load (&q->ht);

  do {
    if (R_UNLIKELY (HT_TAIL (old) == HT_HEAD (old)))
      return NULL;

    new = RSIZE_TO_POINTER (HT_HEAD_INC (old));
  } while (!r_atomic_ptr_cmp_xchg_weak (&q->ht, &old, new));

  /* TODO: Wait and update dirtymap */

  return q->buffer[HT_HEAD (old) % q->size];
}

rpointer
r_queue_ring_lf_peek (RQueueRingLF * q)
{
  rpointer ptr = r_atomic_ptr_load (&q->ht);
  return (HT_TAIL (ptr) == HT_HEAD (ptr)) ? NULL : q->buffer[HT_HEAD (ptr)];
}

rsize
r_queue_ring_lf_size (RQueueRingLF * q)
{
  rpointer ptr = r_atomic_ptr_load (&q->ht);
  return HT_TAIL (ptr) - HT_HEAD (ptr);
}

rboolean
r_queue_ring_lf_is_empty (RQueueRingLF * q)
{
  rpointer ptr = r_atomic_ptr_load (&q->ht);
  return HT_TAIL (ptr) == HT_HEAD (ptr);
}

