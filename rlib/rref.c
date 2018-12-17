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

#include "config.h"
#include "rlib-private.h"
#include <rlib/rref.h>

#include <rlib/rthreads.h>
#include <rlib/data/rlist.h>

static RRWMutex r_ref_weak_mutex = NULL;

void
r_ref__init (void)
{
  r_rwmutex_init (&r_ref_weak_mutex);
}

void
r_ref__deinit (void)
{
  r_rwmutex_clear (&r_ref_weak_mutex);
}

rpointer
r_ref_ref (rpointer ref)
{
  RRef * self = ref;
  r_atomic_uint_fetch_add (&self->refcount, 1);
  return ref;
}

void
r_ref_unref (rpointer ref)
{
  RRef * self = ref;
  if (r_atomic_uint_fetch_sub (&self->refcount, 1) == 1) {
    RCBSList * lst = r_atomic_ptr_exchange (&self->weaklst, NULL);
    /* NOTE: We don't touch the lock as this should be the last reference
     * holding it. Nevertheless, if you get into issues, you most likely are
     * doing r_ref_weak_unref() without control over the instance itself. */
    r_cbslist_call (lst);
    r_cbslist_destroy (lst);
    if (R_LIKELY (self->notify != NULL))
      self->notify (ref);
  }
}

rpointer
r_ref_weak_ref (rpointer ref, RFunc notify, rpointer data)
{
  RCBSList * lst;

  if ((lst = r_cbslist_alloc (notify, data, ref)) != NULL) {
    r_rwmutex_rdlock (&r_ref_weak_mutex);
    while (!r_atomic_ptr_cmp_xchg_weak (&((RRef *)ref)->weaklst, &lst->next, lst))
      ;
    r_rwmutex_rdunlock (&r_ref_weak_mutex);

    return ref;
  }

  return NULL;
}

rboolean
r_ref_weak_unref (rpointer ref, RFunc notify, rpointer data)
{
  RRef * self = ref;
  RCBSList * lst, * head;

  r_rwmutex_wrlock (&r_ref_weak_mutex);
  head = r_atomic_ptr_load (&self->weaklst);
  for (lst = head; lst != NULL; lst = lst->next) {
    if (lst->data.cb == notify && lst->data.data == data) {
      r_atomic_ptr_store (&self->weaklst, r_cbslist_destroy_link (head, lst));
      break;
    }
  }
  r_rwmutex_wrunlock (&r_ref_weak_mutex);
  return lst != NULL;
}

