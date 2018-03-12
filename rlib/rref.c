/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/rref.h>

#include <rlib/data/rlist.h>

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
    RCBList * lst = r_atomic_ptr_exchange (&self->weaklst, NULL);
    r_cblist_call (lst);
    r_cblist_destroy (lst);
    if (R_LIKELY (self->notify != NULL))
      self->notify (ref);
  }
}

rpointer
r_ref_weak_ref (rpointer ref, RFunc notify, rpointer data)
{
  RRef * self = ref;
  RCBList * lst;

  if ((lst = r_cblist_alloc (notify, data, ref)) != NULL) {
    lst->next = r_atomic_ptr_load (&self->weaklst);
    while (!r_atomic_ptr_cmp_xchg_weak (&self->weaklst, &lst->next, lst));

    return ref;
  }

  return NULL;
}

void
r_ref_weak_unref (rpointer ref, RFunc notify, rpointer data)
{
  RRef * self = ref;
  RCBList * lst;

  /* FIXME: Thread-safe??? */
  for (lst = r_atomic_ptr_load (&self->weaklst); lst != NULL; lst = lst->next) {
    if (lst->cb == notify && lst->data == data) {
      r_atomic_ptr_store (&self->weaklst,
          r_cblist_destroy_link (r_atomic_ptr_load (&self->weaklst), lst));
      break;
    }
  }
}

