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

/**
 * SECTION:rref
 * @title: RRef base
 * @short_description: a reference counted abstract base structure
 *
 * Use RRef as a the first member of your struct to make it the base.
 * This gives your structure basic reference counting functionality.
 * When initializing your structure call #r_ref_init which sets reference count
 * to `1` and configures a callback which should cleanup and free memory
 * used by your implementation.
 *
 * Note that you also need to free memory to the structure it self.
 *
 * Example usage:
 * |[<!-- language="C" -->
 * typedef struct {
 *   RRef ref;
 *   int bar;
 * } Foo;
 *
 * Foo *
 * foo_new (int bar)
 * {
 *   Foo * ret;
 *
 *   if ((ret = r_mem_new (Foo)) != NULL) {
 *     r_ref_init (ret, r_free);
 *     ret->bar = bar;
 *   }
 *
 *   return ret;
 * }
 * ]|
 *
 */

/**
 * r_ref_ref:
 * @ref: #RRef instance to add a reference for.
 *
 * Add a reference to @ref atomically.
 *
 * Returns: @ref after reference is increased by one.
 */
rpointer
r_ref_ref (rpointer ref)
{
  RRef * self = ref;
  r_atomic_uint_fetch_add (&self->refcount, 1);
  return ref;
}

/**
 * r_ref_unref:
 * @ref: #RRef instance to remove a reference for.
 *
 * Remove a reference to @ref atomically.
 * If this is the last reference the instance will notify all weak references
 * and internal notify.
 */
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

/**
 * r_ref_weak_ref:
 * @ref:    #RRef instance to add a weak reference for.
 * @notify: Notify function callback which will be called when last reference is removed.
 * @data:   Data associated with the @notify which will be passed as user argument.
 *
 * Add a weak reference to @ref atomically.
 * Make sure @ref is a strong reference. Basically to ensure that it is not
 * possible that @ref will be destroyed as the weak ref is removed.
 *
 * Returns: @ref after reference is increased by one.
 */
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

/**
 * r_ref_weak_unref:
 * @ref: #RRef instance to remove a weak reference for.
 *
 * Remove a weak reference to @ref atomically.
 *
 * **NOTE** This is currently **NOT thread safe**
 */
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

