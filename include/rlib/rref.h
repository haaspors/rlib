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
#ifndef __R_REF_H__
#define __R_REF_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/ratomic.h>

R_BEGIN_DECLS

/**
 * RRef:
 * @refcount: internal refcount. Use #r_ref_refcount to read.
 * @weaklst:  internal list of weak references.
 * @notify:   notify function callback.
 *
 * Base struct for reference counted instances.
 */
typedef struct {
  rauint refcount;
  raptr weaklst;
  RDestroyNotify notify;
} RRef;

/**
 * r_ref_refcount:
 * @ref: #RRef instance.
 *
 * Returns: current reference count.
 */
#define r_ref_refcount(ref) r_atomic_uint_load (&((RRef *)ref)->refcount)

#define R_REF_STATIC_INIT(destroy)        { 0, 0, (RDestroyNotify)destroy }

/**
 * r_ref_init:
 * @ref: #RRef instance.
 *
 * Initializes reference struct. This is basically what should be done after
 * allocating memory for the instance.
 * E.g.
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
 * Returns: current reference count.
 */
#define r_ref_init(ref, destroy)          R_STMT_START {                      \
  r_atomic_uint_store (&((RRef *)ref)->refcount, 1);                          \
  r_atomic_ptr_store (&((RRef *)ref)->weaklst, NULL);                         \
  ((RRef *)ref)->notify = (RDestroyNotify)destroy;                            \
} R_STMT_END

R_API rpointer r_ref_ref (rpointer ref);
R_API void r_ref_unref (rpointer ref);

R_API rpointer r_ref_weak_ref (rpointer ref, RFunc notify, rpointer data);
R_API void r_ref_weak_unref (rpointer ref, RFunc notify, rpointer data);

R_END_DECLS

#endif /* __R_REF_H__ */

