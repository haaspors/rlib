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

/**
 * @defgroup r_ref Refcounting
 * @ingroup r_data
 *
 * @brief @ref RRef is the refcount base struct that every
 * refcounted type in rlib embeds at offset 0 - hashtables, buffers,
 * crypto handles, RTC sessions, parsers, the rest.
 *
 * Concrete types derive from @ref RRef by placing it as the first
 * field of their own struct and supplying a destroy notifier at
 * construction. The @c r_ref_ref / @c r_ref_unref pair drives the
 * lifecycle; @c r_ref_weak_ref / @c r_ref_weak_unref register
 * weak-reference callbacks fired when the refcount drops to zero.
 *
 * @{
 */

/**
 * @file rlib/rref.h
 * @brief Refcount base struct shared by every refcounted type in rlib.
 */

#include <rlib/rtypes.h>
#include <rlib/concurrency/ratomic.h>

R_BEGIN_DECLS

/**
 * @brief Refcount base struct.
 *
 * Embed at offset 0 of the derived type. The @c refcount field is
 * atomic so @c ref / @c unref work safely across threads.
 */
typedef struct {
  rauint refcount;              /**< Atomic reference count. */
  raptr weaklst;                /**< Atomically-published list of weak-ref callbacks. */
  RDestroyNotify notify;        /**< Destructor invoked when @c refcount reaches zero. */
} RRef;

/** @brief Snapshot of the current refcount (atomic load). */
#define r_ref_refcount(ref) r_atomic_uint_load (&((RRef *)ref)->refcount)
/**
 * @brief Static initialiser for an embedded @ref RRef field.
 *
 * The refcount starts at @c 0 so the embedder can call
 * @ref r_ref_ref before the first external reference is handed
 * out; alternatively use @c r_ref_init at runtime.
 */
#define R_REF_STATIC_INIT(destroy)        { 0, 0, (RDestroyNotify)destroy }
/** @brief Initialise an @ref RRef field to refcount 1 with destructor @p destroy. */
#define r_ref_init(self, destroy)         R_STMT_START {                      \
  r_atomic_uint_store (&((RRef *)self)->refcount, 1);                         \
  r_atomic_ptr_store (&((RRef *)self)->weaklst, NULL);                        \
  ((RRef *)self)->notify = (RDestroyNotify)destroy;                           \
} R_STMT_END

/** @brief Increment the refcount and return the same pointer. */
R_API rpointer r_ref_ref (rpointer ref);
/** @brief Decrement the refcount; runs the destructor when it reaches zero. */
R_API void r_ref_unref (rpointer ref);

/**
 * @brief Register a weak-reference callback that fires when @p ref
 * is destroyed.
 *
 * @param ref     The refcounted object.
 * @param notify  Function to invoke when @p ref's refcount reaches zero.
 * @param data    Cookie passed to @p notify.
 */
R_API rpointer r_ref_weak_ref (rpointer ref, RFunc notify, rpointer data);
/** @brief Cancel a previously registered weak-reference callback. */
R_API rboolean r_ref_weak_unref (rpointer ref, RFunc notify, rpointer data);

R_END_DECLS

/** @} */

#endif /* __R_REF_H__ */

