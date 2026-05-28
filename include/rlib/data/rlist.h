/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_LIST_H__
#define __R_LIST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_list Linked lists
 * @ingroup r_data
 *
 * @brief Doubly- and singly-linked list templates plus the four
 * callback-flavoured specialisations that the rest of rlib uses
 * to manage deferred work.
 *
 * Five list types are declared in this header, all generated from
 * @c R__LIST_DECL / @c R__SLIST_DECL templates in
 * @c rlist-internal.h so the surface is uniform across types:
 *
 *   - @c RList — doubly-linked list of @c rpointer values.
 *   - @c RSList — singly-linked list of @c rpointer values.
 *   - @c RFreeList — singly-linked free list pairing a pointer
 *     with its destroy notifier; used to defer cleanup of
 *     heterogeneous resources.
 *   - @c RCBList / @c RCBSList — doubly- / singly-linked
 *     callback lists keyed on @ref RFuncCallbackCtx tuples.
 *   - @c RCBRList — doubly-linked list of
 *     @ref RFuncReturnCallbackCtx tuples (return-value drives
 *     whether the iterator continues).
 *
 * Each type carries the standard set of @c _alloc / @c _alloc_full
 * / @c _prepend / @c _append / @c _contains / @c _destroy
 * accessors emitted by the template. The macros in this header
 * (@c r_list_prepend = @c r_list_prepend_copy etc.) make
 * value-by-copy the default insertion path.
 *
 * @{
 */

/**
 * @file rlib/data/rlist.h
 * @brief Linked-list types: doubly / singly linked plus the
 * callback-flavoured specialisations.
 */

#include <rlib/data/rlist-internal.h>
#include <rlib/data/rcbctx.h>
#include <rlib/data/rhashfuncs.h>

#include <rlib/rmem.h>

R_BEGIN_DECLS

/** @name Doubly-linked list (RList) of rpointer values
 *  @{ */
R__LIST_DECL (RList, r_list, rpointer, R_API)
/** @brief Convenience: @c prepend defaults to value-copy semantics. */
#define r_list_prepend      r_list_prepend_copy
/** @brief Convenience: @c append defaults to value-copy semantics. */
#define r_list_append       r_list_append_copy
/** @brief Convenience: @c contains defaults to identity equality. */
#define r_list_contains     r_list_contains_full
/** @} */

/** @name Singly-linked list (RSList) of rpointer values
 *  @{ */
R__SLIST_DECL (RSList, r_slist, rpointer, R_API)
/** @brief Convenience: @c prepend defaults to value-copy semantics. */
#define r_slist_prepend       r_slist_prepend_copy
/** @brief Convenience: @c append defaults to value-copy semantics. */
#define r_slist_append        r_slist_append_copy
/** @brief Convenience: @c contains defaults to identity equality. */
#define r_slist_contains      r_slist_contains_full
/** @} */

/** @name Free list — defer cleanup of heterogeneous resources
 *  @{ */

/**
 * @brief @c (pointer, destroy-notifier) pair stored in @c RFreeList.
 *
 * Lets a single list track resources allocated by different
 * subsystems: each entry remembers its own free function.
 */
typedef struct {
  rpointer ptr;                 /**< The resource to free. */
  RDestroyNotify notify;        /**< Function that knows how to free it. */
} RFreePtrCtx;

R__SLIST_DECL (RFreeList, r_free_list, RFreePtrCtx, R_API)

static inline RFreeList * r_free_list_alloc (rpointer ptr, RDestroyNotify notify)
{
  RFreeList * ret;
  if ((ret = r_free_list_alloc0 ()) != NULL) {
    ret->data.ptr = ptr;
    ret->data.notify = notify;
  }
  return ret;
}
static inline RFreeList * r_free_list_prepend (RFreeList * lst,
    rpointer ptr, RDestroyNotify notify)
{
  return r_free_list_prepend_link (lst, r_free_list_alloc (ptr, notify));
}

/** @} */

/** @name Callback list (RCBList — doubly-linked)
 *
 * Doubly-linked list of @ref RFuncCallbackCtx tuples. Use for
 * "fire these callbacks later in order" patterns where the caller
 * also needs to walk in reverse.
 *  @{ */
R__LIST_DECL (RCBList, r_cblist, RFuncCallbackCtx, R_API)

/** @brief Allocate a standalone callback node with full ownership wiring. */
R_API RCBList * r_cblist_alloc_full (RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_MALLOC;
/** @brief Convenience: allocate without destroy notifiers. */
#define r_cblist_alloc(cb, data, user)                                        \
  r_cblist_alloc_full (cb, data, NULL, user, NULL)
/** @brief Prepend a new callback to the head with full ownership wiring. */
R_API RCBList * r_cblist_prepend_full (RCBList * head, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Convenience: prepend without destroy notifiers. */
#define r_cblist_prepend(head, cb, data, user)                                \
  r_cblist_prepend_full (head, cb, data, NULL, user, NULL)
/** @brief Append a new callback to the tail with full ownership wiring. */
R_API RCBList * r_cblist_append_full (RCBList * entry, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Convenience: append without destroy notifiers. */
#define r_cblist_append(head, cb, data, user)                                 \
  r_cblist_append_full (head, cb, data, NULL, user, NULL)
/** @brief @c TRUE iff @p head contains a matching @c (cb, data) pair. */
R_API rboolean r_cblist_contains (RCBList * head, RFunc cb, rpointer data);
/**
 * @brief Invoke every callback in the list in order; returns the
 * number called.
 */
R_API rsize r_cblist_call (RCBList * head);

/** @} */

/** @name Return-value callback list (RCBRList — doubly-linked)
 *
 * Same shape as @c RCBList but each callback returns
 * @c rboolean; nodes whose callback returns @c FALSE are removed
 * from the list during iteration. Use for one-shot subscribers or
 * filter chains.
 *  @{ */
R__LIST_DECL (RCBRList, r_cbrlist, RFuncReturnCallbackCtx, R_API)

/** @brief Allocate a standalone return-callback node with full ownership wiring. */
R_API RCBRList * r_cbrlist_alloc_full (RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_MALLOC;
/** @brief Convenience: allocate without destroy notifiers. */
#define r_cbrlist_alloc(cb, data, user)                                       \
  r_cbrlist_alloc_full (cb, data, NULL, user, NULL)
/** @brief Prepend a return-callback to the head. */
R_API RCBRList * r_cbrlist_prepend_full (RCBRList * head, RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Convenience: prepend without destroy notifiers. */
#define r_cbrlist_prepend(head, cb, data, user)                               \
  r_cbrlist_prepend_full (head, cb, data, NULL, user, NULL)
/** @brief Append a return-callback to the tail. */
R_API RCBRList * r_cbrlist_append_full (RCBRList * entry, RFuncReturn cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Convenience: append without destroy notifiers. */
#define r_cbrlist_append(head, cb, data, user)                                \
  r_cbrlist_append_full (head, cb, data, NULL, user, NULL)
/** @brief @c TRUE iff @p head contains a matching @c (cb, data) pair. */
R_API rboolean r_cbrlist_contains (RCBRList * head, RFuncReturn cb, rpointer data);
/**
 * @brief Iterate the list, removing entries whose callback returned
 * @c FALSE.
 *
 * @return The (possibly shorter) list head; pass back through the
 *         original variable.
 */
R_API RCBRList * r_cbrlist_call (RCBRList * head) R_ATTR_WARN_UNUSED_RESULT;

/** @} */

/** @name Callback list (RCBSList — singly-linked)
 *
 * Same surface as @c RCBList but with singly-linked storage;
 * cheaper when reverse traversal isn't needed.
 *  @{ */
R__SLIST_DECL (RCBSList, r_cbslist, RFuncCallbackCtx, R_API)

/** @brief Allocate a standalone callback node (singly-linked). */
R_API RCBSList * r_cbslist_alloc_full (RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_MALLOC;
/** @brief Convenience: allocate without destroy notifiers. */
#define r_cbslist_alloc(cb, data, user)                                       \
  r_cbslist_alloc_full (cb, data, NULL, user, NULL)
/** @brief Prepend a new callback. */
R_API RCBSList * r_cbslist_prepend_full (RCBSList * head, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Convenience: prepend without destroy notifiers. */
#define r_cbslist_prepend(head, cb, data, user)                               \
  r_cbslist_prepend_full (head, cb, data, NULL, user, NULL)
/** @brief Append a new callback. */
R_API RCBSList * r_cbslist_append_full (RCBSList * entry, RFunc cb,
    rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Convenience: append without destroy notifiers. */
#define r_cbslist_append(head, cb, data, user)                                \
  r_cbslist_append_full (head, cb, data, NULL, user, NULL)
/** @brief @c TRUE iff @p head contains a matching @c (cb, data) pair. */
R_API rboolean r_cbslist_contains (RCBSList * head, RFunc cb, rpointer data);
/** @brief Invoke every callback in the list; returns the number called. */
R_API rsize r_cbslist_call (RCBSList * head);

/** @} */

R_END_DECLS

/** @} */

#endif /* __R_LIST_H__ */
