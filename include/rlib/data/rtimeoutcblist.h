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
#ifndef __R_TIMEOUT_CBLIST_H__
#define __R_TIMEOUT_CBLIST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_timeoutcblist Timeout callback list
 * @ingroup r_data
 *
 * @brief Ordered list of callbacks keyed on absolute deadlines;
 * the building block under rlib's event-loop timers.
 *
 * Callers insert @c (deadline, callback) entries via
 * @ref r_timeout_cblist_insert and call
 * @ref r_timeout_cblist_update on each loop tick. The list is
 * kept sorted by deadline so @ref r_timeout_cblist_first_timeout
 * is O(1) and the update walk only inspects entries whose deadline
 * has actually passed.
 *
 * @{
 */

/**
 * @file rlib/data/rtimeoutcblist.h
 * @brief Ordered list of callbacks indexed by absolute deadline.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

/** @brief Opaque, refcounted timeout-callback entry. */
typedef struct RToCB RToCB;
/** @brief Increment the entry's refcount. */
#define r_to_cb_ref r_ref_ref
/** @brief Decrement the entry's refcount; frees when it reaches zero. */
#define r_to_cb_unref r_ref_unref

/**
 * @brief Ordered list of @ref RToCB entries keyed by deadline.
 *
 * Insertion keeps the list sorted by ascending @c ts so the head
 * always carries the soonest deadline.
 */
typedef struct {
  RToCB * head;                 /**< Earliest-deadline entry. */
  RToCB * tail;                 /**< Latest-deadline entry. */

  rsize size;                   /**< Number of pending callbacks. */
} RTimeoutCBList;

/** @brief Static initialiser for an empty @ref RTimeoutCBList. */
#define R_TIMEOUT_CBLIST_INIT { NULL, NULL, 0 }
/** @brief Initialise a stack-allocated @ref RTimeoutCBList to empty. */
#define r_timeout_cblist_init(lst) r_memset (lst, 0, sizeof (RTimeoutCBList))

/**
 * @brief Cancel every pending entry and drop the list to empty.
 *
 * Each entry's destroy notifiers run before its memory is freed.
 */
R_API void r_timeout_cblist_clear (RTimeoutCBList * lst);
/** @brief Number of pending callbacks. */
#define r_timeout_cblist_len(lst) (lst)->size

/**
 * @brief Schedule @p cb to fire at @p ts.
 *
 * The list keeps itself sorted by deadline; insertion is O(n) in
 * the worst case but typically O(1) for monotonically increasing
 * deadlines.
 *
 * @param lst         The list.
 * @param tocb        Out: handle suitable for @ref r_timeout_cblist_cancel.
 *                    Pass @c NULL to discard.
 * @param ts          Absolute deadline (in @ref RClockTime ticks).
 * @param cb          Callback function.
 * @param data        Callback's first argument.
 * @param datanotify  Destroy notifier for @p data, or @c NULL.
 * @param user        Callback's second argument.
 * @param usernotify  Destroy notifier for @p user, or @c NULL.
 */
R_API rboolean r_timeout_cblist_insert (RTimeoutCBList * lst,
    RToCB ** tocb, RClockTime ts, RFunc cb,
    rpointer data, RDestroyNotify datanotify, rpointer user, RDestroyNotify usernotify);
/**
 * @brief Cancel the entry identified by @p cb.
 *
 * The entry's destroy notifiers run before it's removed.
 * @return @c FALSE if @p cb is no longer in the list (already
 *         fired, already cancelled).
 */
R_API rboolean r_timeout_cblist_cancel (RTimeoutCBList * lst, RToCB * cb);
/**
 * @brief Return the deadline of the head entry, or
 * @c R_CLOCK_TIME_NONE if the list is empty.
 *
 * Use to compute the next loop wake-up.
 */
R_API RClockTime r_timeout_cblist_first_timeout (RTimeoutCBList * lst);
/**
 * @brief Fire and remove every entry whose deadline is at or
 * before @p ts; returns the number called.
 *
 * Typical pattern is to feed the current clock value and re-arm
 * the loop's wake-up from @ref r_timeout_cblist_first_timeout
 * afterwards.
 */
R_API rsize r_timeout_cblist_update (RTimeoutCBList * lst, RClockTime ts);

R_END_DECLS

/** @} */

#endif /* __R_TIMEOUT_CBLIST_H__ */

