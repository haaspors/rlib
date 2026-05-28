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
#ifndef __R_CLOCK_H__
#define __R_CLOCK_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rclock.h
 * @brief Refcounted monotonic clock with timeout callbacks; system
 * and synthetic (test) variants.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>
#include <rlib/rtime.h>

R_BEGIN_DECLS

/**
 * @defgroup r_clock Clocks (RClock)
 * @ingroup r_time
 *
 * @brief Refcounted monotonic-clock object with one-shot timeout
 * callbacks.
 *
 * Two implementations:
 *
 *  - **System clock**: singleton fetched via @ref r_system_clock_get,
 *    backed by @ref r_time_get_ts_monotonic.
 *  - **Test clock**: created via @ref r_test_clock_new for use in
 *    tests where time must be advanced manually with
 *    @ref r_test_clock_update_time. Time cannot move backwards.
 *
 * Timeout callbacks registered via @ref r_clock_add_timeout_callback
 * fire when @ref r_clock_process_entries is called and the clock's
 * current time has passed the entry's timestamp; this lets event
 * loops integrate clock-driven work into their main poll.
 *
 * @{
 */

/** @brief Opaque, refcounted clock handle. */
typedef struct RClock RClock;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_clock_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_clock_unref  r_ref_unref

/** @brief Opaque, refcounted clock-timeout-entry handle. */
typedef struct RClockEntry RClockEntry;
/** @brief Take a reference on a clock entry (alias for @ref r_ref_ref). */
#define r_clock_entry_ref   r_ref_ref
/** @brief Drop a reference on a clock entry (alias for @ref r_ref_unref). */
#define r_clock_entry_unref r_ref_unref


/** @brief Return the process-wide system monotonic clock. */
R_API RClock * r_system_clock_get (void);
/**
 * @brief Create a synthetic clock for tests.
 * @param update_on_wait If @c TRUE, @ref r_clock_wait advances the
 *                       clock to the requested timestamp instead of
 *                       blocking on it.
 */
R_API RClock * r_test_clock_new (rboolean update_on_wait) R_ATTR_MALLOC;

/** @brief Read the clock's current monotonic timestamp. */
R_API RClockTime r_clock_get_time (const RClock * clock);
/**
 * @brief Block until the clock reaches @p ts (or update synthetic
 * clocks accordingly).
 * @return The clock time at the end of the wait.
 */
R_API RClockTime r_clock_wait (RClock * clock, RClockTime ts);
/** @brief Convenience: wait until "now + @p delay". */
#define r_clock_wait_relative(clock, delay) \
  r_clock_wait (clock, r_clock_get_time (clock) + (delay))

/**
 * @brief Register a one-shot callback to fire when the clock passes @p ts.
 *
 * @param clock       Clock to register against.
 * @param ts          Absolute timestamp when @p cb should fire.
 * @param cb          Callback function.
 * @param data        First argument passed to @p cb.
 * @param datanotify  Destructor for @p data; may be @c NULL.
 * @param user        Second argument passed to @p cb.
 * @param usernotify  Destructor for @p user; may be @c NULL.
 * @return Refcounted entry handle (also keeps a reference inside the
 *         clock until processed or cancelled).
 */
R_API RClockEntry * r_clock_add_timeout_callback (RClock * clock,
    RClockTime ts, RFunc cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify);
/**
 * @brief Remove a pending entry before it fires.
 * @return @c TRUE if it was still pending; @c FALSE if it had already
 *         fired or been cancelled.
 */
R_API rboolean r_clock_cancel_entry (RClock * clock, RClockEntry * entry);
/** @brief Number of pending timeout entries on @p clock. */
R_API rsize r_clock_timeout_count (const RClock * clock);
/** @brief @c TRUE if @p clock is a synthetic (test) clock. */
R_API rboolean r_clock_is_synthetic (const RClock * clock);

/**
 * @brief Timestamp of the earliest pending timeout, or
 * @c R_CLOCK_TIME_NONE if none.
 */
R_API RClockTime r_clock_first_timeout (RClock * clock);
/**
 * @brief Run every entry whose timestamp has already passed.
 * @param clock Clock to drain.
 * @param out   Optional out-pointer: receives the timestamp of the
 *              next still-pending entry, or @c R_CLOCK_TIME_NONE.
 * @return Number of entries that fired.
 */
R_API ruint r_clock_process_entries (RClock * clock, RClockTime * out);

/**
 * @brief Advance a synthetic clock to @p ts (cannot move backwards).
 * @return @c TRUE on success, @c FALSE if @p clock is not a test
 *         clock or @p ts is in the past.
 */
R_API rboolean r_test_clock_update_time (RClock * clock, RClockTime ts);

R_END_DECLS

/** @} */

#endif /* __R_CLOCK_H__ */
