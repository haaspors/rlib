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
#ifndef __R_CLOCK_H__
#define __R_CLOCK_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>
#include <rlib/rtime.h>

/* Simple abstraction for a monotonic clock
 *
 * System clock
 *  - singleton
 *  - uses r_time_get_ts_monotonic ()
 *
 * Test clock
 *  - for use in tests where time must be updated manually.
 *  - use r_test_clock_update_time () to increase time.
 *  - it is NOT possible to go back in time.
 */

R_BEGIN_DECLS

typedef struct _RClock RClock;
#define r_clock_ref    r_ref_ref
#define r_clock_unref  r_ref_unref

typedef struct _RClockEntry RClockEntry;
#define r_clock_entry_ref   r_ref_ref
#define r_clock_entry_unref r_ref_unref


R_API RClock * r_system_clock_get (void);
R_API RClock * r_test_clock_new (rboolean update_on_wait) R_ATTR_MALLOC;

R_API RClockTime r_clock_get_time (const RClock * clock);
R_API RClockTime r_clock_wait (RClock * clock, RClockTime ts);
#define r_clock_wait_relative(clock, delay) \
  r_clock_wait (clock, r_clock_get_time (clock) + (delay))

R_API RClockEntry * r_clock_add_timeout_callback (RClock * clock,
    RClockTime ts, RFunc cb, rpointer data, RDestroyNotify datanotify,
    rpointer user, RDestroyNotify usernotify);
R_API rboolean r_clock_cancel_entry (RClock * clock, RClockEntry * entry);
R_API rsize r_clock_timeout_count (const RClock * clock);

/* These functions are used by threads/sources that wait for time */
R_API RClockTime r_clock_first_timeout (RClock * clock);
R_API ruint r_clock_process_entries (RClock * clock);

/* RTestClock spesific */
R_API rboolean r_test_clock_update_time (RClock * clock, RClockTime ts);

R_END_DECLS

#endif /* __R_CLOCK_H__ */
