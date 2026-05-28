/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_TIME_H__
#define __R_TIME_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rtime.h
 * @brief Time units, monotonic / wall-clock timestamps, calendar
 * helpers and printf-friendly time-formatting macros.
 */

#include <rlib/rtypes.h>

/**
 * @defgroup r_time Time
 *
 * @brief Sub-nanosecond integer time arithmetic, monotonic and
 * wall-clock timestamps, calendar conversions and timespec /
 * timeval bridging.
 *
 * rlib represents time as @c RClockTime — a 64-bit unsigned count of
 * nanoseconds. All durations and timestamps use this unit; the
 * @c R_NSECOND / @c R_USECOND / @c R_MSECOND / @c R_SECOND constants
 * are scale factors for converting from human-friendly units.
 *
 * @ref r_time_get_ts_monotonic is the right choice for elapsed-time
 * measurements; @ref r_time_get_ts_wallclock follows the system
 * real-time clock (and can therefore jump backwards on adjustment).
 *
 * @{
 */

/** @brief @c TRUE if @p time is not the @c R_CLOCK_TIME_NONE sentinel. */
#define R_CLOCK_TIME_IS_VALID(time)   (((RClockTime)(time)) != R_CLOCK_TIME_NONE)

/** @brief One nanosecond, in @c RClockTime units. */
#define R_NSECOND                     RINT64_CONSTANT (1)
/** @brief One microsecond, in @c RClockTime units. */
#define R_USECOND                     RINT64_CONSTANT (1000)
/** @brief One millisecond, in @c RClockTime units. */
#define R_MSECOND                     RINT64_CONSTANT (1000000)
/** @brief One second, in @c RClockTime units. */
#define R_SECOND                      RINT64_CONSTANT (1000000000)
/** @brief Milliseconds per second. */
#define R_MSEC_PER_SEC                1000
/** @brief Microseconds per second. */
#define R_USEC_PER_SEC                1000000
/** @brief Nanoseconds per second. */
#define R_NSEC_PER_SEC                1000000000
/** @brief Round @p time down to whole hours. */
#define R_TIME_AS_HOURS(time)         ((time) / (R_SECOND * 60 * 60))
/** @brief Round @p time down to whole minutes. */
#define R_TIME_AS_MINUTES(time)       ((time) / (R_SECOND * 60))
/** @brief Round @p time down to whole seconds. */
#define R_TIME_AS_SECONDS(time)       ((time) / R_SECOND)
/** @brief Round @p time down to whole milliseconds. */
#define R_TIME_AS_MSECONDS(time)      ((time) / R_MSECOND)
/** @brief Round @p time down to whole microseconds. */
#define R_TIME_AS_USECONDS(time)      ((time) / R_USECOND)
/** @brief Round @p time down to whole nanoseconds (identity for @c RClockTime). */
#define R_TIME_AS_NSECONDS(time)      ((time) / R_NSECOND)

/** @brief Signed difference @c e - @c s as @c RClockTimeDiff. */
#define R_CLOCK_DIFF(s, e)            (RClockTimeDiff)((e) - (s))

/** @brief Convert a @c struct @c timespec to @c RClockTime. */
#define R_TIMESPEC_TO_TIME(ts)        (RClockTime)((ts).tv_sec * R_SECOND + (ts).tv_nsec * R_NSECOND)
/** @brief Write @c RClockTime @p t into @c struct @c timespec @p ts. */
#define R_TIME_TO_TIMESPEC(t,ts)                                            \
R_STMT_START {                                                              \
  (ts).tv_sec  = (rlong) ( (t) / R_SECOND);                                 \
  (ts).tv_nsec = (rlong) (((t) % R_SECOND) / R_NSECOND);                    \
} R_STMT_END
/** @brief Static initialiser for a @c struct @c timespec from @c RClockTime @p t. */
#define R_TIME_TIMESPEC_INIT(t) { (rlong) ( (t) / R_SECOND),                \
                                  (rlong) (((t) % R_SECOND) / R_NSECOND) }

/** @brief Convert a @c struct @c timeval to @c RClockTime. */
#define R_TIMEVAL_TO_TIME(tv)         (RClockTime)((tv).tv_sec * R_SECOND + (tv).tv_usec * R_USECOND)
/** @brief Write @c RClockTime @p t into @c struct @c timeval @p tv. */
#define R_TIME_TO_TIMEVAL(t,tv)                                             \
R_STMT_START {                                                              \
  (tv).tv_sec  = (rlong) ( (t) / R_SECOND);                                 \
  (tv).tv_usec = (rlong) (((t) % R_SECOND) / R_USECOND);                    \
} R_STMT_END
/** @brief Static initialiser for a @c struct @c timeval from @c RClockTime @p t. */
#define R_TIME_TIMEVAL_INIT(t)  { (rlong) ( (t) / R_SECOND),                \
                                  (rlong) (((t) % R_SECOND) / R_USECOND) }

/** @brief @c printf format string matching @ref R_TIME_ARGS, e.g. @c "0:01:23.456789012". */
#define R_TIME_FORMAT                 "u:%02u:%02u.%09u"
/** @brief Expand to the @c printf arguments for @ref R_TIME_FORMAT. */
#define R_TIME_ARGS(t)                                                      \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) R_TIME_AS_HOURS (t) : 99,             \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) R_TIME_AS_MINUTES (t) % 60 : 99,      \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) R_TIME_AS_SECONDS (t) % 60 : 99,      \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) ((t) % R_SECOND) : 999999999

R_BEGIN_DECLS

/**
 * @brief Read the wall-clock real-time timestamp (@c CLOCK_REALTIME).
 *
 * Subject to NTP / admin adjustments; do not use for measuring elapsed
 * time. Use @ref r_time_get_ts_monotonic instead.
 */
R_API RClockTime r_time_get_ts_wallclock (void);
/**
 * @brief Read the monotonic timestamp (@c CLOCK_MONOTONIC); strictly
 * non-decreasing across calls in a single boot.
 */
R_API RClockTime r_time_get_ts_monotonic (void);
/**
 * @brief Read the raw monotonic timestamp (@c CLOCK_MONOTONIC_RAW
 * on Linux); not subject to NTP slewing.
 */
R_API RClockTime r_time_get_ts_raw (void);

/** @brief Return system uptime in nanoseconds. */
R_API ruint64 r_time_get_uptime (void);

/** @brief @c TRUE if @p year is a Gregorian leap year. */
R_API rboolean r_time_is_leap_year (ruint16 year);
/** @brief Count leap years in the half-open range [@p from, @p to). */
R_API ruint16 r_time_leap_years (ruint16 from, ruint16 to);
/** @brief Days in @p month of @p year (1-12), accounting for leap years. */
R_API rint8 r_time_days_in_month (ruint16 year, ruint8 month);
/**
 * @brief Convert a broken-down date to a Unix timestamp (seconds since
 * 1970-01-01 UTC).
 */
R_API ruint64 r_time_create_unix_time (ruint16 year, ruint8 month, ruint8 day,
    ruint8 hour, ruint8 minute, ruint8 second);
/**
 * @brief Split a Unix timestamp into broken-down date components.
 * @return @c TRUE on success; on failure the out-parameters are left
 *         in an unspecified state.
 */
R_API rboolean r_time_parse_unix_time (ruint64 time,
    ruint16 * year, ruint8 * month, ruint8 * day,
    ruint8 * hour, ruint8 * minute, ruint8 * second);

/** @brief Return the current Unix timestamp (seconds since 1970-01-01 UTC). */
R_API ruint64 r_time_get_unix_time (void);
/** @brief Alias for @ref r_time_get_unix_time. */
#define r_time_get_time_since_epoch() r_time_get_unix_time ()

R_END_DECLS

/** @} */

#endif /* __R_TIME_H__ */
