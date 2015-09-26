/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#ifndef __R_TIME_H__
#define __R_TIME_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#define R_CLOCK_TIME_IS_VALID(time)   (((RClockTime)(time)) != R_CLOCK_TIME_NONE)

#define R_NSECOND                     RINT64_CONSTANT (1)
#define R_USECOND                     RINT64_CONSTANT (1000)
#define R_MSECOND                     RINT64_CONSTANT (1000000)
#define R_SECOND                      RINT64_CONSTANT (1000000000)
#define R_MSEC_PER_SEC                1000        /* (R_SECOND / R_MSECOND) */
#define R_USEC_PER_SEC                1000000     /* (R_SECOND / R_USECOND) */
#define R_NSEC_PER_SEC                1000000000  /* (R_SECOND / R_NSECOND) */
#define R_TIME_AS_HOURS(time)         ((time) / (R_SECOND * 60 * 60))
#define R_TIME_AS_MINUTES(time)       ((time) / (R_SECOND * 60))
#define R_TIME_AS_SECONDS(time)       ((time) / R_SECOND)
#define R_TIME_AS_MSECONDS(time)      ((time) / R_MSECOND)
#define R_TIME_AS_USECONDS(time)      ((time) / R_USECOND)
#define R_TIME_AS_NSECONDS(time)      ((time) / R_NSECOND)

#define R_CLOCK_DIFF(s, e)            (RClockTimeDiff)((e) - (s))

#define R_TIMESPEC_TO_TIME(ts)        (RClockTime)((ts).tv_sec * R_SECOND + (ts).tv_nsec * R_NSECOND)
#define R_TIME_TO_TIMESPEC(t,ts)                                            \
R_STMT_START {                                                              \
  (ts).tv_sec  = (rlong) ( (t) / R_SECOND);                                 \
  (ts).tv_nsec = (rlong) (((t) % R_SECOND) / R_NSECOND);                    \
} R_STMT_END
#define R_TIME_TIMESPEC_INIT(t) { (rlong) ( (t) / R_SECOND),                \
                                  (rlong) (((t) % R_SECOND) / R_NSECOND) }

#define R_TIMEVAL_TO_TIME(tv)         (RClockTime)((tv).tv_sec * R_SECOND + (tv).tv_usec * R_USECOND)
#define R_TIME_TO_TIMEVAL(t,tv)                                             \
R_STMT_START {                                                              \
  (tv).tv_sec  = (rlong) ( (t) / R_SECOND);                                 \
  (tv).tv_usec = (rlong) (((t) % R_SECOND) / R_USECOND);                    \
} R_STMT_END
#define R_TIME_TIMEVAL_INIT(t)  { (rlong) ( (t) / R_SECOND),                \
                                  (rlong) (((t) % R_SECOND) / R_USECOND) }

#define R_TIME_FORMAT                 "u:%02u:%02u.%09u"
#define R_TIME_ARGS(t)                                                      \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) R_TIME_AS_HOURS (t) : 99,             \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) R_TIME_AS_MINUTES (t) % 60 : 99,      \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) R_TIME_AS_SECONDS (t) % 60 : 99,      \
  R_CLOCK_TIME_IS_VALID (t) ? (ruint) ((t) % R_SECOND) : 999999999

R_BEGIN_DECLS

R_API RClockTime r_time_get_ts_wallclock (void);
R_API RClockTime r_time_get_ts_monotonic (void);
R_API RClockTime r_time_get_ts_raw (void);

R_API ruint64 r_time_get_uptime (void);
R_API ruint64 r_time_get_unix_timestamp (void);
#define r_time_get_time_since_epoch() r_time_get_unix_timestamp ()

R_END_DECLS

#endif /* __R_TIME_H__ */
