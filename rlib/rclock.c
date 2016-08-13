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

#include "config.h"
#include <rlib/rclock.h>

#include <rlib/rassert.h>
#include <rlib/rmem.h>
#include <rlib/rthreads.h>

typedef RClockTime (*RClockGetTimeFunc) (const RClock * clock);
typedef RClockTime (*RClockWaitFunc) (RClock * clock, RClockTime ts);

struct _RClock {
  RRef ref;
  RClockGetTimeFunc get_time;
  RClockWaitFunc wait;
};

typedef struct {
  RClock clock;
  rboolean update_on_wait;
  RClockTime ts;
  RMutex mutex;
  RCond cond;
} RTestClock;

#define R_CLOCK_IS_SYSTEM_CLOCK(clock) ((clock)->get_time == r_time_get_ts_monotonic)
#define R_CLOCK_IS_TEST_CLOCK(clock) ((clock)->get_time == r_test_clock_get_time)

RClockTime
r_clock_get_time (const RClock * clock)
{
  return clock->get_time (clock);
}

RClockTime
r_clock_wait (RClock * clock, RClockTime ts)
{
  return clock->wait (clock, ts);
}


/* System clock */
static RClockTime
r_system_clock_wait (RClock * clock, RClockTime ts)
{
  RClockTime now;

  while ((now = r_clock_get_time (clock)) < ts)
    r_thread_usleep (R_TIME_AS_USECONDS (ts - now));

  return now;
}

static RClock g__r_sysclock = { { 0, NULL },
  (RClockGetTimeFunc)r_time_get_ts_monotonic, r_system_clock_wait };

RClock *
r_system_clock_get (void)
{
  return &g__r_sysclock;
}



/* Test clock */
static RClockTime
r_test_clock_get_time (const RClock * clock)
{
  return ((RTestClock *)clock)->ts;
}

static RClockTime
r_test_clock_wait (RClock * clock, RClockTime ts)
{
  RTestClock * testclock;
  RClockTime now;

  /* Segfault or assert if test misuses the clock */
  r_assert (R_CLOCK_IS_TEST_CLOCK (clock));
  testclock = (RTestClock *) clock;

  if (testclock->update_on_wait) {
    r_test_clock_update_time (clock, ts);
    now = testclock->ts;
  } else {
    r_mutex_lock (&testclock->mutex);
    while ((now = r_clock_get_time (clock)) < ts)
      r_cond_wait (&testclock->cond, &testclock->mutex);
    r_mutex_unlock (&testclock->mutex);
  }

  return now;
}

static void
r_test_clock_free (RTestClock * clock)
{
  r_cond_clear (&clock->cond);
  r_mutex_clear (&clock->mutex);
  r_free (clock);
}

RClock *
r_test_clock_new (rboolean update_on_wait)
{
  RTestClock * ret;

  if ((ret = r_mem_new (RTestClock)) != NULL) {
    r_ref_init (ret, r_test_clock_free);
    ret->clock.get_time = r_test_clock_get_time;
    ret->clock.wait = r_test_clock_wait;
    ret->update_on_wait = update_on_wait;
    ret->ts = 0;
    r_mutex_init (&ret->mutex);
    r_cond_init (&ret->cond);
  }

  return (RClock *)ret;
}

rboolean
r_test_clock_update_time (RClock * clock, RClockTime ts)
{
  RTestClock * testclock;
  rboolean ret;

  /* Segfault or assert if test misuses the clock */
  r_assert (R_CLOCK_IS_TEST_CLOCK (clock));
  testclock = (RTestClock *) clock;

  r_mutex_lock (&testclock->mutex);
  if ((ret = (ts >= testclock->ts))) {
    testclock->ts = ts;
    r_cond_broadcast (&testclock->cond);
  }
  r_mutex_unlock (&testclock->mutex);

  return ret;
}

