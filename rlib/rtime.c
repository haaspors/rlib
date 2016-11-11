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

#include "config.h"
#include <rlib/rtime.h>
#include <rlib/rmodule.h>
#include <stdlib.h>
#include <stdio.h>

#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_MACH_MACH_TIME_H
#include <mach/mach_time.h>
#endif
#ifdef HAVE_MACH_CLOCK_H
#include <mach/clock.h>
#endif
#ifdef HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#ifdef HAVE_SYS_SYSINFO_H
#include <sys/sysinfo.h>
#endif


#if defined(R_OS_WIN32)
typedef void (WINAPI * r_win32_get_system_time) (LPFILETIME ft);
static r_win32_get_system_time  g__r_timer_win32GetSystemTime = GetSystemTimeAsFileTime;
static ruint                    g__r_time_ts_monotonic_num    = 100;
static ruint                    g__r_time_ts_monotonic_denom  = 1;
#elif defined(HAVE_MACH_MACH_TIME_H)
static ruint                    g__r_time_ts_monotonic_denom  = 1;
#endif

void
r_time_init (void)
{
#if defined(R_OS_WIN32)
  LARGE_INTEGER frequency;
  RMODULE mod;
  if (r_module_open (&mod, "kernel32.dll")) {
    rpointer win32gst = r_module_lookup (mod, "GetSystemTimePreciseAsFileTime");
    if (win32gst != NULL)
      g__r_timer_win32GetSystemTime = (r_win32_get_system_time) win32gst;
    /* Should we close the module? or keep it open? */
  }

  if (QueryPerformanceFrequency (&frequency)) {
    ruint64 d = r_uint64_gcd (R_SECOND, frequency.QuadPart);
    g__r_time_ts_monotonic_num = R_SECOND / d;
    g__r_time_ts_monotonic_denom = frequency.QuadPart / d;
  }
#elif defined(HAVE_MACH_MACH_TIME_H)
  mach_timebase_info_data_t mtbi;
  mach_timebase_info (&mtbi);
  if ((mtbi.denom % mtbi.numer) != 0)
    abort ();
  g__r_time_ts_monotonic_denom = mtbi.denom / mtbi.numer;
#endif
}

RClockTime
r_time_get_ts_wallclock (void)
{
#if defined(R_OS_WIN32)
  FILETIME ft = { 0, 0 };
  g__r_timer_win32GetSystemTime (&ft);
  return ((RClockTime)ft.dwHighDateTime << 32) | (RClockTime)ft.dwLowDateTime;
#elif defined(__MACH__) && defined(HAVE_SYS_TIME_H)
  struct timeval tval;
  gettimeofday (&tval, NULL);
  return R_TIMEVAL_TO_TIME (tval);
#elif defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_REALTIME)
  struct timespec tspec;
  clock_gettime (CLOCK_REALTIME, &tspec);
  return R_TIMESPEC_TO_TIME (tspec);
#else
#pragma message ("Unsupported platform for wallclock timestamps")
  return R_CLOCK_TIME_NONE;
#endif
}

RClockTime
r_time_get_ts_monotonic (void)
{
#if defined(R_OS_WIN32)
  LARGE_INTEGER counter;
  QueryPerformanceCounter (&counter);
  return (counter.QuadPart * g__r_time_ts_monotonic_num) / g__r_time_ts_monotonic_denom;
#elif defined(HAVE_MACH_MACH_TIME_H)
  return mach_absolute_time () / g__r_time_ts_monotonic_denom;
#elif defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
  struct timespec tspec;
  clock_gettime (CLOCK_MONOTONIC, &tspec);
  return R_TIMESPEC_TO_TIME (tspec);
#else
#pragma message ("Unsupported platform for monotonic timestamps")
  return R_CLOCK_TIME_NONE;
#endif
}

RClockTime
r_time_get_ts_raw (void)
{
#if defined(R_OS_WIN32)
  return r_time_get_ts_monotonic ();
#elif defined(HAVE_MACH_MACH_TIME_H)
  return r_time_get_ts_monotonic ();
#elif defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC_RAW)
  struct timespec tspec;
  clock_gettime (CLOCK_MONOTONIC_RAW, &tspec);
  return R_TIMESPEC_TO_TIME (tspec);
#else
  return R_CLOCK_TIME_NONE;
#endif
}

ruint64
r_time_get_uptime (void)
{
  FILE * f;
  ruint64 ret = 0;

#if defined(R_OS_WIN32)
  /* Thiw will have to do for now, but it might be wrong... */
  return GetTickCount64 () / R_MSEC_PER_SEC;
#else
#if defined(HAVE_SYS_SYSINFO_H)
  struct sysinfo sinfo;
  if (R_LIKELY (sysinfo (&sinfo) == 0))
    return sinfo.uptime;
#elif defined(__MACH__) && defined(HAVE_SYS_SYSCTL_H)
  int mib[2] = { CTL_KERN, KERN_BOOTTIME };
  struct timeval btime;
  size_t size = sizeof (btime);
  if (sysctl (mib, 2, &btime, &size, NULL, 0) != -1 && btime.tv_sec != 0)
    return (ruint64)(time (NULL) - btime.tv_sec);
#endif

  /* Fallback is reading out proc uptime */
  if ((f = fopen ("/proc/uptime", "r")) != NULL) {
    rfloat u, i;
    if (fscanf (f, "%f %f", &u, &i) == 2)
      ret = (ruint64)u;
    fclose (f);
  }

  return ret;
#endif
}

static const ruint8 g__r_time_days_in_month[2][12] = {
  { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
  { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};
static const ruint16 g__r_time_accum_days[2][12] = {
  { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 },
  { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335 }
};

rboolean
r_time_is_leap_year (ruint16 year)
{
  if (R_UNLIKELY (year < 1753)) return FALSE;
  if ((year % 400) == 0) return TRUE;
  if ((year % 100) == 0) return FALSE;
  if ((year %   4) == 0) return TRUE;
  return FALSE;
}

ruint16
r_time_leap_years (ruint16 from, ruint16 to)
{
  ruint16 ret;

  from = MAX (1753, from);
  if (--to <= --from) return 0;

  ret  = (to /   4) - (from /   4);
  ret -= (to / 100) - (from / 100);
  ret += (to / 400) - (from / 400);

  return ret;
}

static rboolean
r_time_is_year_month_day_valid (ruint16 year, ruint8 month, ruint8 day)
{
  if (R_UNLIKELY (year < 1753)) return FALSE;
  if (R_UNLIKELY (month < 1 || month > 12)) return FALSE;
  if (R_UNLIKELY (day < 1)) return FALSE;

  return day <= g__r_time_days_in_month[r_time_is_leap_year (year)][month - 1];
}

rint8
r_time_days_in_month (ruint16 year, ruint8 month)
{
  if (R_UNLIKELY (month < 1 || month > 12)) return -1;
  if (R_UNLIKELY (year < 1753)) return -1;

  return g__r_time_days_in_month[r_time_is_leap_year (year)][month - 1];
}

ruint64
r_time_create_unix_time (ruint16 year, ruint8 month, ruint8 day,
    ruint8 hour, ruint8 minute, ruint8 second)
{
  ruint64 days;

  if (R_UNLIKELY (!r_time_is_year_month_day_valid (year, month, day) || year < 1970))
      return 0;

  days = (year - 1970) * 365 + r_time_leap_years (1970, year);
  days += g__r_time_accum_days[r_time_is_leap_year (year) ? 1 : 0][month - 1];
  days += day - 1;

  return days * 86400 + hour * 3600 + minute * 60 + second;
}

rboolean
r_time_parse_unix_time (ruint64 time,
    ruint16 * year, ruint8 * month, ruint8 * day,
    ruint8 * hour, ruint8 * minute, ruint8 * second)
{
  ruint64 a, b, c, d, e, f;

  if (second != NULL)
    *second = time % 60;
  time /= 60;
  if (minute != NULL)
    *minute = time % 60;
  time /= 60;
  if (hour != NULL)
    *hour = time % 24;
  time /= 24;

  a = (time * 4 + 102032) / 146097 + 15;
  b = time + 2442113 + a - (a / 4);
  c = (20 * b - 2442) / 7305;
  d = b - 365 * c - (c / 4);
  e = d * 1000 / 30601;
  f = d - e * 30 - e * 601 / 1000;

  if (e <= 13) {
     c -= 4716;
     e -= 1;
  } else {
     c -= 4715;
     e -= 13;
  }

  if (year != NULL)
    *year = c;
  if (month != NULL)
    *month = e;
  if (day != NULL)
    *day = f;

  return TRUE;
}

ruint64
r_time_get_unix_time (void)
{
  return (ruint64)time (NULL);
}

