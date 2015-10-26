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
#error Unsupported platform for wallclock timestamps
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
#error Unsupported platform for monotonic timestamps
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

ruint64
r_time_get_unix_timestamp (void)
{
  return (ruint64)time (NULL);
}

