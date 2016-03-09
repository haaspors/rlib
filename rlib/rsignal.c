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
#include <rlib/rsignal.h>
#include <rlib/rmem.h>
#ifdef RLIB_HAVE_SIGNALS
#include <signal.h>
#include <time.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#if defined (R_OS_WIN32)
#include <windows.h>
#ifndef SIGALRM
#define SIGALRM 14
#endif
#elif defined (R_OS_UNIX)
#include <unistd.h>
#endif


struct _RSigAlrmTimer {
  RSignalFunc ofunc;
#ifdef RLIB_HAVE_SIGNALS
#if defined (R_OS_WIN32)
  HANDLE timer;
#elif defined (HAVE_TIMER_CREATE)
  timer_t timer;
  struct sigevent sigev;
  struct itimerspec its;
#elif defined (HAVE_SETITIMER)
  struct itimerval itv;
#elif defined (HAVE_ALARM)
  ruint secs;
#else
#error "Not implemented"
#endif
#endif
};

static rboolean g__r_sig_alrm_in_use = FALSE;

#ifdef R_OS_WIN32
static VOID CALLBACK
_r_sig_alrm_win32_cb (PVOID data, BOOLEAN timeout)
{
  (void) timeout;
  /* This is actually threadsafe! See r_sig_alrm_timer_delete */
  ((RSigAlrmTimer *)data)->ofunc (SIGALRM);
}

#endif

RSigAlrmTimer *
r_sig_alrm_timer_new_oneshot (RClockTime timeout, RSignalFunc func)
{
  RSigAlrmTimer * ret;

  if (timeout == 0 || timeout == R_CLOCK_TIME_NONE)
    return NULL;
  if (g__r_sig_alrm_in_use)
    return NULL;

#if defined (R_OS_WIN32)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = func;
  if (!CreateTimerQueueTimer (&ret->timer, NULL, _r_sig_alrm_win32_cb, ret,
        R_TIME_AS_MSECONDS (timeout), 0,
        WT_EXECUTEONLYONCE | WT_EXECUTEINTIMERTHREAD)) {
    r_free (ret);
    ret = NULL;
  }
#elif defined (HAVE_TIMER_CREATE)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = signal (SIGALRM, func);
  ret->sigev.sigev_notify = SIGEV_SIGNAL;
  ret->sigev.sigev_signo = SIGALRM;
  ret->sigev.sigev_value.sival_ptr = &ret->timer;
  if (timer_create (CLOCK_MONOTONIC, &ret->sigev, &ret->timer) == 0) {
    R_TIME_TO_TIMESPEC (timeout, ret->its.it_value);
    if (timer_settime (ret->timer, 0, &ret->its, NULL) != 0) {
      timer_delete (ret->timer);
      r_free (ret);
      ret = NULL;
    }
  } else {
    r_free (ret);
    ret = NULL;
  }
#elif defined (HAVE_SETITIMER)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = signal (SIGALRM, func);
  g__r_sig_alrm_in_use = TRUE;
  R_TIME_TO_TIMEVAL (timeout, ret->itv.it_value);
  setitimer (ITIMER_REAL, &ret->itv, NULL);
#elif defined (HAVE_ALARM)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = signal (SIGALRM, func);
  g__r_sig_alrm_in_use = TRUE;
  ret->secs = R_TIME_AS_SECONDS (timeout) + ((timeout % R_SECOND) > 0 ? 1 : 0);
  alarm (secs);
#else
  (void) func;
  ret = NULL;
#endif

  return ret;
}

RSigAlrmTimer *
r_sig_alrm_timer_new_interval (RClockTime interval, RSignalFunc func)
{
  RSigAlrmTimer * ret;

  if (interval == 0 || interval == R_CLOCK_TIME_NONE)
    return NULL;
  if (g__r_sig_alrm_in_use)
    return NULL;

#if defined (R_OS_WIN32)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = func;
  if (!CreateTimerQueueTimer (&ret->timer, NULL, _r_sig_alrm_win32_cb, ret,
        R_TIME_AS_MSECONDS (interval), R_TIME_AS_MSECONDS (interval),
        WT_EXECUTEINTIMERTHREAD)) {
    r_free (ret);
    ret = NULL;
  }
#elif defined (HAVE_TIMER_CREATE)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = signal (SIGALRM, func);
  ret->sigev.sigev_notify = SIGEV_SIGNAL;
  ret->sigev.sigev_signo = SIGALRM;
  ret->sigev.sigev_value.sival_ptr = &ret->timer;
  if (timer_create (CLOCK_MONOTONIC, &ret->sigev, &ret->timer) == 0) {
    R_TIME_TO_TIMESPEC (interval, ret->its.it_value);
    R_TIME_TO_TIMESPEC (interval, ret->its.it_interval);
    if (timer_settime (ret->timer, 0, &ret->its, NULL) != 0) {
      timer_delete (ret->timer);
      r_free (ret);
      ret = NULL;
    }
  } else {
    r_free (ret);
    ret = NULL;
  }
#elif defined (HAVE_SETITIMER)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = signal (SIGALRM, func);
  g__r_sig_alrm_in_use = TRUE;
  R_TIME_TO_TIMEVAL (interval, ret->itv.it_value);
  R_TIME_TO_TIMEVAL (interval, ret->itv.it_interval);
  setitimer (ITIMER_REAL, &ret->itv, NULL);
#else
  (void) func;
  ret = NULL;
#endif

  return ret;
}

RSigAlrmTimer *
r_sig_alrm_timer_new_interval_delayed (RClockTime timeout,
    RClockTime interval, RSignalFunc func)
{
  RSigAlrmTimer * ret;

  if (timeout == 0 || timeout == R_CLOCK_TIME_NONE)
    return r_sig_alrm_timer_new_interval (interval, func);
  if (interval == 0 || interval == R_CLOCK_TIME_NONE)
    return r_sig_alrm_timer_new_oneshot (timeout, func);
  if (g__r_sig_alrm_in_use)
    return NULL;

#if defined (R_OS_WIN32)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = func;
  if (!CreateTimerQueueTimer (&ret->timer, NULL, _r_sig_alrm_win32_cb, ret,
        R_TIME_AS_MSECONDS (timeout), R_TIME_AS_MSECONDS (interval),
        WT_EXECUTEINTIMERTHREAD)) {
    r_free (ret);
    ret = NULL;
  }
#elif defined (HAVE_TIMER_CREATE)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = signal (SIGALRM, func);
  if (timer_create (CLOCK_MONOTONIC, NULL, &ret->timer) == 0) {
    R_TIME_TO_TIMESPEC (timeout, ret->its.it_value);
    R_TIME_TO_TIMESPEC (interval, ret->its.it_interval);
    if (timer_settime (ret->timer, 0, &ret->its, NULL) != 0) {
      timer_delete (ret->timer);
      r_free (ret);
      ret = NULL;
    }
  } else {
    r_free (ret);
    ret = NULL;
  }
#elif defined (HAVE_SETITIMER)
  ret = r_mem_new0 (RSigAlrmTimer);
  ret->ofunc = signal (SIGALRM, func);
  g__r_sig_alrm_in_use = TRUE;
  R_TIME_TO_TIMEVAL (timeout, ret->itv.it_value);
  R_TIME_TO_TIMEVAL (interval, ret->itv.it_interval);
  setitimer (ITIMER_REAL, &ret->itv, NULL);
#else
  ret = NULL;
#endif

  return ret;
}

void
r_sig_alrm_timer_cancel (RSigAlrmTimer * timer)
{
  if (timer == NULL)
    return;

#if defined (HAVE_SETITIMER)
  struct itimerval itv = { { 0, 0 }, { 0, 0 } };
  setitimer (ITIMER_REAL, &itv, NULL);
#elif defined (HAVE_ALARM)
  alarm (0);
#endif
  r_sig_alrm_timer_delete (timer);
}

void
r_sig_alrm_timer_delete (RSigAlrmTimer * timer)
{
  if (timer == NULL)
    return;

  g__r_sig_alrm_in_use = FALSE;
#if defined (R_OS_WIN32)
  {
    /* Use an completeion event to make sure we can free the RSigAlrmTimer */
    HANDLE ev = CreateEvent (NULL, TRUE, FALSE, NULL);
    DeleteTimerQueueTimer (NULL, timer->timer, ev);
    WaitForSingleObject (ev, INFINITE);
    CloseHandle (ev);
  }
#else
  signal (SIGALRM, timer->ofunc);
#if defined (HAVE_TIMER_CREATE)
  timer_delete (timer->timer);
#endif
#endif
  r_free (timer);
}

#else

RSigAlrmTimer *
r_sig_alrm_timer_new_oneshot (RClockTime timeout, RSignalFunc func)
{
  (void) timeout;
  (void) func;
  return NULL;
}

RSigAlrmTimer *
r_sig_alrm_timer_new_interval (RClockTime interval, RSignalFunc func)
{
  (void) interval;
  (void) func;
  return NULL;
}

RSigAlrmTimer *
r_sig_alrm_timer_new_interval_delayed (RClockTime timeout,
    RClockTime interval, RSignalFunc func)
{
  (void) timeout;
  (void) interval;
  (void) func;
  return NULL;
}

void
r_sig_alrm_timer_cancel (RSigAlrmTimer * timer)
{
  (void) timer;
}

void
r_sig_alrm_timer_delete (RSigAlrmTimer * timer)
{
  (void) timer;
}

#endif

