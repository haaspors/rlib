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

#include "config.h"
#include "rlib-private.h"
#include <rlib/rtest.h>

#include <rlib/os/rproc.h>
#include <rlib/os/rsignal.h>

#include <rlib/ratomic.h>
#include <rlib/rassert.h>
#include <rlib/renv.h>
#include <rlib/rlog.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>
#include <rlib/rthreads.h>
#include <rlib/rtime.h>
#include <rlib/rtty.h>

#include <setjmp.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif

#ifdef _r_test_mark_position
#undef _r_test_mark_position
#endif

/* FIXME: move forking/process stuff to rproc */
/* FIXME: move pipe stuff to rproc or rpipe? */
/* TODO: Gather test log, 1. r_log 2. r_print[err] 3. stdout/stderr? */

#define R_TEST_THREADS              10240

static RTss                         g__r_test_last_pos_tss = R_TSS_INIT (NULL);

#ifdef R_OS_UNIX
#define _DO_CLR(SGR)  (r_isatty (r_fileno (f))) ? SGR : ""
#else
#define _DO_CLR(SGR) ""
#endif

#define _RESET_CLR    _DO_CLR (R_TTY_SGR_RESET)
#define _TIME_CLR     _DO_CLR (R_TTY_SGR1 (R_TTY_SGR_FG_ARG (R_CLR_CYAN)))
#define _TIME_ERR_CLR _DO_CLR (R_TTY_SGR1 (R_TTY_SGR_FG_ARG (R_CLR_YELLOW)))
#define _RES_CLR(CLR) _DO_CLR (R_TTY_SGR2 (R_TTY_SGR_BOLD_ARG, R_TTY_SGR_FG_ARG(CLR)))

#define _SKIP_ARGS(COUNT) (COUNT) ? (_RES_CLR (R_CLR_BLUE)) : "", COUNT, _RESET_CLR
#define _SUCC_ARGS(COUNT) (COUNT) ? (_RES_CLR (R_CLR_GREEN)) : "", COUNT, _RESET_CLR
#define _FAIL_ARGS(COUNT) (COUNT) ? (_RES_CLR (R_CLR_RED)) : "", COUNT, _RESET_CLR
#define _ERR_ARGS(COUNT)  (COUNT) ? (_RES_CLR (R_CLR_MAGENTA)) : "", COUNT, _RESET_CLR

#if defined (R_OS_WIN32)
static const int g__r_test_sigs[] = {
  SIGABRT, SIGFPE, SIGSEGV, SIGILL
};
#elif defined (R_OS_UNIX)
static const int g__r_test_sigs[] = {
  SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
#ifdef SIGSTKFLT
  SIGSTKFLT,
#endif
  SIGFPE, SIGSEGV, SIGBUS, SIGSYS
#ifdef SIGXCPU
  , SIGXCPU
#endif
#ifdef SIGXFSZ
  , SIGXFSZ
#endif
};
#endif

typedef struct {
  RTestRunState state;

  RThread * thread;
  RSigAlrmTimer * timer;

#if defined (R_OS_WIN32)
  RTestLastPos * lastpos;
  RTestLastPos * failpos;
#elif defined (R_OS_UNIX)
  pid_t pid;
#endif
} RTestRunForkCtx;
#if defined (R_OS_WIN32) || defined (R_OS_UNIX)
static RTestRunForkCtx *    g__r_test_fork_ctx = NULL;
#endif

typedef struct {
  RThread * thread;
  RSigAlrmTimer * timer;

  jmp_buf jb;

  /* <private> */
#ifdef RLIB_HAVE_SIGNALS
#if defined (R_OS_WIN32)
  LPTOP_LEVEL_EXCEPTION_FILTER ouef;
  void (*osigabrt) (int);
#else
#ifdef HAVE_SIGALTSTACK
  stack_t ss;
  stack_t oss;
#endif
#ifdef HAVE_SIGACTION
  struct sigaction sa, osa[R_N_ELEMENTS (g__r_test_sigs)];
#endif
#endif
#endif

  rsize maxposcount;
  RTestLastPos * pos;
  rauint poscount;

  RTestLastPos * lastpos;
  RTestLastPos * failpos;
} RTestRunNoForkCtx;
static RTestRunNoForkCtx *  g__r_test_nofork_ctx = NULL;
static void r_test_run_nofork_cleanup (RTestRunNoForkCtx * ctx);


R_LOG_CATEGORY_DEFINE_STATIC (rtest_logcat, "test", "Test logger",
    R_CLR_BG_MAGENTA | R_CLR_FMT_BOLD);
#define R_LOG_CAT_DEFAULT &rtest_logcat

static const rchar *
r_test_get_run_str (RTestRunState state, const rchar ** runresclr, FILE * f)
{
  switch (state) {
    case R_TEST_RUN_STATE_SUCCESS:
      *runresclr = _RES_CLR (R_CLR_GREEN);
      return "SUCCESS:";
    case R_TEST_RUN_STATE_FAILED:
      *runresclr = _RES_CLR (R_CLR_RED);
      return "FAIL:";
    case R_TEST_RUN_STATE_ERROR:
      *runresclr = _RES_CLR (R_CLR_MAGENTA);
      return "ERROR:";
    case R_TEST_RUN_STATE_SKIP:
      *runresclr = _RES_CLR (R_CLR_BLUE);
      return "SKIP:";
    case R_TEST_RUN_STATE_TIMEOUT:
      *runresclr = _RES_CLR (R_CLR_MAGENTA);
      return "TIMEOUT:";
    default:
      *runresclr = _RES_CLR (R_CLR_CYAN);
      return "INTERR:";
  };
}

void
r_test_init (void)
{
  r_log_category_register (&rtest_logcat);
  if (r_log_category_get_threshold (R_LOG_CAT_DEFAULT) < R_LOG_LEVEL_ERROR)
    r_log_category_set_threshold (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR);
}

rboolean
_r_test_mark_position (const rchar * file, ruint line, const rchar * func,
    rboolean assert)
{
  RTestLastPos * lastpos;

  if (g__r_test_nofork_ctx == NULL)
    return FALSE;

  if (R_UNLIKELY ((lastpos = r_tss_get (&g__r_test_last_pos_tss)) == NULL)) {
    ruint idx;

    idx = r_atomic_uint_fetch_add (&g__r_test_nofork_ctx->poscount, 1);
    if (idx >= g__r_test_nofork_ctx->maxposcount)
      return FALSE;

    lastpos = &g__r_test_nofork_ctx->pos[idx];
    r_tss_set (&g__r_test_last_pos_tss, lastpos);
  }

  lastpos->ts = r_time_get_ts_monotonic ();
  lastpos->file = file;
  lastpos->line = line;
  lastpos->func = func;
  lastpos->assert = assert;

  if (assert)
    g__r_test_nofork_ctx->failpos = lastpos;

  return TRUE;
}

static inline R_ATTR_NORETURN void
r_test_abort (void)
{
  if (g__r_test_nofork_ctx != NULL && g__r_test_nofork_ctx->thread == r_thread_current ())
    longjmp (g__r_test_nofork_ctx->jb, R_TEST_RUN_STATE_FAILED);
  else
    abort ();
}

void
r_test_assertion (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  r_test_assertionv (cat, file, line, func, fmt, args);
  va_end (args);
}

void
r_test_assertionv (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, va_list args)
{
  rchar * msg = r_strvprintf (fmt, args);
  _r_test_mark_position (file, line, func, TRUE);
  r_log_msg (cat, R_LOG_LEVEL_ERROR, file, line, func, msg);
  r_free (msg);
  r_test_abort ();
}

void
r_test_assertion_msg (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func, const rchar * msg)
{
  _r_test_mark_position (file, line, func, TRUE);
  r_log_msg (cat, R_LOG_LEVEL_ERROR, file, line, func, msg);
  r_test_abort ();
}

rchar *
r_test_dup_path (const RTest * test)
{
  return r_strjoin ("/", "", test->suite, test->name, NULL);
}

rboolean
r_test_fill_path (const RTest * test, rchar * path, rsize size)
{
  return r_strnjoin (path, size, "/", "", test->suite, test->name, NULL) != NULL;
}

static const RTest *
r_test_get_module_tests_using_find_section (RMODULE mod, rsize * count)
{
  rpointer sec;
  rsize secsize = 0;

  sec = r_module_find_section (mod, R_STR_WITH_SIZE_ARGS (RTEST_SECTION), &secsize);
  if (count != NULL)
    *count = secsize / sizeof (RTest);

  R_LOG_INFO ("Find '"RTEST_SECTION"' section in module %p -> %p (0x%"RSIZE_MODIFIER"x)",
      mod, sec, secsize);

  return sec;
}

static const RTest *
r_test_get_module_tests_using_magic (RMODULE mod, rsize * count)
{
  rchar name[] = R_STRINGIFY (_RTEST_SYM_)"0";
  const RTest * begin = RSIZE_TO_POINTER (RSIZE_MAX), * end = NULL, * cur, ** sym;
  int i;

  R_LOG_INFO ("Trying to find '"R_STRINGIFY (_RTEST_SYM_)"' symbols"
      " then iterate looking for RTEST magic");
  for (i = 0; i < 10; i++) {
    name[sizeof (R_STRINGIFY (_RTEST_SYM_))-1] = '0' + i;
    if ((sym = r_module_lookup (mod, name)) != NULL &&
        (*sym)->magic == _RTEST_MAGIC) {
      R_LOG_DEBUG ("Resolved '%s': %p", name, *sym);
      begin = MIN (begin, *sym);
      end = MAX (end, *sym);
    } else {
      R_LOG_DEBUG ("Not found '%s'", name);
    }
  }

  if (end == NULL) {
    R_LOG_CRITICAL ("Didn't find any '"R_STRINGIFY (_RTEST_SYM_)"' symbols");
    return NULL;
  }

  for (cur = begin - 1; cur->magic == _RTEST_MAGIC; cur--)
    begin = cur;
  for (cur = end + 1; cur->magic == _RTEST_MAGIC; cur++)
    end = cur;

  R_LOG_INFO ("Found RTESTs: first %p, last %p"
      " (size: 0x%"RSIZE_MODIFIER"x / 0x%"RSIZE_MODIFIER"x == %"RSIZE_FMT")",
      begin, end, RPOINTER_TO_SIZE (end) - RPOINTER_TO_SIZE (begin), sizeof (RTest),
      (RPOINTER_TO_SIZE (end) - RPOINTER_TO_SIZE (begin)) / sizeof (RTest));

  if (count != NULL)
    *count = (end - begin) + 1;

  return begin;
}

const RTest *
r_test_get_module_tests (RMODULE mod, rsize * count)
{
  const RTest * ret;
  RMODULE closemod;

  if (mod == NULL) {
    if ((closemod = mod = r_module_open (NULL, TRUE, NULL)) == NULL)
      return NULL;
  } else {
    closemod = NULL;
  }

  /* Try the r_module_find_section based impl */
  if ((ret = r_test_get_module_tests_using_find_section (mod, count)) == NULL) {
    /* Fallback using the magic symbol */
    R_LOG_CRITICAL ("Use fallback when finding module tests (using RTEST magic)");
    ret = r_test_get_module_tests_using_magic (mod, count);
  }

  if (closemod != NULL)
    r_module_close (mod);

  return ret;
}

#if defined (R_OS_WIN32)
typedef struct {
  const RTest * test;
  rsize __i;
  rboolean notimeout;
  RTestLastPos * lastpos, * failpos;
} RTestWin32Run;

static rpointer
r_test_run_pseudo_fork (rpointer data)
{
  const RTestWin32Run * win32run = data;
  RTestRunState ret;

  ret = r_test_run_nofork (win32run->test, win32run->__i, win32run->notimeout,
      win32run->lastpos, win32run->failpos, NULL, NULL);

  return RINT_TO_POINTER (ret);
}

RTestRunState
r_test_run_fork (const RTest * test, rsize __i, rboolean notimeout,
    RTestLastPos * lastpos, RTestLastPos * failpos, int * pid, int * exitcode)
{
  RTestWin32Run win32run = { test, __i, notimeout, lastpos, failpos };
  RTestRunForkCtx ctx = { R_TEST_RUN_STATE_NONE, NULL, NULL, NULL, NULL };
  rpointer res;

  (void) pid;
  (void) exitcode;

  if (g__r_test_fork_ctx != NULL) abort (); /* Can't use r_assert* here */
  if (g__r_test_nofork_ctx != NULL) abort (); /* Can't use r_assert* here */

  g__r_test_fork_ctx = &ctx;
  ctx.thread = r_thread_new (NULL, r_test_run_pseudo_fork, &win32run);
  res = r_thread_join (ctx.thread);
  g__r_test_fork_ctx = NULL;

  if (ctx.timer != NULL)
    r_sig_alrm_timer_cancel (ctx.timer);

  if (ctx.state != R_TEST_RUN_STATE_NONE) {
    if (ctx.lastpos != NULL)
      r_memcpy (lastpos, ctx.lastpos, sizeof (RTestLastPos));
    if (ctx.failpos != NULL) {
      r_memcpy (failpos, ctx.failpos, sizeof (RTestLastPos));
      ctx.state = R_TEST_RUN_STATE_FAILED; /* Assert on some thread, set failed */
    }

    return ctx.state;
  }

  return (RTestRunState)RPOINTER_TO_INT (res);
}
#elif defined (R_OS_UNIX)
static void
_r_test_fork_timeout_handler (int sig)
{
  if (sig != SIGALRM || g__r_test_fork_ctx == NULL || g__r_test_fork_ctx->thread == NULL)
    return;

  if (g__r_test_fork_ctx->thread == r_thread_current ()) {
    R_LOG_WARNING ("SIGALRM: killing forked process %u", g__r_test_fork_ctx->pid);
    g__r_test_fork_ctx->state = R_TEST_RUN_STATE_TIMEOUT;
    kill (g__r_test_fork_ctx->pid, SIGKILL);
  } else {
    R_LOG_INFO ("SIGALRM: fwd signal to thread %p", g__r_test_fork_ctx->thread);
    r_thread_kill (g__r_test_fork_ctx->thread, sig);
  }
}

static void
r_test_run_fork_setup (RTestRunForkCtx * ctx, pid_t pid, RClockTime timeout)
{
  if (g__r_test_fork_ctx != NULL) abort (); /* Can't use r_assert* here */

  ctx->pid = pid;
  ctx->state = R_TEST_RUN_STATE_NONE;

  ctx->thread = r_thread_ref (r_thread_current ());

  /* Since this is parent process parachute, add 100ms.
   * Meaning; if nofork timeout timer fails, this will kick inn 100ms later
   */
  if (timeout != 0 && timeout != R_CLOCK_TIME_NONE)
    timeout += 100*R_MSECOND;
  ctx->timer = r_sig_alrm_timer_new_oneshot (timeout,
      _r_test_fork_timeout_handler);

  g__r_test_fork_ctx = ctx;
}

static void
r_test_run_fork_cleanup (RTestRunForkCtx * ctx)
{
  if (g__r_test_fork_ctx != ctx)
    return;
  g__r_test_fork_ctx = NULL;

  if (ctx->timer != NULL)
    r_sig_alrm_timer_cancel (ctx->timer);

  r_thread_unref (ctx->thread);
  ctx->thread = NULL;
}

RTestRunState
r_test_run_fork (const RTest * test, rsize __i, rboolean notimeout,
    RTestLastPos * lastpos, RTestLastPos * failpos, int * pidout, int * exitcode)
{
  RTestRunState ret = R_TEST_RUN_STATE_ERROR;
  pid_t pid, wpid;
  int fdp[2];

  if (R_UNLIKELY (test == NULL))
    return ret;

  if (R_UNLIKELY (pipe (fdp) != 0))
    return ret;

  lastpos->ts = r_time_get_ts_monotonic ();
  lastpos->file = __FILE__;
  lastpos->line = __LINE__;
  lastpos->func = R_STRFUNC;
  lastpos->assert = FALSE;

  if ((pid = fork ()) > 0) {
    RTestRunForkCtx ctx;
    int status;

    close(fdp[1]);
    *pidout = (int)pid;
    r_test_run_fork_setup (&ctx, pid, notimeout ? R_CLOCK_TIME_NONE : test->timeout);
    wpid = waitpid (pid, &status, 0);
    r_test_run_fork_cleanup (&ctx);

    if (wpid == pid) {
      if (WIFEXITED (status) && (*exitcode = WEXITSTATUS (status)) == 0) {
        if (read (fdp[0], &ret, sizeof (RTestRunState)) != sizeof (RTestRunState)) {
          R_LOG_WARNING ("Failed to read from pipe to forked child");
          ret = R_TEST_RUN_STATE_ERROR;
        }
        read (fdp[0], lastpos, sizeof (RTestLastPos));
        read (fdp[0], failpos, sizeof (RTestLastPos));
      }
    }
    close(fdp[0]);

    if (ctx.state != R_TEST_RUN_STATE_NONE)
      ret = ctx.state;
  } else if (pid == 0) {
    close(fdp[0]);
    ret = r_test_run_nofork (test, __i, notimeout, lastpos, failpos, NULL, NULL);

    if (write (fdp[1], &ret, sizeof (RTestRunState)) != sizeof (RTestRunState))
      R_LOG_ERROR ("Failed to write to pipe to parent (forker)");
    if (write (fdp[1], lastpos, sizeof (RTestLastPos)) != sizeof (RTestLastPos))
      R_LOG_ERROR ("Failed to write to pipe to parent (forker)");
    if (write (fdp[1], failpos, sizeof (RTestLastPos)) != sizeof (RTestLastPos))
      R_LOG_ERROR ("Failed to write to pipe to parent (forker)");
    close (fdp[1]);
    exit (0);
  } else {
    R_LOG_ERROR ("Failed to fork test /%s/%s/%"RSIZE_FMT,
        test->suite, test->name, __i);
    close(fdp[0]);
    close(fdp[1]);
  }

  return ret;
}
#endif

#ifdef R_OS_WIN32
static void
_r_test_nofork_win32_kill_test_thread (RTestRunState state)
{
  HANDLE h;

  if (g__r_test_fork_ctx == NULL)
    return;

  h = OpenThread (THREAD_TERMINATE, FALSE,
      r_thread_get_id (g__r_test_fork_ctx->thread));
  g__r_test_fork_ctx->state = state;
  if (h != NULL) {
    SuspendThread (h);

    /* Transfer over lastpos and failpos */
    g__r_test_fork_ctx->lastpos = g__r_test_nofork_ctx->lastpos;
    g__r_test_fork_ctx->failpos = g__r_test_nofork_ctx->failpos;

    /* Cross your fingers and hope this will work.... */
    /* If this came from the win32 timer thread we can't cancel the timer.
     * So this will defer the cancel */
    g__r_test_fork_ctx->timer = g__r_test_nofork_ctx->timer;
    g__r_test_nofork_ctx->timer = NULL;
    r_test_run_nofork_cleanup (g__r_test_nofork_ctx);

    TerminateThread (h, (DWORD)state);
  }
  CloseHandle (h);
}
#endif

static void
_r_test_nofork_timeout_handler (int sig)
{
#ifdef R_OS_UNIX
  if (R_UNLIKELY (sig != SIGALRM))
    return;
#else
    (void) sig;
#endif
  if (R_UNLIKELY (g__r_test_nofork_ctx == NULL))
    return;

  r_log (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_WARNING, "???", 0, "???", "test timeout");
  if (g__r_test_nofork_ctx->thread == r_thread_current ()) {
    longjmp (g__r_test_nofork_ctx->jb, R_TEST_RUN_STATE_TIMEOUT);
  } else {
    /* SIGALRM could be raised in any thread, so marshal it over! */
    R_LOG_WARNING ("SIGALRM - Kill test thread %p", g__r_test_nofork_ctx->thread);
#if defined (R_OS_WIN32)
    _r_test_nofork_win32_kill_test_thread (R_TEST_RUN_STATE_TIMEOUT);
#elif defined (R_OS_UNIX)
    r_thread_kill (g__r_test_nofork_ctx->thread, sig);
#endif
  }
}

#if defined (R_OS_WIN32)
static void
_r_test_win32_error (int sig)
{
  if (R_UNLIKELY (g__r_test_nofork_ctx == NULL))
    return;

  if (g__r_test_nofork_ctx->thread == r_thread_current ()) {
    longjmp (g__r_test_nofork_ctx->jb, R_TEST_RUN_STATE_ERROR);
  } else {
    _r_test_nofork_win32_kill_test_thread (R_TEST_RUN_STATE_ERROR);
    r_thread_exit (RINT_TO_POINTER (sig));
  }
}

static LONG WINAPI
_r_test_win32_exception_filter (PEXCEPTION_POINTERS ep)
{
  const rchar * errfile = "???";
  const rchar * errfunc = "???";
  ruint errline = 0;

  if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_STACK_OVERFLOW) {
    r_log (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR, errfile, errline, errfunc,
        "exception code: %u", ep->ExceptionRecord->ExceptionCode);
  }

  _r_test_win32_error (SIGSEGV);

  return EXCEPTION_CONTINUE_SEARCH;
}

static void
_r_test_win32_abort_handler (int sig)
{
  r_log (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR, __FILE__, __LINE__, R_STRFUNC,
      "Signal %d", sig);
  _r_test_win32_error (sig);
}
#elif defined (R_OS_UNIX)
#ifdef RLIB_HAVE_SIGNALS
#ifdef HAVE_SIGACTION
static void
_r_test_nofork_signalhandler (int sig, siginfo_t * si, rpointer uctx)
{
  (void) uctx;

  if (R_UNLIKELY (g__r_test_nofork_ctx == NULL))
    return;

  if (R_UNLIKELY (sig == SIGALRM)) {
    _r_test_nofork_timeout_handler (sig);
    return;
  }

  if (g__r_test_nofork_ctx->thread != r_thread_current ()) {
    /* Because abort() fiddles with the sig mask we must reset manually */
    if (sig == SIGABRT) {
      sigset_t sset;
      sigemptyset (&sset);
      sigaddset (&sset, SIGABRT);
      sigprocmask (SIG_UNBLOCK, &sset, NULL);
    }

    r_thread_kill (g__r_test_nofork_ctx->thread, sig);
#ifdef HAVE_SIGINFO_T_SI_STATUS
    r_thread_exit (RINT_TO_POINTER (si->si_status));
#else
    r_thread_exit (RINT_TO_POINTER (si->si_value.sival_int));
#endif
  } else {
    int val;
    const rchar * errfile = "???";
    const rchar * errfunc = "???";
    ruint errline = 0;

    if (g__r_test_nofork_ctx->failpos) {
      val = R_TEST_RUN_STATE_FAILED;
      errfile = g__r_test_nofork_ctx->failpos->file;
      errline = g__r_test_nofork_ctx->failpos->line;
      errfunc = g__r_test_nofork_ctx->failpos->func;
    } else {
      val = R_TEST_RUN_STATE_ERROR;
    }

#ifdef HAVE_SYS_SIGLIST
    r_log (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR, errfile, errline, errfunc,
        "%s (%d)", sys_siglist[sig], sig);
#else
    r_log (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR, errfile, errline, errfunc,
        "signal: %d", sig);
#endif
    longjmp (g__r_test_nofork_ctx->jb, val);
  }
}
#endif
#endif
#endif

static void
r_test_run_nofork_setup (RTestRunNoForkCtx * ctx, RClockTime timeout)
{
#ifdef RLIB_HAVE_SIGNALS
#if defined (R_OS_UNIX)
#ifdef HAVE_SIGALTSTACK
  static ruint8 _r_test_sigstack[SIGSTKSZ];
#endif
#ifdef HAVE_SIGACTION
  rsize i;
#endif
#endif
#endif
  static RTestLastPos _r_test_lastpos[R_TEST_THREADS];

  if (g__r_test_nofork_ctx != NULL) abort (); /* Can't use r_assert* here */

  ctx->thread = r_thread_ref (r_thread_current ());

#ifdef RLIB_HAVE_SIGNALS
#if defined (R_OS_WIN32)
  ctx->ouef = SetUnhandledExceptionFilter (_r_test_win32_exception_filter);
  _set_abort_behavior (0, _CALL_REPORTFAULT | _WRITE_ABORT_MSG);
  ctx->osigabrt = signal (SIGABRT, _r_test_win32_abort_handler);
#elif defined (R_OS_UNIX)
#ifdef HAVE_SIGALTSTACK
  ctx->ss.ss_size = sizeof (_r_test_sigstack);
  ctx->ss.ss_sp = _r_test_sigstack;
  ctx->ss.ss_flags = 0;
  sigaltstack (&ctx->ss, &ctx->oss);
#endif

#ifdef HAVE_SIGACTION
  ctx->sa.sa_sigaction = _r_test_nofork_signalhandler;
  sigemptyset (&ctx->sa.sa_mask);
  ctx->sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

  for (i = 0; i < R_N_ELEMENTS (g__r_test_sigs); i++)
    sigaction (g__r_test_sigs[i], &ctx->sa, &ctx->osa[i]);
#endif
#endif
#endif

  ctx->timer = r_sig_alrm_timer_new_oneshot (timeout,
      _r_test_nofork_timeout_handler);

  r_memset (_r_test_lastpos, 0, sizeof (_r_test_lastpos));
  ctx->pos = _r_test_lastpos;
  ctx->maxposcount = R_TEST_THREADS;
  ctx->poscount = 0;
  ctx->failpos = NULL;

  r_tss_set (&g__r_test_last_pos_tss, NULL);
  g__r_test_nofork_ctx = ctx;
  if (!_r_test_mark_position (NULL, 0, "test-entry-setup", FALSE))
    abort ();
  ctx->lastpos = r_tss_get (&g__r_test_last_pos_tss);
}

static void
r_test_run_nofork_cleanup (RTestRunNoForkCtx * ctx)
{
#ifdef RLIB_HAVE_SIGNALS
#if defined (R_OS_UNIX)
#ifdef HAVE_SIGACTION
  rsize i;
#endif
#endif
#endif

  if (R_UNLIKELY (ctx == NULL))
    return;
  if (ctx != g__r_test_nofork_ctx)
    return;
  g__r_test_nofork_ctx = NULL;

  if (ctx->timer != NULL)
    r_sig_alrm_timer_cancel (ctx->timer);

#ifdef RLIB_HAVE_SIGNALS
#if defined (R_OS_WIN32)
  signal (SIGABRT, ctx->osigabrt);
  SetUnhandledExceptionFilter (ctx->ouef);
#elif defined (R_OS_UNIX)
#ifdef HAVE_SIGACTION
  for (i = R_N_ELEMENTS (g__r_test_sigs); i > 0; i--)
    sigaction (g__r_test_sigs[i-1], &ctx->osa[i-1], NULL);
#endif

#ifdef HAVE_SIGALTSTACK
  sigaltstack (&ctx->oss, NULL);
#endif
#endif
#endif

  r_thread_unref (ctx->thread);
  ctx->thread = NULL;
}

RTestRunState
r_test_run_nofork (const RTest * test, rsize __i, rboolean notimeout,
    RTestLastPos * lastpos, RTestLastPos * failpos, int * pid, int * exitcode)
{
  RTestRunState ret = R_TEST_RUN_STATE_ERROR;
  RTestRunNoForkCtx ctx;
  int jmpres;

  (void) pid;
  (void) exitcode;

  if (R_UNLIKELY (test == NULL))
    return ret;

  lastpos->ts = r_time_get_ts_monotonic ();
  lastpos->file = __FILE__;
  lastpos->line = __LINE__;
  lastpos->func = R_STRFUNC;
  lastpos->assert = FALSE;

  r_test_run_nofork_setup (&ctx, notimeout ? R_CLOCK_TIME_NONE : test->timeout);
  R_LOG_DEBUG ("About to run: /%s/%s/%"RSIZE_FMT, test->suite, test->name, __i);
  if ((jmpres = setjmp (ctx.jb)) == 0) {
    _r_test_mark_position (test->name, __i, test->suite, FALSE);
    if (test->setup != NULL)    test->setup (test->fdata);
    test->func (__i, test->fdata);
    if (test->teardown != NULL) test->teardown (test->fdata);

    if (ctx.failpos != NULL) {
      ret = R_TEST_RUN_STATE_FAILED;
    } else {
      ret = R_TEST_RUN_STATE_SUCCESS;
    }
  } else {
    ret = (RTestRunState)jmpres;
  }

  r_memcpy (lastpos, ctx.lastpos ? ctx.lastpos : ctx.pos, sizeof (RTestLastPos));
  if (ctx.failpos != NULL)
    r_memcpy (failpos, ctx.failpos, sizeof (RTestLastPos));
  else
    r_memset (failpos, 0, sizeof (RTestLastPos));
  r_test_run_nofork_cleanup (&ctx);

  R_LOG_TRACE ("/%s/%s/%"RSIZE_FMT": %u", test->suite, test->name, __i, ret);
  return ret;
}

RTestReport *
r_test_run_tests_full (const RTest * tests, rsize count, RTestRunFlag flags, FILE * f,
    RTestFilterFunc filter, rpointer data)
{
  typedef RTestRunState (*RTestRunFunc) (const RTest *, rsize, rboolean,
      RTestLastPos *, RTestLastPos *, int * pid, int * exitcode);
  RTestRunFunc runner = r_test_run_nofork;
  RTestReport * ret;
  rboolean notimeout;

  if (r_getenv ("RNOFORK") == NULL)
    runner = r_test_run_fork;
  notimeout = (r_getenv ("RNOTIMEOUT") != NULL);

  if (r_proc_is_debugger_attached ()) {
    runner = r_test_run_nofork;
    notimeout = TRUE;
  }

  if (filter != NULL) {
    rsize i, cur = 0;

    ret = r_malloc0 (sizeof (RTestReport) + (sizeof (RTestRun) * count * 2));

    ret->total = count * 2;
    ret->start = r_time_get_ts_monotonic ();
    for (i = 0; i < count; i++) {
      rsize it_start, it_end, it;

      if (tests[i].magic != _RTEST_MAGIC) continue;

      if (tests[i].type & R_TEST_FLAG_LOOP) {
        it_start = tests[i].loop_start;
        it_end = tests[i].loop_end;
      } else {
        it_start = 0;
        it_end = 1;
      }

      if (cur + it_end - it_start > ret->total) {
        ret->total = (cur * 2) + it_end - it_start;
        ret = r_realloc (ret,
            sizeof (RTestReport) + (sizeof (RTestRun) * ret->total));
      }

      for (it = it_start; it < it_end; it++, cur++) {
        ret->runs[cur].__i = it;
        ret->runs[cur].test = &tests[i];

        if (filter (&tests[i], it, data)) {
          ret->run++;
          ret->runs[cur].state = R_TEST_RUN_STATE_RUNNING;
          ret->runs[cur].start = r_time_get_ts_monotonic ();
          ret->runs[cur].lastpos.ts = ret->runs[cur].start;
          ret->runs[cur].lastpos.file = __FILE__;
          ret->runs[cur].lastpos.line = __LINE__;
          ret->runs[cur].lastpos.func = R_STRFUNC;
          ret->runs[cur].lastpos.assert = FALSE;
          ret->runs[cur].pid = r_proc_get_id ();
          ret->runs[cur].exitcode = 0;
          ret->runs[cur].state = runner (ret->runs[cur].test, it, notimeout,
              &ret->runs[cur].lastpos, &ret->runs[cur].failpos,
              &ret->runs[cur].pid, &ret->runs[cur].exitcode);
          ret->runs[cur].end = r_time_get_ts_monotonic ();

          switch (ret->runs[cur].state) {
            case R_TEST_RUN_STATE_SKIP:
              /* This shouldn't happen */
              ret->run--;
              ret->skip++;
              break;
            case R_TEST_RUN_STATE_SUCCESS:
              ret->success++;
              break;
            case R_TEST_RUN_STATE_FAILED:
              ret->fail++;
              break;
            case R_TEST_RUN_STATE_ERROR:
            default:
              ret->error++;
              break;
          }

          if (flags & R_TEST_RUN_FLAG_PRINT) {
            const rchar * runres, * runresclr;

            runres = r_test_get_run_str (ret->runs[cur].state, &runresclr, f);

            if (ret->runs[cur].test->type & R_TEST_FLAG_LOOP) {
              r_print ("%s%-9s%s[%s%"R_TIME_FORMAT"%s] %s/%s/%s/%"RSIZE_FMT"%s [pid: %d, exit: %d]\n",
                  runresclr, runres, _RESET_CLR,
                  _TIME_CLR, R_TIME_ARGS (ret->runs[cur].end - ret->runs[cur].start), _RESET_CLR,
                  runresclr, ret->runs[cur].test->suite, ret->runs[cur].test->name, ret->runs[cur].__i, _RESET_CLR,
                  ret->runs[cur].pid, ret->runs[cur].exitcode);
            } else {
              r_print ("%s%-9s%s[%s%"R_TIME_FORMAT"%s] %s/%s/%s%s [pid: %d, exit: %d]\n",
                  runresclr, runres, _RESET_CLR,
                  _TIME_CLR, R_TIME_ARGS (ret->runs[cur].end - ret->runs[cur].start), _RESET_CLR,
                  runresclr, ret->runs[cur].test->suite, ret->runs[cur].test->name, _RESET_CLR,
                  ret->runs[cur].pid, ret->runs[cur].exitcode);
            }
          }
        } else {
          ret->runs[cur].start = ret->runs[cur].end = r_time_get_ts_monotonic ();
          ret->runs[cur].state = R_TEST_RUN_STATE_SKIP;
          ret->skip++;
        }
      }
    }
    ret->end = r_time_get_ts_monotonic ();
    ret->total = cur;
  } else {
    ret = NULL;
  }

  return ret;
}

typedef struct {
  RTestType type;
  const rchar * filter;
  RTestRunFlag flags;
} RTestFilterCtx;

static rboolean
r_test_filter_default (const RTest * test, rsize __i, rpointer data)
{
  RTestFilterCtx * ctx = data;
  rchar fullname[1024], * wf;
  rboolean ret;

  (void)__i;

  if ((ctx->type & test->type) == 0)
    return FALSE;
  if (test->skip && (ctx->flags & R_TEST_RUN_FLAG_IGNORE_SKIP) == 0)
    return FALSE;
  if (ctx->filter == NULL)
    return TRUE;

  fullname[0] = 0;
  r_test_fill_path (test, fullname, sizeof (fullname));
  wf = r_strprintf ("*%s*", ctx->filter);
  ret = r_str_match_simple_pattern (fullname, -1, wf);
  r_free (wf);

  return ret;
}

RTestReport *
r_test_run_tests (const RTest * tests, rsize count, RTestRunFlag flags, FILE * f,
    RTestType type, const rchar * filter)
{
  RTestFilterCtx ctx = { type, filter, flags };
  return r_test_run_tests_full (tests, count, flags, f, r_test_filter_default, &ctx);
}

void
r_test_report_print (RTestReport * report, RTestReportFlag flags, FILE * f)
{
  rsize i;
  RClockTime elapsed;
  const rchar * runresclr;

  if ((flags & R_TEST_REPORT_FLAG_VERBOSE) == R_TEST_REPORT_FLAG_VERBOSE) {
    r_fprintf (f,
        "================================================================================\n"
        "Test report:\n"
        "================================================================================\n");
  }

  for (i = 0; i < report->total; i++) {
    RTestRun * run = &report->runs[i];
    if (run->state > R_TEST_RUN_STATE_SUCCESS ||
        (flags & R_TEST_REPORT_FLAG_VERBOSE) == R_TEST_REPORT_FLAG_VERBOSE) {
      elapsed = run->end - run->start;
      const rchar * runres;
      rchar * extra, * name;

      runres = r_test_get_run_str (run->state, &runresclr, f);
      if (run->test->type & R_TEST_FLAG_LOOP)
        name = r_strprintf ("/%s/%s/%"RSIZE_FMT,
            run->test->suite, run->test->name, run->__i);
      else
        name = r_strprintf ("/%s/%s",
            run->test->suite, run->test->name);

      if (run->state > R_TEST_RUN_STATE_SUCCESS) {
        RClockTime attime = run->lastpos.ts - run->start;
        extra = r_strprintf ("\n%9s[%s%"R_TIME_FORMAT"%s] @ %s:%u -> %s()",
            "last ", _TIME_ERR_CLR, R_TIME_ARGS (attime), _RESET_CLR,
            run->lastpos.file, run->lastpos.line, run->lastpos.func);
        if (run->failpos.ts != 0 &&
            r_memcmp (&run->lastpos, &run->failpos, sizeof (RTestLastPos)) != 0) {
          rchar * prev = extra;
          attime = run->failpos.ts - run->start;
          extra = r_strprintf ("%s\n%9s[%s%"R_TIME_FORMAT"%s] @ %s:%u -> %s()",
              prev, "fail ", _TIME_ERR_CLR, R_TIME_ARGS (attime), _RESET_CLR,
              run->failpos.file, run->failpos.line, run->failpos.func);
          r_free (prev);
        }
      } else {
        extra = r_strdup ("");
      }

      r_fprintf (f, "%s%-9s%s[%s%"R_TIME_FORMAT"%s] %s%s%s [pid: %d, exit: %d]%s\n",
          runresclr, runres, _RESET_CLR,
          _TIME_CLR, R_TIME_ARGS (elapsed), _RESET_CLR,
          runresclr, name, _RESET_CLR, run->pid, run->exitcode, extra);
      r_free (name);
      r_free (extra);
    }
  }

  elapsed = report->end - report->start;
  r_fprintf (f,
      "%s\n%"RSIZE_FMT" tests (Ran: %"RSIZE_FMT" %sSkip: %"RSIZE_FMT"%s)"
      " [%s%"R_TIME_FORMAT"%s]\n"
      "\t%sSuccess: %"RSIZE_FMT"%s, %sFailures: %"RSIZE_FMT"%s, %sErrors: %"RSIZE_FMT"%s\n",
      "================================================================================",
      report->total, report->run, _SKIP_ARGS (report->skip),
      _TIME_CLR, R_TIME_ARGS (elapsed), _RESET_CLR,
      _SUCC_ARGS (report->success), _FAIL_ARGS (report->fail), _ERR_ARGS (report->error));
}

