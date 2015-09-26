/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include "rlib-internal.h"
#include <rlib/rtest.h>
#include <rlib/ratomic.h>
#include <rlib/rassert.h>
#include <rlib/renv.h>
#include <rlib/rlog.h>
#include <rlib/rmodule.h>
#include <rlib/rproc.h>
#include <rlib/rsignal.h>
#include <rlib/rstr.h>
#include <rlib/rthreads.h>
#include <rlib/rtime.h>
#include <rlib/rtty.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <string.h>
#ifndef R_OS_WIN32
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#endif


/* FIXME: move forking/process stuff to rproc */
/* FIXME: move pipe stuff to rproc or rpipe? */
/* TODO: Gather test log, 1. r_log 2. r_print[err] 3. stdout/stderr? */

#define R_TEST_THREADS              10240

static RTss                         g__r_test_last_pos_tss = R_TSS_INIT (NULL);

#ifdef R_OS_WIN32
static const int g__r_test_sigs[] = {
  SIGABRT, SIGFPE, SIGSEGV, SIGILL
};
#else
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

#ifdef R_OS_WIN32
  RTestLastPos * lastpos;
  RTestLastPos * failpos;
#else
  pid_t pid;
#endif
} RTestRunForkCtx;
static RTestRunForkCtx *    g__r_test_fork_ctx = NULL;

typedef struct {
  RThread * thread;
  RSigAlrmTimer * timer;

  jmp_buf jb;

  /* <private> */
#ifdef R_OS_WIN32
  LPTOP_LEVEL_EXCEPTION_FILTER ouef;
  void (*osigabrt) (int);
#else
  stack_t ss;
  stack_t oss;
  struct sigaction sa, osa[R_N_ELEMENTS (g__r_test_sigs)];
#endif

  rsize maxposcount;
  RTestLastPos * pos;
  rauint poscount;

  RTestLastPos * lastpos;
  RTestLastPos * failpos;
} RTestRunNoForkCtx;
static RTestRunNoForkCtx *  g__r_test_nofork_ctx = NULL;
static void r_test_run_nofork_cleanup (RTestRunNoForkCtx * ctx);


R_LOG_CATEGORY_DEFINE_STATIC (rtest_logcat, "*** rtest  ***", "Test logger",
    R_CLR_BG_MAGENTA | R_CLR_FMT_BOLD);
#define R_LOG_CAT_DEFAULT &rtest_logcat

void
r_test_init (void)
{
  r_log_category_register (&rtest_logcat);
  if (r_log_category_get_threshold (R_LOG_CAT_DEFAULT) < R_LOG_LEVEL_ERROR)
    r_log_category_set_threshold (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR);
}

rboolean
_r_test_mark_position (const rchar * file, ruint line, const rchar * func,
    rboolean assrt)
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
  lastpos->assrt = assrt;

  if (assrt)
    g__r_test_nofork_ctx->failpos = lastpos;

  return TRUE;
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
  r_test_assertion_msg (cat, file, line, func, msg);
  r_free (msg);
}

void
r_test_assertion_msg (RLogCategory * cat,
    const rchar * file, ruint line, const rchar * func, const rchar * msg)
{
  _r_test_mark_position (file, line, func, TRUE);
  r_log_msg (cat, R_LOG_LEVEL_ERROR, file, line, func, msg);
  if (g__r_test_nofork_ctx != NULL && g__r_test_nofork_ctx->thread == r_thread_current ())
    longjmp (g__r_test_nofork_ctx->jb, R_TEST_RUN_STATE_FAILED);
  else
    abort ();
}

rsize
r_test_get_local_test_count (rsize * runs)
{
  rsize ret = 0;
  r_test_get_local_tests (&ret, runs);
  return ret;
}

static const RTest *
r_test_find_magic_sym (RMODULE mod)
{
  const RTest ** sym;
  int i;
  rchar name[] = R_STRINGIFY (_RTEST_SYM_)"\0\0\0";

  if (mod == NULL)
    return NULL;

  for (i = 0; i < 10; i++) {
    name[sizeof (R_STRINGIFY (_RTEST_SYM_))-1] = '0' + i;
    R_LOG_TRACE ("resolving %s", name);
    if ((sym = r_module_lookup (mod, name)) != NULL)
      return *sym;
  }

  return NULL;
}

const RTest *
r_test_get_local_tests (rsize * tests, rsize * runs)
{
  const RTest * begin, * end, * sym, * cur;
  rsize total;
  RMODULE mod;
  if (!r_module_open (&mod, NULL))
    return NULL;

  sym = r_test_find_magic_sym (mod);
  r_module_close (mod);

  if (sym == NULL) {
    R_LOG_CRITICAL ("%s not found", R_STRINGIFY (_RTEST_SYM_));
    return NULL;
  } else if (sym->magic != _RTEST_MAGIC) {
    R_LOG_CRITICAL ("%s found, but magic (0x%x) was not 0x%x",
        R_STRINGIFY (_RTEST_SYM_), sym->magic, _RTEST_MAGIC);
    return NULL;
  }

  begin = end = sym;

  for (cur = begin - 1; cur->magic == _RTEST_MAGIC; cur--)
    begin = cur;
  for (cur = end + 1; cur->magic == _RTEST_MAGIC; cur++)
    end = cur;

  R_LOG_TRACE ("Found RTESTs: first %p, last %p (size: %"RSIZE_FMT")",
      begin, end, sizeof (RTest));
  for (cur = begin, total = 0; cur <= end; cur++) {
    if (cur->type & R_TEST_FLAG_LOOP)
      total += (cur->loop_end - cur->loop_start);
    else
      total++;
  }

  if (tests != NULL)
    *tests = (end - begin) + 1;
  if (runs)
    *runs = total;

  return begin;
}

#ifdef R_OS_WIN32
typedef struct {
  const RTest * test;
  rsize __i;
  RClockTime timeout;
  RTestLastPos * lastpos, * failpos;
} RTestWin32Run;

static rpointer
r_test_run_pseudo_fork (rpointer data)
{
  const RTestWin32Run * win32run = data;
  RTestRunState ret;

  ret = r_test_run_nofork (win32run->test, win32run->__i, win32run->timeout,
      win32run->lastpos, win32run->failpos);

  return RINT_TO_POINTER (ret);
}

RTestRunState
r_test_run_fork (const RTest * test, rsize __i, RClockTime timeout,
    RTestLastPos * lastpos, RTestLastPos * failpos)
{
  RTestWin32Run win32run = { test, __i, timeout, lastpos, failpos };
  RTestRunForkCtx ctx = { R_TEST_RUN_STATE_NONE, NULL, NULL, NULL, NULL };
  rpointer res;

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
      memcpy (lastpos, ctx.lastpos, sizeof (RTestLastPos));
    if (ctx.failpos != NULL) {
      memcpy (failpos, ctx.failpos, sizeof (RTestLastPos));
      ctx.state = R_TEST_RUN_STATE_FAILED; /* Assert on some thread, set failed */
    }

    return ctx.state;
  }

  return (RTestRunState)RPOINTER_TO_INT (res);
}
#else
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
r_test_run_fork (const RTest * test, rsize __i, RClockTime timeout,
    RTestLastPos * lastpos, RTestLastPos * failpos)
{
  RTestRunState ret = R_TEST_RUN_STATE_ERROR;
  pid_t pid, wpid;
  int fdp[2];

  if (R_UNLIKELY (test == NULL))
    return ret;

  if (R_UNLIKELY (pipe (fdp) != 0))
    return ret;

  if ((pid = fork ()) > 0) {
    RTestRunForkCtx ctx;
    int status;

    close(fdp[1]);
    r_test_run_fork_setup (&ctx, pid, timeout);
    wpid = waitpid (pid, &status, 0);
    r_test_run_fork_cleanup (&ctx);

    if (ctx.state != R_TEST_RUN_STATE_NONE)
      ret = ctx.state;

    lastpos->ts = r_time_get_ts_monotonic ();
    lastpos->line = 0;
    lastpos->file = lastpos->func = NULL;
    lastpos->assrt = FALSE;

    if (wpid == pid) {
      if (WIFEXITED (status)) {
        ret = (RTestRunState)WEXITSTATUS (status);

        if (read (fdp[0], lastpos, sizeof (RTestLastPos)) != sizeof (RTestLastPos))
          R_LOG_WARNING ("Failed to read from pipe to forked child");
        if (read (fdp[0], failpos, sizeof (RTestLastPos)) != sizeof (RTestLastPos))
          R_LOG_WARNING ("Failed to read from pipe to forked child");
      }
    }
  } else if (pid == 0) {
    RTestRunState res;
    close(fdp[0]);
    res = r_test_run_nofork (test, __i, timeout, lastpos, failpos);

    if (write (fdp[1], lastpos, sizeof (RTestLastPos)) != sizeof (RTestLastPos))
      R_LOG_WARNING ("Failed to write to pipe to parent (forker)");
    if (write (fdp[1], failpos, sizeof (RTestLastPos)) != sizeof (RTestLastPos))
      R_LOG_WARNING ("Failed to write to pipe to parent (forker)");
    close (fdp[1]);
    exit ((int)res);
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
#ifndef R_OS_WIN32
  if (R_UNLIKELY (sig != SIGALRM))
    return;
#endif
  if (R_UNLIKELY (g__r_test_nofork_ctx == NULL))
    return;

  r_log (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_WARNING, "???", 0, "???", "test timeout");
  if (g__r_test_nofork_ctx->thread == r_thread_current ()) {
    longjmp (g__r_test_nofork_ctx->jb, R_TEST_RUN_STATE_TIMEOUT);
  } else {
    /* SIGALRM could be raised in any thread, so marshal it over! */
    R_LOG_WARNING ("SIGALRM - Kill test thread %p", g__r_test_nofork_ctx->thread);
#ifdef R_OS_WIN32
    _r_test_nofork_win32_kill_test_thread (R_TEST_RUN_STATE_TIMEOUT);
#else
    r_thread_kill (g__r_test_nofork_ctx->thread, sig);
#endif
  }
}

#ifdef R_OS_WIN32
static void
_r_test_win32_err_handler (int sig)
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

  _r_test_win32_err_handler (SIGSEGV);

  return EXCEPTION_CONTINUE_SEARCH;
}
#else
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
    r_thread_exit (RINT_TO_POINTER (si->si_status));
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

    r_log (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR, errfile, errline, errfunc,
        "%s (%d)", sys_siglist[sig], sig);
    longjmp (g__r_test_nofork_ctx->jb, val);
  }
}
#endif

static void
r_test_run_nofork_setup (RTestRunNoForkCtx * ctx, RClockTime timeout)
{
#ifndef R_OS_WIN32
  static ruint8 _r_test_sigstack[SIGSTKSZ];
#endif
  static RTestLastPos _r_test_lastpos[R_TEST_THREADS];
  rsize i;

  if (g__r_test_nofork_ctx != NULL) abort (); /* Can't use r_assert* here */

  ctx->thread = r_thread_ref (r_thread_current ());

#ifdef R_OS_WIN32
  ctx->ouef = SetUnhandledExceptionFilter (_r_test_win32_exception_filter);
  _set_abort_behavior (0, _CALL_REPORTFAULT | _WRITE_ABORT_MSG);
  ctx->osigabrt = signal (SIGABRT, _r_test_win32_err_handler);
#else
  ctx->ss.ss_size = sizeof (_r_test_sigstack);
  ctx->ss.ss_sp = _r_test_sigstack;
  ctx->ss.ss_flags = 0;
  sigaltstack (&ctx->ss, &ctx->oss);

  ctx->sa.sa_sigaction = _r_test_nofork_signalhandler;
  sigemptyset (&ctx->sa.sa_mask);
  ctx->sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

  for (i = 0; i < R_N_ELEMENTS (g__r_test_sigs); i++)
    sigaction (g__r_test_sigs[i], &ctx->sa, &ctx->osa[i]);
#endif

  ctx->timer = r_sig_alrm_timer_new_oneshot (timeout,
      _r_test_nofork_timeout_handler);

  memset (_r_test_lastpos, 0, sizeof (_r_test_lastpos));
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
  rsize i;

  if (R_UNLIKELY (ctx == NULL))
    return;
  if (ctx != g__r_test_nofork_ctx)
    return;
  g__r_test_nofork_ctx = NULL;

  if (ctx->timer != NULL)
    r_sig_alrm_timer_cancel (ctx->timer);

#ifdef R_OS_WIN32
  signal (SIGABRT, ctx->osigabrt);
  SetUnhandledExceptionFilter (ctx->ouef);
#else
  for (i = R_N_ELEMENTS (g__r_test_sigs); i > 0; i--)
    sigaction (g__r_test_sigs[i-1], &ctx->osa[i-1], NULL);

  sigaltstack (&ctx->oss, NULL);
#endif

  r_thread_unref (ctx->thread);
  ctx->thread = NULL;
}

RTestRunState
r_test_run_nofork (const RTest * test, rsize __i, RClockTime timeout,
    RTestLastPos * lastpos, RTestLastPos * failpos)
{
  RTestRunState ret = R_TEST_RUN_STATE_ERROR;
  RTestRunNoForkCtx ctx;
  int jmpres;

  if (R_UNLIKELY (test == NULL))
    return ret;

  r_test_run_nofork_setup (&ctx, timeout);
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

  memcpy (lastpos, ctx.lastpos ? ctx.lastpos : ctx.pos, sizeof (RTestLastPos));
  if (ctx.failpos != NULL)
    memcpy (failpos, ctx.failpos, sizeof (RTestLastPos));
  else
    memset (failpos, 0, sizeof (RTestLastPos));
  r_test_run_nofork_cleanup (&ctx);

  R_LOG_TRACE ("/%s/%s/%"RSIZE_FMT": %u", test->suite, test->name, __i, ret);
  return ret;
}

RTestReport *
r_test_run_local_tests_full (RTestFilterFunc filter, rpointer data)
{
  typedef RTestRunState (*RTestRunFunc) (const RTest *, rsize, RClockTime,
      RTestLastPos *, RTestLastPos *);
  RTestRunFunc runner = r_test_run_nofork;
  rsize defs, total, i;
  const RTest * begin;
  RTestReport * ret;
  RClockTime timeout;

  if (r_getenv ("RNOFORK") == NULL)
    runner = r_test_run_fork;

  if (r_proc_is_debugger_attached ())
    runner = r_test_run_nofork;

  if (filter != NULL && (begin = r_test_get_local_tests (&defs, &total)) != NULL) {
    ret = r_malloc0 (sizeof (RTestReport) + (sizeof (RTestRun) * total));
    RTestRun * run = ret->runs;

    ret->total = total;
    ret->start = r_time_get_ts_monotonic ();
    for (i = 0; i < defs; i++) {
      const RTest * test = &begin[i];
      rsize it_start, it_end, it;

      if (test->type & R_TEST_FLAG_LOOP) {
        it_start = test->loop_start;
        it_end = test->loop_end;
      } else {
        it_start = 0;
        it_end = 1;
      }

      for (it = it_start; it < it_end; it++, run++) {
        run->__i = it;
        run->test = test;
        timeout = test->timeout;

        if (filter (test, it, data)) {
          ret->run++;
          run->state = R_TEST_RUN_STATE_RUNNING;
          run->start = r_time_get_ts_monotonic ();
          run->state = runner (test, it, timeout, &run->lastpos, &run->failpos);
          run->end = r_time_get_ts_monotonic ();

          switch (run->state) {
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
        } else {
          run->start = run->end = r_time_get_ts_monotonic ();
          run->state = R_TEST_RUN_STATE_SKIP;
          ret->skip++;
        }
      }
    }
    ret->end = r_time_get_ts_monotonic ();
  } else {
    ret = NULL;
  }

  return ret;
}

typedef struct {
  RTestType type;
  rboolean ignore_skip;
} RTestFilterCtx;

static rboolean
r_test_filter_default (const RTest * test, rsize __i, rpointer data)
{
  RTestFilterCtx * ctx = data;
  rboolean noskip = !test->skip || ctx->ignore_skip;
  rboolean type = (ctx->type & test->type) != 0;

  (void)__i;

  return type && noskip;
}

RTestReport *
r_test_run_local_tests (RTestType type, rboolean ignore_skip)
{
  RTestFilterCtx ctx = { type, ignore_skip };

  return r_test_run_local_tests_full (r_test_filter_default, &ctx);
}

void
r_test_report_print (RTestReport * report, rboolean verbose, FILE * f)
{
  rsize i;
  RClockTime elapsed;
  const rchar * runresclr;

#ifndef R_OS_WIN32
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

  for (i = 0; i < report->total; i++) {
    RTestRun * run = &report->runs[i];
    if (run->state > R_TEST_RUN_STATE_SUCCESS || verbose) {
      elapsed = run->end - run->start;
      const rchar * runres;
      rchar * extra, * name;

      switch (run->state) {
        case R_TEST_RUN_STATE_SUCCESS:
          runres = "SUCCESS:";
          runresclr = _RES_CLR (R_CLR_GREEN);
          break;
        case R_TEST_RUN_STATE_FAILED:
          runres = "FAIL:";
          runresclr = _RES_CLR (R_CLR_RED);
          break;
        case R_TEST_RUN_STATE_ERROR:
          runres = "ERROR:";
          runresclr = _RES_CLR (R_CLR_MAGENTA);
          break;
        case R_TEST_RUN_STATE_SKIP:
          runres = "SKIP:";
          runresclr = _RES_CLR (R_CLR_BLUE);
          break;
        case R_TEST_RUN_STATE_TIMEOUT:
          runres = "TIMEOUT:";
          runresclr = _RES_CLR (R_CLR_MAGENTA);
          break;
        default:
          runres = "INTERR:";
          runresclr = _RES_CLR (R_CLR_CYAN);
          break;
      };

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
            memcmp (&run->lastpos, &run->failpos, sizeof (RTestLastPos)) != 0) {
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

      r_fprintf (f, "%s%-9s%s[%s%"R_TIME_FORMAT"%s] %s%s%s%s\n",
          runresclr, runres, _RESET_CLR,
          _TIME_CLR, R_TIME_ARGS (elapsed), _RESET_CLR,
          runresclr, name, _RESET_CLR, extra);
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

