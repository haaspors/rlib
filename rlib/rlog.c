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
#include "rlib-private.h"
#include <rlib/rlog.h>
#include <rlib/ralloc.h>
#include <rlib/renv.h>
#include <rlib/rlist.h>
#include <rlib/rstr.h>
#include <rlib/rthreads.h>
#include <rlib/rtime.h>
#include <rlib/rtty.h>
#include <stdio.h>
#include <string.h>
#ifdef R_OS_WIN32
#include <process.h>
#define pid_t int
#else
#include <unistd.h>
#endif


rauint _r_log_level_min = R_LOG_LEVEL_DEFAULT;
R_LOG_CATEGORY_DEFINE (_r_log_cat_assert, "*** assert ***", "Assertions logger",
    R_CLR_FMT_BOLD | R_CLR_BG_RED);

static ruint g__r_log_level_default = R_LOG_LEVEL_DEFAULT;
static rboolean g__r_log_ignore_threshold = FALSE;
static rboolean g__r_log_color = TRUE;
static RLogFunc g__r_log_default_handler = r_log_default_handler;
static rpointer g__r_log_default_handler_data = NULL;
static RClockTime g__r_log_ts_start = R_CLOCK_TIME_NONE;
static RSList * g__r_log_cats = NULL;


static rboolean
r_log_configure (const rchar * cfg)
{
  rulong lvl;
  rchar * end;

  /* FIXME: Parse list with string functions */
  lvl = strtoul (cfg, &end, 10);
  if (end > cfg && *end == 0 && lvl < R_LOG_LEVEL_MAX) {
    r_log_set_default_level (lvl);
    return TRUE;
  }

  return FALSE;
}

void
r_log_init (void)
{
  const rchar * env;
  FILE * file = NULL; /* NULL means stderr */

  if ((env = r_getenv ("R_DEBUG_FILE")) != NULL) {
    if (r_str_equals (env, "-"))
      file = stdout;
    else
      file = fopen (env, "w"); /* FIXME: Add file API */
  }
  r_log_override_default_handler (r_log_default_handler, file, NULL);

  if (r_getenv ("R_DEBUG_NO_COLOR") != NULL)
    g__r_log_color = FALSE;

  if ((env = r_getenv ("R_DEBUG")) != NULL)
    r_log_configure (env);

  r_log_category_register (R_LOG_CAT_ASSERT);
  /* Make sure assertions are always going through the log system */
  r_log_category_set_threshold (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR);

  g__r_log_ts_start = r_time_get_ts_monotonic ();
}

const rchar *
r_log_level_get_name (RLogLevel lvl)
{
  static const rchar * lvlname[R_LOG_LEVEL_COUNT] = {
    "",
    "ERROR",
    "CRITICAL",
    "WARNING",
    "FIXME",
    "INFO",
    "DEBUG",
    "TRACE"
  };

  return lvlname[lvl];
}

static const rchar *
r_log_level_get_term_clr_code (RLogLevel lvl)
{
  static const rchar * lvlcolor[R_LOG_LEVEL_COUNT] = {
                R_TTY_SGR2 (R_TTY_SGR_NORMAL_ARG, R_TTY_SGR_FG_ARG (R_CLR_DEFAULT)),
  /* ERROR   */ R_TTY_SGR2 (R_TTY_SGR_BOLD_ARG,   R_TTY_SGR_FG_ARG (R_CLR_RED)),
  /* CRITICAL*/ R_TTY_SGR2 (R_TTY_SGR_NORMAL_ARG, R_TTY_SGR_FG_ARG (R_CLR_RED)),
  /* WARNING */ R_TTY_SGR2 (R_TTY_SGR_BOLD_ARG,   R_TTY_SGR_FG_ARG (R_CLR_YELLOW)),
  /* FIXME   */ R_TTY_SGR2 (R_TTY_SGR_BOLD_ARG,   R_TTY_SGR_FG_ARG (R_CLR_MAGENTA)),
  /* INFO    */ R_TTY_SGR2 (R_TTY_SGR_BOLD_ARG,   R_TTY_SGR_FG_ARG (R_CLR_GREEN)),
  /* DEBUG   */ R_TTY_SGR2 (R_TTY_SGR_NORMAL_ARG, R_TTY_SGR_FG_ARG (R_CLR_CYAN)),
  /* TRACE   */ R_TTY_SGR2 (R_TTY_SGR_NORMAL_ARG, R_TTY_SGR_FG_ARG (R_CLR_WHITE)),
  };

  return lvlcolor[lvl];
}

static void
r_log_update_level_min (RLogLevel lvl)
{
  ruint old = _r_log_level_min;
  while (old < lvl) {
    if (r_atomic_uint_cmp_xchg_weak (&_r_log_level_min, &old, (ruint)lvl))
      break;
  }
}

void
r_log_set_default_level (RLogLevel lvl)
{
  g__r_log_level_default = lvl;
  r_log_update_level_min (lvl);
}

RLogLevel
r_log_get_default_level (void)
{
  return g__r_log_level_default;
}

rboolean
r_log_category_register (RLogCategory * cat)
{
  if (R_UNLIKELY (r_slist_contains (g__r_log_cats, cat)))
    return FALSE;
  g__r_log_cats = r_slist_prepend (g__r_log_cats, cat);
  cat->threshold = g__r_log_level_default;
  return TRUE;
}

rboolean
r_log_category_unregister (RLogCategory * cat)
{
  if (R_UNLIKELY (!r_slist_contains (g__r_log_cats, cat)))
    return FALSE;

  g__r_log_cats = r_slist_remove (g__r_log_cats, cat);
  return TRUE;
}

RLogCategory *
r_log_category_find (const rchar * name)
{
  RSList * it;

  for (it = g__r_log_cats; it != NULL; it = r_slist_next (it)) {
    RLogCategory * cat = r_slist_data (it);
    if (r_str_equals (cat->name, name))
      return cat;
  }

  return NULL;
}

void
r_log_category_set_threshold (RLogCategory * cat, RLogLevel lvl)
{
  cat->threshold = lvl;
  r_log_update_level_min (lvl);
}

static inline void
r_log_it (RLogCategory * cat, RLogLevel lvl, const rchar * file, ruint line,
    const rchar * func, const rchar * msg)
{
  /* TODO: Should this call handle just one handler or multiple registered? */
  g__r_log_default_handler (cat, lvl, file, line, func, msg,
      g__r_log_default_handler_data);
}

void
r_log (RLogCategory * cat, RLogLevel lvl, const rchar * file, ruint line,
    const rchar * func, const rchar * fmt, ...)
{
  va_list args;

  va_start (args, fmt);
  r_logv (cat, lvl, file, line, func, fmt, args);
  va_end (args);
}

void
r_logv (RLogCategory * cat, RLogLevel lvl, const rchar * file, ruint line,
    const rchar * func, const rchar * fmt, va_list args)
{
  rchar * msg;

  if (R_UNLIKELY (cat == NULL))
    abort ();
  if (lvl > cat->threshold && !g__r_log_ignore_threshold)
    return;

  msg = r_strvprintf (fmt, args);
  r_log_it (cat, lvl, file, line, func, msg);
  r_free (msg);
}

void
r_log_msg (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func, const rchar * msg)
{
  if (R_UNLIKELY (cat == NULL))
    abort ();
  if (lvl > cat->threshold && !g__r_log_ignore_threshold)
    return;

  r_log_it (cat, lvl, file, line, func, msg);
}

void
r_log_mem_dump (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const ruint8 * ptr, rsize size, rsize bytesperline)
{
  rchar * msg = r_alloca (R_STR_MEM_DUMP_SIZE (bytesperline));

  if (R_UNLIKELY (cat == NULL))
    abort ();
  if (lvl > cat->threshold && !g__r_log_ignore_threshold)
    return;

  while (size > bytesperline) {
    r_str_mem_dump (msg, ptr, bytesperline, bytesperline);
    r_log_it (cat, lvl, file, line, func, msg);
    size -= bytesperline;
    ptr  += bytesperline;
  }

  if (size > 0) {
    r_str_mem_dump (msg, ptr, size, bytesperline);
    r_log_it (cat, lvl, file, line, func, msg);
  }
}

RLogFunc
r_log_override_default_handler (RLogFunc func, rpointer data, rpointer * old)
{
  /* FIXME: Should this be done thread safe? */
  RLogFunc oldfunc = g__r_log_default_handler;
  rpointer olddata = g__r_log_default_handler_data;

  g__r_log_default_handler = func;
  g__r_log_default_handler_data = data;

  if (old != NULL)
    *old = olddata;

  return oldfunc;
}

void
r_log_default_handler (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg, rpointer user_data)
{
  FILE * f = user_data == NULL ? stderr : (FILE *)user_data;
  pid_t pid = getpid ();
  RClockTime elapsed = r_time_get_ts_monotonic () - g__r_log_ts_start;

#define CLK_FMT "%"R_TIME_FORMAT
#define PID_FMT "%5d"
#if RLIB_SIZEOF_VOID_P == 8
#define THR_FMT "%14p"
#else
#define THR_FMT "%10p"
#endif
#define LVL_FMT "%-8s"
#define CAT_FMT "%16s %s:%d:%s ()"
#define MSG_FMT "%s"

#ifdef R_OS_UNIX
  if (g__r_log_color && r_isatty(r_fileno(f))) {
    rchar clr[R_TTY_MAX_CC];
    r_tty_clr_to_str (cat->clr, clr);

    r_fprintf (f,
        CLK_FMT" "PID_FMT" "THR_FMT" %s"LVL_FMT" %s"CAT_FMT R_TTY_SGR_RESET" "MSG_FMT"\n",
        R_TIME_ARGS (elapsed), pid, r_thread_current (),
        r_log_level_get_term_clr_code (lvl), r_log_level_get_name (lvl),
        clr, cat->name, file, line, func,
        msg);
  } else
#else
  (void)r_log_level_get_term_clr_code;
#endif
  {
    r_fprintf (f, CLK_FMT" "PID_FMT" "THR_FMT" "LVL_FMT" "CAT_FMT" "MSG_FMT"\n",
        R_TIME_ARGS (elapsed), pid, r_thread_current (),
        r_log_level_get_name (lvl),
        cat->name, file, line, func, msg);
  }
  fflush (f);
}

static void
r_log_keep_last_handler (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg, rpointer user_data)
{
  RLogKeepLastCtx * ctx = user_data;

  ctx->last.cat = cat;
  ctx->last.lvl = lvl;
  ctx->last.line = line;
  ctx->last.file = file;
  ctx->last.func = func;
  r_free (ctx->last.msg);
  ctx->last.msg = r_strdup (msg);

  if (lvl > cat->threshold)
    return;

  if (ctx->oldfunc != NULL && cat != ctx->cat)
    ctx->oldfunc (cat, lvl, file, line, func, msg, ctx->olddata);
}

void
r_log_keep_last_begin_full (RLogKeepLastCtx * ctx, RLogCategory * cat,
    rboolean ignore_threshold)
{
  r_log_update_level_min (R_LOG_LEVEL_MAX);
  g__r_log_ignore_threshold = ignore_threshold;

  memset (ctx, 0, sizeof (RLogKeepLastCtx));
  ctx->oldfunc = r_log_override_default_handler (r_log_keep_last_handler,
      ctx, &ctx->olddata);
  ctx->cat = cat;
}

void
r_log_keep_last_end (RLogKeepLastCtx * ctx, rboolean reset)
{
  g__r_log_ignore_threshold = FALSE;
  r_log_override_default_handler (ctx->oldfunc, ctx->olddata, NULL);

  if (reset)
    r_log_keep_last_reset (ctx);
}

void
r_log_keep_last_reset (RLogKeepLastCtx * ctx)
{
  r_free (ctx->last.msg);
}

