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
#include "rlib-internal.h"
#include <rlib/rlog.h>
#include <rlib/ralloc.h>
#include <rlib/rtty.h>
#include <rlib/renv.h>
#include <rlib/rstr.h>
#include <rlib/rthreads.h>
#include <rlib/rtime.h>
#include <stdio.h>
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
static rboolean g__r_log_color = TRUE;
static RLogFunc g__r_log_default_handler = r_log_default_handler;
static rpointer g__r_log_default_handler_data = NULL;
static RClockTime g__r_log_ts_start = R_CLOCK_TIME_NONE;

#if 0
R_LOG_CATEGORY_DEFINE_STATIC (g__r_log_cat_defualt,
    "none", "Default fallback log category", 0);
#endif


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
  rpointer data;

  if ((env = r_getenv ("R_DEBUG_FILE")) != NULL) {
    if (r_str_equals (env, "-"))
      file = stdout;
    else
      file = fopen (env, "w"); /* FIXME: Add file API */
  }

  if (r_getenv ("R_DEBUG_NO_COLOR") != NULL)
    g__r_log_color = FALSE;

  data = file;
  r_log_override_default_handler (r_log_default_handler, &data);

  if ((env = r_getenv ("R_DEBUG")) != NULL)
    r_log_configure (env);

  r_log_category_register (R_LOG_CAT_ASSERT);
  /* Make sure assertions are always going through the log system */
  if (r_log_category_get_threshold (R_LOG_CAT_ASSERT) < R_LOG_LEVEL_ERROR)
    r_log_category_set_threshold (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR);

  g__r_log_ts_start = r_time_get_ts_monotonic ();
}

const rchar *
r_log_level_get_name (RLogLevel lvl)
{
  static const rchar * lvlname[R_LOG_LEVEL_COUNT] = {
    "",
    "ERROR   ",
    "CRITICAL",
    "WARNING ",
    "FIXME   ",
    "INFO    ",
    "DEBUG   ",
    "TRACE   "
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
  (void)cat;
  /* TODO: Add category to list of categories */
  cat->threshold = g__r_log_level_default;
  return TRUE;
}

rboolean
r_log_category_unregister (RLogCategory * cat)
{
  (void)cat;
  /* TODO: Remove category from list of categories */
  return TRUE;
}

RLogCategory *
_r_log_find_category (const rchar * name)
{
  (void)name;
  /* TODO: Implement, dependent on register/unregister */
  return NULL;
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
  if (lvl > cat->threshold)
    return;

  msg = r_strvprintf (fmt, args);
  g__r_log_default_handler (cat, lvl, file, line, func, msg,
      g__r_log_default_handler_data);
  r_free (msg);
}

void
r_log_msg (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func, const rchar * msg)
{
  if (R_UNLIKELY (cat == NULL))
    abort ();
  if (lvl > cat->threshold)
    return;

  g__r_log_default_handler (cat, lvl, file, line, func, msg,
      g__r_log_default_handler_data);
}

void
r_log_mem_dump (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const ruint8 * ptr, rsize size, rsize bytesperline)
{
  rchar * msg = r_alloca (R_STR_MEM_DUMP_SIZE (bytesperline));

  if (R_UNLIKELY (cat == NULL))
    abort ();
  if (lvl > cat->threshold)
    return;

  while (size > bytesperline) {
    r_str_mem_dump (msg, ptr, bytesperline, bytesperline);
    g__r_log_default_handler (cat, lvl, file, line, func, msg,
        g__r_log_default_handler_data);
    size -= bytesperline;
    ptr  += bytesperline;
  }

  if (size > 0) {
    r_str_mem_dump (msg, ptr, size, bytesperline);
    g__r_log_default_handler (cat, lvl, file, line, func, msg,
        g__r_log_default_handler_data);
  }
}

RLogFunc
r_log_override_default_handler (RLogFunc func, rpointer * data)
{
  RLogFunc oldfunc = g__r_log_default_handler;
  g__r_log_default_handler = func;

  if (data) {
    rpointer olddata = g__r_log_default_handler_data;
    g__r_log_default_handler_data = *data;
    *data = olddata;
  }

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
#define LVL_FMT "%s"
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

