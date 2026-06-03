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
#include <rlib/os/rtty.h>
#include <rlib/concurrency/ratomic.h>
#include <rlib/concurrency/rthreads.h>
#include <rlib/rstr.h>

#include <stdlib.h>     /* abort */

/* The print / printerr handlers are process-global (func, data) pairs.
 * Reads (r_print / r_printerr) and writes (the override setters) are
 * kept pair-consistent with a seqlock: a writer bumps an odd
 * "in progress" version around its two stores, a reader re-checks the
 * version and retries if it moved, so a concurrent override can never
 * hand a reader a freshly installed func paired with the previous
 * handler's data. The read path takes no lock and never blocks. */
static raptr  printfunc;        /* RPrintFunc bits, 0 => use the default */
static raptr  printfuncdata;
static raptr  printerrfunc;
static raptr  printerrfuncdata;
static rauint printseq;         /* even: stable, odd: a write is in progress */

/* A print handler that calls back into the same r_print / r_printerr
 * would recurse forever -- a bug in the handler. Trap it with a
 * thread-local flag set only while the handler runs. */
#define R_PRINT_REENTRY_PRINT     0x1u
#define R_PRINT_REENTRY_PRINTERR  0x2u
static RTss   printreentry = R_TSS_INIT (NULL);

/* Seqlock read: load the (func, data) pair as a consistent snapshot. */
static void
r_print_handler_get (raptr * pfunc, raptr * pdata,
    RPrintFunc * func, rpointer * data)
{
  ruint s0, s1;

  do {
    s0 = r_atomic_uint_load (&printseq);
    *func = (RPrintFunc) r_atomic_ptr_load (pfunc);
    *data = r_atomic_ptr_load (pdata);
    s1 = r_atomic_uint_load (&printseq);
  } while (R_UNLIKELY (s0 != s1 || (s0 & 1) != 0));
}

/* Seqlock write: publish a new (func, data) pair, returning the old one.
 * The CAS to claim the odd version also serialises concurrent writers. */
static void
r_print_handler_set (raptr * pfunc, raptr * pdata,
    RPrintFunc func, rpointer data, RPrintFunc * oldfunc, rpointer * olddata)
{
  ruint s;

  do {
    s = r_atomic_uint_load (&printseq);
  } while ((s & 1) != 0 || !r_atomic_uint_cmp_xchg_weak (&printseq, &s, s + 1));

  if (oldfunc != NULL)
    *oldfunc = (RPrintFunc) r_atomic_ptr_load (pfunc);
  if (olddata != NULL)
    *olddata = r_atomic_ptr_load (pdata);

  r_atomic_ptr_store (pfunc, (rpointer) func);
  r_atomic_ptr_store (pdata, data);

  r_atomic_uint_store (&printseq, s + 2);
}

/* Snapshot the handler, trap re-entry, then run the handler outside any
 * lock (it may block on I/O; it must not recurse into the printer). */
static int
r_print_dispatch (raptr * pfunc, raptr * pdata, RPrintFunc deflt,
    ruint rebit, const rchar * str, int ret)
{
  RPrintFunc func;
  rpointer data;
  ruint reentry;

  r_print_handler_get (pfunc, pdata, &func, &data);
  if (func == NULL) {
    func = deflt;
    data = NULL;
  }

  reentry = RPOINTER_TO_UINT (r_tss_get (&printreentry));
  if (R_UNLIKELY ((reentry & rebit) != 0))
    abort ();
  r_tss_set (&printreentry, RUINT_TO_POINTER (reentry | rebit));

  if (R_UNLIKELY (!func (str, (rsize) ret, data)))
    ret = -1;

  r_tss_set (&printreentry, RUINT_TO_POINTER (reentry));
  return ret;
}

void
r_override_print_handler (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata)
{
  r_print_handler_set (&printfunc, &printfuncdata, func, data, oldfunc, olddata);
}

void
r_override_printerr_handler (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata)
{
  r_print_handler_set (&printerrfunc, &printerrfuncdata, func, data, oldfunc, olddata);
}

int
r_print (const rchar * fmt, ...)
{
  va_list args;
  rchar *str = NULL;
  int ret;

  va_start (args, fmt);
  ret = r_vasprintf (&str, fmt, args);
  va_end (args);

  if (R_LIKELY (ret > 0 && str != NULL))
    ret = r_print_dispatch (&printfunc, &printfuncdata, r_print_default,
        R_PRINT_REENTRY_PRINT, str, ret);

  r_free (str);
  return ret;
}

int
r_printerr (const rchar * fmt, ...)
{
  va_list args;
  rchar *str = NULL;
  int ret;

  va_start (args, fmt);
  ret = r_vasprintf (&str, fmt, args);
  va_end (args);

  if (R_LIKELY (ret > 0 && str != NULL))
    ret = r_print_dispatch (&printerrfunc, &printerrfuncdata, r_printerr_default,
        R_PRINT_REENTRY_PRINTERR, str, ret);

  r_free (str);
  return ret;
}

rboolean
r_print_default (const rchar * str, rsize size, rpointer data)
{
  (void)size;
  (void)data;
  fputs (str, stdout);
  return TRUE;
}

rboolean
r_printerr_default (const rchar * str, rsize size, rpointer data)
{
  (void)size;
  (void)data;
  fputs (str, stderr);
  return TRUE;
}

rchar *
r_tty_clr_to_str (RColorFlags clr, rchar str[R_TTY_MAX_CC])
{
  rchar * pos = str;
  *(pos++) = '\x1B';
  *(pos++) = '[';
  *(pos++) = '0';
  *(pos++) = '0';

  if (clr & R_CLR_FMT_BOLD) {
    *(pos++) = ';';
    *(pos++) = '1';
  }

  if (clr & R_CLR_FMT_UNDERLINE) {
    *(pos++) = ';';
    *(pos++) = '4';
  }

  if (clr & R_CLR_FG_MASK) {
    *(pos++) = ';';
    *(pos++) = '3';
    *(pos++) = (clr & R_CLR_FG_MASK) + '0';
  }

  if (clr & R_CLR_BG_MASK) {
    *(pos++) = ';';
    *(pos++) = '4';
    *(pos++) = ((clr & R_CLR_BG_MASK) >> 4) + '0';
  }

  *(pos++) = 'm';
  *pos = 0;
  return str;
}

