/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/rlib.h>

static RPrintFunc printfunc         = NULL;
static rpointer   printfuncdata     = NULL;
static RPrintFunc printerrfunc      = NULL;
static rpointer   printerrfuncdata  = NULL;

void
r_override_print_handler (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata)
{
  if (oldfunc != NULL)
    *oldfunc = printfunc;
  if (olddata != NULL)
    *olddata = printfuncdata;

  printfunc = func;
  printfuncdata = data;
}

void
r_override_printerr_handler (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata)
{
  if (oldfunc != NULL)
    *oldfunc = printerrfunc;
  if (olddata != NULL)
    *olddata = printerrfuncdata;

  printerrfunc = func;
  printerrfuncdata = data;
}

/* TODO: This should be implemented as a c-str function at some point! */
static int
_r_vasprintf (rchar ** str, const rchar * fmt, va_list ap)
{
  int ret;
#if defined(HAVE_VASPRINTF)
  ret = vasprintf (str, fmt, ap);
#elif defined(HAVE_VSPRINTF)
  valist ap_copy;
  va_copy (ap_copy, ap);
#ifdef HAVE__VSCPRINTF
  ret = _vscprintf (fmt, ap_copy);
#else
  ret = vsprintf (NULL, fmt, ap_copy);
#endif
  va_end (ap_copy);
  if (R_LIKELY (ret >= 0)) {
    *str = malloc (ret + 1);
    if (R_LIKELY (*str != NULL)) {
      ret = vsprintf (*str, fmt, ap);
      if (R_UNLIKELY (ret < 0)) {
        free (*str);
        *str = NULL;
      }
    }
  }
#else
#error r_str_vprintf not implemented
#endif
  return ret;
}

int
r_print (const rchar * fmt, ...)
{
  va_list args;
  rchar *str = NULL;
  int ret;

  /* TODO: Prevent re-etnry? use TLS */

  va_start (args, fmt);
  ret = _r_vasprintf (&str, fmt, args);
  va_end (args);

  if (R_LIKELY (ret > 0 && str != NULL)) {
    RPrintFunc func;
    rpointer data;

    if (R_LIKELY (printfunc == NULL)) {
      func = r_print_default;
      data = NULL;
    } else {
      func = printfunc;
      data = printfuncdata;
    }

    if (R_UNLIKELY (!func (str, (rsize)ret, data)))
      ret = -1;
  }

  return ret;
}

int
r_printerr (const rchar * fmt, ...)
{
  va_list args;
  rchar *str = NULL;
  int ret;

  /* TODO: Prevent re-etnry? use TLS */

  va_start (args, fmt);
  ret = _r_vasprintf (&str, fmt, args);
  va_end (args);

  if (R_LIKELY (ret > 0 && str != NULL)) {
    RPrintFunc func;
    rpointer data;

    if (R_LIKELY (printerrfunc == NULL)) {
      func = r_printerr_default;
      data = NULL;
    } else {
      func = printerrfunc;
      data = printerrfuncdata;
    }

    if (R_UNLIKELY (!func (str, (rsize)ret, data)))
      ret = -1;
  }

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

