/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_TTY_H__
#define __R_TTY_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rclr.h>
#include <stdarg.h>
#include <stdio.h>
#ifdef R_OS_WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

R_BEGIN_DECLS

#define R_TTY_MAX_CC              32
#define R_TTY_CSI                 "\x1B["
#define R_TTY_SGR1(param)         R_TTY_CSI param "m"
#define R_TTY_SGR_RESET           R_TTY_SGR1 (R_TTY_SGR_CLS_ARG)
#define R_TTY_SGR(P1)             R_TTY_SGR1 (P1)
#define R_TTY_SGR2(P1,P2)         R_TTY_SGR1 (P1";"P2)
#define R_TTY_SGR3(P1,P2,P3)      R_TTY_SGR1 (P1";"P2";"P3)
#define R_TTY_SGR4(P1,P2,P3,P4)   R_TTY_SGR1 (P1";"P2";"P3";"P4)

#define R_TTY_SGR_CLS_ARG         "0"
#define R_TTY_SGR_BOLD_ARG        "1"
#define R_TTY_SGR_NOBOLD_ARG      "21"
#define R_TTY_SGR_FAINT_ARG       "2"
#define R_TTY_SGR_NORMAL_ARG      "22"
#define R_TTY_SGR_ITALIC_ARG      "3"
#define R_TTY_SGR_NOITALIC_ARG    "23"
#define R_TTY_SGR_UNDERLINE_ARG   "4"
#define R_TTY_SGR_NOUNDERLINE_ARG "24"
#define R_TTY_SGR_BLINK_ARG       "5"
#define R_TTY_SGR_NOBLINK_ARG     "25"
#define R_TTY_SGR_INVERSE_ARG     "7"
#define R_TTY_SGR_NOINVERSE_ARG   "27"
#define R_TTY_SGR_CONSEAL_ARG     "8"
#define R_TTY_SGR_REVEAL_ARG      "28"
#define R_TTY_SGR_FG_ARG(CLR)     "3"R_STRINGIFY (CLR) /* 30-39 */
#define R_TTY_SGR_BG_ARG(CLR)     "4"R_STRINGIFY (CLR) /* 40-49 */

rchar * r_tty_clr_to_str (RColorFlags clr, rchar str[R_TTY_MAX_CC]);

#ifdef R_OS_WIN32
#define r_isatty      _isatty
#define r_fileno      _fileno
#else
#define r_isatty      isatty
#define r_fileno      fileno
#endif

#define r_printf      printf
#define r_vprintf     vprintf
#define r_fprintf     fprintf
#define r_vfprintf    vfprintf
#define r_sprintf     sprintf
#define r_vsprintf    vsprintf
#define r_snprintf    snprintf
#define r_vsnprintf   vsnprintf

R_API int r_print (const rchar * fmt, ...) R_ATTR_PRINTF (1, 2);
R_API int r_printerr (const rchar * fmt, ...) R_ATTR_PRINTF (1, 2);
typedef rboolean (*RPrintFunc) (const rchar * str, rsize size, rpointer data);
R_API void r_override_print_handler    (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata);
R_API void r_override_printerr_handler (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata);

R_API rboolean r_print_default (const rchar * str, rsize size, rpointer data);
R_API rboolean r_printerr_default (const rchar * str, rsize size, rpointer data);

R_END_DECLS

#endif /* __R_TTY_H__ */

