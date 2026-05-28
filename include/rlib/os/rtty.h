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
#ifndef __R_TTY_H__
#define __R_TTY_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/os/rtty.h
 * @brief TTY-aware printing: ANSI SGR escape sequences, isatty
 * detection and overridable stdout / stderr sinks.
 */

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

/**
 * @defgroup r_tty Terminal output and ANSI escapes
 * @ingroup r_os
 *
 * @brief Helpers for writing to stdout / stderr with optional ANSI
 * styling.
 *
 * Two layers:
 *   - Macros that build SGR ("Select Graphic Rendition") escape
 *     sequences at compile time (@ref R_TTY_SGR / @ref R_TTY_SGR_RESET
 *     and the @c R_TTY_SGR_*_ARG token constants).
 *   - Function wrappers around the C-library print/printerr that flow
 *     through swappable sinks (@ref r_override_print_handler) so the
 *     application can capture or redirect output.
 *
 * The colour-flag conversion helper @ref r_tty_clr_to_str renders a
 * @c RColorFlags bitmask into a complete CSI escape ready to write.
 *
 * @{
 */

/** @brief Maximum length of a colour-control escape produced by @ref r_tty_clr_to_str. */
#define R_TTY_MAX_CC              32
/** @brief ANSI Control Sequence Introducer: @c "ESC[". */
#define R_TTY_CSI                 "\x1B["
/** @brief Build a 1-parameter SGR escape. */
#define R_TTY_SGR1(param)         R_TTY_CSI param "m"
/** @brief Reset all SGR attributes. */
#define R_TTY_SGR_RESET           R_TTY_SGR1 (R_TTY_SGR_CLS_ARG)
/** @brief Alias for @ref R_TTY_SGR1. */
#define R_TTY_SGR(P1)             R_TTY_SGR1 (P1)
/** @brief 2-parameter SGR escape. */
#define R_TTY_SGR2(P1,P2)         R_TTY_SGR1 (P1";"P2)
/** @brief 3-parameter SGR escape. */
#define R_TTY_SGR3(P1,P2,P3)      R_TTY_SGR1 (P1";"P2";"P3)
/** @brief 4-parameter SGR escape. */
#define R_TTY_SGR4(P1,P2,P3,P4)   R_TTY_SGR1 (P1";"P2";"P3";"P4)

/** @name SGR parameter tokens
 *  String literals that name the standard SGR codes; combine into
 *  escape sequences with @ref R_TTY_SGR* macros.
 *  @{ */
#define R_TTY_SGR_CLS_ARG         "0"   /**< Reset / clear all attributes. */
#define R_TTY_SGR_BOLD_ARG        "1"   /**< Bold. */
#define R_TTY_SGR_NOBOLD_ARG      "21"  /**< Cancel @c BOLD. */
#define R_TTY_SGR_FAINT_ARG       "2"   /**< Faint. */
#define R_TTY_SGR_NORMAL_ARG      "22"  /**< Normal intensity (cancel @c FAINT/@c BOLD). */
#define R_TTY_SGR_ITALIC_ARG      "3"   /**< Italic. */
#define R_TTY_SGR_NOITALIC_ARG    "23"  /**< Cancel @c ITALIC. */
#define R_TTY_SGR_UNDERLINE_ARG   "4"   /**< Underline. */
#define R_TTY_SGR_NOUNDERLINE_ARG "24"  /**< Cancel @c UNDERLINE. */
#define R_TTY_SGR_BLINK_ARG       "5"   /**< Blink. */
#define R_TTY_SGR_NOBLINK_ARG     "25"  /**< Cancel @c BLINK. */
#define R_TTY_SGR_INVERSE_ARG     "7"   /**< Swap foreground / background. */
#define R_TTY_SGR_NOINVERSE_ARG   "27"  /**< Cancel @c INVERSE. */
#define R_TTY_SGR_CONSEAL_ARG     "8"   /**< Conceal. */
#define R_TTY_SGR_REVEAL_ARG      "28"  /**< Cancel @c CONSEAL. */
/** @brief Build a foreground colour token (30-39). */
#define R_TTY_SGR_FG_ARG(CLR)     "3"R_STRINGIFY (CLR)
/** @brief Build a background colour token (40-49). */
#define R_TTY_SGR_BG_ARG(CLR)     "4"R_STRINGIFY (CLR)
/** @} */

/**
 * @brief Render a colour-flag bitmask into a CSI escape sequence.
 * @param clr Colour and attribute bits to render.
 * @param str Caller-provided buffer of at least @ref R_TTY_MAX_CC bytes.
 * @return @p str, populated with a null-terminated escape sequence.
 */
rchar * r_tty_clr_to_str (RColorFlags clr, rchar str[R_TTY_MAX_CC]);

#ifdef R_OS_WIN32
/** @brief Portable wrapper around C-library @c isatty. */
#define r_isatty      _isatty
/** @brief Portable wrapper around C-library @c fileno. */
#define r_fileno      _fileno
#else
#define r_isatty      isatty
#define r_fileno      fileno
#endif

/** @brief Alias for C-library @c printf. */
#define r_printf      printf
/** @brief Alias for C-library @c vprintf. */
#define r_vprintf     vprintf
/** @brief Alias for C-library @c fprintf. */
#define r_fprintf     fprintf
/** @brief Alias for C-library @c vfprintf. */
#define r_vfprintf    vfprintf

/**
 * @brief Print to stdout via the currently-installed print handler.
 * @return Number of bytes written, or @c -1 on error.
 */
R_API int r_print (const rchar * fmt, ...) R_ATTR_PRINTF (1, 2);
/**
 * @brief Print to stderr via the currently-installed printerr handler.
 * @return Number of bytes written, or @c -1 on error.
 */
R_API int r_printerr (const rchar * fmt, ...) R_ATTR_PRINTF (1, 2);
/**
 * @brief Print-sink signature: receive a chunk of text and decide how
 * to handle it (write to stdio, append to a buffer, ...).
 * @return @c TRUE on success, @c FALSE to signal an error to the caller.
 */
typedef rboolean (*RPrintFunc) (const rchar * str, rsize size, rpointer data);
/**
 * @brief Install a new sink for @ref r_print.
 * @param func     New sink, or @c NULL to restore the default.
 * @param data     Opaque pointer forwarded to @p func on every call.
 * @param oldfunc  Optional out-pointer: receives the previously-installed sink.
 * @param olddata  Optional out-pointer: receives the previous @c data.
 */
R_API void r_override_print_handler    (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata);
/** @brief Like @ref r_override_print_handler but for @ref r_printerr. */
R_API void r_override_printerr_handler (RPrintFunc func, rpointer data,
    RPrintFunc * oldfunc, rpointer * olddata);

/** @brief Default stdout sink (writes via the C library). */
R_API rboolean r_print_default (const rchar * str, rsize size, rpointer data);
/** @brief Default stderr sink (writes via the C library). */
R_API rboolean r_printerr_default (const rchar * str, rsize size, rpointer data);

R_END_DECLS

/** @} */

#endif /* __R_TTY_H__ */

