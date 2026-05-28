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
#ifndef __R_ASCII_H__
#define __R_ASCII_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

/**
 * @defgroup r_ascii ASCII
 * @ingroup r_charset
 * @brief Locale-independent ASCII character classification and case
 * conversion. Counterparts to the standard @c <ctype.h> predicates.
 * @{
 */

/**
 * @file rlib/charset/rascii.h
 * @brief ASCII character classification and case conversion.
 *
 * Locale-independent counterparts to the @c <ctype.h> predicates and
 * @c <ctype.h>-style case conversion. All classification predicates
 * are macros that index a shared 256-entry lookup table; they're
 * branch-free and safe to use on @c rchar / signed @c char (the
 * macro cast to @c ruint8 keeps negative chars away from out-of-
 * bounds table access).
 *
 * For multibyte / Unicode handling see @c rlib/charset/runicode.h.
 */

R_BEGIN_DECLS

/**
 * @brief Bit flags backing the classification predicate macros.
 *
 * Each entry of @c r_ascii_table is an @c ruint16 OR-set of these
 * flags. The predicate macros mask out a single flag and return
 * non-zero / zero. Not meant to be referenced directly by callers;
 * use the @c r_ascii_is* macros instead.
 */
typedef enum {
  R_ASCII_ALNUM  = 1 << 0,    /**< Alphabetic or digit. */
  R_ASCII_ALPHA  = 1 << 1,    /**< Alphabetic ('a'-'z' or 'A'-'Z'). */
  R_ASCII_CNTRL  = 1 << 2,    /**< Control character (0x00-0x1f and 0x7f). */
  R_ASCII_DIGIT  = 1 << 3,    /**< Decimal digit ('0'-'9'). */
  R_ASCII_GRAPH  = 1 << 4,    /**< Printable, excluding space. */
  R_ASCII_LOWER  = 1 << 5,    /**< Lowercase letter. */
  R_ASCII_PRINT  = 1 << 6,    /**< Printable, including space. */
  R_ASCII_PUNCT  = 1 << 7,    /**< Punctuation. */
  R_ASCII_SPACE  = 1 << 8,    /**< Whitespace (' ', '\\t', '\\n', '\\v', '\\f', '\\r'). */
  R_ASCII_UPPER  = 1 << 9,    /**< Uppercase letter. */
  R_ASCII_XDIGIT = 1 << 10    /**< Hexadecimal digit ('0'-'9', 'a'-'f', 'A'-'F'). */
} RAsciiType;

/**
 * @brief 256-entry lookup table indexed by @c ruint8 byte value.
 *
 * Each entry holds the OR of @c RAsciiType flags applicable to that
 * byte. Backing storage for the classification macros below.
 */
R_API extern const ruint16 r_ascii_table[256];

/**
 * @name Character classification
 * @{
 */
/** @brief TRUE iff @p c is alphabetic or a decimal digit. */
#define r_ascii_isalnum(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_ALNUM) != 0)
/** @brief TRUE iff @p c is an alphabetic character. */
#define r_ascii_isalpha(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_ALPHA) != 0)
/** @brief TRUE iff @p c is a control character. */
#define r_ascii_iscntrl(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_CNTRL) != 0)
/** @brief TRUE iff @p c is a decimal digit. */
#define r_ascii_isdigit(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_DIGIT) != 0)
/** @brief TRUE iff @p c is printable and not whitespace. */
#define r_ascii_isgraph(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_GRAPH) != 0)
/** @brief TRUE iff @p c is a lowercase letter. */
#define r_ascii_islower(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_LOWER) != 0)
/** @brief TRUE iff @p c is printable (graph + space). */
#define r_ascii_isprint(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_PRINT) != 0)
/** @brief TRUE iff @p c is a punctuation character. */
#define r_ascii_ispunct(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_PUNCT) != 0)
/** @brief TRUE iff @p c is whitespace. */
#define r_ascii_isspace(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_SPACE) != 0)
/** @brief TRUE iff @p c is an uppercase letter. */
#define r_ascii_isupper(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_UPPER) != 0)
/** @brief TRUE iff @p c is a hexadecimal digit. */
#define r_ascii_isxdigit(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_XDIGIT) != 0)
/** @} */

/**
 * @name Digit values
 * @{
 */
/**
 * @brief Return the numeric value of decimal digit @p c (0-9).
 * @return Value in @c [0,9], or -1 if @p c isn't a decimal digit.
 */
R_API rint8 r_ascii_digit_value (rchar c);
/**
 * @brief Return the numeric value of hex digit @p c (0-15).
 * @return Value in @c [0,15], or -1 if @p c isn't a hex digit.
 */
R_API rint8 r_ascii_xdigit_value (rchar c);
/** @} */

/**
 * @name Case conversion
 * @{
 */
/**
 * @brief Return @p c upper-cased.
 *
 * Non-letter inputs and already-uppercase letters are returned
 * unchanged.
 */
#define r_ascii_upper(c) r_ascii_islower (c) ? ((c) - 0x20) : (c)
/**
 * @brief Return @p c lower-cased.
 *
 * Non-letter inputs and already-lowercase letters are returned
 * unchanged.
 */
#define r_ascii_lower(c) r_ascii_isupper (c) ? ((c) + 0x20) : (c)
/**
 * @brief Upper-case every byte in @p str in place.
 * @param str Buffer to convert.
 * @param len Bytes to convert, or -1 to fall back to @c r_strlen.
 * @return @p str.
 */
R_API rchar * r_ascii_make_upper (rchar * str, rssize len);
/**
 * @brief Lower-case every byte in @p str in place.
 * @param str Buffer to convert.
 * @param len Bytes to convert, or -1 to fall back to @c r_strlen.
 * @return @p str.
 */
R_API rchar * r_ascii_make_lower (rchar * str, rssize len);
/** @} */

R_END_DECLS

/** @} */ /* r_ascii group */

#endif /* __R_ASCII_H__ */
