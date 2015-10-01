/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_ASCII_H__
#define __R_ASCII_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

typedef enum {
  R_ASCII_ALNUM  = 1 << 0,
  R_ASCII_ALPHA  = 1 << 1,
  R_ASCII_CNTRL  = 1 << 2,
  R_ASCII_DIGIT  = 1 << 3,
  R_ASCII_GRAPH  = 1 << 4,
  R_ASCII_LOWER  = 1 << 5,
  R_ASCII_PRINT  = 1 << 6,
  R_ASCII_PUNCT  = 1 << 7,
  R_ASCII_SPACE  = 1 << 8,
  R_ASCII_UPPER  = 1 << 9,
  R_ASCII_XDIGIT = 1 << 10
} RAsciiType;

R_API extern const ruint16 r_ascii_table[256];

#define r_ascii_isalnum(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_ALNUM) != 0)
#define r_ascii_isalpha(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_ALPHA) != 0)
#define r_ascii_iscntrl(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_CNTRL) != 0)
#define r_ascii_isdigit(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_DIGIT) != 0)
#define r_ascii_isgraph(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_GRAPH) != 0)
#define r_ascii_islower(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_LOWER) != 0)
#define r_ascii_isprint(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_PRINT) != 0)
#define r_ascii_ispunct(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_PUNCT) != 0)
#define r_ascii_isspace(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_SPACE) != 0)
#define r_ascii_isupper(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_UPPER) != 0)
#define r_ascii_isxdigit(c) ((r_ascii_table[(ruint8) (c)] & R_ASCII_XDIGIT) != 0)

R_END_DECLS

#endif /* __R_ASCII_H__ */
