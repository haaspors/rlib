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
#include <rlib/rmath.h>

#define GCD_DEFINE(func, type)      \
  type func (type a, type b) {      \
    type c;                         \
    while ((a) != 0) {              \
      c = a; a = b%a; b = c;        \
    }                               \
    return b;                       \
  }

R_API GCD_DEFINE (r_int_gcd,    int);
R_API GCD_DEFINE (r_uint_gcd,   ruint);
R_API GCD_DEFINE (r_int64_gcd,  rint64);
R_API GCD_DEFINE (r_uint64_gcd, ruint64);

