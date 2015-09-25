/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
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

