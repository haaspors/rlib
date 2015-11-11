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
#include <rlib/rassert.h>
#include <math.h>

/* FIXME: Fix float/double classify/signbit if not C99 compiler */

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

RFpClass
r_float_classify (rfloat v)
{
  switch (fpclassify (v)) {
    case FP_INFINITE:
      return R_FP_CLASS_INFINITE;
    case FP_NAN:
      return R_FP_CLASS_NAN;
    case FP_ZERO:
      return R_FP_CLASS_ZERO;
    case FP_SUBNORMAL:
      return R_FP_CLASS_SUBNORMAL;
    case FP_NORMAL:
      return R_FP_CLASS_NORMAL;
    default:
      r_assert_not_reached ();
      break;
  }
}

rboolean
r_float_signbit (rfloat v)
{
  return signbit (v) != 0;
}

RFpClass
r_double_classify (rdouble v)
{
  switch (fpclassify (v)) {
    case FP_INFINITE:
      return R_FP_CLASS_INFINITE;
    case FP_NAN:
      return R_FP_CLASS_NAN;
    case FP_ZERO:
      return R_FP_CLASS_ZERO;
    case FP_SUBNORMAL:
      return R_FP_CLASS_SUBNORMAL;
    case FP_NORMAL:
      return R_FP_CLASS_NORMAL;
    default:
      r_assert_not_reached ();
      break;
  }
}

rboolean
r_double_signbit (rdouble v)
{
  return signbit (v) != 0;
}

