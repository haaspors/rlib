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
#ifndef __R_MATH_H__
#define __R_MATH_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

R_API int     r_int_gcd    (int a,      int b);
R_API ruint   r_uint_gcd   (ruint a,    ruint b);
R_API rint64  r_int64_gcd  (rint64 a,   rint64 b);
R_API ruint64 r_uint64_gcd (ruint64 a,  ruint64 b);

typedef enum {
  R_FP_CLASS_SUBNORMAL = -2,
  R_FP_CLASS_NORMAL    = -1,
  R_FP_CLASS_ZERO      =  0,
  R_FP_CLASS_INFINITE  =  1,
  R_FP_CLASS_NAN       =  2,
} RFpClass;

R_API RFpClass r_float_classify  (rfloat v);
R_API RFpClass r_double_classify (rdouble v);

#define r_float_isfinite(v) (r_float_classify (v) <= R_FP_CLASS_ZERO)
#define r_float_isinf(v)    (r_float_classify (v) == R_FP_CLASS_INFINITE)
#define r_float_isnan(v)    (r_float_classify (v) == R_FP_CLASS_NAN)
#define r_float_isnormal(v) (r_float_classify (v) == R_FP_CLASS_NORMAL)
R_API rboolean r_float_signbit  (rfloat v);

#define r_double_isfinite(v) (r_double_classify (v) <= R_FP_CLASS_ZERO)
#define r_double_isinf(v)    (r_double_classify (v) == R_FP_CLASS_INFINITE)
#define r_double_isnan(v)    (r_double_classify (v) == R_FP_CLASS_NAN)
#define r_double_isnormal(v) (r_double_classify (v) == R_FP_CLASS_NORMAL)
R_API rboolean r_double_signbit  (rdouble v);

R_END_DECLS

#endif /* __R_MATH_H__ */
