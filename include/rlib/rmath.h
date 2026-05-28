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

/**
 * @file rlib/rmath.h
 * @brief Integer GCD and IEEE-754 classification helpers.
 */

#include <rlib/rtypes.h>

/**
 * @defgroup r_math Math helpers
 *
 * @brief A small collection of math utilities that aren't covered by
 * @c <math.h>: integer greatest-common-divisor across the standard
 * widths, plus IEEE-754 classification predicates that don't depend
 * on @c <math.h> @c FP_* macros being available.
 *
 * @{
 */

R_BEGIN_DECLS

/** @name Greatest common divisor
 *  Euclid's algorithm at four widths.
 *  @{ */
/** @brief GCD of two @c int values. */
R_API int     r_int_gcd    (int a,      int b);
/** @brief GCD of two @c ruint values. */
R_API ruint   r_uint_gcd   (ruint a,    ruint b);
/** @brief GCD of two @c rint64 values. */
R_API rint64  r_int64_gcd  (rint64 a,   rint64 b);
/** @brief GCD of two @c ruint64 values. */
R_API ruint64 r_uint64_gcd (ruint64 a,  ruint64 b);
/** @} */

/** @brief IEEE-754 classification returned by @ref r_float_classify / @ref r_double_classify. */
typedef enum {
  R_FP_CLASS_SUBNORMAL = -2,  /**< Subnormal / denormalised. */
  R_FP_CLASS_NORMAL    = -1,  /**< Normal finite value. */
  R_FP_CLASS_ZERO      =  0,  /**< Positive or negative zero. */
  R_FP_CLASS_INFINITE  =  1,  /**< Positive or negative infinity. */
  R_FP_CLASS_NAN       =  2,  /**< NaN (quiet or signalling). */
} RFpClass;

/** @brief Classify an IEEE-754 single-precision value. */
R_API RFpClass r_float_classify  (rfloat v);
/** @brief Classify an IEEE-754 double-precision value. */
R_API RFpClass r_double_classify (rdouble v);

/** @brief @c TRUE if @p v is finite (not Inf, not NaN). */
#define r_float_isfinite(v) (r_float_classify (v) <= R_FP_CLASS_ZERO)
/** @brief @c TRUE if @p v is positive or negative infinity. */
#define r_float_isinf(v)    (r_float_classify (v) == R_FP_CLASS_INFINITE)
/** @brief @c TRUE if @p v is NaN. */
#define r_float_isnan(v)    (r_float_classify (v) == R_FP_CLASS_NAN)
/** @brief @c TRUE if @p v is a normal finite value. */
#define r_float_isnormal(v) (r_float_classify (v) == R_FP_CLASS_NORMAL)
/** @brief @c TRUE if @p v's IEEE-754 sign bit is set (works for -0.0). */
R_API rboolean r_float_signbit  (rfloat v);

/** @brief @c TRUE if @p v is finite (not Inf, not NaN). */
#define r_double_isfinite(v) (r_double_classify (v) <= R_FP_CLASS_ZERO)
/** @brief @c TRUE if @p v is positive or negative infinity. */
#define r_double_isinf(v)    (r_double_classify (v) == R_FP_CLASS_INFINITE)
/** @brief @c TRUE if @p v is NaN. */
#define r_double_isnan(v)    (r_double_classify (v) == R_FP_CLASS_NAN)
/** @brief @c TRUE if @p v is a normal finite value. */
#define r_double_isnormal(v) (r_double_classify (v) == R_FP_CLASS_NORMAL)
/** @brief @c TRUE if @p v's IEEE-754 sign bit is set (works for -0.0). */
R_API rboolean r_double_signbit  (rdouble v);

R_END_DECLS

/** @} */

#endif /* __R_MATH_H__ */
