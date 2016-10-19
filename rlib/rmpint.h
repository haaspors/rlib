/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MPINT_H__
#define __R_MPINT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

#define RMPINT_DEF_DIGITS     64
#define RMPINT_DEF_ISPRIME_T  8

typedef ruint32         rmpint_digit;
typedef ruint64         rmpint_word;
typedef struct {
  ruint16         dig_alloc, dig_used;
  ruint32         sign;
  rmpint_digit *  data;
} rmpint;

#define r_mpint_init(mpi)       r_mpint_init_size (mpi, RMPINT_DEF_DIGITS)
R_API void r_mpint_init_size (rmpint * mpi, ruint16 digits);
R_API void r_mpint_init_binary (rmpint * mpi, rconstpointer data, rsize size);
R_API void r_mpint_init_str (rmpint * mpi, const rchar * str,
    const rchar ** endptr, ruint base);
R_API void r_mpint_init_copy (rmpint * dst, const rmpint * src);
R_API void r_mpint_clear (rmpint * mpi);

R_API ruint8 * r_mpint_to_binary_new (const rmpint * mpi, rsize * size) R_ATTR_MALLOC;
R_API rboolean r_mpint_to_binary (const rmpint * mpi, ruint8 * bin, rsize * size);
R_API rboolean r_mpint_to_binary_with_size (const rmpint * mpi, ruint8 * bin, rsize size);
R_API rchar * r_mpint_to_str (const rmpint * mpi);

#define r_mpint_iszero(mpi)       ((mpi)->dig_used == 0)
#define r_mpint_iseven(mpi)       ((mpi)->dig_used > 0 && (((mpi)->data[0] & 1) == 0))
#define r_mpint_isodd(mpi)        ((mpi)->dig_used > 0 && (((mpi)->data[0] & 1) == 1))
#define r_mpint_isneg(mpi)        ((mpi)->dig_used > 0 && (mpi)->sign)

#define r_mpint_isprime(mpi)      r_mpint_isprime_t (mpi, RMPINT_DEF_ISPRIME_T)
R_API rboolean r_mpint_isprime_t (const rmpint * mpi, ruint t);

#define r_mpint_digits_used(mpi)  (mpi)->dig_used
#define r_mpint_bytes_used(mpi)   ((ruint)((mpi)->dig_used > 0 ?              \
    (ruint)(((ruint)(mpi)->dig_used * sizeof (rmpint_digit)) -                \
    (ruint)RUINT32_CLZ (r_mpint_get_digit (mpi, (mpi)->dig_used - 1)) / 8) :  \
    ((ruint)0)))
#define r_mpint_bits_used(mpi)    ((ruint)((mpi)->dig_used > 0 ?              \
    (ruint)(((ruint)(mpi)->dig_used * sizeof (rmpint_digit) * 8) -            \
    (ruint)RUINT32_CLZ (r_mpint_get_digit (mpi, (mpi)->dig_used - 1))) :      \
    ((ruint)0)))
#define r_mpint_clamp(mpi)   R_STMT_START {                           \
  while ((mpi)->dig_used > 0 && (mpi)->data[(mpi)->dig_used-1] == 0)  \
    (mpi)->dig_used--;                                                \
  (mpi)->sign = (mpi)->dig_used > 0 ? (mpi)->sign : 0;                \
} R_STMT_END

R_API void r_mpint_zero (rmpint * mpi);
R_API void r_mpint_set (rmpint * mpi, const rmpint * b);
R_API void r_mpint_set_binary (rmpint * mpi, rconstpointer data, rsize size);
R_API void r_mpint_set_i32 (rmpint * mpi, rint32 value);
R_API void r_mpint_set_u32 (rmpint * mpi, ruint32 value);
R_API void r_mpint_set_i64 (rmpint * mpi, rint64 value);
R_API void r_mpint_set_u64 (rmpint * mpi, ruint64 value);
#define r_mpint_get_digit(mpi, d) (mpi)->data[d]

//R_API ruint32 r_mpint_clz (const rmpint * mpi);
R_API ruint32 r_mpint_ctz (const rmpint * mpi);

R_API int r_mpint_cmp (const rmpint * a, const rmpint * b);
R_API int r_mpint_ucmp (const rmpint * a, const rmpint * b);
R_API int r_mpint_cmp_i32 (const rmpint * a, rint32 b);
R_API int r_mpint_ucmp_u32 (const rmpint * a, ruint32 b);

R_API rboolean r_mpint_add (rmpint * dst, const rmpint * a, const rmpint * b);
R_API rboolean r_mpint_add_i32 (rmpint * dst, const rmpint * a, rint32 b);
R_API rboolean r_mpint_add_u32 (rmpint * dst, const rmpint * a, ruint32 b);

R_API rboolean r_mpint_sub (rmpint * dst, const rmpint * a, const rmpint * b);
R_API rboolean r_mpint_sub_i32 (rmpint * dst, const rmpint * a, rint32 b);
R_API rboolean r_mpint_sub_u32 (rmpint * dst, const rmpint * a, ruint32 b);

R_API rboolean r_mpint_shl (rmpint * dst, const rmpint * a, ruint32 bits);
R_API rboolean r_mpint_shr (rmpint * dst, const rmpint * a, ruint32 bits);
R_API rboolean r_mpint_shl_digit (rmpint * dst, const rmpint * a, ruint16 d);
R_API rboolean r_mpint_shr_digit (rmpint * dst, const rmpint * a, ruint16 d);

R_API rboolean r_mpint_mul (rmpint * dst, const rmpint * a, const rmpint * b);
R_API rboolean r_mpint_mul_i32 (rmpint * dst, const rmpint * a, rint32 b);
R_API rboolean r_mpint_mul_u32 (rmpint * dst, const rmpint * a, ruint32 b);

R_API rboolean r_mpint_div (rmpint * q, rmpint * r, const rmpint * n, const rmpint * d);
R_API rboolean r_mpint_div_i32 (rmpint * q, rmpint * r, const rmpint * n, rint32 d);
R_API rboolean r_mpint_div_u32 (rmpint * q, rmpint * r, const rmpint * n, ruint32 d);

R_API rboolean r_mpint_exp (rmpint * dst, const rmpint * b, ruint16 e);

#define r_mpint_mod(dst, n, d)            r_mpint_div (NULL, dst, n, d)
#define r_mpint_mod_i32(dst, n, d)        r_mpint_div_i32 (NULL, dst, n, d)
#define r_mpint_mod_u32(dst, n, d)        r_mpint_div_u32 (NULL, dst, n, d)

#define r_mpint_mulmod(dst, a, b, d)      (r_mpint_mul (dst, a, b) && r_mpint_mod (dst, dst, d))
#define r_mpint_mulmod_i32(dst, a, b, d)  (r_mpint_mul (dst, a, b) && r_mpint_mod_i32 (dst, dst, d))
#define r_mpint_mulmod_u32(dst, a, b, d)  (r_mpint_mul (dst, a, b) && r_mpint_mod_u32 (dst, dst, d))

R_API rboolean r_mpint_invmod (rmpint * dst, const rmpint * a, const rmpint * m);
R_API rboolean r_mpint_expmod (rmpint * dst, const rmpint * b, const rmpint * e, const rmpint * m);

R_API rboolean r_mpint_gcd (rmpint * dst, const rmpint * a, const rmpint * b);
R_API rboolean r_mpint_lcm (rmpint * dst, const rmpint * a, const rmpint * b);

R_END_DECLS

#endif /* __R_MPINT_H__ */

