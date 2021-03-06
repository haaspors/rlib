/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MPINT_PRIVATE_H__
#define __R_MPINT_PRIVATE_H__

#if !defined(RLIB_COMPILATION)
#error "rmpint-private.h should only be used internally in rlib!"
#endif

#include <rlib/data/rmpint.h>

R_BEGIN_DECLS

#define r_mpint_ensure_bits (mpi, bits) \
  r_mpint_ensure_digits (mpi, (bits + sizeof (rmpint_digit) - 1) / sizeof (rmpint_digit))
R_API_HIDDEN void r_mpint_ensure_digits (rmpint * mpi, ruint16 digits);

R_API_HIDDEN rboolean r_mpint_add_unsigned (rmpint * dst,
    const rmpint * a, const rmpint * b);
/* NOTE: a MUST be bigger than b */
R_API_HIDDEN rboolean r_mpint_sub_unsigned (rmpint * dst,
    const rmpint * a, const rmpint * b);

#define RMPINT_N_PRIMES       256
R_API_HIDDEN extern const rmpint_digit r_mpint_primes[RMPINT_N_PRIMES];
R_API_HIDDEN RMpintPrimeTest r_mpint_prime_miller_rabin (const rmpint * n, const rmpint * a);
R_API_HIDDEN RMpintPrimeTest r_mpint_prime_miller_rabin_full (const rmpint * n, RPrng * prng);

R_API_HIDDEN rboolean r_mpint_montgomery_setup (rmpint_digit * mp, const rmpint * m);
R_API_HIDDEN rboolean r_mpint_montgomery_reduce (rmpint * a, const rmpint * m,
    rmpint_digit mp);
R_API_HIDDEN rboolean r_mpint_montgomery_normalize (rmpint * a, const rmpint * m);

R_END_DECLS

#endif /* __R_MPINT_PRIVATE_H__ */

