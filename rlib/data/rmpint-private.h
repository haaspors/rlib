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

R_API_HIDDEN rboolean r_mpint_montgomery_reduce (rmpint * a, const rmpint * m,
    rmpint_digit mp);
/* Constant-time variant of r_mpint_montgomery_reduce. Same semantics
 * (a := a * R^-1 mod m) but the final "subtract m if >= m" step is
 * unconditional + masked, and the result's dig_used is forced to
 * digits_used(m) regardless of value - subsequent ops see a
 * fixed-width representation. Caller must guarantee a < m * R at
 * entry (the standard precondition for Montgomery reduction). */
R_API_HIDDEN rboolean r_mpint_montgomery_reduce_ct (rmpint * a,
    const rmpint * m, rmpint_digit mp);
/* Scratch-hoisting variant for hot paths. c must have dig_alloc at
 * least 2 * digits_used(m) + 1; r_mpint_expmod_ct passes the same
 * scratch through every iteration of its inner ladder to avoid the
 * per-call allocation the convenience wrapper above incurs. */
R_API_HIDDEN rboolean r_mpint_montgomery_reduce_ct_into (rmpint * a,
    const rmpint * m, rmpint_digit mp, rmpint * c);
R_API_HIDDEN rboolean r_mpint_montgomery_normalize (rmpint * a, const rmpint * m);

R_END_DECLS

#endif /* __R_MPINT_PRIVATE_H__ */

