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

#include <rlib/rrand.h>

R_BEGIN_DECLS

#define RMPINT_DEF_DIGITS     64
#define RMPINT_DEF_ISPRIME_T  8

typedef ruint32         rmpint_digit;
typedef ruint64         rmpint_word;
typedef struct {
  ruint16         dig_alloc, dig_used;
  ruint32         sign;
  /* Bit 0 (R_MPINT_FLAG_SECURE_CLEAR): wipe data with r_memclear_secure
   * on r_mpint_clear. Set this on any mpint that carries a secret
   * (private scalars, nonces, intermediate plaintexts) so the buffer
   * doesn't leak into freed heap when the mpint is released. */
  ruint32         flags;
  rmpint_digit *  data;
} rmpint;

#define R_MPINT_FLAG_SECURE_CLEAR (1u << 0)

#define R_MPINT_INIT            { 0, 0, 0, 0, NULL }
#define r_mpint_init(mpi)       r_mpint_init_size (mpi, RMPINT_DEF_DIGITS)
R_API void r_mpint_init_size (rmpint * mpi, ruint16 digits);
/* Same shape as r_mpint_init but with R_MPINT_FLAG_SECURE_CLEAR set,
 * so the underlying buffer gets wiped on r_mpint_clear. Use this for
 * any mpint that will hold secret material at any point in its life
 * - the flag is sticky across set / copy / arithmetic, so callers
 * only need to remember to use this at init time. */
R_API void r_mpint_init_secure (rmpint * mpi);
/* One-shot wrappers around init_secure + set_binary / + set, so a
 * key being imported from raw bytes or copied from another mpint
 * never spends a moment with the secure flag clear. */
R_API void r_mpint_init_binary_secure (rmpint * mpi, rconstpointer data, rsize size);
R_API void r_mpint_init_copy_secure (rmpint * mpi, const rmpint * b);
/* Flip the secure-clear flag on an existing mpint. Useful when an
 * mpint was init'd via r_mpint_init_binary / _copy / _str and only
 * afterwards turns out to need secure handling. */
R_API void r_mpint_set_secure_clear (rmpint * mpi);
/* Initialise dst as a normal (default-size) mpint, then OR in
 * R_MPINT_FLAG_SECURE_CLEAR if any source in the NULL-terminated
 * argument list has it set. Scratch mpints inside arithmetic
 * primitives use this so they inherit the secure-clear treatment
 * of whichever operand contributed to them, without each call
 * site having to repeat the conditional. */
R_API void r_mpint_init_from (rmpint * dst, const rmpint * src1, ...)
    R_ATTR_NULL_TERMINATED;
/* Same shape with a caller-chosen initial digit capacity, for call
 * sites that allocate a specifically-sized scratch up front. */
R_API void r_mpint_init_size_from (rmpint * dst, ruint16 digits,
    const rmpint * src1, ...) R_ATTR_NULL_TERMINATED;
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

R_API rboolean r_mpint_gen_prime_full (rmpint * mpi, rsize bits, rboolean safe,
    RPrng * prng);
#define r_mpint_gen_prime(mpi, bits, prng) r_mpint_gen_prime_full (mpi, bits, FALSE, prng)

typedef enum {
  R_MPINT_ERROR = -1,
  R_MPINT_NON_PRIME = 0,
  R_MPINT_CERTAIN_PRIME,
  R_MPINT_POSSIBLE_PRIME,
} RMpintPrimeTest;

R_API RMpintPrimeTest r_mpint_isprime_t (const rmpint * mpi, ruint t);
#define r_mpint_isprime(mpi) r_mpint_isprime_t (mpi, RMPINT_DEF_ISPRIME_T)

R_API void r_mpint_zero (rmpint * mpi);
R_API void r_mpint_set (rmpint * mpi, const rmpint * b);
R_API void r_mpint_set_binary (rmpint * mpi, rconstpointer data, rsize size);
R_API void r_mpint_set_i32 (rmpint * mpi, rint32 value);
R_API void r_mpint_set_u32 (rmpint * mpi, ruint32 value);
R_API void r_mpint_set_i64 (rmpint * mpi, rint64 value);
R_API void r_mpint_set_u64 (rmpint * mpi, ruint64 value);
/* Constant-time conditional swap: if `bit` is non-zero, exchange
 * the metadata and data pointer of `a` and `b`; if zero, leave
 * both untouched. Same execution time and memory access pattern
 * regardless of the bit, so a Montgomery ladder driven by it
 * doesn't leak the scalar's bit pattern through the per-step
 * branch shape. The contents of `data` are NOT swapped - only
 * the pointer - so this is O(1) regardless of the operand size. */
R_API void r_mpint_swap_ct (rmpint * a, rmpint * b, ruint32 bit);
/* Treat reads past dig_used as zero. mpint operations promise that
 * `data[0..dig_used)` carries the value, but several producers (e.g.
 * the final shr in r_mpint_div, and any path that shortens dig_used
 * without zeroing the now-unused tail) leave stale bytes behind in
 * `data[dig_used..dig_alloc)`. Without this clamp, consumers that
 * loop up to `MAX(a->dig_used, b->dig_used)` and read both operands -
 * notably r_mpint_add_unsigned with dst aliasing the shorter operand -
 * end up folding that stale data into the result. */
#define r_mpint_get_digit(mpi, d) \
  ((d) < (mpi)->dig_used ? (mpi)->data[d] : (rmpint_digit)0)

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
/* Constant-time variant of r_mpint_expmod. Iterates exactly exp_bits
 * bits over the exponent and routes the per-bit dispatch through
 * r_mpint_swap_ct rather than secret-indexed lookups; the per-
 * iteration Montgomery reduce runs through the CT variant. The base
 * b is treated as non-secret: the initial lift into Montgomery form
 * is variable-time.
 *
 * exp_bits must upper-bound the bit length of e - silent truncation
 * otherwise. bit_count(m) is always safe; a tighter bound (such as
 * bit_count(q) for DSA's k < q) saves work. The bit window is the
 * one timing channel the caller fully controls; pick the same value
 * across calls if uniformity matters.
 *
 * Residual leak: r_mpint backs the intermediates, so each per-bit
 * Mont mul iterates the intermediate value's dig_used. That leaks
 * the bit length of the partial product, not the exponent. Removing
 * this would require either a fixed-width type sized for the modulus
 * (cf. RMpintFE for ECC) or non-clamping rmpint variants. For DSA's
 * mod-p path the leak is on intermediate g^(partial-k) values, not
 * on k directly. */
R_API rboolean r_mpint_expmod_ct (rmpint * dst, const rmpint * b,
    const rmpint * e, const rmpint * m, ruint exp_bits);
/* Compute the per-modulus Montgomery inverse mp = -m^-1 mod 2^digit_bits.
 * Used by r_mpint_expmod_ct_with_mp and any other caller that wants
 * to cache the mp once per modulus rather than recompute on every
 * Montgomery operation. m must be odd. */
R_API rboolean r_mpint_montgomery_setup (rmpint_digit * mp, const rmpint * m);

/* Variant of r_mpint_expmod_ct that takes the per-modulus Montgomery
 * inverse mp as input rather than deriving it from m on every call.
 * Callers that sign / decrypt repeatedly with the same modulus
 * (RSA private operations, DSA signing) cache mp on their key struct
 * - one r_mpint_montgomery_setup at construction instead of one per
 * call. Same exp_bits semantics and residual-leak behaviour as
 * r_mpint_expmod_ct above. */
R_API rboolean r_mpint_expmod_ct_with_mp (rmpint * dst, const rmpint * b,
    const rmpint * e, const rmpint * m, rmpint_digit mp, ruint exp_bits);

R_API rboolean r_mpint_gcd (rmpint * dst, const rmpint * a, const rmpint * b);
R_API rboolean r_mpint_lcm (rmpint * dst, const rmpint * a, const rmpint * b);


/* --- Fixed-width Montgomery-form field elements (RMpintFE).
 *
 * Unlike rmpint, RMpintFE stores its digits inline in the struct
 * (no heap, no dig_used field) and every primitive iterates exactly
 * the modulus's digit count regardless of operand value. That gives
 * genuinely constant-time arithmetic at the cycle-count level - no
 * residual leak through r_mpint_clamp shrinking dig_used to the
 * value's bit length.
 *
 * Used by the ECC scalar-mul ladder (rlib/crypto/recurve.c). DSA
 * signing and RSA private operations want the same primitives. The
 * type is public so consumers outside rlib can reuse the same
 * audited implementation - same reason r_mpint_swap_ct and the rest
 * of the CT primitives live in this header. --- */

/* Widest curve we ship is secp521r1 at 17 32-bit digits; +1 leaves
 * headroom for the Montgomery accumulator's top carry slot. DSA |q|
 * (256 bits) fits comfortably; RSA moduli do not - that's what
 * RMpintFE_Big below is for. */
#define R_MPINT_FE_MAX_DIGITS  18

typedef struct {
  rmpint_digit d[R_MPINT_FE_MAX_DIGITS];
} RMpintFE;

/* Per-modulus Montgomery context. All FE primitives below take a
 * pointer to one of these so the modulus / its Montgomery inverse /
 * the digit width don't have to thread through every call site. */
typedef struct {
  RMpintFE p;
  rmpint_digit mp;            /* -p^-1 mod 2^digit_bits */
  ruint16 n_digits;           /* number of digits the modulus occupies */
} RMpintFEMontCtx;

/* RSA-width parallel to RMpintFE. Covers up to RSA-8192 (256 32-bit
 * digits for the full modulus, 128 for a CRT half) with one carry
 * slot of margin. The function bodies are generated from the same
 * template as the ECC width, so the two surfaces share one audited
 * implementation - only the storage width and the function-name
 * prefix differ. Bump this if you need RSA-16384 or wider. */
#define R_MPINT_FE_BIG_MAX_DIGITS  257

typedef struct {
  rmpint_digit d[R_MPINT_FE_BIG_MAX_DIGITS];
} RMpintFE_Big;

typedef struct {
  RMpintFE_Big p;
  rmpint_digit mp;
  ruint16 n_digits;
} RMpintFE_BigMontCtx;

/* ---- Per-modulus setup. Both helpers are one-time costs paid by the
 * caller before any FE arithmetic; the resulting ctx + mont_r_squared
 * are reusable across as many FE operations as the modulus is in
 * scope for. ---- */

/* Fill ctx (p, mp, n_digits) from an mpint modulus. Returns FALSE if
 * m is even or larger than R_MPINT_FE_MAX_DIGITS digits. */
R_API rboolean r_mpint_fe_mont_ctx_init (RMpintFEMontCtx * ctx, const rmpint * m);

/* Compute R^2 mod m for the supplied n-digit modulus (R = 2^(32*n)).
 * Used to feed mont_r_squared into r_mpint_fe_mont_in / _invmod_mont. */
R_API rboolean r_mpint_fe_compute_r_squared (RMpintFE * out, const rmpint * m,
    ruint16 n);

/* ---- Lifecycle / conversion. ---- */

R_API void r_mpint_fe_zero (RMpintFE * x);
R_API void r_mpint_fe_copy (RMpintFE * dst, const RMpintFE * src);
/* Copy mpi -> fe, zero-padded to n digits. Truncates beyond n. */
R_API void r_mpint_fe_from_mpint (RMpintFE * fe, const rmpint * mpi, ruint16 n);
/* Copy fe -> mpi, ending with r_mpint_clamp so the mpint side stays
 * canonical (value-dependent, but the value has left the CT path by
 * this point - it's en route to a public output). */
R_API rboolean r_mpint_fe_to_mpint (rmpint * mpi, const RMpintFE * fe, ruint16 n);

/* ---- Constant-time helpers (no field arithmetic). ---- */

/* All-ones mask iff x's low n digits are zero; all-zeros otherwise. */
R_API rmpint_digit r_mpint_fe_iszero_ct (const RMpintFE * x, ruint16 n);
/* out := (mask == all-ones) ? a : b, digit-wise over n digits. Safe
 * to alias out with a or b (digits read before write). */
R_API void r_mpint_fe_select_ct (RMpintFE * out, rmpint_digit mask,
    const RMpintFE * a, const RMpintFE * b, ruint16 n);
/* Branchless XOR-swap of two FEs gated on bit. */
R_API void r_mpint_fe_swap_ct (RMpintFE * a, RMpintFE * b,
    ruint32 bit, ruint16 n);

/* ---- Modular arithmetic mod p (inputs in [0, p), outputs in [0, p)).
 * Add / sub commute with the Montgomery transform, so they work both
 * for normal-form and Mont-form operands. ---- */

R_API void r_mpint_fe_add (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * b, const RMpintFEMontCtx * ctx);
R_API void r_mpint_fe_sub (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * b, const RMpintFEMontCtx * ctx);

/* Montgomery multiplication via CIOS: out := a * b * R^-1 mod p
 * (R = 2^(32 * n_digits)). If a and b are in Mont form, out is too. */
R_API void r_mpint_fe_mul_mont (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * b, const RMpintFEMontCtx * ctx);
R_API void r_mpint_fe_sqr_mont (RMpintFE * out, const RMpintFE * a,
    const RMpintFEMontCtx * ctx);

/* Lift / unlift between normal and Montgomery form. The mont_in
 * variant needs mont_r_squared (= R^2 mod p) precomputed by the
 * caller - it lives outside RMpintFEMontCtx because not every caller
 * needs it. */
R_API void r_mpint_fe_mont_in (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * mont_r_squared, const RMpintFEMontCtx * ctx);
R_API void r_mpint_fe_mont_out (RMpintFE * out, const RMpintFE * a,
    const RMpintFEMontCtx * ctx);

/* ---- Derived operations built on the primitives above. ---- */

/* Fermat-based modular inversion in Mont form: out := a_M^(p-2) mod p
 * (also in Mont form). Requires p prime and a coprime to p (a == 0
 * returns 0). p_minus_2_bits is the bit length of (p - 2) - drives
 * the inner exponentiation loop. */
R_API void r_mpint_fe_invmod_mont (RMpintFE * out, const RMpintFE * a_M,
    const RMpintFE * p_minus_2, ruint p_minus_2_bits,
    const RMpintFE * mont_r_squared, const RMpintFEMontCtx * ctx);

/* ---- Big-width counterparts. The function semantics match the
 * RMpintFE primitives above byte-for-byte (they are emitted from the
 * same template); only the storage width and the type / function
 * name spellings differ. The ctx / r-squared / exponent-bits inputs
 * are the same role; consult the RMpintFE comments above for the
 * details. ---- */

R_API rboolean r_mpint_fe_big_mont_ctx_init (RMpintFE_BigMontCtx * ctx,
    const rmpint * m);
R_API rboolean r_mpint_fe_big_compute_r_squared (RMpintFE_Big * out,
    const rmpint * m, ruint16 n);

R_API void r_mpint_fe_big_zero (RMpintFE_Big * x);
R_API void r_mpint_fe_big_copy (RMpintFE_Big * dst, const RMpintFE_Big * src);
R_API void r_mpint_fe_big_from_mpint (RMpintFE_Big * fe, const rmpint * mpi,
    ruint16 n);
R_API rboolean r_mpint_fe_big_to_mpint (rmpint * mpi, const RMpintFE_Big * fe,
    ruint16 n);

R_API rmpint_digit r_mpint_fe_big_iszero_ct (const RMpintFE_Big * x, ruint16 n);
R_API void r_mpint_fe_big_select_ct (RMpintFE_Big * out, rmpint_digit mask,
    const RMpintFE_Big * a, const RMpintFE_Big * b, ruint16 n);
R_API void r_mpint_fe_big_swap_ct (RMpintFE_Big * a, RMpintFE_Big * b,
    ruint32 bit, ruint16 n);

R_API void r_mpint_fe_big_add (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * b, const RMpintFE_BigMontCtx * ctx);
R_API void r_mpint_fe_big_sub (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * b, const RMpintFE_BigMontCtx * ctx);

R_API void r_mpint_fe_big_mul_mont (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * b, const RMpintFE_BigMontCtx * ctx);
R_API void r_mpint_fe_big_sqr_mont (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_BigMontCtx * ctx);

R_API void r_mpint_fe_big_mont_in (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_Big * mont_r_squared, const RMpintFE_BigMontCtx * ctx);
R_API void r_mpint_fe_big_mont_out (RMpintFE_Big * out, const RMpintFE_Big * a,
    const RMpintFE_BigMontCtx * ctx);

R_API void r_mpint_fe_big_invmod_mont (RMpintFE_Big * out,
    const RMpintFE_Big * a_M,
    const RMpintFE_Big * p_minus_2, ruint p_minus_2_bits,
    const RMpintFE_Big * mont_r_squared, const RMpintFE_BigMontCtx * ctx);

R_END_DECLS

#endif /* __R_MPINT_H__ */

