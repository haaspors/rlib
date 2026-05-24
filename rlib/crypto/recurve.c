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

#include "config.h"
#include "rcrypto-private.h"
#include "../data/rmpint-private.h"

#include <rlib/crypto/recurve.h>

#include <rlib/asn1/roid.h>
#include <rlib/rmem.h>

typedef struct {
  REcurveID curve;
  rsize coord_bytes;
  const ruint8 * p_data;  rsize p_size;
  const ruint8 * a_data;  rsize a_size;
  const ruint8 * b_data;  rsize b_size;
  const ruint8 * n_data;  rsize n_size;
  const ruint8 * gx_data; rsize gx_size;
  const ruint8 * gy_data; rsize gy_size;
} REcurveParamData;

#include "recurve-curves.inc"

void
r_ecurve_point_init (REcurveAffinePoint * point)
{
  r_mpint_init (&point->x);
  r_mpint_init (&point->y);
  point->is_infinity = TRUE;
}

void
r_ecurve_point_clear (REcurveAffinePoint * point)
{
  r_mpint_clear (&point->x);
  r_mpint_clear (&point->y);
  point->is_infinity = TRUE;
}

void
r_ecurve_point_set_infinity (REcurveAffinePoint * point)
{
  r_mpint_zero (&point->x);
  r_mpint_zero (&point->y);
  point->is_infinity = TRUE;
}

void
r_ecurve_point_copy (REcurveAffinePoint * dst, const REcurveAffinePoint * src)
{
  r_mpint_set (&dst->x, &src->x);
  r_mpint_set (&dst->y, &src->y);
  dst->is_infinity = src->is_infinity;
}

static const REcurveParamData *
r_ecurve_param_data_find (REcurveID curve)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (g__recurves); i++) {
    if (g__recurves[i].curve == curve)
      return &g__recurves[i];
  }
  return NULL;
}

rboolean
r_ecurve_init (REcurve * curve, REcurveID named)
{
  const REcurveParamData * pd;

  if (R_UNLIKELY (curve == NULL))
    return FALSE;
  if ((pd = r_ecurve_param_data_find (named)) == NULL)
    return FALSE;

  r_mpint_init_binary (&curve->p, pd->p_data, pd->p_size);
  r_mpint_init_binary (&curve->a, pd->a_data, pd->a_size);
  r_mpint_init_binary (&curve->b, pd->b_data, pd->b_size);
  r_mpint_init_binary (&curve->n, pd->n_data, pd->n_size);
  r_ecurve_point_init (&curve->G);
  r_mpint_set_binary (&curve->G.x, pd->gx_data, pd->gx_size);
  r_mpint_set_binary (&curve->G.y, pd->gy_data, pd->gy_size);
  curve->G.is_infinity = FALSE;
  curve->coord_bytes = pd->coord_bytes;

  /* Precompute Montgomery setup constants used by the constant-time
   * scalar-mul ladder. mont_mp = -p^-1 mod 2^digit_bits is the per-
   * digit reduction multiplier; mont_r_squared is R^2 mod p, used to
   * lift a normal-form value into Montgomery form via a single
   * Montgomery multiplication; mont_a is the a coefficient already
   * in Montgomery form (a * R mod p), kept here so the dbl formula
   * doesn't have to lift it on every call. */
  if (!r_mpint_montgomery_setup (&curve->mont_mp, &curve->p)) {
    r_ecurve_clear (curve);
    return FALSE;
  }
  /* Compute R^2 mod p in two steps: normalize lifts to R mod p,
   * then a plain (non-Montgomery) square + reduce mod p gives
   * R^2 mod p. Note we can't use Montgomery multiplication for
   * this step - M(R, R) = R * R / R = R, not R^2. */
  r_mpint_init (&curve->mont_r_squared);
  if (!r_mpint_montgomery_normalize (&curve->mont_r_squared, &curve->p) ||
      !r_mpint_mul (&curve->mont_r_squared, &curve->mont_r_squared,
        &curve->mont_r_squared) ||
      !r_mpint_mod (&curve->mont_r_squared, &curve->mont_r_squared, &curve->p)) {
    r_ecurve_clear (curve);
    return FALSE;
  }
  /* mont_a = a * R mod p. With R^2 mod p in hand, one Montgomery
   * multiplication M(a, R^2) = a * R^2 / R = a * R does the lift. */
  r_mpint_init (&curve->mont_a);
  if (!r_mpint_mul (&curve->mont_a, &curve->a, &curve->mont_r_squared) ||
      !r_mpint_montgomery_reduce_ct (&curve->mont_a, &curve->p, curve->mont_mp)) {
    r_ecurve_clear (curve);
    return FALSE;
  }
  /* p_minus_2: Fermat inverter computes a^(p-2) mod p. p is an odd
   * prime so p-2 fits without any borrow. */
  r_mpint_init (&curve->p_minus_2);
  if (!r_mpint_sub_i32 (&curve->p_minus_2, &curve->p, 2)) {
    r_ecurve_clear (curve);
    return FALSE;
  }
  return TRUE;
}

void
r_ecurve_clear (REcurve * curve)
{
  r_mpint_clear (&curve->p);
  r_mpint_clear (&curve->a);
  r_mpint_clear (&curve->b);
  r_mpint_clear (&curve->n);
  r_ecurve_point_clear (&curve->G);
  r_mpint_clear (&curve->mont_r_squared);
  r_mpint_clear (&curve->mont_a);
  r_mpint_clear (&curve->p_minus_2);
}

/* --- Internal field arithmetic, in a fixed-width Montgomery
 * representation. The REcurveFE type stores a value mod p as a flat
 * inline array of digits, sized once at compile time to fit our
 * widest curve. Every primitive iterates exactly the curve's digit
 * count - no clamping, no dig_used field that varies with the value
 * the variable currently holds. That removes the residual memory-
 * access leak the rmpint-based path had (where r_mpint_mul's inner
 * loop iterates the operand's actual bit length).
 *
 * REcurveFEContext gathers the per-curve constants in FE form and is
 * built fresh at the top of scalar_mul, so the public REcurve struct
 * doesn't have to expose this internal representation. --- */

/* secp521r1 is the widest curve we ship, needing 17 32-bit digits; +1
 * leaves room for headroom and keeps small structs aligned. */
#define R_ECURVE_FE_MAX_DIGITS  18

typedef struct {
  rmpint_digit d[R_ECURVE_FE_MAX_DIGITS];
} REcurveFE;

typedef struct {
  REcurveFE p;
  REcurveFE mont_r_squared;
  REcurveFE mont_a;
  REcurveFE p_minus_2;
  REcurveFE n;
  rmpint_digit mp;            /* -p^-1 mod 2^digit_bits */
  ruint16 n_digits;           /* curve's p / n / etc. all fit in n_digits digits */
  ruint p_minus_2_bits;       /* bit length of p-2, drives the Fermat exp loop */
  ruint n_bits;               /* bit length of curve order, drives scalar conditioning */
} REcurveFEContext;

/* Per-iteration scratch for the Jacobian dbl + add. Allocated as a
 * single struct on the scalar_mul stack frame so the FE temporaries
 * survive across all ladder iterations without per-call setup cost.
 * The 21 slots cover the wider operation (r_ecurve_jp_add); jp_dbl
 * reuses the first 11 under different aliases. */
typedef struct {
  REcurveFE t[21];
} REcurveJacobianScratch;

/* ---- FE primitives. All CT and infallible (no heap, no failure). ---- */

static void
r_ecurve_fe_zero (REcurveFE * x)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (x->d); i++)
    x->d[i] = 0;
}

static void
r_ecurve_fe_copy (REcurveFE * dst, const REcurveFE * src)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (dst->d); i++)
    dst->d[i] = src->d[i];
}

/* Copy an mpint's value into an FE, zero-padding to n digits. The
 * "truncate beyond n" branch is unreachable for curve constants and
 * for scalars in the documented [0, 2^(32*n)) range, so it doesn't
 * leak anything callers care about. */
static void
r_ecurve_fe_from_mpint (REcurveFE * fe, const rmpint * mpi, ruint16 n)
{
  ruint16 i;
  ruint16 to_copy = mpi->dig_used;
  if (to_copy > n) to_copy = n;
  for (i = 0; i < to_copy; i++)
    fe->d[i] = mpi->data[i];
  for (i = to_copy; i < R_ECURVE_FE_MAX_DIGITS; i++)
    fe->d[i] = 0;
}

/* Extract a normal-form FE into an mpint, ending with a clamp so the
 * caller-visible mpint is canonical. The clamp is value-dependent,
 * but the FE has already left the CT-sensitive code path at this
 * point - it's en route to the public REcurveAffinePoint output. */
static rboolean
r_ecurve_fe_to_mpint (rmpint * mpi, const REcurveFE * fe, ruint16 n)
{
  ruint16 i;
  r_mpint_ensure_digits (mpi, n);
  if (R_UNLIKELY (mpi->dig_alloc < n)) return FALSE;
  for (i = 0; i < n; i++)
    mpi->data[i] = fe->d[i];
  for (i = n; i < mpi->dig_alloc; i++)
    mpi->data[i] = 0;
  mpi->dig_used = n;
  mpi->sign = 0;
  r_mpint_clamp (mpi);
  return TRUE;
}

/* Mask returns all-ones if x's low n digits are all zero, else all-zeros. */
static rmpint_digit
r_ecurve_fe_iszero_ct (const REcurveFE * x, ruint16 n)
{
  ruint16 i;
  rmpint_digit acc = 0;
  rmpint_digit nz;
  for (i = 0; i < n; i++)
    acc |= x->d[i];
  nz = (acc | ((rmpint_digit)0 - acc)) >> (sizeof (rmpint_digit) * 8 - 1);
  return nz - (rmpint_digit)1;
}

/* out := (mask == all-ones) ? a : b, digit-wise over n digits.
 * Aliasing out with a or b is safe (each digit is read before write). */
static void
r_ecurve_fe_select_ct (REcurveFE * out, rmpint_digit mask,
    const REcurveFE * a, const REcurveFE * b, ruint16 n)
{
  ruint16 i;
  for (i = 0; i < n; i++)
    out->d[i] = (a->d[i] & mask) | (b->d[i] & ~mask);
}

/* Branchless XOR-swap of two FEs (n low digits) gated on `bit`. */
static void
r_ecurve_fe_swap_ct (REcurveFE * a, REcurveFE * b, ruint32 bit, ruint16 n)
{
  rmpint_digit mask = (rmpint_digit)0 - (rmpint_digit)(bit & 1u);
  ruint16 i;
  for (i = 0; i < n; i++) {
    rmpint_digit d = (a->d[i] ^ b->d[i]) & mask;
    a->d[i] ^= d;
    b->d[i] ^= d;
  }
}

/* out := (a + b) mod p, inputs and output in [0, p). */
static void
r_ecurve_fe_add (REcurveFE * out, const REcurveFE * a, const REcurveFE * b,
    const REcurveFEContext * ctx)
{
  rmpint_digit t[R_ECURVE_FE_MAX_DIGITS + 1];
  rmpint_digit scratch[R_ECURVE_FE_MAX_DIGITS + 1];
  ruint16 i, n = ctx->n_digits;
  rmpint_word u;
  rmpint_digit carry = 0, borrow = 0, mask;

  for (i = 0; i < n; i++) {
    u = (rmpint_word)a->d[i] + (rmpint_word)b->d[i] + (rmpint_word)carry;
    t[i] = (rmpint_digit)u;
    carry = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
  }
  t[n] = carry;

  /* scratch = t - p, in n+1 digits. Borrow flags "t < p". */
  for (i = 0; i < n; i++) {
    u = (rmpint_word)t[i] - (rmpint_word)ctx->p.d[i] - (rmpint_word)borrow;
    scratch[i] = (rmpint_digit)u;
    borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);
  }
  u = (rmpint_word)t[n] - (rmpint_word)borrow;
  scratch[n] = (rmpint_digit)u;
  borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);

  /* borrow == 1 means t < p; keep t. borrow == 0 means t >= p; use scratch. */
  mask = (rmpint_digit)0 - (rmpint_digit)((borrow & 1u) ^ 1u);
  for (i = 0; i < n; i++)
    out->d[i] = (t[i] & ~mask) | (scratch[i] & mask);
  for (i = n; i < R_ECURVE_FE_MAX_DIGITS; i++)
    out->d[i] = 0;
}

/* out := (a - b) mod p. If a < b the subtract underflows and we add
 * p back via a borrow-driven mask, so the operation stays branchless. */
static void
r_ecurve_fe_sub (REcurveFE * out, const REcurveFE * a, const REcurveFE * b,
    const REcurveFEContext * ctx)
{
  rmpint_digit t[R_ECURVE_FE_MAX_DIGITS];
  ruint16 i, n = ctx->n_digits;
  rmpint_word u;
  rmpint_digit borrow = 0, carry = 0, mask;

  for (i = 0; i < n; i++) {
    u = (rmpint_word)a->d[i] - (rmpint_word)b->d[i] - (rmpint_word)borrow;
    t[i] = (rmpint_digit)u;
    borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);
  }

  /* If borrow=1, t is the 2's-complement of -(b-a); adding p (also
   * mod 2^(32n)) lands at p - (b - a) = a - b + p, the canonical
   * non-negative result. The carry out of this add is discarded by
   * design - the value fits in n digits. */
  mask = (rmpint_digit)0 - (rmpint_digit)(borrow & 1u);
  for (i = 0; i < n; i++) {
    u = (rmpint_word)t[i] + (rmpint_word)(ctx->p.d[i] & mask) + (rmpint_word)carry;
    out->d[i] = (rmpint_digit)u;
    carry = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
  }
  for (i = n; i < R_ECURVE_FE_MAX_DIGITS; i++)
    out->d[i] = 0;
}

/* Montgomery multiplication via CIOS (Coarsely Integrated Operand
 * Scanning). out := a * b * R^-1 mod p, R = 2^(32*n). Aliasing out
 * with a or b is fine (we read a and b through their original
 * pointers and only write to out at the end). */
static void
r_ecurve_fe_mul_mont (REcurveFE * out, const REcurveFE * a, const REcurveFE * b,
    const REcurveFEContext * ctx)
{
  rmpint_digit T[R_ECURVE_FE_MAX_DIGITS + 2];
  rmpint_digit scratch[R_ECURVE_FE_MAX_DIGITS + 1];
  ruint16 i, j, n = ctx->n_digits;
  rmpint_word u;
  rmpint_digit c, mu, borrow = 0, mask;

  for (i = 0; i < n + 2; i++) T[i] = 0;

  for (i = 0; i < n; i++) {
    /* T = T + a * b[i] */
    c = 0;
    for (j = 0; j < n; j++) {
      u = (rmpint_word)T[j] +
          (rmpint_word)a->d[j] * (rmpint_word)b->d[i] +
          (rmpint_word)c;
      T[j] = (rmpint_digit)u;
      c = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
    }
    u = (rmpint_word)T[n] + (rmpint_word)c;
    T[n] = (rmpint_digit)u;
    T[n + 1] = (rmpint_digit)(T[n + 1] +
        (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8)));

    /* mu = T[0] * mp. Choosing mu this way makes T[0] zero after the
     * next multiply-add, which is what lets the right-shift be exact. */
    mu = T[0] * ctx->mp;

    /* T = T + mu * p */
    c = 0;
    for (j = 0; j < n; j++) {
      u = (rmpint_word)T[j] +
          (rmpint_word)mu * (rmpint_word)ctx->p.d[j] +
          (rmpint_word)c;
      T[j] = (rmpint_digit)u;
      c = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
    }
    u = (rmpint_word)T[n] + (rmpint_word)c;
    T[n] = (rmpint_digit)u;
    T[n + 1] = (rmpint_digit)(T[n + 1] +
        (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8)));

    /* T >>= digit_bits. T[0] is zero by construction. */
    for (j = 0; j < n + 1; j++) T[j] = T[j + 1];
    T[n + 1] = 0;
  }

  /* T is in [0, 2p). Conditional subtract p (over n+1 digits, since
   * T[n] can carry a 1 from the last iteration). */
  for (j = 0; j < n; j++) {
    u = (rmpint_word)T[j] - (rmpint_word)ctx->p.d[j] - (rmpint_word)borrow;
    scratch[j] = (rmpint_digit)u;
    borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);
  }
  u = (rmpint_word)T[n] - (rmpint_word)borrow;
  scratch[n] = (rmpint_digit)u;
  borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);

  mask = (rmpint_digit)0 - (rmpint_digit)((borrow & 1u) ^ 1u);
  for (j = 0; j < n; j++)
    out->d[j] = (T[j] & ~mask) | (scratch[j] & mask);
  for (j = n; j < R_ECURVE_FE_MAX_DIGITS; j++)
    out->d[j] = 0;
}

static void
r_ecurve_fe_sqr_mont (REcurveFE * out, const REcurveFE * a,
    const REcurveFEContext * ctx)
{
  r_ecurve_fe_mul_mont (out, a, a, ctx);
}

/* Normal -> Montgomery: out = a * R mod p. */
static void
r_ecurve_fe_mont_in (REcurveFE * out, const REcurveFE * a,
    const REcurveFEContext * ctx)
{
  r_ecurve_fe_mul_mont (out, a, &ctx->mont_r_squared, ctx);
}

/* Montgomery -> normal: out = a / R mod p. Performed as M(a, 1), which
 * gives a * 1 * R^-1 = a/R. */
static void
r_ecurve_fe_mont_out (REcurveFE * out, const REcurveFE * a,
    const REcurveFEContext * ctx)
{
  REcurveFE one;
  r_ecurve_fe_zero (&one);
  one.d[0] = 1;
  r_ecurve_fe_mul_mont (out, a, &one, ctx);
}

/* Fermat-based inversion in Montgomery form: out = a_M^(p-2) mod p
 * (also in Mont form). Left-to-right Montgomery exponentiation with
 * swap-wrap CT dispatch on each exponent bit. The exponent is
 * curve-public (p-2 for the named curve) so its bit pattern doesn't
 * leak anything; the secret is the base, and the CT FE primitives
 * keep that base's bit pattern out of timing. */
static void
r_ecurve_fe_invmod_mont (REcurveFE * out, const REcurveFE * a_M,
    const REcurveFEContext * ctx)
{
  REcurveFE R[2], one;
  ruint i;
  rmpint_digit bit;

  r_ecurve_fe_zero (&one);
  one.d[0] = 1;
  r_ecurve_fe_mont_in (&R[0], &one, ctx);   /* R[0] = 1 in Mont (= R mod p) */
  r_ecurve_fe_copy (&R[1], a_M);             /* R[1] = a_M */

  for (i = ctx->p_minus_2_bits; i > 0; i--) {
    ruint bp = i - 1;
    bit = (ctx->p_minus_2.d[bp / (sizeof (rmpint_digit) * 8)] >>
           (bp % (sizeof (rmpint_digit) * 8))) & 1u;

    r_ecurve_fe_swap_ct (&R[0], &R[1], (ruint32)bit, ctx->n_digits);
    r_ecurve_fe_mul_mont (&R[1], &R[0], &R[1], ctx);
    r_ecurve_fe_sqr_mont (&R[0], &R[0], ctx);
    r_ecurve_fe_swap_ct (&R[0], &R[1], (ruint32)bit, ctx->n_digits);
  }

  r_ecurve_fe_copy (out, &R[0]);
  r_memclear_secure (R, sizeof (R));
}

/* ---- Jacobian-projective point arithmetic on FE coords. A point
 * (X, Y, Z) represents the affine (X/Z^2, Y/Z^3); Z = 0 marks the
 * identity. All coordinates are in Mont form. ---- */

typedef struct {
  REcurveFE X;
  REcurveFE Y;
  REcurveFE Z;
} REcurveJacobianPoint;

static void
r_ecurve_jp_init (REcurveJacobianPoint * P)
{
  r_ecurve_fe_zero (&P->X);
  r_ecurve_fe_zero (&P->Y);
  r_ecurve_fe_zero (&P->Z);
}

static void
r_ecurve_jp_clear (REcurveJacobianPoint * P)
{
  r_memclear_secure (P, sizeof (*P));
}

static void
r_ecurve_jp_swap_ct (REcurveJacobianPoint * a, REcurveJacobianPoint * b,
    ruint32 bit, ruint16 n)
{
  r_ecurve_fe_swap_ct (&a->X, &b->X, bit, n);
  r_ecurve_fe_swap_ct (&a->Y, &b->Y, bit, n);
  r_ecurve_fe_swap_ct (&a->Z, &b->Z, bit, n);
}

static void
r_ecurve_jp_scratch_init (REcurveJacobianScratch * s)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (s->t); i++)
    r_ecurve_fe_zero (&s->t[i]);
}

static void
r_ecurve_jp_scratch_clear (REcurveJacobianScratch * s)
{
  r_memclear_secure (s, sizeof (*s));
}

/* Jacobian doubling, generic short Weierstrass y^2 = x^3 + ax + b.
 * Z=0 input ("identity") propagates to Z=0 output because the new
 * Z' = 2*Y*Z is multiplied by Z; X' and Y' fall out as junk but the
 * Z=0 marker keeps the point classified as identity. */
static void
r_ecurve_jp_dbl (REcurveJacobianPoint * out, const REcurveJacobianPoint * P,
    const REcurveFEContext * ctx, REcurveJacobianScratch * s)
{
  REcurveFE * const XX   = &s->t[0];
  REcurveFE * const YY   = &s->t[1];
  REcurveFE * const YYYY = &s->t[2];
  REcurveFE * const ZZ   = &s->t[3];
  REcurveFE * const Z4   = &s->t[4];
  REcurveFE * const S    = &s->t[5];
  REcurveFE * const M    = &s->t[6];
  REcurveFE * const T    = &s->t[7];
  REcurveFE * const Znew = &s->t[8];
  REcurveFE * const Ynew = &s->t[9];
  REcurveFE * const tmp  = &s->t[10];

  /* All reads of P happen before any write to out, so aliasing out
   * with P is fine. */
  r_ecurve_fe_sqr_mont (XX, &P->X, ctx);
  r_ecurve_fe_sqr_mont (YY, &P->Y, ctx);
  r_ecurve_fe_sqr_mont (YYYY, YY, ctx);
  r_ecurve_fe_sqr_mont (ZZ, &P->Z, ctx);
  r_ecurve_fe_sqr_mont (Z4, ZZ, ctx);

  /* S = 4 * X * YY */
  r_ecurve_fe_mul_mont (tmp, &P->X, YY, ctx);
  r_ecurve_fe_add (S, tmp, tmp, ctx);
  r_ecurve_fe_add (S, S, S, ctx);

  /* M = 3 * XX + a * Z^4 */
  r_ecurve_fe_mul_mont (M, &ctx->mont_a, Z4, ctx);
  r_ecurve_fe_add (tmp, XX, XX, ctx);
  r_ecurve_fe_add (tmp, tmp, XX, ctx);
  r_ecurve_fe_add (M, M, tmp, ctx);

  /* T = M^2 - 2*S  ( = X' ) */
  r_ecurve_fe_sqr_mont (T, M, ctx);
  r_ecurve_fe_sub (T, T, S, ctx);
  r_ecurve_fe_sub (T, T, S, ctx);

  /* Y' = M * (S - T) - 8 * YYYY */
  r_ecurve_fe_sub (tmp, S, T, ctx);
  r_ecurve_fe_mul_mont (Ynew, M, tmp, ctx);
  r_ecurve_fe_add (tmp, YYYY, YYYY, ctx);
  r_ecurve_fe_add (tmp, tmp, tmp, ctx);
  r_ecurve_fe_add (tmp, tmp, tmp, ctx);
  r_ecurve_fe_sub (Ynew, Ynew, tmp, ctx);

  /* Z' = 2 * Y * Z. Reads of P->Y / P->Z happen before writes to
   * out->Y / out->Z, so the aliased case is safe. */
  r_ecurve_fe_mul_mont (Znew, &P->Y, &P->Z, ctx);
  r_ecurve_fe_add (Znew, Znew, Znew, ctx);

  r_ecurve_fe_copy (&out->X, T);
  r_ecurve_fe_copy (&out->Y, Ynew);
  r_ecurve_fe_copy (&out->Z, Znew);
}

/* Jacobian addition. Standard formula plus a branchless identity
 * fix-up: when either input has Z=0 the formula's output isn't the
 * correct sum (Z3 lands at 0 but X3,Y3 are garbage), so we mask in
 * the non-identity operand. The P == Q case is left intentionally
 * undefined here because the ladder invariant R1 = R0 + base_point
 * keeps R0 and R1 from ever coinciding (base_point != identity).
 * The P == -Q case is incidentally handled by the formula because
 * H = 0, R != 0 makes Z3 = 0. */
static void
r_ecurve_jp_add (REcurveJacobianPoint * out, const REcurveJacobianPoint * P,
    const REcurveJacobianPoint * Q, const REcurveFEContext * ctx,
    REcurveJacobianScratch * s)
{
  REcurveFE * const Z1Z1    = &s->t[0];
  REcurveFE * const Z2Z2    = &s->t[1];
  REcurveFE * const Z1cubed = &s->t[2];
  REcurveFE * const Z2cubed = &s->t[3];
  REcurveFE * const U1      = &s->t[4];
  REcurveFE * const U2      = &s->t[5];
  REcurveFE * const S1      = &s->t[6];
  REcurveFE * const S2      = &s->t[7];
  REcurveFE * const H       = &s->t[8];
  REcurveFE * const R       = &s->t[9];
  REcurveFE * const H2      = &s->t[10];
  REcurveFE * const H3      = &s->t[11];
  REcurveFE * const U1H2    = &s->t[12];
  REcurveFE * const X3      = &s->t[13];
  REcurveFE * const Y3      = &s->t[14];
  REcurveFE * const Z3      = &s->t[15];
  REcurveFE * const tmp     = &s->t[16];
  REcurveFE * const X_final = &s->t[17];
  REcurveFE * const Y_final = &s->t[18];
  REcurveFE * const Z_final = &s->t[19];
  ruint16 n = ctx->n_digits;
  rmpint_digit p_is_zero, q_is_zero;

  /* Identity probes computed up front, before the standard formula
   * trashes the operands' images in scratch. */
  p_is_zero = r_ecurve_fe_iszero_ct (&P->Z, n);
  q_is_zero = r_ecurve_fe_iszero_ct (&Q->Z, n);

  /* Standard formula. */
  r_ecurve_fe_sqr_mont (Z1Z1, &P->Z, ctx);
  r_ecurve_fe_sqr_mont (Z2Z2, &Q->Z, ctx);
  r_ecurve_fe_mul_mont (Z1cubed, &P->Z, Z1Z1, ctx);
  r_ecurve_fe_mul_mont (Z2cubed, &Q->Z, Z2Z2, ctx);

  r_ecurve_fe_mul_mont (U1, &P->X, Z2Z2, ctx);
  r_ecurve_fe_mul_mont (U2, &Q->X, Z1Z1, ctx);
  r_ecurve_fe_mul_mont (S1, &P->Y, Z2cubed, ctx);
  r_ecurve_fe_mul_mont (S2, &Q->Y, Z1cubed, ctx);

  r_ecurve_fe_sub (H, U2, U1, ctx);
  r_ecurve_fe_sub (R, S2, S1, ctx);

  r_ecurve_fe_sqr_mont (H2, H, ctx);
  r_ecurve_fe_mul_mont (H3, H, H2, ctx);
  r_ecurve_fe_mul_mont (U1H2, U1, H2, ctx);

  /* X3 = R^2 - H^3 - 2 * U1*H^2 */
  r_ecurve_fe_sqr_mont (X3, R, ctx);
  r_ecurve_fe_sub (X3, X3, H3, ctx);
  r_ecurve_fe_sub (X3, X3, U1H2, ctx);
  r_ecurve_fe_sub (X3, X3, U1H2, ctx);

  /* Y3 = R * (U1*H^2 - X3) - S1*H^3 */
  r_ecurve_fe_sub (tmp, U1H2, X3, ctx);
  r_ecurve_fe_mul_mont (Y3, R, tmp, ctx);
  r_ecurve_fe_mul_mont (tmp, S1, H3, ctx);
  r_ecurve_fe_sub (Y3, Y3, tmp, ctx);

  /* Z3 = Z1 * Z2 * H */
  r_ecurve_fe_mul_mont (Z3, &P->Z, &Q->Z, ctx);
  r_ecurve_fe_mul_mont (Z3, Z3, H, ctx);

  /* Identity fix-up: pick (computed; P; Q) per the (p,q) zero pair. */
  r_ecurve_fe_select_ct (X_final, q_is_zero, &P->X, X3, n);
  r_ecurve_fe_select_ct (Y_final, q_is_zero, &P->Y, Y3, n);
  r_ecurve_fe_select_ct (Z_final, q_is_zero, &P->Z, Z3, n);
  r_ecurve_fe_select_ct (X_final, p_is_zero, &Q->X, X_final, n);
  r_ecurve_fe_select_ct (Y_final, p_is_zero, &Q->Y, Y_final, n);
  r_ecurve_fe_select_ct (Z_final, p_is_zero, &Q->Z, Z_final, n);

  /* Assign last so out can safely alias P or Q. */
  r_ecurve_fe_copy (&out->X, X_final);
  r_ecurve_fe_copy (&out->Y, Y_final);
  r_ecurve_fe_copy (&out->Z, Z_final);
}

/* Jacobian -> affine: divide out the Z. Identity (Z=0) maps to
 * is_infinity = TRUE. The Z != 0 path costs one Fermat inversion +
 * a handful of field multiplications. */
static rboolean
r_ecurve_jp_to_affine (REcurveAffinePoint * out, const REcurveJacobianPoint * P,
    const REcurveFEContext * ctx)
{
  REcurveFE Z_inv, Z2_inv, Z3_inv, x_M, y_M, x_norm, y_norm;
  ruint16 n = ctx->n_digits;
  rboolean ok = TRUE;

  if (r_ecurve_fe_iszero_ct (&P->Z, n) != 0) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_ecurve_fe_invmod_mont (&Z_inv, &P->Z, ctx);
  r_ecurve_fe_sqr_mont (&Z2_inv, &Z_inv, ctx);
  r_ecurve_fe_mul_mont (&Z3_inv, &Z_inv, &Z2_inv, ctx);
  r_ecurve_fe_mul_mont (&x_M, &P->X, &Z2_inv, ctx);
  r_ecurve_fe_mul_mont (&y_M, &P->Y, &Z3_inv, ctx);
  r_ecurve_fe_mont_out (&x_norm, &x_M, ctx);
  r_ecurve_fe_mont_out (&y_norm, &y_M, ctx);

  if (!r_ecurve_fe_to_mpint (&out->x, &x_norm, n) ||
      !r_ecurve_fe_to_mpint (&out->y, &y_norm, n))
    ok = FALSE;
  out->is_infinity = FALSE;

  r_memclear_secure (&Z_inv, sizeof (Z_inv));
  r_memclear_secure (&Z2_inv, sizeof (Z2_inv));
  r_memclear_secure (&Z3_inv, sizeof (Z3_inv));
  r_memclear_secure (&x_M, sizeof (x_M));
  r_memclear_secure (&y_M, sizeof (y_M));
  return ok;
}

rboolean
r_ecurve_point_neg (REcurveAffinePoint * out, const REcurveAffinePoint * a,
    const REcurve * curve)
{
  if (a->is_infinity) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }
  r_mpint_set (&out->x, &a->x);
  /* y' = p - y, with the standing convention that y is already in
   * [0, p), so the subtraction is unsigned. y == 0 stays 0 (point is
   * its own inverse). */
  if (r_mpint_iszero (&a->y)) {
    r_mpint_zero (&out->y);
  } else if (!r_mpint_sub (&out->y, &curve->p, &a->y)) {
    return FALSE;
  }
  out->is_infinity = FALSE;
  return TRUE;
}

rboolean
r_ecurve_point_dbl (REcurveAffinePoint * out, const REcurveAffinePoint * a,
    const REcurve * curve)
{
  rmpint slope, t, num, den, x_new;
  rboolean ok;

  if (a->is_infinity || r_mpint_iszero (&a->y)) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_mpint_init (&slope);
  r_mpint_init (&t);
  r_mpint_init (&num);
  r_mpint_init (&den);
  r_mpint_init (&x_new);

  /* slope = (3 * x^2 + a) / (2 * y) mod p */
  ok = r_mpint_mulmod (&num, &a->x, &a->x, &curve->p) &&
       r_mpint_mul_u32 (&num, &num, 3) &&
       r_mpint_add (&num, &num, &curve->a) &&
       r_mpint_mod (&num, &num, &curve->p) &&
       r_mpint_mul_u32 (&den, &a->y, 2) &&
       r_mpint_mod (&den, &den, &curve->p) &&
       r_mpint_invmod (&den, &den, &curve->p) &&
       r_mpint_mulmod (&slope, &num, &den, &curve->p);
  if (!ok) goto out;

  /* X = slope^2 - 2 * x mod p. Reduce 2*x mod p first; otherwise the
   * intermediate slope^2 - 2x can land as low as -2p and a single
   * "add p if negative" leaves it negative, with r_mpint_mod then
   * treating the magnitude as positive and producing nonsense. */
  ok = r_mpint_mulmod (&x_new, &slope, &slope, &curve->p) &&
       r_mpint_mul_u32 (&t, &a->x, 2) &&
       r_mpint_mod (&t, &t, &curve->p) &&
       r_mpint_sub (&x_new, &x_new, &t);
  if (ok && r_mpint_isneg (&x_new))
    ok = r_mpint_add (&x_new, &x_new, &curve->p);
  if (!ok) goto out;

  /* Y = slope * (x - X) - y mod p — compute (x - X) first via the
   * same negative-then-add-p dance, then multiply and subtract y. */
  ok = r_mpint_sub (&t, &a->x, &x_new);
  if (ok && r_mpint_isneg (&t))
    ok = r_mpint_add (&t, &t, &curve->p);
  ok = ok &&
       r_mpint_mulmod (&t, &slope, &t, &curve->p) &&
       r_mpint_sub (&t, &t, &a->y);
  if (ok && r_mpint_isneg (&t))
    ok = r_mpint_add (&t, &t, &curve->p);
  ok = ok && r_mpint_mod (&t, &t, &curve->p);
  if (!ok) goto out;

  r_mpint_set (&out->x, &x_new);
  r_mpint_set (&out->y, &t);
  out->is_infinity = FALSE;

out:
  r_mpint_clear (&slope);
  r_mpint_clear (&t);
  r_mpint_clear (&num);
  r_mpint_clear (&den);
  r_mpint_clear (&x_new);
  return ok;
}

rboolean
r_ecurve_point_add (REcurveAffinePoint * out, const REcurveAffinePoint * a,
    const REcurveAffinePoint * b, const REcurve * curve)
{
  rmpint slope, t, num, den, x_new, neg_by;
  rboolean ok, y_neg;

  if (a->is_infinity) {
    r_ecurve_point_copy (out, b);
    return TRUE;
  }
  if (b->is_infinity) {
    r_ecurve_point_copy (out, a);
    return TRUE;
  }
  if (r_mpint_cmp (&a->x, &b->x) == 0) {
    /* Equal x: either P == Q (double) or P == -Q (infinity). */
    if (r_mpint_cmp (&a->y, &b->y) == 0)
      return r_ecurve_point_dbl (out, a, curve);
    /* y_b == -y_a (mod p) iff y_a + y_b == 0 (mod p). For points in
     * canonical form (y in [0, p)) this is equivalent to checking
     * y_a + y_b == p, which we approximate with the simpler "either
     * y_a == 0 and y_b == 0 (handled above by the y_a==y_b branch)
     * or y_b == p - y_a". */
    r_mpint_init (&neg_by);
    if (!r_mpint_sub (&neg_by, &curve->p, &a->y)) {
      r_mpint_clear (&neg_by);
      return FALSE;
    }
    y_neg = (r_mpint_cmp (&b->y, &neg_by) == 0);
    r_mpint_clear (&neg_by);
    if (y_neg) {
      r_ecurve_point_set_infinity (out);
      return TRUE;
    }
    /* Same x but neither equal nor negated — caller passed something
     * pathological that can't sit on a valid short-Weierstrass curve.
     * Refuse rather than produce nonsense. */
    return FALSE;
  }

  r_mpint_init (&slope);
  r_mpint_init (&t);
  r_mpint_init (&num);
  r_mpint_init (&den);
  r_mpint_init (&x_new);

  /* slope = (y_b - y_a) / (x_b - x_a) mod p; both subtractions handled
   * with the same negative-then-add-p pattern as dbl. */
  ok = r_mpint_sub (&num, &b->y, &a->y);
  if (ok && r_mpint_isneg (&num))
    ok = r_mpint_add (&num, &num, &curve->p);
  ok = ok && r_mpint_sub (&den, &b->x, &a->x);
  if (ok && r_mpint_isneg (&den))
    ok = r_mpint_add (&den, &den, &curve->p);
  ok = ok &&
       r_mpint_invmod (&den, &den, &curve->p) &&
       r_mpint_mulmod (&slope, &num, &den, &curve->p);
  if (!ok) goto out;

  /* X = slope^2 - x_a - x_b mod p */
  ok = r_mpint_mulmod (&x_new, &slope, &slope, &curve->p) &&
       r_mpint_sub (&x_new, &x_new, &a->x);
  if (ok && r_mpint_isneg (&x_new))
    ok = r_mpint_add (&x_new, &x_new, &curve->p);
  ok = ok && r_mpint_sub (&x_new, &x_new, &b->x);
  if (ok && r_mpint_isneg (&x_new))
    ok = r_mpint_add (&x_new, &x_new, &curve->p);
  ok = ok && r_mpint_mod (&x_new, &x_new, &curve->p);
  if (!ok) goto out;

  /* Y = slope * (x_a - X) - y_a mod p */
  ok = r_mpint_sub (&t, &a->x, &x_new);
  if (ok && r_mpint_isneg (&t))
    ok = r_mpint_add (&t, &t, &curve->p);
  ok = ok &&
       r_mpint_mulmod (&t, &slope, &t, &curve->p) &&
       r_mpint_sub (&t, &t, &a->y);
  if (ok && r_mpint_isneg (&t))
    ok = r_mpint_add (&t, &t, &curve->p);
  ok = ok && r_mpint_mod (&t, &t, &curve->p);
  if (!ok) goto out;

  r_mpint_set (&out->x, &x_new);
  r_mpint_set (&out->y, &t);
  out->is_infinity = FALSE;

out:
  r_mpint_clear (&slope);
  r_mpint_clear (&t);
  r_mpint_clear (&num);
  r_mpint_clear (&den);
  r_mpint_clear (&x_new);
  return ok;
}

rboolean
r_ecurve_point_is_on_curve (const REcurveAffinePoint * point,
    const REcurve * curve)
{
  rmpint lhs, rhs, t;
  rboolean ok;

  /* Infinity is on every curve by convention. */
  if (point->is_infinity)
    return TRUE;

  /* Coordinates must be in [0, p). */
  if (r_mpint_isneg (&point->x) || r_mpint_isneg (&point->y) ||
      r_mpint_cmp (&point->x, &curve->p) >= 0 ||
      r_mpint_cmp (&point->y, &curve->p) >= 0)
    return FALSE;

  r_mpint_init (&lhs);
  r_mpint_init (&rhs);
  r_mpint_init (&t);

  /* lhs = y^2 mod p; rhs = x^3 + a*x + b mod p */
  ok = r_mpint_mulmod (&lhs, &point->y, &point->y, &curve->p) &&
       r_mpint_mulmod (&rhs, &point->x, &point->x, &curve->p) &&
       r_mpint_mulmod (&rhs, &rhs, &point->x, &curve->p) &&
       r_mpint_mulmod (&t, &curve->a, &point->x, &curve->p) &&
       r_mpint_add (&rhs, &rhs, &t) &&
       r_mpint_add (&rhs, &rhs, &curve->b) &&
       r_mpint_mod (&rhs, &rhs, &curve->p);
  ok = ok && (r_mpint_cmp (&lhs, &rhs) == 0);

  r_mpint_clear (&lhs);
  r_mpint_clear (&rhs);
  r_mpint_clear (&t);
  return ok;
}

rboolean
r_ecurve_point_scalar_mul (REcurveAffinePoint * out, const rmpint * scalar,
    const REcurveAffinePoint * point, const REcurve * curve)
{
  /* Left-to-right Montgomery ladder in Jacobian-projective coords.
   * The ladder maintains R1 = R0 + P; per bit we swap R0/R1 in
   * constant time, perform a single "R1 = R0 + R1; R0 = 2*R0", and
   * swap back. Working in Jacobian removes the per-step inversion
   * that affine slope arithmetic required - we pay one Fermat
   * inversion at the end (in r_ecurve_jp_to_affine) instead of two
   * per bit, which is the property that makes the constant-time
   * Fermat inverter practical here.
   *
   * Scalar conditioning: instead of iterating bit_count(scalar) bits
   * (which would leak the scalar's bit length via the loop count and
   * also leak whether the scalar is zero via the fast-path branch),
   * precompute k' such that k' has a fixed bit_count(n)+1 bits and
   * k' === k (mod n). Then iterate exactly that fixed bit count.
   * The choice between k+n and k+2n is mask-selected on whether the
   * bit at position bit_count(n) of (k+n) is set: if it is, k+n has
   * the required extra bit and is used directly; otherwise k+n is
   * one bit short and we use k+2n, which (with n < 2^bit_count(n))
   * lands the high bit one position up by construction. Both
   * choices satisfy [k']P = [k]P since [n]P = [2n]P = identity.
   *
   * Identity is still encoded as Z=0; the Jacobian dbl propagates
   * that naturally, and r_ecurve_jp_add masks in the non-identity
   * operand when one side has Z=0 - so the leading-zero bits at the
   * start of k' (above its conditioned MSB) do not require value-
   * dependent branching. */
  REcurveFEContext ctx;
  REcurveFE x_norm, y_norm, one;
  REcurveJacobianPoint R0, R1;
  REcurveJacobianScratch scratch;
  /* Scalar conditioning needs literal multi-digit add (not mod p), so
   * use raw digit arrays sized to n+1 digits for k+n and k+2n. */
  rmpint_digit k1[R_ECURVE_FE_MAX_DIGITS + 1];
  rmpint_digit k2[R_ECURVE_FE_MAX_DIGITS + 1];
  rmpint_digit k_prime[R_ECURVE_FE_MAX_DIGITS + 1];
  ruint16 n, i, to_copy;
  ruint nbits, bp;
  ruint j;
  rmpint_word u;
  rmpint_digit bit, msb_set, mask, carry;
  rboolean ok = FALSE;

  /* point->is_infinity is public caller-side metadata - branching on
   * it doesn't leak anything sensitive. A zero scalar is handled
   * inside the ladder: conditioning maps k=0 to k' = 2n which has
   * the conditioned MSB set, the ladder runs the full iteration
   * count and lands at R0 = identity. */
  if (point->is_infinity) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  /* Build the FE context from the curve's precomputed rmpint
   * constants. This is a few digit copies per constant - much cheaper
   * than one ladder iteration. */
  n = r_mpint_digits_used (&curve->p);
  ctx.n_digits = n;
  ctx.mp = curve->mont_mp;
  ctx.p_minus_2_bits = r_mpint_bits_used (&curve->p_minus_2);
  ctx.n_bits = r_mpint_bits_used (&curve->n);
  r_ecurve_fe_from_mpint (&ctx.p, &curve->p, n);
  r_ecurve_fe_from_mpint (&ctx.mont_r_squared, &curve->mont_r_squared, n);
  r_ecurve_fe_from_mpint (&ctx.mont_a, &curve->mont_a, n);
  r_ecurve_fe_from_mpint (&ctx.p_minus_2, &curve->p_minus_2, n);
  r_ecurve_fe_from_mpint (&ctx.n, &curve->n, n);

  r_ecurve_jp_init (&R0);
  r_ecurve_jp_init (&R1);
  r_ecurve_jp_scratch_init (&scratch);

  /* R0 stays at identity (X=Y=Z=0). R1 is the input point lifted
   * into Jacobian Mont form: (x_M, y_M, 1_M), where 1_M = R mod p
   * is computed as mont_in(1). */
  r_ecurve_fe_from_mpint (&x_norm, &point->x, n);
  r_ecurve_fe_from_mpint (&y_norm, &point->y, n);
  r_ecurve_fe_mont_in (&R1.X, &x_norm, &ctx);
  r_ecurve_fe_mont_in (&R1.Y, &y_norm, &ctx);
  r_ecurve_fe_zero (&one);
  one.d[0] = 1;
  r_ecurve_fe_mont_in (&R1.Z, &one, &ctx);

  /* Condition the scalar in n+1 digit literal arithmetic (not mod p):
   *   k1 = k + n
   *   k2 = k + 2n
   * The mask-select picks whichever has its bit at position nbits set,
   * so k_prime ends up with exactly nbits+1 bits, MSB always 1. */
  nbits = ctx.n_bits;

  /* Copy scalar into k1[0..n], zero-padded. Truncating beyond n digits
   * is the documented "scalar in [0, 2^(32*n))" precondition; the only
   * way we lose info is if a caller passes a scalar exceeding that. */
  to_copy = scalar->dig_used;
  if (to_copy > n) to_copy = n;
  for (i = 0; i < to_copy; i++) k1[i] = scalar->data[i];
  for (i = to_copy; i < n + 1; i++) k1[i] = 0;

  /* k1 += n (literal n+1 digit add). */
  carry = 0;
  for (i = 0; i < n; i++) {
    u = (rmpint_word)k1[i] + (rmpint_word)ctx.n.d[i] + (rmpint_word)carry;
    k1[i] = (rmpint_digit)u;
    carry = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
  }
  u = (rmpint_word)k1[n] + (rmpint_word)carry;
  k1[n] = (rmpint_digit)u;

  /* k2 = k1 + n. */
  carry = 0;
  for (i = 0; i < n; i++) {
    u = (rmpint_word)k1[i] + (rmpint_word)ctx.n.d[i] + (rmpint_word)carry;
    k2[i] = (rmpint_digit)u;
    carry = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
  }
  u = (rmpint_word)k1[n] + (rmpint_word)carry;
  k2[n] = (rmpint_digit)u;

  /* Bit at position nbits of k1: if set, k1 already has nbits+1 bits;
   * else k2 does (because n < 2^nbits means 2n's top bit lands at
   * position nbits). */
  msb_set = (k1[nbits / (sizeof (rmpint_digit) * 8)] >>
             (nbits % (sizeof (rmpint_digit) * 8))) & 1u;
  mask = (rmpint_digit)0 - msb_set;
  for (i = 0; i < n + 1; i++)
    k_prime[i] = (k1[i] & mask) | (k2[i] & ~mask);

  /* Iterate exactly nbits + 1 bits, starting from the conditioned MSB
   * (always 1). */
  for (j = nbits + 1; j > 0; j--) {
    bp = j - 1;
    bit = (k_prime[bp / (sizeof (rmpint_digit) * 8)] >>
           (bp % (sizeof (rmpint_digit) * 8))) & 1u;

    r_ecurve_jp_swap_ct (&R0, &R1, (ruint32)bit, n);
    r_ecurve_jp_add (&R1, &R0, &R1, &ctx, &scratch);
    r_ecurve_jp_dbl (&R0, &R0, &ctx, &scratch);
    r_ecurve_jp_swap_ct (&R0, &R1, (ruint32)bit, n);
  }

  if (r_ecurve_jp_to_affine (out, &R0, &ctx))
    ok = TRUE;

  r_memclear_secure (k1, sizeof (k1));
  r_memclear_secure (k2, sizeof (k2));
  r_memclear_secure (k_prime, sizeof (k_prime));
  r_memclear_secure (&x_norm, sizeof (x_norm));
  r_memclear_secure (&y_norm, sizeof (y_norm));
  r_memclear_secure (&ctx, sizeof (ctx));
  r_ecurve_jp_scratch_clear (&scratch);
  r_ecurve_jp_clear (&R0);
  r_ecurve_jp_clear (&R1);
  return ok;
}

rboolean
r_ecurve_point_to_uncompressed (const REcurveAffinePoint * point,
    const REcurve * curve, ruint8 * out, rsize * outsize)
{
  rsize need;

  if (R_UNLIKELY (point == NULL || curve == NULL ||
        out == NULL || outsize == NULL))
    return FALSE;

  if (point->is_infinity) {
    if (*outsize < 1) return FALSE;
    out[0] = 0x00;
    *outsize = 1;
    return TRUE;
  }

  need = 1 + 2 * curve->coord_bytes;
  if (*outsize < need)
    return FALSE;

  out[0] = 0x04;
  if (!r_mpint_to_binary_with_size (&point->x, out + 1, curve->coord_bytes) ||
      !r_mpint_to_binary_with_size (&point->y, out + 1 + curve->coord_bytes,
          curve->coord_bytes))
    return FALSE;
  *outsize = need;
  return TRUE;
}

rboolean
r_ecurve_point_from_uncompressed (const ruint8 * in, rsize insize,
    const REcurve * curve, REcurveAffinePoint * out)
{
  if (R_UNLIKELY (in == NULL || curve == NULL || out == NULL))
    return FALSE;

  if (insize == 1 && in[0] == 0x00) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  if (insize != 1 + 2 * curve->coord_bytes || in[0] != 0x04)
    return FALSE;

  r_mpint_set_binary (&out->x, in + 1, curve->coord_bytes);
  r_mpint_set_binary (&out->y, in + 1 + curve->coord_bytes, curve->coord_bytes);
  out->is_infinity = FALSE;

  if (!r_ecurve_point_is_on_curve (out, curve)) {
    r_ecurve_point_set_infinity (out);
    return FALSE;
  }
  return TRUE;
}

rboolean
r_ecurve_id_from_oid (REcurveID * curve,
    rconstpointer oid, rsize oidsize)
{
  if (R_UNLIKELY (curve == NULL)) return FALSE;
  if (R_UNLIKELY (oid == NULL)) return FALSE;
  if (R_UNLIKELY (oidsize == 0)) return FALSE;

  if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP192R1))
    *curve = R_ECURVE_ID_SECP192R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP256R1))
    *curve = R_ECURVE_ID_SECP256R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP224R1))
    *curve = R_ECURVE_ID_SECP224R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP384R1))
    *curve = R_ECURVE_ID_SECP384R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP521R1))
    *curve = R_ECURVE_ID_SECP521R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP192K1))
    *curve = R_ECURVE_ID_SECP192K1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP224K1))
    *curve = R_ECURVE_ID_SECP224K1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP256K1))
    *curve = R_ECURVE_ID_SECP256K1;
  else
    return FALSE;

  return TRUE;
}
