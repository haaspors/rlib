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

/* --- Internal Montgomery-form field arithmetic. Used by the
 * constant-time scalar-mul ladder. All inputs/outputs are mpints
 * in Montgomery form (value * R mod p) unless otherwise noted.
 * The curve's precomputed mont_mp / mont_r_squared / mont_a are
 * the per-curve setup values. --- */

/* CT zero-check across a fixed n-digit prefix of a's buffer. Returns
 * an all-ones rmpint_digit mask if every digit is zero, an all-zeros
 * mask otherwise. Reads exactly n digits regardless of a->dig_used,
 * so the test does not leak the operand's bit length. Caller must
 * ensure a->dig_alloc >= n. */
static rmpint_digit
r_mpint_iszero_n_ct (const rmpint * a, ruint16 n)
{
  ruint16 i;
  rmpint_digit acc = 0;
  rmpint_digit nz;

  for (i = 0; i < n; i++)
    acc |= a->data[i];
  /* (acc | -acc) has its top bit set iff acc != 0. Shift down to a
   * single 0/1 in nz, then nz - 1 gives all-ones if zero, 0 if not. */
  nz = (acc | ((rmpint_digit)0 - acc)) >> (sizeof (rmpint_digit) * 8 - 1);
  return nz - (rmpint_digit)1;
}

/* CT digit-wise select: out := (mask == all-ones) ? a : b, over the
 * first n digits of each input. Output is left with dig_used = n and
 * no clamp (so the dig_used itself is value-independent). Caller
 * ensures a, b, out have dig_alloc >= n. */
static void
r_mpint_select_n_ct (rmpint * out, rmpint_digit mask,
    const rmpint * a, const rmpint * b, ruint16 n)
{
  ruint16 i;

  r_mpint_ensure_digits (out, n);
  for (i = 0; i < n; i++)
    out->data[i] = (a->data[i] & mask) | (b->data[i] & ~mask);
  for (i = n; i < out->dig_alloc; i++)
    out->data[i] = 0;
  out->dig_used = n;
  out->sign = 0;
}

/* "if a >= p, a := a - p". Branchless XOR-select, but ends with a
 * value-dependent r_mpint_clamp - the result's bit-length leaks
 * via dig_used, which the rest of the mpint API depends on for
 * its no-leading-zeros invariant (r_mpint_cmp returns non-zero
 * for values that are equal-but-padded). A future constant-time
 * memory-access pass should revisit. */
static void
r_ecurve_cond_subp_ct (rmpint * a, const rmpint * p)
{
  ruint16 x, n;
  rmpint_digit borrow, mask;
  rmpint_digit * scratch;
  rmpint_word t;

  n = r_mpint_digits_used (p);
  r_mpint_ensure_digits (a, n + 1);
  for (x = a->dig_used; x < n + 1; x++)
    a->data[x] = 0;
  a->dig_used = n + 1;
  a->sign = 0;

  scratch = r_alloca ((n + 1) * sizeof (rmpint_digit));
  borrow = 0;
  for (x = 0; x < n; x++) {
    t = (rmpint_word)a->data[x] -
        (rmpint_word)r_mpint_get_digit (p, x) -
        (rmpint_word)borrow;
    scratch[x] = (rmpint_digit)t;
    borrow = (rmpint_digit)((t >> (sizeof (rmpint_digit) * 8)) & 1u);
  }
  t = (rmpint_word)a->data[n] - (rmpint_word)borrow;
  scratch[n] = (rmpint_digit)t;
  borrow = (rmpint_digit)((t >> (sizeof (rmpint_digit) * 8)) & 1u);

  mask = (rmpint_digit)0 - (rmpint_digit)((borrow & 1u) ^ 1u);
  for (x = 0; x < n + 1; x++)
    a->data[x] = (a->data[x] & ~mask) | (scratch[x] & mask);

  r_mpint_clamp (a);
  r_memclear_secure (scratch, (n + 1) * sizeof (rmpint_digit));
}

/* out := a * b * R^-1 mod p. If a and b are in Montgomery form,
 * out is in Montgomery form too. */
static rboolean
r_ecurve_mont_mul (rmpint * out, const rmpint * a, const rmpint * b,
    const REcurve * curve)
{
  return r_mpint_mul (out, a, b) &&
         r_mpint_montgomery_reduce_ct (out, &curve->p, curve->mont_mp);
}

/* out := a^2 * R^-1 mod p. */
static rboolean
r_ecurve_mont_sqr (rmpint * out, const rmpint * a, const REcurve * curve)
{
  return r_ecurve_mont_mul (out, a, a, curve);
}

/* out := (a + b) mod p. Inputs may be in Montgomery form or normal -
 * addition commutes with the Montgomery transform. */
static rboolean
r_ecurve_mont_add (rmpint * out, const rmpint * a, const rmpint * b,
    const REcurve * curve)
{
  if (!r_mpint_add (out, a, b))
    return FALSE;
  r_ecurve_cond_subp_ct (out, &curve->p);
  return TRUE;
}

/* out := (a - b) mod p. Computed as (a + p - b) so the intermediate
 * never goes negative; then a constant-time conditional subtract of
 * p brings it back into [0, p). r_mpint_add / _sub iterate digits
 * and write each output position after reading the matching input
 * digits, so the in-place form is safe when out aliases a or b. */
static rboolean
r_ecurve_mont_sub (rmpint * out, const rmpint * a, const rmpint * b,
    const REcurve * curve)
{
  if (!r_mpint_add (out, a, &curve->p) ||
      !r_mpint_sub (out, out, b))
    return FALSE;
  r_ecurve_cond_subp_ct (out, &curve->p);
  return TRUE;
}

/* out := a * R mod p. Lifts a normal-form value into Montgomery
 * form via one Montgomery multiplication with R^2. */
static rboolean
r_ecurve_mont_in (rmpint * out, const rmpint * a, const REcurve * curve)
{
  return r_ecurve_mont_mul (out, a, &curve->mont_r_squared, curve);
}

/* out := a / R mod p. Drops a Montgomery-form value back to normal
 * form via Montgomery reduction. */
static rboolean
r_ecurve_mont_out (rmpint * out, const rmpint * a, const REcurve * curve)
{
  if (out != a)
    r_mpint_set (out, a);
  return r_mpint_montgomery_reduce_ct (out, &curve->p, curve->mont_mp);
}

/* out_M := base_M^exp in Montgomery form. base is already in
 * Montgomery form on entry; out is in Montgomery form on exit
 * (i.e. (base_actual^exp) * R mod p).
 *
 * Left-to-right Montgomery ladder over the exponent bits, with the
 * per-bit dispatch routed through r_mpint_swap_ct so cache and
 * branch behaviour stay independent of the bit being processed.
 * The CT Montgomery reduce keeps the per-iteration field ops
 * branch-free on the secret base too. The exponent here is
 * curve->p_minus_2 (a public per-curve constant), so timing
 * variation in exp itself - bit length, set-bit count - is fine;
 * what matters is that the secret base's bit pattern doesn't
 * influence control flow.
 *
 * Invariant after each iteration: R[1] = R[0] * base_M (in
 * Montgomery form). Starting from R[0] = 1_M, R[1] = base_M, the
 * pair evolves so R[0] = base_M^(exp_bits_seen) at the end. */
static rboolean
r_ecurve_mont_expmod (rmpint * out, const rmpint * base_M,
    const rmpint * exp, const REcurve * curve)
{
  rmpint R[2];
  ruint16 didx, bidx;
  rmpint_digit bit;
  rboolean ok = FALSE;

  r_mpint_init_from (&R[0], base_M, &curve->p, NULL);
  r_mpint_init_from (&R[1], base_M, &curve->p, NULL);

  /* R[0] = 1 in Montgomery form (= R mod p). R[1] = base_M. */
  if (!r_mpint_montgomery_normalize (&R[0], &curve->p))
    goto cleanup;
  r_mpint_set (&R[1], base_M);

  for (didx = r_mpint_digits_used (exp); didx > 0; didx--) {
    rmpint_digit dig = r_mpint_get_digit (exp, didx - 1);
    for (bidx = 0; bidx < sizeof (rmpint_digit) * 8; bidx++) {
      bit = (dig >> (sizeof (rmpint_digit) * 8 - 1)) & 1;
      dig <<= 1;

      /* swap-wrap routes the conventional
       *   if (bit) { R[0] = R[0]*R[1]; R[1] = R[1]^2; }
       *   else     { R[1] = R[0]*R[1]; R[0] = R[0]^2; }
       * through a fixed sequence: swap, do the bit=0 branch, swap
       * back. See r_ecurve_point_scalar_mul for the same pattern
       * on the EC ladder. */
      r_mpint_swap_ct (&R[0], &R[1], (ruint32)bit);
      if (!r_ecurve_mont_mul (&R[1], &R[0], &R[1], curve) ||
          !r_ecurve_mont_sqr (&R[0], &R[0], curve))
        goto cleanup;
      r_mpint_swap_ct (&R[0], &R[1], (ruint32)bit);
    }
  }

  r_mpint_set (out, &R[0]);
  ok = TRUE;
cleanup:
  r_mpint_clear (&R[0]);
  r_mpint_clear (&R[1]);
  return ok;
}

/* out_M := (a_M)^-1 in Montgomery form, via Fermat's little
 * theorem: for a in (Z/pZ)*, a^(p-1) = 1, so a^-1 = a^(p-2).
 *
 * Running the exponentiation directly in the Montgomery domain
 * keeps the operand in Montgomery form throughout - no detour
 * through normal form + r_mpint_mulmod, both of which are
 * variable-time on the secret value. */
static rboolean
r_ecurve_mont_invmod (rmpint * out, const rmpint * a, const REcurve * curve)
{
  return r_ecurve_mont_expmod (out, a, &curve->p_minus_2, curve);
}

/* --- Internal Jacobian-projective point arithmetic, used inside
 * the scalar-mul ladder. A Jacobian point (X, Y, Z) represents the
 * affine point (X/Z^2, Y/Z^3), with Z=0 marking the identity. All
 * coordinates are stored in Montgomery form. Working in projective
 * coords keeps the per-step cost at a few field multiplications
 * (no inversion), so the single Fermat-based inversion at the end
 * for the affine conversion is amortised over all bits of the
 * scalar. --- */

typedef struct {
  rmpint X;
  rmpint Y;
  rmpint Z;
} REcurveJacobianPoint;

/* Pre-allocated scratch pool used by the Jacobian dbl + add. The
 * mpints live for the duration of one scalar_mul - allocating them
 * here once and reusing across all ~521 ladder steps avoids the
 * malloc / free churn the per-call init / clear pattern would
 * otherwise incur (the secure-clear flag makes that churn even more
 * expensive: each free zeroes the digit buffer before releasing).
 *
 * The 21 slots cover the worst case (r_ecurve_jp_add); the dbl
 * uses the first 11 under different aliases. Keeping a single pool
 * shared between the two operations keeps the scalar_mul setup
 * compact - the alternative is two separate scratch structs which
 * would duplicate the per-call buffer pressure. */
typedef struct {
  rmpint t[21];
} REcurveJacobianScratch;

static void
r_ecurve_jp_scratch_init (REcurveJacobianScratch * s)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (s->t); i++)
    r_mpint_init_secure (&s->t[i]);
}

static void
r_ecurve_jp_scratch_clear (REcurveJacobianScratch * s)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (s->t); i++)
    r_mpint_clear (&s->t[i]);
}

static void
r_ecurve_jp_init (REcurveJacobianPoint * P)
{
  /* Inherit secure-clear so any intermediate the ladder accumulates
   * gets wiped on r_mpint_clear, just like the affine point lifecycle. */
  r_mpint_init_secure (&P->X);
  r_mpint_init_secure (&P->Y);
  r_mpint_init_secure (&P->Z);
}

static void
r_ecurve_jp_clear (REcurveJacobianPoint * P)
{
  r_mpint_clear (&P->X);
  r_mpint_clear (&P->Y);
  r_mpint_clear (&P->Z);
}

static void
r_ecurve_jp_swap_ct (REcurveJacobianPoint * a, REcurveJacobianPoint * b,
    ruint32 bit)
{
  r_mpint_swap_ct (&a->X, &b->X, bit);
  r_mpint_swap_ct (&a->Y, &b->Y, bit);
  r_mpint_swap_ct (&a->Z, &b->Z, bit);
}

/* Jacobian doubling, generic short Weierstrass y^2 = x^3 + ax + b.
 * Z=0 input ("identity") propagates to Z=0 output because the new
 * Z' = 2*Y*Z is multiplied by Z; X' and Y' fall out as junk but the
 * Z=0 marker keeps the point classified as identity, so callers
 * don't have to special-case it. */
static rboolean
r_ecurve_jp_dbl (REcurveJacobianPoint * out,
    const REcurveJacobianPoint * P, const REcurve * curve,
    REcurveJacobianScratch * s)
{
  rmpint * const XX   = &s->t[0];
  rmpint * const YY   = &s->t[1];
  rmpint * const YYYY = &s->t[2];
  rmpint * const ZZ   = &s->t[3];
  rmpint * const Z4   = &s->t[4];
  rmpint * const S    = &s->t[5];
  rmpint * const M    = &s->t[6];
  rmpint * const T    = &s->t[7];
  rmpint * const Znew = &s->t[8];
  rmpint * const Ynew = &s->t[9];
  rmpint * const tmp  = &s->t[10];

  /* All reads of P happen before any write to out, so out aliasing P
   * is fine. */
  if (!r_ecurve_mont_sqr (XX,   &P->X, curve))   return FALSE; /* X^2 */
  if (!r_ecurve_mont_sqr (YY,   &P->Y, curve))   return FALSE; /* Y^2 */
  if (!r_ecurve_mont_sqr (YYYY, YY,    curve))   return FALSE; /* Y^4 */
  if (!r_ecurve_mont_sqr (ZZ,   &P->Z, curve))   return FALSE; /* Z^2 */
  if (!r_ecurve_mont_sqr (Z4,   ZZ,    curve))   return FALSE; /* Z^4 */

  /* S = 4 * X * YY */
  if (!r_ecurve_mont_mul (tmp, &P->X, YY,  curve)) return FALSE;
  if (!r_ecurve_mont_add (S,   tmp,   tmp, curve)) return FALSE;
  if (!r_ecurve_mont_add (S,   S,     S,   curve)) return FALSE;

  /* M = 3 * XX + a * Z^4 */
  if (!r_ecurve_mont_mul (M,   &curve->mont_a, Z4, curve)) return FALSE;
  if (!r_ecurve_mont_add (tmp, XX, XX, curve))             return FALSE;
  if (!r_ecurve_mont_add (tmp, tmp, XX, curve))            return FALSE;
  if (!r_ecurve_mont_add (M,   M, tmp, curve))             return FALSE;

  /* T = M^2 - 2*S  ( = X' ) */
  if (!r_ecurve_mont_sqr (T, M, curve))     return FALSE;
  if (!r_ecurve_mont_sub (T, T, S, curve))  return FALSE;
  if (!r_ecurve_mont_sub (T, T, S, curve))  return FALSE;

  /* Y' = M * (S - T) - 8 * YYYY */
  if (!r_ecurve_mont_sub (tmp,  S, T, curve))     return FALSE;
  if (!r_ecurve_mont_mul (Ynew, M, tmp, curve))   return FALSE;
  if (!r_ecurve_mont_add (tmp,  YYYY, YYYY, curve)) return FALSE;
  if (!r_ecurve_mont_add (tmp,  tmp, tmp, curve))   return FALSE;
  if (!r_ecurve_mont_add (tmp,  tmp, tmp, curve))   return FALSE;
  if (!r_ecurve_mont_sub (Ynew, Ynew, tmp, curve))  return FALSE;

  /* Z' = 2 * Y * Z. Must read P->Y / P->Z before writing out->Y / out->Z
   * (matters when out aliases P). */
  if (!r_ecurve_mont_mul (Znew, &P->Y, &P->Z, curve)) return FALSE;
  if (!r_ecurve_mont_add (Znew, Znew, Znew, curve))   return FALSE;

  r_mpint_set (&out->X, T);
  r_mpint_set (&out->Y, Ynew);
  r_mpint_set (&out->Z, Znew);

  return TRUE;
}

/* Jacobian addition. Standard formula plus a branchless identity
 * fix-up: when either input has Z=0 the formula's output isn't the
 * correct sum (Z3 lands at 0 but X3,Y3 are garbage), so we mask in
 * the non-identity operand. The P == Q case is left intentionally
 * undefined here because the ladder invariant R1 = R0 + base_point
 * keeps R0 and R1 from ever coinciding (base_point != identity).
 * The P == -Q case (R1 - R0 = base_point != 0 means this can't
 * happen either) is incidentally handled by the formula because
 * H = 0, R != 0 makes Z3 = 0. */
static rboolean
r_ecurve_jp_add (REcurveJacobianPoint * out,
    const REcurveJacobianPoint * P, const REcurveJacobianPoint * Q,
    const REcurve * curve, REcurveJacobianScratch * s)
{
  rmpint * const Z1Z1    = &s->t[0];
  rmpint * const Z2Z2    = &s->t[1];
  rmpint * const Z1cubed = &s->t[2];
  rmpint * const Z2cubed = &s->t[3];
  rmpint * const U1      = &s->t[4];
  rmpint * const U2      = &s->t[5];
  rmpint * const S1      = &s->t[6];
  rmpint * const S2      = &s->t[7];
  rmpint * const H       = &s->t[8];
  rmpint * const R       = &s->t[9];
  rmpint * const H2      = &s->t[10];
  rmpint * const H3      = &s->t[11];
  rmpint * const U1H2    = &s->t[12];
  rmpint * const X3      = &s->t[13];
  rmpint * const Y3      = &s->t[14];
  rmpint * const Z3      = &s->t[15];
  rmpint * const tmp     = &s->t[16];
  rmpint * const X_final = &s->t[17];
  rmpint * const Y_final = &s->t[18];
  rmpint * const Z_final = &s->t[19];
  rmpint_digit p_is_zero, q_is_zero;
  ruint16 n;

  n = r_mpint_digits_used (&curve->p);

  /* Identity probes are computed up front so they reflect the state
   * of the operands before the standard formula trashes intermediate
   * buffers. The +1 covers the fixed-width Montgomery representation
   * that r_mpint_montgomery_reduce_ct produces (n + 1 digits, low end
   * padded with zeros for a true zero). */
  p_is_zero = r_mpint_iszero_n_ct (&P->Z, (ruint16)(n + 1));
  q_is_zero = r_mpint_iszero_n_ct (&Q->Z, (ruint16)(n + 1));

  /* Standard formula: U1 = X1*Z2^2, U2 = X2*Z1^2, S1 = Y1*Z2^3,
   * S2 = Y2*Z1^3, H = U2 - U1, R = S2 - S1. */
  if (!r_ecurve_mont_sqr (Z1Z1, &P->Z, curve))            return FALSE;
  if (!r_ecurve_mont_sqr (Z2Z2, &Q->Z, curve))            return FALSE;
  if (!r_ecurve_mont_mul (Z1cubed, &P->Z, Z1Z1, curve))   return FALSE;
  if (!r_ecurve_mont_mul (Z2cubed, &Q->Z, Z2Z2, curve))   return FALSE;

  if (!r_ecurve_mont_mul (U1, &P->X, Z2Z2, curve))         return FALSE;
  if (!r_ecurve_mont_mul (U2, &Q->X, Z1Z1, curve))         return FALSE;
  if (!r_ecurve_mont_mul (S1, &P->Y, Z2cubed, curve))      return FALSE;
  if (!r_ecurve_mont_mul (S2, &Q->Y, Z1cubed, curve))      return FALSE;

  if (!r_ecurve_mont_sub (H, U2, U1, curve))   return FALSE;
  if (!r_ecurve_mont_sub (R, S2, S1, curve))   return FALSE;

  if (!r_ecurve_mont_sqr (H2, H, curve))             return FALSE;
  if (!r_ecurve_mont_mul (H3, H, H2, curve))         return FALSE;
  if (!r_ecurve_mont_mul (U1H2, U1, H2, curve))      return FALSE;

  /* X3 = R^2 - H^3 - 2 * U1*H^2 */
  if (!r_ecurve_mont_sqr (X3, R, curve))             return FALSE;
  if (!r_ecurve_mont_sub (X3, X3, H3, curve))        return FALSE;
  if (!r_ecurve_mont_sub (X3, X3, U1H2, curve))      return FALSE;
  if (!r_ecurve_mont_sub (X3, X3, U1H2, curve))      return FALSE;

  /* Y3 = R * (U1*H^2 - X3) - S1*H^3 */
  if (!r_ecurve_mont_sub (tmp, U1H2, X3, curve))    return FALSE;
  if (!r_ecurve_mont_mul (Y3, R, tmp, curve))       return FALSE;
  if (!r_ecurve_mont_mul (tmp, S1, H3, curve))      return FALSE;
  if (!r_ecurve_mont_sub (Y3, Y3, tmp, curve))      return FALSE;

  /* Z3 = Z1 * Z2 * H */
  if (!r_ecurve_mont_mul (Z3, &P->Z, &Q->Z, curve))   return FALSE;
  if (!r_ecurve_mont_mul (Z3, Z3, H, curve))          return FALSE;

  /* Identity fix-up via masked select:
   *   X_final = q_is_zero ? P.X : X3;     (then) p_is_zero ? Q.X : X_final
   *   ... same for Y, Z.
   * The double pass correctly handles all four (p, q) identity
   * combinations: see the case table in this function's docstring. */
  r_mpint_select_n_ct (X_final, q_is_zero, &P->X, X3, (ruint16)(n + 1));
  r_mpint_select_n_ct (Y_final, q_is_zero, &P->Y, Y3, (ruint16)(n + 1));
  r_mpint_select_n_ct (Z_final, q_is_zero, &P->Z, Z3, (ruint16)(n + 1));
  r_mpint_select_n_ct (X_final, p_is_zero, &Q->X, X_final, (ruint16)(n + 1));
  r_mpint_select_n_ct (Y_final, p_is_zero, &Q->Y, Y_final, (ruint16)(n + 1));
  r_mpint_select_n_ct (Z_final, p_is_zero, &Q->Z, Z_final, (ruint16)(n + 1));

  /* Assign last so out can safely alias P or Q. */
  r_mpint_set (&out->X, X_final);
  r_mpint_set (&out->Y, Y_final);
  r_mpint_set (&out->Z, Z_final);

  return TRUE;
}

/* Jacobian -> affine: divide out the Z. Identity (Z=0) maps to
 * is_infinity = TRUE. The Z != 0 path costs one Fermat inversion +
 * a handful of field multiplications. */
static rboolean
r_ecurve_jp_to_affine (REcurveAffinePoint * out,
    const REcurveJacobianPoint * P, const REcurve * curve)
{
  rmpint Z_inv, Z2_inv, Z3_inv, x_M, y_M;
  ruint16 n = r_mpint_digits_used (&curve->p);
  rboolean ok = FALSE;

  if (r_mpint_iszero_n_ct (&P->Z, (ruint16)(n + 1)) != 0) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_mpint_init_secure (&Z_inv);
  r_mpint_init_secure (&Z2_inv);
  r_mpint_init_secure (&Z3_inv);
  r_mpint_init_secure (&x_M);
  r_mpint_init_secure (&y_M);

  if (!r_ecurve_mont_invmod (&Z_inv, &P->Z, curve))             goto cleanup;
  if (!r_ecurve_mont_sqr (&Z2_inv, &Z_inv, curve))              goto cleanup;
  if (!r_ecurve_mont_mul (&Z3_inv, &Z_inv, &Z2_inv, curve))     goto cleanup;
  if (!r_ecurve_mont_mul (&x_M, &P->X, &Z2_inv, curve))         goto cleanup;
  if (!r_ecurve_mont_mul (&y_M, &P->Y, &Z3_inv, curve))         goto cleanup;
  if (!r_ecurve_mont_out (&out->x, &x_M, curve))                goto cleanup;
  if (!r_ecurve_mont_out (&out->y, &y_M, curve))                goto cleanup;
  out->is_infinity = FALSE;
  ok = TRUE;

cleanup:
  r_mpint_clear (&Z_inv);
  r_mpint_clear (&Z2_inv);
  r_mpint_clear (&Z3_inv);
  r_mpint_clear (&x_M);
  r_mpint_clear (&y_M);
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
  REcurveJacobianPoint R0, R1;
  REcurveJacobianScratch scratch;
  rmpint k1, k2, k_prime;
  ruint16 niter_digits, dig_bound, i;
  ruint nbits, bp, j;
  rmpint_digit bit, msb_set, mask;
  rboolean ok = FALSE;

  /* point->is_infinity is a public flag (caller-side metadata), so
   * branching on it doesn't leak anything sensitive. The scalar
   * fast-path is handled inside the ladder: a zero scalar produces
   * a k' = 2n with bit at position bit_count(n) set; the ladder
   * runs the full iteration count and lands at R0 = identity. */
  if (point->is_infinity) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_ecurve_jp_init (&R0);
  r_ecurve_jp_init (&R1);
  r_ecurve_jp_scratch_init (&scratch);
  r_mpint_init_secure (&k1);
  r_mpint_init_secure (&k2);
  r_mpint_init_secure (&k_prime);

  /* R0 stays at identity (X=Y=Z=0 from init; Z=0 marks it). R1 is
   * the input point lifted into Jacobian: (x_M, y_M, 1_M), where
   * 1_M = R mod p is what r_mpint_montgomery_normalize produces. */
  if (!r_ecurve_mont_in (&R1.X, &point->x, curve) ||
      !r_ecurve_mont_in (&R1.Y, &point->y, curve) ||
      !r_mpint_montgomery_normalize (&R1.Z, &curve->p))
    goto cleanup;

  /* Condition the scalar. niter_digits + 1 covers the worst case for
   * either candidate (k + 2n < 3n always fits in n.dig_used + 1
   * digits for the curves we ship). */
  niter_digits = r_mpint_digits_used (&curve->n);
  nbits = r_mpint_bits_used (&curve->n);
  dig_bound = (ruint16)(niter_digits + 1);

  if (!r_mpint_add (&k1, scalar, &curve->n) ||
      !r_mpint_add (&k2, &k1, &curve->n))
    goto cleanup;

  /* Force fixed width so the select + bit extraction below read a
   * known number of digits regardless of the operand's actual value. */
  r_mpint_ensure_digits (&k1, dig_bound);
  r_mpint_ensure_digits (&k2, dig_bound);
  for (i = k1.dig_used; i < dig_bound; i++) k1.data[i] = 0;
  for (i = k2.dig_used; i < dig_bound; i++) k2.data[i] = 0;
  k1.dig_used = dig_bound;
  k2.dig_used = dig_bound;

  /* mask = all-ones if bit at position nbits of k1 is set (use k1),
   * else all-zeros (use k2). */
  msb_set = (k1.data[nbits / (sizeof (rmpint_digit) * 8)] >>
             (nbits % (sizeof (rmpint_digit) * 8))) & 1u;
  mask = (rmpint_digit)0 - msb_set;
  r_mpint_select_n_ct (&k_prime, mask, &k1, &k2, dig_bound);

  /* Iterate exactly nbits + 1 bits (the fixed bit count of k'),
   * starting from the conditioned MSB which is always 1. */
  for (j = nbits + 1; j > 0; j--) {
    bp = j - 1;
    bit = (k_prime.data[bp / (sizeof (rmpint_digit) * 8)] >>
           (bp % (sizeof (rmpint_digit) * 8))) & 1u;

    r_ecurve_jp_swap_ct (&R0, &R1, (ruint32)bit);
    if (!r_ecurve_jp_add (&R1, &R0, &R1, curve, &scratch)) goto cleanup;
    if (!r_ecurve_jp_dbl (&R0, &R0, curve, &scratch))      goto cleanup;
    r_ecurve_jp_swap_ct (&R0, &R1, (ruint32)bit);
  }

  if (!r_ecurve_jp_to_affine (out, &R0, curve))
    goto cleanup;
  ok = TRUE;

cleanup:
  r_mpint_clear (&k1);
  r_mpint_clear (&k2);
  r_mpint_clear (&k_prime);
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
