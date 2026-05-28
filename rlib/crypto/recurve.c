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

#include <rlib/format/roid.h>
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

/* --- Internal ECC field-element context and Jacobian point arithmetic.
 * The underlying fixed-width Montgomery primitives (RMpintFE,
 * r_mpint_fe_*) live in rmpint-private.h; here we just stash the
 * ECC-specific overlay - the precomputed Mont form of the curve
 * coefficient a, the order n (for scalar conditioning), and the
 * Fermat exponent (p - 2). The context is built fresh at the top of
 * scalar_mul so the public REcurve struct doesn't have to expose any
 * of this. --- */

typedef struct {
  RMpintFEMontCtx mont;       /* p, mp, n_digits */
  RMpintFE mont_r_squared;    /* R^2 mod p, used for Mont in/out */
  RMpintFE mont_a;            /* a * R mod p, used by the Jacobian dbl */
  RMpintFE p_minus_2;         /* Fermat exponent for inversion */
  RMpintFE n;                 /* group order, used by scalar conditioning */
  ruint p_minus_2_bits;       /* bit length of p-2, drives the Fermat loop */
  ruint n_bits;               /* bit length of group order */
} REcurveFEContext;

/* Scratch pool used by the Jacobian dbl + add. Allocated as a single
 * struct on the scalar_mul stack frame so the FE temporaries survive
 * across all ladder iterations without per-call setup cost. 21 slots
 * cover the wider operation (r_ecurve_jp_add); jp_dbl reuses the
 * first 11 under different aliases. */
typedef struct {
  RMpintFE t[21];
} REcurveJacobianScratch;

/* Jacobian-projective point. (X, Y, Z) represents the affine
 * (X/Z^2, Y/Z^3); Z = 0 marks identity. All coords in Mont form. */
typedef struct {
  RMpintFE X;
  RMpintFE Y;
  RMpintFE Z;
} REcurveJacobianPoint;

static void
r_ecurve_jp_init (REcurveJacobianPoint * P)
{
  r_mpint_fe_zero (&P->X);
  r_mpint_fe_zero (&P->Y);
  r_mpint_fe_zero (&P->Z);
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
  r_mpint_fe_swap_ct (&a->X, &b->X, bit, n);
  r_mpint_fe_swap_ct (&a->Y, &b->Y, bit, n);
  r_mpint_fe_swap_ct (&a->Z, &b->Z, bit, n);
}

static void
r_ecurve_jp_scratch_init (REcurveJacobianScratch * s)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (s->t); i++)
    r_mpint_fe_zero (&s->t[i]);
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
  RMpintFE * const XX   = &s->t[0];
  RMpintFE * const YY   = &s->t[1];
  RMpintFE * const YYYY = &s->t[2];
  RMpintFE * const ZZ   = &s->t[3];
  RMpintFE * const Z4   = &s->t[4];
  RMpintFE * const S    = &s->t[5];
  RMpintFE * const M    = &s->t[6];
  RMpintFE * const T    = &s->t[7];
  RMpintFE * const Znew = &s->t[8];
  RMpintFE * const Ynew = &s->t[9];
  RMpintFE * const tmp  = &s->t[10];

  /* All reads of P happen before any write to out, so aliasing out
   * with P is fine. */
  r_mpint_fe_sqr_mont (XX, &P->X, &ctx->mont);
  r_mpint_fe_sqr_mont (YY, &P->Y, &ctx->mont);
  r_mpint_fe_sqr_mont (YYYY, YY, &ctx->mont);
  r_mpint_fe_sqr_mont (ZZ, &P->Z, &ctx->mont);
  r_mpint_fe_sqr_mont (Z4, ZZ, &ctx->mont);

  /* S = 4 * X * YY */
  r_mpint_fe_mul_mont (tmp, &P->X, YY, &ctx->mont);
  r_mpint_fe_add (S, tmp, tmp, &ctx->mont);
  r_mpint_fe_add (S, S, S, &ctx->mont);

  /* M = 3 * XX + a * Z^4 */
  r_mpint_fe_mul_mont (M, &ctx->mont_a, Z4, &ctx->mont);
  r_mpint_fe_add (tmp, XX, XX, &ctx->mont);
  r_mpint_fe_add (tmp, tmp, XX, &ctx->mont);
  r_mpint_fe_add (M, M, tmp, &ctx->mont);

  /* T = M^2 - 2*S  ( = X' ) */
  r_mpint_fe_sqr_mont (T, M, &ctx->mont);
  r_mpint_fe_sub (T, T, S, &ctx->mont);
  r_mpint_fe_sub (T, T, S, &ctx->mont);

  /* Y' = M * (S - T) - 8 * YYYY */
  r_mpint_fe_sub (tmp, S, T, &ctx->mont);
  r_mpint_fe_mul_mont (Ynew, M, tmp, &ctx->mont);
  r_mpint_fe_add (tmp, YYYY, YYYY, &ctx->mont);
  r_mpint_fe_add (tmp, tmp, tmp, &ctx->mont);
  r_mpint_fe_add (tmp, tmp, tmp, &ctx->mont);
  r_mpint_fe_sub (Ynew, Ynew, tmp, &ctx->mont);

  /* Z' = 2 * Y * Z. Reads of P->Y / P->Z happen before writes to
   * out->Y / out->Z, so the aliased case is safe. */
  r_mpint_fe_mul_mont (Znew, &P->Y, &P->Z, &ctx->mont);
  r_mpint_fe_add (Znew, Znew, Znew, &ctx->mont);

  r_mpint_fe_copy (&out->X, T);
  r_mpint_fe_copy (&out->Y, Ynew);
  r_mpint_fe_copy (&out->Z, Znew);
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
  RMpintFE * const Z1Z1    = &s->t[0];
  RMpintFE * const Z2Z2    = &s->t[1];
  RMpintFE * const Z1cubed = &s->t[2];
  RMpintFE * const Z2cubed = &s->t[3];
  RMpintFE * const U1      = &s->t[4];
  RMpintFE * const U2      = &s->t[5];
  RMpintFE * const S1      = &s->t[6];
  RMpintFE * const S2      = &s->t[7];
  RMpintFE * const H       = &s->t[8];
  RMpintFE * const R       = &s->t[9];
  RMpintFE * const H2      = &s->t[10];
  RMpintFE * const H3      = &s->t[11];
  RMpintFE * const U1H2    = &s->t[12];
  RMpintFE * const X3      = &s->t[13];
  RMpintFE * const Y3      = &s->t[14];
  RMpintFE * const Z3      = &s->t[15];
  RMpintFE * const tmp     = &s->t[16];
  RMpintFE * const X_final = &s->t[17];
  RMpintFE * const Y_final = &s->t[18];
  RMpintFE * const Z_final = &s->t[19];
  ruint16 n = ctx->mont.n_digits;
  rmpint_digit p_is_zero, q_is_zero;

  /* Identity probes computed up front, before the standard formula
   * trashes the operands' images in scratch. */
  p_is_zero = r_mpint_fe_iszero_ct (&P->Z, n);
  q_is_zero = r_mpint_fe_iszero_ct (&Q->Z, n);

  /* Standard formula. */
  r_mpint_fe_sqr_mont (Z1Z1, &P->Z, &ctx->mont);
  r_mpint_fe_sqr_mont (Z2Z2, &Q->Z, &ctx->mont);
  r_mpint_fe_mul_mont (Z1cubed, &P->Z, Z1Z1, &ctx->mont);
  r_mpint_fe_mul_mont (Z2cubed, &Q->Z, Z2Z2, &ctx->mont);

  r_mpint_fe_mul_mont (U1, &P->X, Z2Z2, &ctx->mont);
  r_mpint_fe_mul_mont (U2, &Q->X, Z1Z1, &ctx->mont);
  r_mpint_fe_mul_mont (S1, &P->Y, Z2cubed, &ctx->mont);
  r_mpint_fe_mul_mont (S2, &Q->Y, Z1cubed, &ctx->mont);

  r_mpint_fe_sub (H, U2, U1, &ctx->mont);
  r_mpint_fe_sub (R, S2, S1, &ctx->mont);

  r_mpint_fe_sqr_mont (H2, H, &ctx->mont);
  r_mpint_fe_mul_mont (H3, H, H2, &ctx->mont);
  r_mpint_fe_mul_mont (U1H2, U1, H2, &ctx->mont);

  /* X3 = R^2 - H^3 - 2 * U1*H^2 */
  r_mpint_fe_sqr_mont (X3, R, &ctx->mont);
  r_mpint_fe_sub (X3, X3, H3, &ctx->mont);
  r_mpint_fe_sub (X3, X3, U1H2, &ctx->mont);
  r_mpint_fe_sub (X3, X3, U1H2, &ctx->mont);

  /* Y3 = R * (U1*H^2 - X3) - S1*H^3 */
  r_mpint_fe_sub (tmp, U1H2, X3, &ctx->mont);
  r_mpint_fe_mul_mont (Y3, R, tmp, &ctx->mont);
  r_mpint_fe_mul_mont (tmp, S1, H3, &ctx->mont);
  r_mpint_fe_sub (Y3, Y3, tmp, &ctx->mont);

  /* Z3 = Z1 * Z2 * H */
  r_mpint_fe_mul_mont (Z3, &P->Z, &Q->Z, &ctx->mont);
  r_mpint_fe_mul_mont (Z3, Z3, H, &ctx->mont);

  /* Identity fix-up: pick (computed; P; Q) per the (p,q) zero pair. */
  r_mpint_fe_select_ct (X_final, q_is_zero, &P->X, X3, n);
  r_mpint_fe_select_ct (Y_final, q_is_zero, &P->Y, Y3, n);
  r_mpint_fe_select_ct (Z_final, q_is_zero, &P->Z, Z3, n);
  r_mpint_fe_select_ct (X_final, p_is_zero, &Q->X, X_final, n);
  r_mpint_fe_select_ct (Y_final, p_is_zero, &Q->Y, Y_final, n);
  r_mpint_fe_select_ct (Z_final, p_is_zero, &Q->Z, Z_final, n);

  /* Assign last so out can safely alias P or Q. */
  r_mpint_fe_copy (&out->X, X_final);
  r_mpint_fe_copy (&out->Y, Y_final);
  r_mpint_fe_copy (&out->Z, Z_final);
}

/* Jacobian -> affine: divide out the Z. Identity (Z=0) maps to
 * is_infinity = TRUE. The Z != 0 path costs one Fermat inversion +
 * a handful of field multiplications. */
static rboolean
r_ecurve_jp_to_affine (REcurveAffinePoint * out, const REcurveJacobianPoint * P,
    const REcurveFEContext * ctx)
{
  RMpintFE Z_inv, Z2_inv, Z3_inv, x_M, y_M, x_norm, y_norm;
  ruint16 n = ctx->mont.n_digits;
  rboolean ok = TRUE;

  if (r_mpint_fe_iszero_ct (&P->Z, n) != 0) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_mpint_fe_invmod_mont (&Z_inv, &P->Z, &ctx->p_minus_2, ctx->p_minus_2_bits,
      &ctx->mont_r_squared, &ctx->mont);
  r_mpint_fe_sqr_mont (&Z2_inv, &Z_inv, &ctx->mont);
  r_mpint_fe_mul_mont (&Z3_inv, &Z_inv, &Z2_inv, &ctx->mont);
  r_mpint_fe_mul_mont (&x_M, &P->X, &Z2_inv, &ctx->mont);
  r_mpint_fe_mul_mont (&y_M, &P->Y, &Z3_inv, &ctx->mont);
  r_mpint_fe_mont_out (&x_norm, &x_M, &ctx->mont);
  r_mpint_fe_mont_out (&y_norm, &y_M, &ctx->mont);

  if (!r_mpint_fe_to_mpint (&out->x, &x_norm, n) ||
      !r_mpint_fe_to_mpint (&out->y, &y_norm, n))
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
  RMpintFE x_norm, y_norm, one;
  REcurveJacobianPoint R0, R1;
  REcurveJacobianScratch scratch;
  /* Scalar conditioning needs literal multi-digit add (not mod p), so
   * use raw digit arrays sized to n+1 digits for k+n and k+2n. */
  rmpint_digit k1[R_MPINT_FE_MAX_DIGITS + 1];
  rmpint_digit k2[R_MPINT_FE_MAX_DIGITS + 1];
  rmpint_digit k_prime[R_MPINT_FE_MAX_DIGITS + 1];
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
  if (!r_mpint_fe_mont_ctx_init (&ctx.mont, &curve->p))
    return FALSE;
  n = ctx.mont.n_digits;
  ctx.p_minus_2_bits = r_mpint_bits_used (&curve->p_minus_2);
  ctx.n_bits = r_mpint_bits_used (&curve->n);
  r_mpint_fe_from_mpint (&ctx.mont_r_squared, &curve->mont_r_squared, n);
  r_mpint_fe_from_mpint (&ctx.mont_a, &curve->mont_a, n);
  r_mpint_fe_from_mpint (&ctx.p_minus_2, &curve->p_minus_2, n);
  r_mpint_fe_from_mpint (&ctx.n, &curve->n, n);

  r_ecurve_jp_init (&R0);
  r_ecurve_jp_init (&R1);
  r_ecurve_jp_scratch_init (&scratch);

  /* R0 stays at identity (X=Y=Z=0). R1 is the input point lifted
   * into Jacobian Mont form: (x_M, y_M, 1_M), where 1_M = R mod p
   * is computed as mont_in(1). */
  r_mpint_fe_from_mpint (&x_norm, &point->x, n);
  r_mpint_fe_from_mpint (&y_norm, &point->y, n);
  r_mpint_fe_mont_in (&R1.X, &x_norm, &ctx.mont_r_squared, &ctx.mont);
  r_mpint_fe_mont_in (&R1.Y, &y_norm, &ctx.mont_r_squared, &ctx.mont);
  r_mpint_fe_zero (&one);
  one.d[0] = 1;
  r_mpint_fe_mont_in (&R1.Z, &one, &ctx.mont_r_squared, &ctx.mont);

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

const ruint8 *
r_ecurve_oid_from_id (REcurveID curve, rsize * size)
{
  /* Inverse of r_ecurve_id_from_oid - returns a pointer to the
   * pre-encoded OID bytes plus their length. Length is needed
   * separately because several curve OIDs (SECP224R1 / 384R1 / 521R1
   * / 192K1 / 224K1 / 256K1) contain an embedded \x00, so strlen on
   * the macro truncates them mid-OID and r_asn1_bin_encoder_add_oid_rawsz
   * is unusable. NULL for any curve we don't have an OID mapping for;
   * *size is then set to 0. */
#define R_ECURVE_RETURN_OID(macro) \
    do { \
      if (size != NULL) *size = sizeof (macro) - 1; \
      return (const ruint8 *)(macro); \
    } while (0)

  switch (curve) {
    case R_ECURVE_ID_SECP192R1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP192R1);
    case R_ECURVE_ID_SECP224R1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP224R1);
    case R_ECURVE_ID_SECP256R1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP256R1);
    case R_ECURVE_ID_SECP384R1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP384R1);
    case R_ECURVE_ID_SECP521R1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP521R1);
    case R_ECURVE_ID_SECP192K1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP192K1);
    case R_ECURVE_ID_SECP224K1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP224K1);
    case R_ECURVE_ID_SECP256K1: R_ECURVE_RETURN_OID (R_EC_GRP_OID_SECP256K1);
    default:
      if (size != NULL) *size = 0;
      return NULL;
  }
#undef R_ECURVE_RETURN_OID
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
