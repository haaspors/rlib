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
}

/* --- Internal Montgomery-form field arithmetic. Used by the
 * constant-time scalar-mul ladder. All inputs/outputs are mpints
 * in Montgomery form (value * R mod p) unless otherwise noted.
 * The curve's precomputed mont_mp / mont_r_squared / mont_a are
 * the per-curve setup values. --- */

/* "if a >= p, a := a - p". Branchless XOR-select, but ends with a
 * value-dependent r_mpint_clamp - the result's bit-length leaks
 * via dig_used, which the rest of the mpint API depends on for
 * its no-leading-zeros invariant (r_mpint_cmp returns non-zero
 * for values that are equal-but-padded). Item 4 of #100
 * (constant-time memory access patterns) should revisit. */
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
 * p brings it back into [0, p). */
static rboolean
r_ecurve_mont_sub (rmpint * out, const rmpint * a, const rmpint * b,
    const REcurve * curve)
{
  rmpint tmp;
  rboolean ok;

  r_mpint_init (&tmp);
  ok = r_mpint_add (&tmp, a, &curve->p) &&
       r_mpint_sub (out, &tmp, b);
  r_mpint_clear (&tmp);
  if (!ok) return FALSE;
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

/* out_M := (a_M)^-1 in Montgomery form. Uses the existing
 * variable-time r_mpint_invmod internally - that's the residual
 * leak item 3 of #100 will replace with constant-time Fermat
 * (a^(p-2) via constant-time expmod).
 *
 * Algebraic derivation: invmod(a_M) returns (a*R)^-1 = a^-1 * R^-1
 * in normal form. Multiplying that by R^2 (full multiply, not
 * Montgomery) gives a^-1 * R^-1 * R^2 = a^-1 * R = (a^-1)_M, which
 * is what callers need to feed back into mont_mul. */
static rboolean
r_ecurve_mont_invmod (rmpint * out, const rmpint * a, const REcurve * curve)
{
  rmpint inv;
  rboolean ok;

  r_mpint_init (&inv);
  ok = r_mpint_invmod (&inv, a, &curve->p) &&
       r_mpint_mulmod (out, &inv, &curve->mont_r_squared, &curve->p);
  r_mpint_clear (&inv);
  return ok;
}

/* Internal dbl operating on Montgomery-form points. Assumes a is
 * in Montgomery form and curve->mont_a is precomputed. Produces
 * out in Montgomery form. */
static rboolean
r_ecurve_point_dbl_mont (REcurveAffinePoint * out,
    const REcurveAffinePoint * a, const REcurve * curve)
{
  rmpint slope, t, num, den;
  rboolean ok;

  if (a->is_infinity || r_mpint_iszero (&a->y)) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_mpint_init (&slope);
  r_mpint_init (&t);
  r_mpint_init (&num);
  r_mpint_init (&den);

  /* num = 3 * x^2 + a (all in Montgomery form) */
  ok = r_ecurve_mont_sqr (&t, &a->x, curve) &&            /* t = (x^2)_M */
       r_ecurve_mont_add (&num, &t, &t, curve) &&         /* num = 2 * x^2_M */
       r_ecurve_mont_add (&num, &num, &t, curve) &&       /* num = 3 * x^2_M */
       r_ecurve_mont_add (&num, &num, &curve->mont_a, curve);
  if (!ok) goto out;

  /* den = 2 * y (in Montgomery form) */
  ok = r_ecurve_mont_add (&den, &a->y, &a->y, curve);
  if (!ok) goto out;

  /* slope = num / den = num * inv(den) (in Montgomery form) */
  ok = r_ecurve_mont_invmod (&t, &den, curve) &&
       r_ecurve_mont_mul (&slope, &num, &t, curve);
  if (!ok) goto out;

  /* X = slope^2 - 2*x mod p (Montgomery) */
  ok = r_ecurve_mont_sqr (&num, &slope, curve) &&
       r_ecurve_mont_sub (&t, &num, &a->x, curve) &&
       r_ecurve_mont_sub (&num, &t, &a->x, curve);   /* num holds X */
  if (!ok) goto out;

  /* Y = slope * (x - X) - y mod p (Montgomery) */
  ok = r_ecurve_mont_sub (&t, &a->x, &num, curve) &&
       r_ecurve_mont_mul (&den, &slope, &t, curve) &&
       r_ecurve_mont_sub (&t, &den, &a->y, curve);   /* t holds Y */
  if (!ok) goto out;

  r_mpint_set (&out->x, &num);
  r_mpint_set (&out->y, &t);
  out->is_infinity = FALSE;

out:
  r_mpint_clear (&slope);
  r_mpint_clear (&t);
  r_mpint_clear (&num);
  r_mpint_clear (&den);
  return ok;
}

/* Internal add operating on Montgomery-form points. Same shape as
 * r_ecurve_point_add but every modular operation runs through the
 * Montgomery helpers. The "equal x" branches still defer to dbl
 * or set_infinity. */
static rboolean
r_ecurve_point_add_mont (REcurveAffinePoint * out,
    const REcurveAffinePoint * a, const REcurveAffinePoint * b,
    const REcurve * curve)
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
    if (r_mpint_cmp (&a->y, &b->y) == 0)
      return r_ecurve_point_dbl_mont (out, a, curve);
    /* y_b == -y_a holds in Montgomery form for the same reason it
     * holds in normal form: negation is linear and commutes with
     * multiplication by R. The check is plain p - y_a_M; both
     * operands are mpints in [0, p) so a plain unsigned subtract
     * suffices. */
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
    return FALSE;
  }

  r_mpint_init (&slope);
  r_mpint_init (&t);
  r_mpint_init (&num);
  r_mpint_init (&den);
  r_mpint_init (&x_new);

  /* num = b->y - a->y mod p (Montgomery form) */
  /* den = b->x - a->x mod p (Montgomery form) */
  ok = r_ecurve_mont_sub (&num, &b->y, &a->y, curve) &&
       r_ecurve_mont_sub (&den, &b->x, &a->x, curve);
  if (!ok) goto out;

  /* slope = num / den (Montgomery form) */
  ok = r_ecurve_mont_invmod (&t, &den, curve) &&
       r_ecurve_mont_mul (&slope, &num, &t, curve);
  if (!ok) goto out;

  /* X = slope^2 - a->x - b->x mod p */
  ok = r_ecurve_mont_sqr (&x_new, &slope, curve) &&
       r_ecurve_mont_sub (&x_new, &x_new, &a->x, curve) &&
       r_ecurve_mont_sub (&x_new, &x_new, &b->x, curve);
  if (!ok) goto out;

  /* Y = slope * (a->x - X) - a->y mod p */
  ok = r_ecurve_mont_sub (&t, &a->x, &x_new, curve) &&
       r_ecurve_mont_mul (&t, &slope, &t, curve) &&
       r_ecurve_mont_sub (&t, &t, &a->y, curve);
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

/* Constant-time swap of two affine points: exchanges x / y mpint
 * metadata + data pointer and the is_infinity flag iff bit is set,
 * with no data-dependent branches or copies. */
static void
r_ecurve_point_swap_ct (REcurveAffinePoint * a, REcurveAffinePoint * b,
    ruint32 bit)
{
  ruint32 mask = 0u - (ruint32)(bit & 1u);
  ruint32 d;

  r_mpint_swap_ct (&a->x, &b->x, bit);
  r_mpint_swap_ct (&a->y, &b->y, bit);
  d = ((ruint32)a->is_infinity ^ (ruint32)b->is_infinity) & mask;
  a->is_infinity = (rboolean)((ruint32)a->is_infinity ^ d);
  b->is_infinity = (rboolean)((ruint32)b->is_infinity ^ d);
}

rboolean
r_ecurve_point_scalar_mul (REcurveAffinePoint * out, const rmpint * scalar,
    const REcurveAffinePoint * point, const REcurve * curve)
{
  /* Left-to-right Montgomery ladder, run in the Montgomery field
   * representation: the input point is lifted to (x*R, y*R) once
   * on entry, every add / dbl in the loop body uses Montgomery
   * multiplication and constant-time field add/sub, and the
   * final R0 is mapped back to normal coordinates on exit. The
   * per-step Montgomery reduce replaces the variable-time
   * schoolbook long-division that r_mpint_mod used to do, so the
   * timing of the scalar-mul body no longer depends on the value
   * of intermediate results.
   *
   * The bit-dispatch in the loop body uses r_ecurve_point_swap_ct
   * around a single "R1 = R0 + R1; R0 = 2 * R0" sequence (item 1
   * of #100), so both bit values exercise the same operations in
   * the same order; only the swap-or-not is bit-dependent, and
   * the swap itself is branchless.
   *
   * Residual leak: r_ecurve_mont_invmod still calls the variable-
   * time r_mpint_invmod for the slope inversion (one per step).
   * That's the channel item 3 of #100 closes with a Fermat-based
   * constant-time inversion. */
  REcurveAffinePoint R0, R1;
  ruint16 d, b;
  rmpint_digit bit;
  rboolean ok = FALSE;

  if (r_mpint_iszero (scalar) || point->is_infinity) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_ecurve_point_init (&R0);
  r_ecurve_point_init (&R1);

  /* R0 stays at infinity (set by init); lift the input point into
   * Montgomery form directly into R1 (= R1.x = x * R mod p,
   * R1.y = y * R mod p). The ladder maintains R1 - R0 == P
   * throughout, both in Montgomery and after the final mont_out. */
  if (!r_ecurve_mont_in (&R1.x, &point->x, curve) ||
      !r_ecurve_mont_in (&R1.y, &point->y, curve))
    goto cleanup;
  R1.is_infinity = FALSE;

  for (d = r_mpint_digits_used (scalar); d > 0; d--) {
    rmpint_digit dig = r_mpint_get_digit (scalar, d - 1);
    for (b = 0; b < sizeof (rmpint_digit) * 8; b++) {
      bit = (dig >> (sizeof (rmpint_digit) * 8 - 1)) & 1;
      dig <<= 1;

      r_ecurve_point_swap_ct (&R0, &R1, (ruint32)bit);
      if (!r_ecurve_point_add_mont (&R1, &R0, &R1, curve)) goto cleanup;
      if (!r_ecurve_point_dbl_mont (&R0, &R0, curve)) goto cleanup;
      r_ecurve_point_swap_ct (&R0, &R1, (ruint32)bit);
    }
  }

  /* Map R0 back to normal coordinates for the caller. */
  if (R0.is_infinity) {
    r_ecurve_point_set_infinity (out);
  } else {
    if (!r_ecurve_mont_out (&out->x, &R0.x, curve) ||
        !r_ecurve_mont_out (&out->y, &R0.y, curve))
      goto cleanup;
    out->is_infinity = FALSE;
  }
  ok = TRUE;

cleanup:
  r_ecurve_point_clear (&R0);
  r_ecurve_point_clear (&R1);
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
