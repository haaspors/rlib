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
  /* Left-to-right Montgomery ladder. Maintain (R0, R1) such that
   * R1 - R0 == point at every step; one add + one dbl per scalar bit
   * keeps the high-level branch shape uniform regardless of the
   * scalar's bit pattern. The underlying mpint ops aren't constant-
   * time, so this isn't full side-channel hardening — that's a
   * separate concern. */
  REcurveAffinePoint R0, R1, tmp;
  ruint16 d, b;
  rmpint_digit bit;
  rboolean ok = FALSE;

  if (r_mpint_iszero (scalar) || point->is_infinity) {
    r_ecurve_point_set_infinity (out);
    return TRUE;
  }

  r_ecurve_point_init (&R0);
  r_ecurve_point_init (&R1);
  r_ecurve_point_init (&tmp);
  r_ecurve_point_set_infinity (&R0);
  r_ecurve_point_copy (&R1, point);

  for (d = r_mpint_digits_used (scalar); d > 0; d--) {
    rmpint_digit dig = r_mpint_get_digit (scalar, d - 1);
    for (b = 0; b < sizeof (rmpint_digit) * 8; b++) {
      bit = (dig >> (sizeof (rmpint_digit) * 8 - 1)) & 1;
      dig <<= 1;
      if (bit) {
        if (!r_ecurve_point_add (&tmp, &R0, &R1, curve)) goto cleanup;
        r_ecurve_point_copy (&R0, &tmp);
        if (!r_ecurve_point_dbl (&tmp, &R1, curve)) goto cleanup;
        r_ecurve_point_copy (&R1, &tmp);
      } else {
        if (!r_ecurve_point_add (&tmp, &R0, &R1, curve)) goto cleanup;
        r_ecurve_point_copy (&R1, &tmp);
        if (!r_ecurve_point_dbl (&tmp, &R0, curve)) goto cleanup;
        r_ecurve_point_copy (&R0, &tmp);
      }
    }
  }

  r_ecurve_point_copy (out, &R0);
  ok = TRUE;

cleanup:
  r_ecurve_point_clear (&R0);
  r_ecurve_point_clear (&R1);
  r_ecurve_point_clear (&tmp);
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
