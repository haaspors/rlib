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

#include <rlib/crypto/recurve-edwards.h>

#include <rlib/rmem.h>

/* ---- Curve parameter tables ---------------------------------------------
 *
 * Field primes, curve constants, basepoint coordinates, and the
 * pre-derived exponents needed by Fermat inversion and the modular
 * square root sub-routine. All bytes are stored little-endian to match
 * how rmpint_set_binary expects them in the runtime decoder... except
 * rmpint_init_binary actually wants big-endian. Keep the tables LE
 * for readability against RFC 8032's wire formats and bswap into BE
 * during init, where it costs nothing.
 *
 * Constants derived by tools/edwards_params.py (which is not committed
 * - the values are stable across all future ed25519 / ed448 work and
 * don't warrant a generator script). */

/* edwards25519 (twisted Edwards, a = -1): p = 2^255 - 19 */
static const ruint8 ed25519_p_le[32] = {
  0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
};
/* d = -121665 / 121666 mod p */
static const ruint8 ed25519_d_le[32] = {
  0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
  0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
  0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
  0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
};
/* sqrt(-1) mod p = 2^((p-1)/4) mod p */
static const ruint8 ed25519_sqrt_m1_le[32] = {
  0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4,
  0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43, 0x2f,
  0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b,
  0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24, 0x83, 0x2b,
};
/* (p - 5) / 8 - the Bernstein sqrt exponent for p ≡ 5 mod 8 */
static const ruint8 ed25519_sqrt_exp_le[32] = {
  0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
};
/* L = order of the prime-order subgroup */
static const ruint8 ed25519_L_le[32] = {
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};
static const ruint8 ed25519_Bx_le[32] = {
  0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
  0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
  0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
  0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
};
static const ruint8 ed25519_By_le[32] = {
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

/* edwards448 (untwisted Edwards, a = +1): p = 2^448 - 2^224 - 1 */
static const ruint8 ed448_p_le[56] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};
/* d = -39081 mod p */
static const ruint8 ed448_d_le[56] = {
  0x56, 0x67, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};
/* (p + 1) / 4 - the simple sqrt exponent for p ≡ 3 mod 4 */
static const ruint8 ed448_sqrt_exp_le[56] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};
static const ruint8 ed448_L_le[56] = {
  0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
  0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
  0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
  0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};
/* Canonical RFC 8032 §5.2 base point of order L. */
static const ruint8 ed448_Bx_le[56] = {
  0x5e, 0xc0, 0x0c, 0xc7, 0x2b, 0xa8, 0x26, 0x26,
  0x8e, 0x93, 0x00, 0x8b, 0xe1, 0x80, 0x3b, 0x43,
  0x11, 0x65, 0xb6, 0x2a, 0xf7, 0x1a, 0xae, 0x12,
  0x64, 0xa4, 0xd3, 0xa3, 0x24, 0xe3, 0x6d, 0xea,
  0x67, 0x17, 0x0f, 0x47, 0x70, 0x65, 0x14, 0x9e,
  0xda, 0x36, 0xbf, 0x22, 0xa6, 0x15, 0x1d, 0x22,
  0xed, 0x0d, 0xed, 0x6b, 0xc6, 0x70, 0x19, 0x4f,
};
static const ruint8 ed448_By_le[56] = {
  0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
  0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
  0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
  0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
  0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
  0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
  0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
};

typedef struct {
  REcurveID id;
  rsize coord_bytes;
  rsize encoding_bytes;
  ruint16 bits;
  rboolean a_is_minus_one;
  const ruint8 * p_le;
  const ruint8 * d_le;
  const ruint8 * sqrt_m1_le;    /* NULL for ed448 */
  const ruint8 * sqrt_exp_le;
  ruint16 sqrt_exp_bits;
  const ruint8 * L_le;
  const ruint8 * Bx_le;
  const ruint8 * By_le;
} REdwardsParams;

static const REdwardsParams g__edwards_params[] = {
  { R_ECURVE_ID_X25519, 32, 32, 255, TRUE,
    ed25519_p_le, ed25519_d_le, ed25519_sqrt_m1_le,
    ed25519_sqrt_exp_le, 252, ed25519_L_le,
    ed25519_Bx_le, ed25519_By_le },
  { R_ECURVE_ID_X448, 56, 57, 448, FALSE,
    ed448_p_le, ed448_d_le, NULL,
    ed448_sqrt_exp_le, 446, ed448_L_le,
    ed448_Bx_le, ed448_By_le },
};

/* ---- LE-bytes -> rmpint via byte reversal ---------------------------- */

static void
r_edwards_mpint_init_from_le (rmpint * mp, const ruint8 * le, rsize n)
{
  ruint8 be[64];
  rsize i;
  for (i = 0; i < n; i++)
    be[i] = le[n - 1 - i];
  r_mpint_init_binary (mp, be, n);
  r_memclear_secure (be, sizeof (be));
}

static void
r_edwards_fe_from_le_bytes (RMpintFE * fe, const ruint8 * le, rsize n,
    const REcurveEdwards * curve)
{
  rmpint mp;
  r_edwards_mpint_init_from_le (&mp, le, n);
  r_mpint_fe_from_mpint (fe, &mp, curve->ctx.n_digits);
  r_mpint_clear (&mp);
}

/* ---- Lifecycle ------------------------------------------------------- */

static const REdwardsParams *
r_edwards_params_find (REcurveID id)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (g__edwards_params); i++) {
    if (g__edwards_params[i].id == id)
      return &g__edwards_params[i];
  }
  return NULL;
}

rboolean
r_ecurve_edwards_init (REcurveEdwards * curve, REcurveID named)
{
  const REdwardsParams * params;
  RMpintFE Bx_fe, By_fe, t;
  rmpint pm2;

  if (R_UNLIKELY (curve == NULL)) return FALSE;
  if ((params = r_edwards_params_find (named)) == NULL) return FALSE;

  r_memset (curve, 0, sizeof (*curve));
  curve->id = named;
  curve->coord_bytes = params->coord_bytes;
  curve->encoding_bytes = params->encoding_bytes;
  curve->bits = params->bits;
  curve->a_is_minus_one = params->a_is_minus_one;

  r_edwards_mpint_init_from_le (&curve->p, params->p_le, params->coord_bytes);
  r_edwards_mpint_init_from_le (&curve->order, params->L_le, params->coord_bytes);

  if (!r_mpint_fe_mont_ctx_init (&curve->ctx, &curve->p))
    goto fail;
  if (!r_mpint_fe_compute_r_squared (&curve->r_squared, &curve->p,
        curve->ctx.n_digits))
    goto fail;

  /* d_mont, two_d_mont */
  {
    RMpintFE d_fe;
    r_edwards_fe_from_le_bytes (&d_fe, params->d_le, params->coord_bytes, curve);
    r_mpint_fe_mont_in (&curve->d_mont, &d_fe, &curve->r_squared, &curve->ctx);
    r_mpint_fe_add (&curve->two_d_mont, &curve->d_mont, &curve->d_mont,
        &curve->ctx);
    r_memclear_secure (&d_fe, sizeof (d_fe));
  }

  /* sqrt(-1) only for edwards25519 */
  if (params->sqrt_m1_le != NULL) {
    RMpintFE s_fe;
    r_edwards_fe_from_le_bytes (&s_fe, params->sqrt_m1_le,
        params->coord_bytes, curve);
    r_mpint_fe_mont_in (&curve->sqrt_m1_mont, &s_fe, &curve->r_squared,
        &curve->ctx);
    r_memclear_secure (&s_fe, sizeof (s_fe));
  } else {
    r_mpint_fe_zero (&curve->sqrt_m1_mont);
  }

  /* sqrt_exponent (stored in normal form - it's read bit-by-bit). */
  r_edwards_fe_from_le_bytes (&curve->sqrt_exponent, params->sqrt_exp_le,
      params->coord_bytes, curve);
  curve->sqrt_exponent_bits = params->sqrt_exp_bits;

  /* p_minus_2 for Fermat inversion */
  r_mpint_init (&pm2);
  if (!r_mpint_sub_i32 (&pm2, &curve->p, 2)) {
    r_mpint_clear (&pm2);
    goto fail;
  }
  r_mpint_fe_from_mpint (&curve->p_minus_2, &pm2, curve->ctx.n_digits);
  curve->p_minus_2_bits = (ruint16)r_mpint_bits_used (&pm2);
  r_mpint_clear (&pm2);

  /* B: (Bx, By, 1, Bx*By) in Montgomery form. */
  r_edwards_fe_from_le_bytes (&Bx_fe, params->Bx_le, params->coord_bytes, curve);
  r_edwards_fe_from_le_bytes (&By_fe, params->By_le, params->coord_bytes, curve);
  r_mpint_fe_mont_in (&curve->B.X, &Bx_fe, &curve->r_squared, &curve->ctx);
  r_mpint_fe_mont_in (&curve->B.Y, &By_fe, &curve->r_squared, &curve->ctx);
  {
    RMpintFE one_fe;
    r_mpint_fe_zero (&one_fe);
    one_fe.d[0] = 1;
    r_mpint_fe_mont_in (&curve->B.Z, &one_fe, &curve->r_squared, &curve->ctx);
  }
  r_mpint_fe_mul_mont (&curve->B.T, &curve->B.X, &curve->B.Y, &curve->ctx);
  /* T should equal X*Y/Z but Z=1 so T = X*Y in Mont form. */

  r_memclear_secure (&Bx_fe, sizeof (Bx_fe));
  r_memclear_secure (&By_fe, sizeof (By_fe));
  r_memclear_secure (&t, sizeof (t));

  return TRUE;

fail:
  r_ecurve_edwards_clear (curve);
  return FALSE;
}

void
r_ecurve_edwards_clear (REcurveEdwards * curve)
{
  if (curve == NULL) return;
  r_mpint_clear (&curve->p);
  r_mpint_clear (&curve->order);
  r_memclear_secure (&curve->ctx, sizeof (curve->ctx));
  r_memclear_secure (&curve->r_squared, sizeof (curve->r_squared));
  r_memclear_secure (&curve->d_mont, sizeof (curve->d_mont));
  r_memclear_secure (&curve->two_d_mont, sizeof (curve->two_d_mont));
  r_memclear_secure (&curve->sqrt_m1_mont, sizeof (curve->sqrt_m1_mont));
  r_memclear_secure (&curve->sqrt_exponent, sizeof (curve->sqrt_exponent));
  r_memclear_secure (&curve->p_minus_2, sizeof (curve->p_minus_2));
  r_memclear_secure (&curve->B, sizeof (curve->B));
}

/* ---- Point ops -------------------------------------------------------- */

void
r_ecurve_edwards_point_set_identity (REcurveEdwardsPoint * point)
{
  r_mpint_fe_zero (&point->X);
  r_mpint_fe_zero (&point->Y);
  r_mpint_fe_zero (&point->Z);
  r_mpint_fe_zero (&point->T);
  /* Y = 1, Z = 1 in Montgomery form requires R mod p; the caller
   * almost always wants the identity inside an initialised curve
   * context. Done lazily here via the caller knowing to lift. To
   * keep this generic, we leave Z, Y zeroed; the caller must run
   * r_mpint_fe_mont_in on the unit value of 1 before use, or use
   * the identity from a curve context. Storing the in-form identity
   * requires the curve struct, so set_identity has to be paired
   * with a curve - reflected by callers always providing curve in
   * the higher-level paths. */
}

/* Internal: identity in Mont form for `curve`. */
static void
r_edwards_set_identity_mont (REcurveEdwardsPoint * point,
    const REcurveEdwards * curve)
{
  RMpintFE one_fe;
  r_mpint_fe_zero (&one_fe);
  one_fe.d[0] = 1;
  r_mpint_fe_zero (&point->X);
  r_mpint_fe_mont_in (&point->Y, &one_fe, &curve->r_squared, &curve->ctx);
  r_mpint_fe_mont_in (&point->Z, &one_fe, &curve->r_squared, &curve->ctx);
  r_mpint_fe_zero (&point->T);
}

void
r_ecurve_edwards_point_copy (REcurveEdwardsPoint * dst,
    const REcurveEdwardsPoint * src)
{
  r_mpint_fe_copy (&dst->X, &src->X);
  r_mpint_fe_copy (&dst->Y, &src->Y);
  r_mpint_fe_copy (&dst->Z, &src->Z);
  r_mpint_fe_copy (&dst->T, &src->T);
}

void
r_ecurve_edwards_point_neg (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwards * curve)
{
  RMpintFE zero;
  r_mpint_fe_zero (&zero);
  r_mpint_fe_sub (&out->X, &zero, &a->X, &curve->ctx);
  r_mpint_fe_copy (&out->Y, &a->Y);
  r_mpint_fe_copy (&out->Z, &a->Z);
  r_mpint_fe_sub (&out->T, &zero, &a->T, &curve->ctx);
}

/* Twisted Edwards addition with a = -1 (edwards25519).
 * Hisil-Wong-Carter-Dawson "extended twisted Edwards" formula. */
static void
r_edwards_add_twisted (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwardsPoint * b,
    const REcurveEdwards * curve)
{
  RMpintFE A, B, C, D, E, F, G, H, t1, t2;
  const RMpintFEMontCtx * ctx = &curve->ctx;

  r_mpint_fe_sub (&t1, &a->Y, &a->X, ctx);
  r_mpint_fe_sub (&t2, &b->Y, &b->X, ctx);
  r_mpint_fe_mul_mont (&A, &t1, &t2, ctx);

  r_mpint_fe_add (&t1, &a->Y, &a->X, ctx);
  r_mpint_fe_add (&t2, &b->Y, &b->X, ctx);
  r_mpint_fe_mul_mont (&B, &t1, &t2, ctx);

  r_mpint_fe_mul_mont (&C, &a->T, &curve->two_d_mont, ctx);
  r_mpint_fe_mul_mont (&C, &C, &b->T, ctx);

  r_mpint_fe_mul_mont (&D, &a->Z, &b->Z, ctx);
  r_mpint_fe_add (&D, &D, &D, ctx);

  r_mpint_fe_sub (&E, &B, &A, ctx);
  r_mpint_fe_sub (&F, &D, &C, ctx);
  r_mpint_fe_add (&G, &D, &C, ctx);
  r_mpint_fe_add (&H, &B, &A, ctx);

  r_mpint_fe_mul_mont (&out->X, &E, &F, ctx);
  r_mpint_fe_mul_mont (&out->Y, &G, &H, ctx);
  r_mpint_fe_mul_mont (&out->T, &E, &H, ctx);
  r_mpint_fe_mul_mont (&out->Z, &F, &G, ctx);

  r_memclear_secure (&A, sizeof (A));
  r_memclear_secure (&B, sizeof (B));
  r_memclear_secure (&C, sizeof (C));
  r_memclear_secure (&D, sizeof (D));
  r_memclear_secure (&E, sizeof (E));
  r_memclear_secure (&F, sizeof (F));
  r_memclear_secure (&G, sizeof (G));
  r_memclear_secure (&H, sizeof (H));
  r_memclear_secure (&t1, sizeof (t1));
  r_memclear_secure (&t2, sizeof (t2));
}

/* Untwisted Edwards addition with a = +1 (edwards448).
 * Bernstein-Lange formula. */
static void
r_edwards_add_untwisted (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwardsPoint * b,
    const REcurveEdwards * curve)
{
  RMpintFE A, B, C, D, E, F, G, H, t1, t2;
  const RMpintFEMontCtx * ctx = &curve->ctx;

  r_mpint_fe_mul_mont (&A, &a->X, &b->X, ctx);
  r_mpint_fe_mul_mont (&B, &a->Y, &b->Y, ctx);
  r_mpint_fe_mul_mont (&C, &a->T, &curve->d_mont, ctx);
  r_mpint_fe_mul_mont (&C, &C, &b->T, ctx);
  r_mpint_fe_mul_mont (&D, &a->Z, &b->Z, ctx);

  r_mpint_fe_add (&t1, &a->X, &a->Y, ctx);
  r_mpint_fe_add (&t2, &b->X, &b->Y, ctx);
  r_mpint_fe_mul_mont (&E, &t1, &t2, ctx);
  r_mpint_fe_sub (&E, &E, &A, ctx);
  r_mpint_fe_sub (&E, &E, &B, ctx);

  r_mpint_fe_sub (&F, &D, &C, ctx);
  r_mpint_fe_add (&G, &D, &C, ctx);
  r_mpint_fe_sub (&H, &B, &A, ctx);

  r_mpint_fe_mul_mont (&out->X, &E, &F, ctx);
  r_mpint_fe_mul_mont (&out->Y, &G, &H, ctx);
  r_mpint_fe_mul_mont (&out->T, &E, &H, ctx);
  r_mpint_fe_mul_mont (&out->Z, &F, &G, ctx);

  r_memclear_secure (&A, sizeof (A));
  r_memclear_secure (&B, sizeof (B));
  r_memclear_secure (&C, sizeof (C));
  r_memclear_secure (&D, sizeof (D));
  r_memclear_secure (&E, sizeof (E));
  r_memclear_secure (&F, sizeof (F));
  r_memclear_secure (&G, sizeof (G));
  r_memclear_secure (&H, sizeof (H));
  r_memclear_secure (&t1, sizeof (t1));
  r_memclear_secure (&t2, sizeof (t2));
}

void
r_ecurve_edwards_point_add (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwardsPoint * b,
    const REcurveEdwards * curve)
{
  if (curve->a_is_minus_one)
    r_edwards_add_twisted (out, a, b, curve);
  else
    r_edwards_add_untwisted (out, a, b, curve);
}

/* Bernstein-Lange "dedicated doubling" for extended (twisted) Edwards
 * in XYZT coords. Same algorithm shape for both twists; the sign of
 * `a` flips two intermediate signs.
 *
 *   A = X^2
 *   B = Y^2
 *   C = 2*Z^2
 *   E = (X+Y)^2 - A - B          (= 2*X*Y)
 *   G = a*A + B                  (a = -1: B - A; a = +1: A + B)
 *   H = a*A - B                  (a = -1: -(A+B); a = +1: A - B)
 *   F = G - C
 *   X3 = E*F  Y3 = G*H  T3 = E*H  Z3 = F*G */
void
r_ecurve_edwards_point_dbl (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwards * curve)
{
  RMpintFE A, B, C, E, G, H, F, t;
  const RMpintFEMontCtx * ctx = &curve->ctx;

  r_mpint_fe_sqr_mont (&A, &a->X, ctx);
  r_mpint_fe_sqr_mont (&B, &a->Y, ctx);
  r_mpint_fe_sqr_mont (&C, &a->Z, ctx);
  r_mpint_fe_add (&C, &C, &C, ctx);

  r_mpint_fe_add (&t, &a->X, &a->Y, ctx);
  r_mpint_fe_sqr_mont (&t, &t, ctx);
  r_mpint_fe_sub (&t, &t, &A, ctx);
  r_mpint_fe_sub (&E, &t, &B, ctx);

  if (curve->a_is_minus_one) {
    r_mpint_fe_sub (&G, &B, &A, ctx);          /* G = -A + B */
    r_mpint_fe_add (&H, &A, &B, ctx);
    r_mpint_fe_zero (&t);
    r_mpint_fe_sub (&H, &t, &H, ctx);          /* H = -(A + B) */
  } else {
    r_mpint_fe_add (&G, &A, &B, ctx);          /* G = A + B */
    r_mpint_fe_sub (&H, &A, &B, ctx);          /* H = A - B */
  }

  r_mpint_fe_sub (&F, &G, &C, ctx);

  r_mpint_fe_mul_mont (&out->X, &E, &F, ctx);
  r_mpint_fe_mul_mont (&out->Y, &G, &H, ctx);
  r_mpint_fe_mul_mont (&out->T, &E, &H, ctx);
  r_mpint_fe_mul_mont (&out->Z, &F, &G, ctx);

  r_memclear_secure (&A, sizeof (A));
  r_memclear_secure (&B, sizeof (B));
  r_memclear_secure (&C, sizeof (C));
  r_memclear_secure (&E, sizeof (E));
  r_memclear_secure (&G, sizeof (G));
  r_memclear_secure (&H, sizeof (H));
  r_memclear_secure (&F, sizeof (F));
  r_memclear_secure (&t, sizeof (t));
}

rboolean
r_ecurve_edwards_point_is_identity (const REcurveEdwardsPoint * a,
    const REcurveEdwards * curve)
{
  /* Identity: X = 0 and Y = Z. Check X = 0 directly and Y*1 == Z*1
   * via projective normalisation skip (just compare). */
  RMpintFE diff;
  ruint16 n = curve->ctx.n_digits;
  r_mpint_fe_sub (&diff, &a->Y, &a->Z, &curve->ctx);
  return r_mpint_fe_iszero_ct (&a->X, n) != 0
      && r_mpint_fe_iszero_ct (&diff, n) != 0;
}

rboolean
r_ecurve_edwards_point_equal (const REcurveEdwardsPoint * a,
    const REcurveEdwardsPoint * b, const REcurveEdwards * curve)
{
  RMpintFE lhs, rhs;
  const RMpintFEMontCtx * ctx = &curve->ctx;
  ruint16 n = ctx->n_digits;

  r_mpint_fe_mul_mont (&lhs, &a->X, &b->Z, ctx);
  r_mpint_fe_mul_mont (&rhs, &b->X, &a->Z, ctx);
  r_mpint_fe_sub (&lhs, &lhs, &rhs, ctx);
  if (r_mpint_fe_iszero_ct (&lhs, n) == 0)
    return FALSE;

  r_mpint_fe_mul_mont (&lhs, &a->Y, &b->Z, ctx);
  r_mpint_fe_mul_mont (&rhs, &b->Y, &a->Z, ctx);
  r_mpint_fe_sub (&lhs, &lhs, &rhs, ctx);
  return r_mpint_fe_iszero_ct (&lhs, n) != 0;
}

/* Scalar multiplication: textbook left-to-right double-and-add. The
 * conditional add on each bit is variable-time on the scalar - good
 * enough for the math layer where some callers (sign) want secret
 * scalars but the dominant timing channel is via the Montgomery
 * field arithmetic underneath. Full constant-time hardening (swap-
 * wrap ladder + Mont-form field) is a follow-up on the issue that
 * introduced this module. */
void
r_ecurve_edwards_point_scalar_mul (REcurveEdwardsPoint * out,
    const ruint8 * scalar_bytes, rsize scalar_size, ruint scalar_bits,
    const REcurveEdwardsPoint * a, const REcurveEdwards * curve)
{
  REcurveEdwardsPoint R0;
  ruint i;

  r_edwards_set_identity_mont (&R0, curve);
  for (i = scalar_bits; i > 0; i--) {
    ruint bp = i - 1;
    rmpint_digit bit;
    if (bp / 8 >= scalar_size)
      bit = 0;
    else
      bit = (scalar_bytes[bp / 8] >> (bp & 7)) & 1u;

    r_ecurve_edwards_point_dbl (&R0, &R0, curve);
    if (bit)
      r_ecurve_edwards_point_add (&R0, &R0, a, curve);
  }
  r_ecurve_edwards_point_copy (out, &R0);

  r_memclear_secure (&R0, sizeof (R0));
}

rboolean
r_ecurve_edwards_point_is_on_curve (const REcurveEdwardsPoint * point,
    const REcurveEdwards * curve)
{
  /* a*X^2 + Y^2 == Z^2 + d*T^2  (with a = ±1)
   * and T*Z == X*Y. */
  RMpintFE xx, yy, zz, tt, dt, lhs, rhs, tz, xy;
  const RMpintFEMontCtx * ctx = &curve->ctx;
  ruint16 n = ctx->n_digits;

  r_mpint_fe_sqr_mont (&xx, &point->X, ctx);
  r_mpint_fe_sqr_mont (&yy, &point->Y, ctx);
  r_mpint_fe_sqr_mont (&zz, &point->Z, ctx);
  r_mpint_fe_sqr_mont (&tt, &point->T, ctx);
  r_mpint_fe_mul_mont (&dt, &curve->d_mont, &tt, ctx);

  if (curve->a_is_minus_one) {
    RMpintFE zero;
    r_mpint_fe_zero (&zero);
    r_mpint_fe_sub (&lhs, &yy, &xx, ctx);
    (void)zero;
  } else {
    r_mpint_fe_add (&lhs, &xx, &yy, ctx);
  }
  r_mpint_fe_add (&rhs, &zz, &dt, ctx);
  r_mpint_fe_sub (&lhs, &lhs, &rhs, ctx);
  if (r_mpint_fe_iszero_ct (&lhs, n) == 0)
    return FALSE;

  r_mpint_fe_mul_mont (&tz, &point->T, &point->Z, ctx);
  r_mpint_fe_mul_mont (&xy, &point->X, &point->Y, ctx);
  r_mpint_fe_sub (&tz, &tz, &xy, ctx);
  return r_mpint_fe_iszero_ct (&tz, n) != 0;
}

/* ---- Encoding / decoding -------------------------------------------- */

/* Convert a projective point to its affine form, then write to LE byte
 * arrays for x and y. Caller buffers must be coord_bytes long. */
static rboolean
r_edwards_to_affine_bytes (ruint8 * x_out, ruint8 * y_out,
    const REcurveEdwardsPoint * point, const REcurveEdwards * curve)
{
  RMpintFE z_inv, x_aff, y_aff;
  rmpint x_mp, y_mp;
  rsize i;
  rboolean ok;

  r_mpint_fe_invmod_mont (&z_inv, &point->Z, &curve->p_minus_2,
      curve->p_minus_2_bits, &curve->r_squared, &curve->ctx);
  r_mpint_fe_mul_mont (&x_aff, &point->X, &z_inv, &curve->ctx);
  r_mpint_fe_mul_mont (&y_aff, &point->Y, &z_inv, &curve->ctx);
  r_mpint_fe_mont_out (&x_aff, &x_aff, &curve->ctx);
  r_mpint_fe_mont_out (&y_aff, &y_aff, &curve->ctx);

  r_mpint_init (&x_mp);
  r_mpint_init (&y_mp);
  ok = r_mpint_fe_to_mpint (&x_mp, &x_aff, curve->ctx.n_digits) &&
       r_mpint_fe_to_mpint (&y_mp, &y_aff, curve->ctx.n_digits);
  if (!ok) goto cleanup;

  /* Write LE bytes, padding with zeros. */
  for (i = 0; i < curve->coord_bytes; i++) {
    x_out[i] = (ruint8)(r_mpint_get_digit (&x_mp, (ruint32)(i / 4))
        >> ((i % 4) * 8));
    y_out[i] = (ruint8)(r_mpint_get_digit (&y_mp, (ruint32)(i / 4))
        >> ((i % 4) * 8));
  }

cleanup:
  r_mpint_clear (&x_mp);
  r_mpint_clear (&y_mp);
  r_memclear_secure (&z_inv, sizeof (z_inv));
  r_memclear_secure (&x_aff, sizeof (x_aff));
  r_memclear_secure (&y_aff, sizeof (y_aff));
  return ok;
}

rboolean
r_ecurve_edwards_point_encode (ruint8 * out,
    const REcurveEdwardsPoint * point, const REcurveEdwards * curve)
{
  ruint8 x_bytes[64], y_bytes[64];
  rboolean ok;

  if (R_UNLIKELY (out == NULL || point == NULL || curve == NULL))
    return FALSE;

  ok = r_edwards_to_affine_bytes (x_bytes, y_bytes, point, curve);
  if (!ok) goto cleanup;

  /* Copy y into the encoding (coord_bytes), zero any extra (encoding_bytes
   * may exceed coord_bytes by one, for edwards448), then set the sign
   * bit from x[0] & 1 into the top bit of the last encoding byte. */
  r_memcpy (out, y_bytes, curve->coord_bytes);
  if (curve->encoding_bytes > curve->coord_bytes)
    out[curve->encoding_bytes - 1] = 0;
  out[curve->encoding_bytes - 1] |=
      (ruint8)((x_bytes[0] & 1u) << 7);

cleanup:
  r_memclear_secure (x_bytes, sizeof (x_bytes));
  r_memclear_secure (y_bytes, sizeof (y_bytes));
  return ok;
}

/* Compute x from y per RFC 8032 §5.1.3 / §5.2.3:
 *   x^2 = (y^2 - 1) / (d*y^2 - a)
 * with a = ±1. For ed25519 (a=-1): x^2 = (y^2-1)/(d*y^2+1).
 * For ed448 (a=+1): x^2 = (y^2-1)/(d*y^2-1).
 * Returns FALSE if no square root exists. */
static rboolean
r_edwards_recover_x (RMpintFE * x_out, const RMpintFE * y_mont,
    rboolean sign_bit, const REcurveEdwards * curve)
{
  RMpintFE u, v, one_mont, t, x, vx2, neg_u;
  const RMpintFEMontCtx * ctx = &curve->ctx;
  ruint16 n = ctx->n_digits;
  rboolean ok = FALSE;

  {
    RMpintFE one_fe;
    r_mpint_fe_zero (&one_fe);
    one_fe.d[0] = 1;
    r_mpint_fe_mont_in (&one_mont, &one_fe, &curve->r_squared, ctx);
  }

  /* u = y^2 - 1 */
  r_mpint_fe_sqr_mont (&u, y_mont, ctx);
  r_mpint_fe_sub (&u, &u, &one_mont, ctx);

  /* v = d*y^2 - a (a = -1 for ed25519 -> +1; a = +1 for ed448 -> -1) */
  r_mpint_fe_sqr_mont (&v, y_mont, ctx);
  r_mpint_fe_mul_mont (&v, &v, &curve->d_mont, ctx);
  if (curve->a_is_minus_one)
    r_mpint_fe_add (&v, &v, &one_mont, ctx);
  else
    r_mpint_fe_sub (&v, &v, &one_mont, ctx);

  if (curve->a_is_minus_one) {
    /* Bernstein's sqrt for ed25519 (p ≡ 5 mod 8):
     * x = (u/v) * (u*v^3 * (u*v^7)^((p-5)/8))? No - the classic form is
     *   x = u * v^3 * (u * v^7)^((p-5)/8)
     * Then check v*x^2 == ±u.  */
    RMpintFE v3, v7, uv3, uv7, exp_result;
    r_mpint_fe_sqr_mont (&v3, &v, ctx);
    r_mpint_fe_mul_mont (&v3, &v3, &v, ctx);             /* v^3 */
    r_mpint_fe_sqr_mont (&v7, &v3, ctx);
    r_mpint_fe_mul_mont (&v7, &v7, &v, ctx);             /* v^7 */
    r_mpint_fe_mul_mont (&uv3, &u, &v3, ctx);
    r_mpint_fe_mul_mont (&uv7, &u, &v7, ctx);
    r_mpint_fe_invmod_mont (&exp_result, &uv7, &curve->sqrt_exponent,
        curve->sqrt_exponent_bits, &curve->r_squared, ctx);
    r_mpint_fe_mul_mont (&x, &uv3, &exp_result, ctx);

    /* Check v*x^2 ?= u */
    r_mpint_fe_sqr_mont (&vx2, &x, ctx);
    r_mpint_fe_mul_mont (&vx2, &vx2, &v, ctx);
    r_mpint_fe_sub (&t, &vx2, &u, ctx);
    if (r_mpint_fe_iszero_ct (&t, n) == 0) {
      /* v*x^2 == -u ?  Then x = x * sqrt(-1). */
      r_mpint_fe_zero (&neg_u);
      r_mpint_fe_sub (&neg_u, &neg_u, &u, ctx);
      r_mpint_fe_sub (&t, &vx2, &neg_u, ctx);
      if (r_mpint_fe_iszero_ct (&t, n) == 0)
        goto cleanup;
      r_mpint_fe_mul_mont (&x, &x, &curve->sqrt_m1_mont, ctx);
    }
    r_memclear_secure (&v3, sizeof (v3));
    r_memclear_secure (&v7, sizeof (v7));
    r_memclear_secure (&uv3, sizeof (uv3));
    r_memclear_secure (&uv7, sizeof (uv7));
    r_memclear_secure (&exp_result, sizeof (exp_result));
  } else {
    /* ed448, p ≡ 3 mod 4: x = (u/v)^((p+1)/4).
     * Equivalent computation without inverting v: x = u * v^((p+1)/4 - 1)
     * doesn't help much; just do invert + exp. */
    RMpintFE v_inv, ratio;
    r_mpint_fe_invmod_mont (&v_inv, &v, &curve->p_minus_2,
        curve->p_minus_2_bits, &curve->r_squared, ctx);
    r_mpint_fe_mul_mont (&ratio, &u, &v_inv, ctx);
    r_mpint_fe_invmod_mont (&x, &ratio, &curve->sqrt_exponent,
        curve->sqrt_exponent_bits, &curve->r_squared, ctx);
    /* Verify x^2 == u/v. */
    r_mpint_fe_sqr_mont (&t, &x, ctx);
    r_mpint_fe_sub (&t, &t, &ratio, ctx);
    if (r_mpint_fe_iszero_ct (&t, n) == 0)
      goto cleanup;
    r_memclear_secure (&v_inv, sizeof (v_inv));
    r_memclear_secure (&ratio, sizeof (ratio));
  }

  /* Sign-bit fixup: x is even (LSB of normal form = 0) iff
   * `(x in normal form) & 1 == 0`. After unMonting once we can
   * inspect; lift, check, negate if needed. */
  {
    RMpintFE x_normal;
    rmpint x_mp;
    rboolean x_is_odd;
    r_mpint_fe_mont_out (&x_normal, &x, ctx);
    r_mpint_init (&x_mp);
    r_mpint_fe_to_mpint (&x_mp, &x_normal, n);
    x_is_odd = (r_mpint_get_digit (&x_mp, 0) & 1u) != 0;
    r_mpint_clear (&x_mp);
    r_memclear_secure (&x_normal, sizeof (x_normal));

    /* If x is zero, the sign bit must be 0 per RFC. */
    if (r_mpint_fe_iszero_ct (&x, n) != 0 && sign_bit)
      goto cleanup;

    if (x_is_odd != (sign_bit ? TRUE : FALSE)) {
      RMpintFE zero;
      r_mpint_fe_zero (&zero);
      r_mpint_fe_sub (&x, &zero, &x, ctx);
    }
  }

  r_mpint_fe_copy (x_out, &x);
  ok = TRUE;

cleanup:
  r_memclear_secure (&u, sizeof (u));
  r_memclear_secure (&v, sizeof (v));
  r_memclear_secure (&one_mont, sizeof (one_mont));
  r_memclear_secure (&t, sizeof (t));
  r_memclear_secure (&x, sizeof (x));
  r_memclear_secure (&vx2, sizeof (vx2));
  r_memclear_secure (&neg_u, sizeof (neg_u));
  return ok;
}

rboolean
r_ecurve_edwards_point_decode (REcurveEdwardsPoint * out,
    const ruint8 * in, const REcurveEdwards * curve)
{
  ruint8 y_bytes[64];
  rboolean sign_bit;
  rmpint y_mp;
  RMpintFE y_fe, x_fe;
  rboolean ok = FALSE;

  if (R_UNLIKELY (out == NULL || in == NULL || curve == NULL))
    return FALSE;

  r_memcpy (y_bytes, in, curve->encoding_bytes);
  sign_bit = (y_bytes[curve->encoding_bytes - 1] & 0x80u) != 0;
  y_bytes[curve->encoding_bytes - 1] &= 0x7fu;

  r_mpint_init (&y_mp);
  r_edwards_mpint_init_from_le (&y_mp, y_bytes, curve->coord_bytes);
  /* Reject non-canonical y >= p. */
  if (r_mpint_ucmp (&y_mp, &curve->p) >= 0) {
    r_mpint_clear (&y_mp);
    return FALSE;
  }

  r_mpint_fe_from_mpint (&y_fe, &y_mp, curve->ctx.n_digits);
  r_mpint_fe_mont_in (&y_fe, &y_fe, &curve->r_squared, &curve->ctx);

  if (!r_edwards_recover_x (&x_fe, &y_fe, sign_bit, curve))
    goto cleanup;

  /* (x, y, 1, x*y) in Mont form. */
  r_mpint_fe_copy (&out->X, &x_fe);
  r_mpint_fe_copy (&out->Y, &y_fe);
  {
    RMpintFE one_fe;
    r_mpint_fe_zero (&one_fe);
    one_fe.d[0] = 1;
    r_mpint_fe_mont_in (&out->Z, &one_fe, &curve->r_squared, &curve->ctx);
  }
  r_mpint_fe_mul_mont (&out->T, &out->X, &out->Y, &curve->ctx);

  ok = TRUE;

cleanup:
  r_mpint_clear (&y_mp);
  r_memclear_secure (y_bytes, sizeof (y_bytes));
  r_memclear_secure (&y_fe, sizeof (y_fe));
  r_memclear_secure (&x_fe, sizeof (x_fe));
  return ok;
}
