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

#include <rlib/crypto/recurve-montgomery.h>

#include <rlib/rmem.h>

/* Curve25519: p = 2^255 - 19, A24 = (486662 - 2) / 4 = 121665, u_G = 9.
 * Subgroup order = 8 * L where L = 2^252 + 27742317777372353535851937790883648493.
 * Stored full group order 8L. */
static const ruint8 c25519_p[] = {
  0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};
static const ruint8 c25519_order[] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xa6, 0xf7, 0xce, 0xf5, 0x17, 0xbc, 0xe6, 0xb2,
  0xc0, 0x93, 0x18, 0xd2, 0xe7, 0xae, 0x9f, 0x68
};

/* Curve448: p = 2^448 - 2^224 - 1, A24 = (156326 - 2) / 4 = 39081, u_G = 5.
 * Subgroup order = 4 * L where L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
 * Stored full group order 4L. */
static const ruint8 c448_p[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};
static const ruint8 c448_order[] = {
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xfd, 0xf3, 0x28, 0x8f, 0xa7, 0x11, 0x3b, 0x6d,
  0x26, 0xbb, 0x58, 0xda, 0x40, 0x85, 0xb3, 0x09, 0xca, 0x37, 0x16, 0x3d,
  0x54, 0x8d, 0xe3, 0x0a, 0x4a, 0xad, 0x61, 0x13, 0xcc
};

typedef struct {
  REcurveID id;
  ruint16 bits;
  rsize coord_bytes;
  const ruint8 * p_be;   rsize p_size;
  const ruint8 * order_be; rsize order_size;
  ruint32 u_G;
  ruint32 A24;
} RMontgomeryParams;

static const RMontgomeryParams g__mont_params[] = {
  { R_ECURVE_ID_X25519, 255, 32,
      c25519_p,     sizeof (c25519_p),
      c25519_order, sizeof (c25519_order),
      9,     121665 },
  { R_ECURVE_ID_X448,   448, 56,
      c448_p,       sizeof (c448_p),
      c448_order,   sizeof (c448_order),
      5,     39081 },
};

static const RMontgomeryParams *
r_montgomery_params_find (REcurveID id)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (g__mont_params); i++) {
    if (g__mont_params[i].id == id)
      return &g__mont_params[i];
  }
  return NULL;
}

rboolean
r_ecurve_montgomery_init (REcurveMontgomery * curve, REcurveID named)
{
  const RMontgomeryParams * params;
  rmpint A24_mp, pm2;
  RMpintFE A24_fe;

  if (R_UNLIKELY (curve == NULL))
    return FALSE;
  if ((params = r_montgomery_params_find (named)) == NULL)
    return FALSE;

  r_memset (curve, 0, sizeof (*curve));
  curve->id = named;
  curve->bits = params->bits;
  curve->coord_bytes = params->coord_bytes;

  r_mpint_init_binary (&curve->p, params->p_be, params->p_size);
  r_mpint_init (&curve->u_G);
  r_mpint_set_u32 (&curve->u_G, params->u_G);
  r_mpint_init_binary (&curve->order, params->order_be, params->order_size);

  if (!r_mpint_fe_mont_ctx_init (&curve->ctx, &curve->p))
    goto fail;
  if (!r_mpint_fe_compute_r_squared (&curve->r_squared, &curve->p,
        curve->ctx.n_digits))
    goto fail;

  /* A24_mont = (A - 2) / 4 in Montgomery form. The constant is small
   * enough (< 2^17 for both curves) that the lift fits in a u32. */
  r_mpint_init (&A24_mp);
  r_mpint_set_u32 (&A24_mp, params->A24);
  r_mpint_fe_from_mpint (&A24_fe, &A24_mp, curve->ctx.n_digits);
  r_mpint_fe_mont_in (&curve->A24_mont, &A24_fe, &curve->r_squared, &curve->ctx);
  r_mpint_clear (&A24_mp);

  r_mpint_init (&pm2);
  if (!r_mpint_sub_i32 (&pm2, &curve->p, 2)) {
    r_mpint_clear (&pm2);
    goto fail;
  }
  r_mpint_fe_from_mpint (&curve->p_minus_2, &pm2, curve->ctx.n_digits);
  curve->p_minus_2_bits = (ruint16)r_mpint_bits_used (&pm2);
  r_mpint_clear (&pm2);

  return TRUE;

fail:
  r_ecurve_montgomery_clear (curve);
  return FALSE;
}

void
r_ecurve_montgomery_clear (REcurveMontgomery * curve)
{
  if (curve == NULL) return;
  r_mpint_clear (&curve->p);
  r_mpint_clear (&curve->u_G);
  r_mpint_clear (&curve->order);
  r_memclear_secure (&curve->ctx, sizeof (curve->ctx));
  r_memclear_secure (&curve->r_squared, sizeof (curve->r_squared));
  r_memclear_secure (&curve->A24_mont, sizeof (curve->A24_mont));
  r_memclear_secure (&curve->p_minus_2, sizeof (curve->p_minus_2));
}

/* Little-endian byte-array -> RMpintFE. Mirrors decodeLittleEndian
 * in RFC 7748 §5 but lands in an FE directly so the ladder can keep
 * everything in fixed-width form. Caller guarantees buf is
 * curve->coord_bytes long. */
static void
r_montgomery_decode_le (RMpintFE * out, const ruint8 * buf, ruint16 n_digits)
{
  ruint16 i;
  rsize byte_count = (rsize)n_digits * sizeof (rmpint_digit);
  rmpint_digit acc;

  r_mpint_fe_zero (out);
  for (i = 0; i < n_digits; i++) {
    rsize off = (rsize)i * sizeof (rmpint_digit);
    acc = 0;
    if (off + 0 < byte_count) acc |= (rmpint_digit)buf[off + 0];
    if (off + 1 < byte_count) acc |= ((rmpint_digit)buf[off + 1] << 8);
    if (off + 2 < byte_count) acc |= ((rmpint_digit)buf[off + 2] << 16);
    if (off + 3 < byte_count) acc |= ((rmpint_digit)buf[off + 3] << 24);
    out->d[i] = acc;
  }
}

/* Inverse of the above. Writes exactly coord_bytes of little-endian
 * output. n_digits >= ceil(coord_bytes / 4); the loop ignores any FE
 * digits past coord_bytes. */
static void
r_montgomery_encode_le (ruint8 * out, rsize coord_bytes, const RMpintFE * a)
{
  rsize i;
  for (i = 0; i < coord_bytes; i++) {
    rmpint_digit d = a->d[i / sizeof (rmpint_digit)];
    out[i] = (ruint8)(d >> ((i % sizeof (rmpint_digit)) * 8));
  }
}

/* Per RFC 7748 §5: X25519's u-coordinate decoding masks bit 255 of
 * the input (the top bit of byte 31) before the little-endian decode.
 * X448 has no unused bits and decodes directly. */
static void
r_montgomery_decode_u (RMpintFE * out, const ruint8 * in_u,
    const REcurveMontgomery * curve)
{
  if (curve->id == R_ECURVE_ID_X25519) {
    ruint8 masked[32];
    r_memcpy (masked, in_u, 32);
    masked[31] &= 0x7f;
    r_montgomery_decode_le (out, masked, curve->ctx.n_digits);
    r_memclear_secure (masked, sizeof (masked));
  } else {
    r_montgomery_decode_le (out, in_u, curve->ctx.n_digits);
  }
}

/* RFC 7748 §5 scalar clamping. Operates on a working copy of the
 * caller's 32 / 56-byte buffer - the original isn't modified. */
static void
r_montgomery_clamp (ruint8 * scalar, REcurveID id)
{
  if (id == R_ECURVE_ID_X25519) {
    scalar[0]  &= 0xf8;
    scalar[31] &= 0x7f;
    scalar[31] |= 0x40;
  } else {
    /* X448 */
    scalar[0]  &= 0xfc;
    scalar[55] |= 0x80;
  }
}

/* One ladder step. (x_2, z_2) and (x_3, z_3) are the two parallel
 * point pairs; x_1 is the input u-coordinate. All operands in
 * Montgomery form. Reads + writes everything via the scratch
 * temporaries so the per-step allocation is one stack frame. */
static void
r_montgomery_ladder_step (RMpintFE * x_2, RMpintFE * z_2,
    RMpintFE * x_3, RMpintFE * z_3, const RMpintFE * x_1,
    const REcurveMontgomery * curve)
{
  RMpintFE A, AA, B, BB, E, C, D, DA, CB, t;
  const RMpintFEMontCtx * ctx = &curve->ctx;

  /* A = x_2 + z_2 ; AA = A^2
   * B = x_2 - z_2 ; BB = B^2
   * E = AA - BB
   * C = x_3 + z_3
   * D = x_3 - z_3
   * DA = D * A ; CB = C * B
   * x_3 = (DA + CB)^2
   * z_3 = x_1 * (DA - CB)^2
   * x_2 = AA * BB
   * z_2 = E * (AA + a24 * E) */

  r_mpint_fe_add (&A,  x_2, z_2, ctx);
  r_mpint_fe_sqr_mont (&AA, &A, ctx);
  r_mpint_fe_sub (&B,  x_2, z_2, ctx);
  r_mpint_fe_sqr_mont (&BB, &B, ctx);
  r_mpint_fe_sub (&E,  &AA, &BB, ctx);
  r_mpint_fe_add (&C,  x_3, z_3, ctx);
  r_mpint_fe_sub (&D,  x_3, z_3, ctx);
  r_mpint_fe_mul_mont (&DA, &D, &A, ctx);
  r_mpint_fe_mul_mont (&CB, &C, &B, ctx);

  r_mpint_fe_add (&t, &DA, &CB, ctx);
  r_mpint_fe_sqr_mont (x_3, &t, ctx);

  r_mpint_fe_sub (&t, &DA, &CB, ctx);
  r_mpint_fe_sqr_mont (&t, &t, ctx);
  r_mpint_fe_mul_mont (z_3, x_1, &t, ctx);

  r_mpint_fe_mul_mont (x_2, &AA, &BB, ctx);

  r_mpint_fe_mul_mont (&t, &curve->A24_mont, &E, ctx);
  r_mpint_fe_add (&t, &AA, &t, ctx);
  r_mpint_fe_mul_mont (z_2, &E, &t, ctx);

  r_memclear_secure (&A, sizeof (A));
  r_memclear_secure (&AA, sizeof (AA));
  r_memclear_secure (&B, sizeof (B));
  r_memclear_secure (&BB, sizeof (BB));
  r_memclear_secure (&E, sizeof (E));
  r_memclear_secure (&C, sizeof (C));
  r_memclear_secure (&D, sizeof (D));
  r_memclear_secure (&DA, sizeof (DA));
  r_memclear_secure (&CB, sizeof (CB));
  r_memclear_secure (&t, sizeof (t));
}

rboolean
r_ecurve_montgomery_ladder (ruint8 * out_u, const ruint8 * scalar,
    const ruint8 * in_u, const REcurveMontgomery * curve)
{
  ruint8 k[56];                 /* Max coord_bytes across supported curves. */
  RMpintFE x_1, x_2, z_2, x_3, z_3, one_mont, one_fe, z_inv;
  ruint16 n;
  ruint i;
  ruint32 swap = 0;
  rboolean ok = FALSE;

  if (R_UNLIKELY (out_u == NULL || scalar == NULL ||
        in_u == NULL || curve == NULL))
    return FALSE;
  if (R_UNLIKELY (curve->coord_bytes > sizeof (k)))
    return FALSE;

  n = curve->ctx.n_digits;

  /* Clamp on a working copy so the caller's scalar is untouched. */
  r_memcpy (k, scalar, curve->coord_bytes);
  r_montgomery_clamp (k, curve->id);

  /* x_1 = decodeU(in_u), lifted into Mont form. */
  r_montgomery_decode_u (&x_1, in_u, curve);
  r_mpint_fe_mont_in (&x_1, &x_1, &curve->r_squared, &curve->ctx);

  /* x_2 = 1_M, z_2 = 0; x_3 = x_1, z_3 = 1_M. */
  r_mpint_fe_zero (&one_fe);
  one_fe.d[0] = 1;
  r_mpint_fe_mont_in (&one_mont, &one_fe, &curve->r_squared, &curve->ctx);

  r_mpint_fe_copy (&x_2, &one_mont);
  r_mpint_fe_zero (&z_2);
  r_mpint_fe_copy (&x_3, &x_1);
  r_mpint_fe_copy (&z_3, &one_mont);

  /* Iterate from bit (bits - 1) down to 0, MSB-first as per RFC 7748. */
  for (i = curve->bits; i > 0; i--) {
    ruint bp = i - 1;
    ruint32 k_t = (k[bp / 8] >> (bp & 7)) & 1u;
    swap ^= k_t;
    r_mpint_fe_swap_ct (&x_2, &x_3, swap, n);
    r_mpint_fe_swap_ct (&z_2, &z_3, swap, n);
    swap = k_t;

    r_montgomery_ladder_step (&x_2, &z_2, &x_3, &z_3, &x_1, curve);
  }
  r_mpint_fe_swap_ct (&x_2, &x_3, swap, n);
  r_mpint_fe_swap_ct (&z_2, &z_3, swap, n);

  /* Return x_2 * z_2^(p - 2) ; lift back out of Mont form. */
  r_mpint_fe_invmod_mont (&z_inv, &z_2, &curve->p_minus_2,
      curve->p_minus_2_bits, &curve->r_squared, &curve->ctx);
  r_mpint_fe_mul_mont (&x_2, &x_2, &z_inv, &curve->ctx);
  r_mpint_fe_mont_out (&x_2, &x_2, &curve->ctx);

  r_montgomery_encode_le (out_u, curve->coord_bytes, &x_2);

  /* RFC 7748 §6 contributory check: a zero shared u is the small-
   * subgroup outcome that DH callers MUST reject. Surface as FALSE so
   * the wrapper layer doesn't have to inspect the bytes. iszero_ct
   * returns all-ones when the value is zero. */
  ok = (r_mpint_fe_iszero_ct (&x_2, n) == (rmpint_digit)0);

  r_memclear_secure (k, sizeof (k));
  r_memclear_secure (&x_1, sizeof (x_1));
  r_memclear_secure (&x_2, sizeof (x_2));
  r_memclear_secure (&z_2, sizeof (z_2));
  r_memclear_secure (&x_3, sizeof (x_3));
  r_memclear_secure (&z_3, sizeof (z_3));
  r_memclear_secure (&one_mont, sizeof (one_mont));
  r_memclear_secure (&one_fe, sizeof (one_fe));
  r_memclear_secure (&z_inv, sizeof (z_inv));

  return ok;
}
