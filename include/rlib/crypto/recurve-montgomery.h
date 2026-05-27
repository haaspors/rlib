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
#ifndef __R_CRYPTO_ECURVE_MONTGOMERY_H__
#define __R_CRYPTO_ECURVE_MONTGOMERY_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/recurve.h>
#include <rlib/data/rmpint.h>

/**
 * @defgroup r_ecurve_montgomery Montgomery curves (Curve25519 / Curve448)
 * @brief u-coordinate Montgomery ladder for the RFC 7748 curves.
 * @{
 */

/**
 * @file rlib/crypto/recurve-montgomery.h
 * @brief Montgomery-form elliptic curves: By^2 = x^3 + Ax^2 + x over GF(p).
 *
 * Distinct from the short-Weierstrass surface in @c rlib/crypto/recurve.h -
 * the algebra doesn't overlap and the X25519 / X448 scalar multiplication
 * uses the u-coordinate-only Montgomery ladder rather than generic
 * point add / double. The two layers share only the @c REcurveID enum.
 *
 * Supported curves: Curve25519 (@c R_ECURVE_ID_X25519) and Curve448
 * (@c R_ECURVE_ID_X448), the two curves underpinning the X25519 / X448
 * Diffie-Hellman key exchange of RFC 7748.
 *
 * The ladder operates on little-endian byte buffers - the wire format
 * RFC 7748 specifies - so callers don't have to think about field-element
 * marshalling. Scalar clamping per RFC 7748 §5 happens internally on a
 * working copy; the caller-supplied scalar is never modified.
 *
 * The underlying field arithmetic runs in Montgomery form via the
 * fixed-width @c RMpintFE primitives, giving constant-time inner
 * operations across both supported curves. The ladder loop itself is
 * the standard branch-uniform conditional-swap construction.
 */

R_BEGIN_DECLS

/**
 * @brief Per-curve parameters and precomputed field-element constants
 * driving the Montgomery ladder.
 *
 * Populate via @c r_ecurve_montgomery_init for a named curve; release
 * with @c r_ecurve_montgomery_clear. The struct is plain data and may
 * live on the stack or be embedded in a larger key wrapper. The
 * precomputed @c RMpintFE constants (Montgomery-form A24, R^2 mod p,
 * the Fermat exponent for inversion) are the per-modulus setup that
 * the ladder reuses across every call.
 */
typedef struct {
  REcurveID id;                 /**< @brief Curve identity (X25519 / X448). */
  rsize coord_bytes;            /**< @brief 32 (Curve25519) or 56 (Curve448). */
  ruint16 bits;                 /**< @brief 255 or 448 - drives clamping
                                    and the decode-side high-bit mask. */

  rmpint p;                     /**< @brief Field prime. */
  rmpint u_G;                   /**< @brief Base-point u-coordinate. */
  /**
   * @brief Order of the prime-order subgroup of the base point.
   *
   * Stored for downstream consumers (signing schemes that need it for
   * scalar reductions); the ladder itself does not use it.
   */
  rmpint order;

  RMpintFEMontCtx ctx;          /**< @brief Per-modulus Montgomery context. */
  RMpintFE r_squared;           /**< @brief R^2 mod p, used to lift values
                                    into Montgomery form. */
  RMpintFE A24_mont;            /**< @brief (A - 2) / 4 in Montgomery form:
                                    121665 for Curve25519, 39081 for
                                    Curve448 (per RFC 7748 §5). */
  RMpintFE p_minus_2;           /**< @brief Fermat exponent for the final
                                    field-element inversion. */
  ruint16 p_minus_2_bits;       /**< @brief Bit length of @c p_minus_2,
                                    driving the inversion loop. */
} REcurveMontgomery;

/**
 * @brief Initialise a Montgomery curve from its named identifier.
 *
 * Populates the field prime, base-point u-coordinate, subgroup order,
 * and all precomputed Montgomery-form constants needed by the ladder.
 *
 * @param curve  Output curve to initialise. Must be non-NULL.
 * @param named  One of @c R_ECURVE_ID_X25519 or @c R_ECURVE_ID_X448.
 * @return @c TRUE on success; @c FALSE if @p curve is NULL or @p named
 *         is not one of the two supported Montgomery curves.
 */
R_API rboolean r_ecurve_montgomery_init (REcurveMontgomery * curve,
    REcurveID named);

/**
 * @brief Release storage held by a @c REcurveMontgomery.
 *
 * Clears the mpint members and securely wipes the precomputed
 * Montgomery-form field elements. Safe to call on a zero-initialised
 * struct and idempotent against a NULL pointer.
 *
 * @param curve  Curve to clear; may be NULL.
 */
R_API void r_ecurve_montgomery_clear (REcurveMontgomery * curve);

/**
 * @brief RFC 7748 §5 Montgomery ladder, u-coordinate only.
 *
 * Computes @p scalar times the point with u-coordinate @p in_u and
 * writes the resulting u-coordinate to @p out_u. The scalar is clamped
 * on an internal working copy per RFC 7748 §5 (clamp_25519 for
 * Curve25519, clamp_448 for Curve448), so callers pass the raw 32 /
 * 56-byte buffer without pre-processing.
 *
 * For X25519 the high bit of @p in_u is masked off before decoding,
 * per RFC 7748 §5. X448 has no unused bits and decodes the input
 * as-is.
 *
 * @param out_u   Destination buffer, @c curve->coord_bytes long.
 *                Written as little-endian.
 * @param scalar  Caller's scalar, @c curve->coord_bytes long,
 *                little-endian. Not modified.
 * @param in_u    Input u-coordinate, @c curve->coord_bytes long,
 *                little-endian.
 * @param curve   Initialised curve from @c r_ecurve_montgomery_init.
 *
 * @return @c TRUE on a non-zero result; @c FALSE on NULL arguments or
 *         on the small-subgroup outcome where the resulting u is zero.
 *         The latter is the RFC 7748 §6 contributory-behaviour check
 *         that Diffie-Hellman callers are required to apply anyway;
 *         the all-zero buffer is still written so callers that need
 *         the raw value can inspect it.
 */
R_API rboolean r_ecurve_montgomery_ladder (ruint8 * out_u,
    const ruint8 * scalar, const ruint8 * in_u,
    const REcurveMontgomery * curve);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_ECURVE_MONTGOMERY_H__ */
