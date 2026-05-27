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
#ifndef __R_CRYPTO_ECURVE_EDWARDS_H__
#define __R_CRYPTO_ECURVE_EDWARDS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/recurve.h>
#include <rlib/data/rmpint.h>

/**
 * @defgroup r_ecurve_edwards Twisted Edwards curves (edwards25519 / edwards448)
 * @brief Twisted Edwards point arithmetic on the curves underlying
 * the RFC 8032 EdDSA signature schemes.
 * @{
 */

/**
 * @file rlib/crypto/recurve-edwards.h
 * @brief Twisted-Edwards elliptic curves used by the EdDSA family.
 *
 * edwards25519 (the twisted Edwards curve birationally equivalent to
 * Curve25519) and edwards448 (untwisted Edwards, birationally
 * equivalent to Curve448). Points live in extended Edwards
 * coordinates @c (X, Y, Z, T) in Montgomery form, so the unified
 * addition formula handles every input without exceptional cases.
 *
 * The two curves differ in the sign of the twist constant
 * @c a: @c -1 for edwards25519 and @c +1 for edwards448. This
 * leaks into the doubling and the point-add formulas, which are
 * dispatched on @c REcurveEdwards::a_is_minus_one.
 *
 * Points and curves are kept distinct from the short-Weierstrass
 * surface in @c rlib/crypto/recurve.h and the Montgomery surface
 * in @c rlib/crypto/recurve-montgomery.h; the three share only
 * the @c REcurveID enum.
 */

R_BEGIN_DECLS

/**
 * @brief Edwards-form point in extended projective coordinates.
 *
 * The affine point is @c (X/Z, Y/Z) and @c T satisfies the
 * invariant @c T*Z == X*Y. All four coordinates are stored in
 * Montgomery form for the curve's field, so the arithmetic
 * primitives in this module can drive @c r_mpint_fe_mul_mont
 * directly.
 */
typedef struct {
  RMpintFE X;     /**< @brief X coordinate (Mont form). */
  RMpintFE Y;     /**< @brief Y coordinate (Mont form). */
  RMpintFE Z;     /**< @brief Projective Z (Mont form). */
  RMpintFE T;     /**< @brief Auxiliary T = X*Y/Z (Mont form). */
} REcurveEdwardsPoint;

/**
 * @brief Per-curve parameters and precomputed field-element
 * constants driving the Edwards point arithmetic.
 *
 * Populate via @c r_ecurve_edwards_init for a named curve; release
 * with @c r_ecurve_edwards_clear. The struct is plain data and may
 * live on the stack or be embedded in a larger key wrapper.
 */
typedef struct {
  REcurveID id;                 /**< @brief Curve identity. */
  rsize coord_bytes;            /**< @brief Bytes per field element
                                     (32 for edwards25519, 56 for
                                     edwards448). */
  rsize encoding_bytes;         /**< @brief RFC 8032 point encoding
                                     length (32 for edwards25519,
                                     57 for edwards448). */
  ruint16 bits;                 /**< @brief Field bit-length
                                     (255 / 448). */
  rboolean a_is_minus_one;      /**< @brief @c TRUE for edwards25519
                                     (twisted, @c a = -1); @c FALSE
                                     for edwards448 (untwisted,
                                     @c a = +1). */

  rmpint p;                     /**< @brief Field prime. */
  rmpint order;                 /**< @brief Order of the prime-order
                                     subgroup of the base point. */

  RMpintFEMontCtx ctx;          /**< @brief Per-modulus Mont context. */
  RMpintFE r_squared;           /**< @brief R^2 mod p. */
  RMpintFE d_mont;              /**< @brief Curve constant d in
                                     Montgomery form. */
  RMpintFE two_d_mont;          /**< @brief 2*d in Montgomery form;
                                     used by the edwards25519 add. */
  RMpintFE sqrt_m1_mont;        /**< @brief sqrt(-1) mod p in
                                     Montgomery form; used by the
                                     edwards25519 x-recovery. Unused
                                     for edwards448. */
  RMpintFE sqrt_exponent;       /**< @brief Modular-sqrt exponent
                                     ((p - 5) / 8 for edwards25519,
                                     (p + 1) / 4 for edwards448). */
  ruint16 sqrt_exponent_bits;   /**< @brief Bit length of @c sqrt_exponent. */
  RMpintFE p_minus_2;           /**< @brief Fermat inversion exponent. */
  ruint16 p_minus_2_bits;       /**< @brief Bit length of @c p_minus_2. */

  REcurveEdwardsPoint B;        /**< @brief Base point in extended
                                     Montgomery form. */
} REcurveEdwards;

/**
 * @brief Initialise an Edwards curve from a named identifier.
 *
 * @param curve  Output curve to initialise. Must be non-NULL.
 * @param named  @c R_ECURVE_ID_X25519 (which selects edwards25519,
 *               the EdDSA-side curve birationally equivalent to
 *               Curve25519) or @c R_ECURVE_ID_X448 (selects
 *               edwards448).
 *
 * @return @c TRUE on success; @c FALSE for NULL inputs or
 *         unsupported curves.
 */
R_API rboolean r_ecurve_edwards_init (REcurveEdwards * curve,
    REcurveID named);

/**
 * @brief Release storage held by an @c REcurveEdwards.
 *
 * @param curve  Curve to clear; may be NULL.
 */
R_API void r_ecurve_edwards_clear (REcurveEdwards * curve);

/**
 * @brief Set @p point to the identity element @c O = (0, 1, 1, 0).
 */
R_API void r_ecurve_edwards_point_set_identity (REcurveEdwardsPoint * point);

/**
 * @brief Copy @p src into @p dst.
 */
R_API void r_ecurve_edwards_point_copy (REcurveEdwardsPoint * dst,
    const REcurveEdwardsPoint * src);

/**
 * @brief Negate a point: @c (X, Y, Z, T) -> (-X, Y, Z, -T).
 *
 * Safe to alias @p out with @p a.
 */
R_API void r_ecurve_edwards_point_neg (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwards * curve);

/**
 * @brief Point addition using the unified extended-Edwards formula.
 *
 * Handles every input including the identity and equal points
 * without special cases. Safe to alias @p out with either operand.
 */
R_API void r_ecurve_edwards_point_add (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwardsPoint * b,
    const REcurveEdwards * curve);

/**
 * @brief Point doubling.
 *
 * Safe to alias @p out with @p a.
 */
R_API void r_ecurve_edwards_point_dbl (REcurveEdwardsPoint * out,
    const REcurveEdwardsPoint * a, const REcurveEdwards * curve);

/**
 * @brief Test whether @p a represents the identity element.
 *
 * The identity is the projective class of @c (0, 1, _, _), so the
 * check normalises by comparing @c X*Z2 == 0 and @c Y*Z2 == Z*Z2
 * for the @c Z=1-normalised form. Returns @c TRUE / @c FALSE rather
 * than a constant-time mask; callers that need CT identity testing
 * should use the value-level comparison directly on a normalised
 * affine form.
 */
R_API rboolean r_ecurve_edwards_point_is_identity (const REcurveEdwardsPoint * a,
    const REcurveEdwards * curve);

/**
 * @brief Test whether two points are projectively equal.
 *
 * Compares @c X1*Z2 == X2*Z1 and @c Y1*Z2 == Y2*Z1, the standard
 * equivalence relation for extended Edwards coordinates.
 */
R_API rboolean r_ecurve_edwards_point_equal (const REcurveEdwardsPoint * a,
    const REcurveEdwardsPoint * b, const REcurveEdwards * curve);

/**
 * @brief Scalar multiplication: @c out = scalar * a.
 *
 * Uses a left-to-right swap-wrap ladder so the per-bit branch shape
 * is independent of the scalar. @p scalar_bytes is interpreted as a
 * little-endian integer of @p scalar_size bytes; the highest bit
 * acted on is determined by @p scalar_bits (the caller is
 * responsible for clamping per RFC 8032 §5.1.5 / §5.2.5).
 *
 * Safe to alias @p out with @p a.
 */
R_API void r_ecurve_edwards_point_scalar_mul (REcurveEdwardsPoint * out,
    const ruint8 * scalar_bytes, rsize scalar_size, ruint scalar_bits,
    const REcurveEdwardsPoint * a, const REcurveEdwards * curve);

/**
 * @brief Test the curve equation @c a*X^2 + Y^2 == Z^2 + d*T^2 and
 * @c T*Z == X*Y.
 */
R_API rboolean r_ecurve_edwards_point_is_on_curve (const REcurveEdwardsPoint * point,
    const REcurveEdwards * curve);

/**
 * @brief Encode a point per RFC 8032 §5.1.2 / §5.2.2.
 *
 * Writes @c encoding_bytes of little-endian @c y, with the sign of
 * @c x packed into the top bit of the final byte. The point is
 * normalised to its affine (Z=1) form internally.
 *
 * @param out      Destination buffer of @c curve->encoding_bytes bytes.
 * @param point    Point to encode.
 * @param curve    Initialised curve.
 * @return @c TRUE on success; @c FALSE on NULL inputs.
 */
R_API rboolean r_ecurve_edwards_point_encode (ruint8 * out,
    const REcurveEdwardsPoint * point, const REcurveEdwards * curve);

/**
 * @brief Decode an RFC 8032 point encoding into @p out.
 *
 * Reads @c encoding_bytes from @p in: little-endian @c y plus a
 * sign bit. Recovers @c x via modular square root and verifies the
 * curve equation. Rejects non-canonical @c y (greater than or equal
 * to the field prime) and encodings that fail the sqrt step.
 *
 * @param out    Destination point (must be initialised).
 * @param in     @c curve->encoding_bytes input bytes.
 * @param curve  Initialised curve.
 * @return @c TRUE on a valid canonical encoding of an on-curve
 *         point; @c FALSE otherwise.
 */
R_API rboolean r_ecurve_edwards_point_decode (REcurveEdwardsPoint * out,
    const ruint8 * in, const REcurveEdwards * curve);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_ECURVE_EDWARDS_H__ */
