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
#ifndef __R_CRYPTO_ECURVE_H__
#define __R_CRYPTO_ECURVE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/data/rmpint.h>

/**
 * @defgroup r_ecurve Short-Weierstrass elliptic curves
 * @brief Named prime curves and affine point arithmetic for the
 * short-Weierstrass form y^2 = x^3 + ax + b over GF(p).
 * @{
 */

/**
 * @file rlib/crypto/recurve.h
 * @brief Short-Weierstrass elliptic curves: named prime curves and
 * affine point operations.
 *
 * The supported curves are the six prime curves enumerated by SEC 2
 * v2 / NIST FIPS 186-4: secp192r1, secp224r1, secp256r1, secp384r1,
 * secp521r1, secp256k1. They share the affine point type
 * @c REcurveAffinePoint and the point operations (negate, double,
 * add, scalar-mul, on-curve check, SEC 1 uncompressed encode /
 * decode).
 *
 * @c REcurveID is the broader IANA TLS NamedGroup enum that also
 * names binary @c sect* curves, Brainpool curves, the Montgomery
 * curves Curve25519 / Curve448, and the finite-field DH groups -
 * those live for identifier round-tripping; this module's math
 * layer only initialises the prime-curve subset. The Montgomery
 * curves have their own surface in
 * @c rlib/crypto/recurve-montgomery.h.
 *
 * Scalar multiplication uses a constant-time Jacobian-projective
 * ladder running on the fixed-width @c RMpintFE Montgomery stack;
 * the ladder's branch shape is independent of the scalar bits, so
 * secret-scalar callers (ECDSA, ECDH) don't leak via branch timing.
 * The underlying field arithmetic in @c rmpint is variable-time on
 * value magnitudes, so this is "branch-uniform CT" rather than
 * strict CT - good enough to remove the dominant key-dependent
 * branch leak; full timing hardening is tracked as a follow-up on
 * the issue that introduced this module.
 */

R_BEGIN_DECLS

/**
 * @brief Identifiers for the named elliptic curves and TLS / DH
 * groups defined by the IANA registries.
 *
 * The values match the TLS NamedGroup codepoints (RFC 4492, RFC
 * 7027, RFC 7919, TLS 1.3) so they can flow directly through
 * extension parsers without translation. Not every entry is
 * supported by the math layer: @c r_ecurve_init returns @c FALSE
 * for anything outside the prime curves currently shipped, and the
 * Montgomery curves are handled by a separate surface in
 * @c rlib/crypto/recurve-montgomery.h.
 */
typedef enum {
  R_ECURVE_ID_NONE                             = 0,       /**< @brief Sentinel for "no curve". */
  R_ECURVE_ID_SECT163K1                        = 0x0001,  /**< @brief Binary curve sect163k1 (RFC 4492). */
  R_ECURVE_ID_SECT163R1                        = 0x0002,  /**< @brief Binary curve sect163r1 (RFC 4492). */
  R_ECURVE_ID_SECT163R2                        = 0x0003,  /**< @brief Binary curve sect163r2 (RFC 4492). */
  R_ECURVE_ID_SECT193R1                        = 0x0004,  /**< @brief Binary curve sect193r1 (RFC 4492). */
  R_ECURVE_ID_SECT193R2                        = 0x0005,  /**< @brief Binary curve sect193r2 (RFC 4492). */
  R_ECURVE_ID_SECT233K1                        = 0x0006,  /**< @brief Binary curve sect233k1 (RFC 4492). */
  R_ECURVE_ID_SECT233R1                        = 0x0007,  /**< @brief Binary curve sect233r1 (RFC 4492). */
  R_ECURVE_ID_SECT239K1                        = 0x0008,  /**< @brief Binary curve sect239k1 (RFC 4492). */
  R_ECURVE_ID_SECT283K1                        = 0x0009,  /**< @brief Binary curve sect283k1 (RFC 4492). */
  R_ECURVE_ID_SECT283R1                        = 0x000a,  /**< @brief Binary curve sect283r1 (RFC 4492). */
  R_ECURVE_ID_SECT409K1                        = 0x000b,  /**< @brief Binary curve sect409k1 (RFC 4492). */
  R_ECURVE_ID_SECT409R1                        = 0x000c,  /**< @brief Binary curve sect409r1 (RFC 4492). */
  R_ECURVE_ID_SECT571K1                        = 0x000d,  /**< @brief Binary curve sect571k1 (RFC 4492). */
  R_ECURVE_ID_SECT571R1                        = 0x000e,  /**< @brief Binary curve sect571r1 (RFC 4492). */
  R_ECURVE_ID_SECP160K1                        = 0x000f,  /**< @brief Prime curve secp160k1 (RFC 4492; not initialised by the math layer). */
  R_ECURVE_ID_SECP160R1                        = 0x0010,  /**< @brief Prime curve secp160r1 (RFC 4492; not initialised by the math layer). */
  R_ECURVE_ID_SECP160R2                        = 0x0011,  /**< @brief Prime curve secp160r2 (RFC 4492; not initialised by the math layer). */
  R_ECURVE_ID_SECP192K1                        = 0x0012,  /**< @brief Prime curve secp192k1 (RFC 4492; not initialised by the math layer). */
  R_ECURVE_ID_SECP192R1                        = 0x0013,  /**< @brief Prime curve secp192r1 / NIST P-192 (RFC 4492). */
  R_ECURVE_ID_SECP224K1                        = 0x0014,  /**< @brief Prime curve secp224k1 (RFC 4492; not initialised by the math layer). */
  R_ECURVE_ID_SECP224R1                        = 0x0015,  /**< @brief Prime curve secp224r1 / NIST P-224 (RFC 4492). */
  R_ECURVE_ID_SECP256K1                        = 0x0016,  /**< @brief Prime curve secp256k1 (RFC 4492). */
  R_ECURVE_ID_SECP256R1                        = 0x0017,  /**< @brief Prime curve secp256r1 / NIST P-256 (RFC 4492). */
  R_ECURVE_ID_SECP384R1                        = 0x0018,  /**< @brief Prime curve secp384r1 / NIST P-384 (RFC 4492). */
  R_ECURVE_ID_SECP521R1                        = 0x0019,  /**< @brief Prime curve secp521r1 / NIST P-521 (RFC 4492). */
  R_ECURVE_ID_BRAINPOOLP256R1                  = 0x001a,  /**< @brief Brainpool brainpoolP256r1 (RFC 7027; not initialised by the math layer). */
  R_ECURVE_ID_BRAINPOOLP348R1                  = 0x001b,  /**< @brief Brainpool brainpoolP384r1 (RFC 7027; not initialised by the math layer). */
  R_ECURVE_ID_BRAINPOOLP512R1                  = 0x001c,  /**< @brief Brainpool brainpoolP512r1 (RFC 7027; not initialised by the math layer). */
  R_ECURVE_ID_X25519                           = 0x001d,  /**< @brief Curve25519, handled by @c rlib/crypto/recurve-montgomery.h. */
  R_ECURVE_ID_X448                             = 0x001e,  /**< @brief Curve448, handled by @c rlib/crypto/recurve-montgomery.h. */
  R_ECURVE_ID_FFDHE2048                        = 0x0100,  /**< @brief Finite-field DH group ffdhe2048 (RFC 7919). */
  R_ECURVE_ID_FFDHE3072                        = 0x0101,  /**< @brief Finite-field DH group ffdhe3072 (RFC 7919). */
  R_ECURVE_ID_FFDHE4096                        = 0x0102,  /**< @brief Finite-field DH group ffdhe4096 (RFC 7919). */
  R_ECURVE_ID_FFDHE6144                        = 0x0103,  /**< @brief Finite-field DH group ffdhe6144 (RFC 7919). */
  R_ECURVE_ID_FFDHE8192                        = 0x0104,  /**< @brief Finite-field DH group ffdhe8192 (RFC 7919). */
  R_ECURVE_ID_ARBITRARY_EXPLICIT_PRIME_CURVES  = 0xff01,  /**< @brief Explicit prime curve placeholder (RFC 4492). */
  R_ECURVE_ID_ARBITRARY_EXPLICIT_CHAR2_CURVES  = 0xff02,  /**< @brief Explicit binary curve placeholder (RFC 4492). */
} REcurveID;

/**
 * @brief Short-Weierstrass affine point.
 *
 * Identity (the algebraic infinity) is tracked via the
 * @c is_infinity flag rather than a magic coordinate, so callers
 * don't have to special-case e.g. @c (0, 0), which is a valid
 * finite point on many curves.
 */
typedef struct {
  rmpint x;                 /**< @brief Affine x-coordinate (unused when @c is_infinity). */
  rmpint y;                 /**< @brief Affine y-coordinate (unused when @c is_infinity). */
  rboolean is_infinity;     /**< @brief @c TRUE iff this point is the group identity. */
} REcurveAffinePoint;

/**
 * @brief Per-curve parameters for short-Weierstrass form @c y^2 =
 * x^3 + ax + b over @c GF(p), with subgroup of prime order @c n
 * generated by @c G.
 *
 * @c a, @c b, @c n, @c G are stored in normal (non-Montgomery) form
 * so the public point API can keep operating on raw coordinates.
 * The Montgomery setup constants (@c mont_mp, @c mont_r_squared)
 * and a pre-converted copy of the @c a coefficient
 * (@c mont_a = a * R mod p) are precomputed at @c r_ecurve_init so
 * the secret-dependent scalar-multiplication ladder can run a
 * constant-time Montgomery variant of the point arithmetic without
 * paying conversion cost per bit. @c p_minus_2 is the Fermat
 * exponent used by the constant-time inverter inside the ladder.
 */
typedef struct {
  rmpint p;                   /**< @brief Field prime. */
  rmpint a;                   /**< @brief Curve coefficient a. */
  rmpint b;                   /**< @brief Curve coefficient b. */
  rmpint n;                   /**< @brief Order of the prime-order subgroup generated by @c G. */
  REcurveAffinePoint G;       /**< @brief Generator of the prime-order subgroup. */
  rsize coord_bytes;          /**< @brief Bytes per coordinate when encoded (e.g. 32 for secp256r1). */
  rmpint_digit mont_mp;       /**< @brief @c -p^-1 mod 2^digit_bits. */
  rmpint mont_r_squared;      /**< @brief @c R^2 mod p. */
  rmpint mont_a;              /**< @brief @c a * R mod p, used by the Montgomery doubling. */
  rmpint p_minus_2;           /**< @brief @c p - 2, the Fermat inversion exponent. */
} REcurve;

/**
 * @brief Initialise an affine point as the group identity (infinity).
 *
 * Initialises both mpint coordinates to zero and sets
 * @c is_infinity to @c TRUE.
 *
 * @param point  Point to initialise; must be non-NULL.
 */
R_API void r_ecurve_point_init (REcurveAffinePoint * point);

/**
 * @brief Release the mpint coordinates held by @p point and mark
 * the point as the identity.
 *
 * @param point  Point to clear; must be non-NULL.
 */
R_API void r_ecurve_point_clear (REcurveAffinePoint * point);

/**
 * @brief Set @p point to the group identity (infinity).
 *
 * Zeros the coordinates and sets @c is_infinity to @c TRUE; does
 * not allocate or free.
 *
 * @param point  Point to overwrite.
 */
R_API void r_ecurve_point_set_infinity (REcurveAffinePoint * point);

/**
 * @brief Copy @p src into @p dst, including the @c is_infinity flag.
 *
 * @p dst must already be initialised. Coordinates are deep-copied
 * via @c r_mpint_set.
 *
 * @param dst  Destination point (must be initialised).
 * @param src  Source point.
 */
R_API void r_ecurve_point_copy (REcurveAffinePoint * dst, const REcurveAffinePoint * src);

/**
 * @brief Initialise an @c REcurve from a named curve.
 *
 * Populates @c p, @c a, @c b, @c n, the generator @c G, and all
 * precomputed Montgomery constants. Only the prime curves currently
 * shipped (secp192r1 / secp224r1 / secp256r1 / secp384r1 /
 * secp521r1 / secp256k1) are supported.
 *
 * @param curve  Output curve to initialise.
 * @param named  Curve identifier.
 * @return @c TRUE on success; @c FALSE if @p curve is NULL or @p
 *         named is not a supported prime curve.
 */
R_API rboolean r_ecurve_init (REcurve * curve, REcurveID named);

/**
 * @brief Release the storage held by @p curve.
 *
 * Clears every mpint member; the struct itself is not freed.
 *
 * @param curve  Curve to clear.
 */
R_API void r_ecurve_clear (REcurve * curve);

/**
 * @brief Map an X.509 / SEC 1 elliptic-curve OID to the matching
 * @c REcurveID.
 *
 * @param curve    Output curve id on success; unchanged on failure.
 * @param oid      OID byte buffer.
 * @param oidsize  Length of @p oid in bytes.
 * @return @c TRUE on a recognised OID, @c FALSE otherwise.
 */
R_API rboolean r_ecurve_id_from_oid (REcurveID * curve,
    rconstpointer oid, rsize oidsize);

/**
 * @brief Inverse of @c r_ecurve_id_from_oid: return the pre-encoded
 * OID bytes for a curve id.
 *
 * The length is written to @c *size when @p size is non-NULL.
 * Length is exposed because several curve OIDs contain an embedded
 * NUL byte; a NUL-terminated convention would truncate them.
 *
 * @param curve  Curve identifier.
 * @param size   Optional out-pointer for the OID length; may be NULL.
 * @return Pointer to the OID bytes, or NULL (with @c *size set to 0)
 *         for unknown curves.
 */
R_API const ruint8 * r_ecurve_oid_from_id (REcurveID curve, rsize * size);

/**
 * @brief Negate a curve point: @c out = -a.
 *
 * For finite points, @c -(x, y) = (x, p - y). Identity negates to
 * itself.
 *
 * @param out    Destination point (may alias @p a).
 * @param a      Input point.
 * @param curve  Curve parameters.
 * @return @c TRUE on success; @c FALSE on NULL inputs or arithmetic failure.
 */
R_API rboolean r_ecurve_point_neg (REcurveAffinePoint * out,
    const REcurveAffinePoint * a, const REcurve * curve);

/**
 * @brief Double a curve point: @c out = 2 * a.
 *
 * Dispatches to the standard short-Weierstrass doubling formulae.
 * Doubling the identity yields the identity; doubling a point of
 * order 2 (where @c y = 0) yields the identity.
 *
 * @param out    Destination point (may alias @p a).
 * @param a      Input point.
 * @param curve  Curve parameters.
 * @return @c TRUE on success; @c FALSE on NULL inputs or arithmetic failure.
 */
R_API rboolean r_ecurve_point_dbl (REcurveAffinePoint * out,
    const REcurveAffinePoint * a, const REcurve * curve);

/**
 * @brief Add two curve points: @c out = a + b.
 *
 * Handles the identity inputs, the @c P + (-P) = O case, and
 * dispatches to @c r_ecurve_point_dbl when @c a == b.
 *
 * @param out    Destination point (may alias @p a or @p b).
 * @param a      First addend.
 * @param b      Second addend.
 * @param curve  Curve parameters.
 * @return @c TRUE on success; @c FALSE on NULL inputs or arithmetic failure.
 */
R_API rboolean r_ecurve_point_add (REcurveAffinePoint * out,
    const REcurveAffinePoint * a, const REcurveAffinePoint * b,
    const REcurve * curve);

/**
 * @brief Test whether @p point satisfies the curve equation.
 *
 * Returns @c TRUE for the identity by convention. For finite points,
 * checks @c y^2 == x^3 + ax + b (mod p).
 *
 * @param point  Point to test.
 * @param curve  Curve parameters.
 * @return @c TRUE if on the curve; @c FALSE otherwise (or on NULL inputs).
 */
R_API rboolean r_ecurve_point_is_on_curve (const REcurveAffinePoint * point,
    const REcurve * curve);

/**
 * @brief Scalar multiplication: @c out = scalar * point.
 *
 * Uses a left-to-right Jacobian-projective ladder with a
 * branch-uniform conditional-swap structure so the scalar's bit
 * pattern does not affect the branch shape. Field arithmetic
 * remains variable-time on values; see the file-level overview
 * above for the full hardening caveat.
 *
 * @param out     Destination point (may alias @p point).
 * @param scalar  Multiplier (interpreted as an unsigned integer).
 * @param point   Base point.
 * @param curve   Curve parameters.
 * @return @c TRUE on success; @c FALSE on NULL inputs or arithmetic failure.
 */
R_API rboolean r_ecurve_point_scalar_mul (REcurveAffinePoint * out,
    const rmpint * scalar, const REcurveAffinePoint * point,
    const REcurve * curve);

/**
 * @brief SEC 1 uncompressed encoding: @c 0x04 || X || Y, padded to
 * @c curve->coord_bytes.
 *
 * The identity encodes as a single @c 0x00 byte. Compressed
 * encoding (@c 0x02 / @c 0x03) is not yet supported.
 *
 * @param point    Point to encode.
 * @param curve    Curve parameters.
 * @param out      Destination buffer.
 * @param outsize  In: capacity of @p out. Out: bytes actually written.
 * @return @c TRUE on success; @c FALSE on NULL inputs or insufficient capacity.
 */
R_API rboolean r_ecurve_point_to_uncompressed (const REcurveAffinePoint * point,
    const REcurve * curve, ruint8 * out, rsize * outsize);

/**
 * @brief Decode an SEC 1 uncompressed point and validate it.
 *
 * Parses the @c 0x04 prefix, decodes @c X / @c Y (each zero-padded
 * to @c coord_bytes), and runs on-curve validation. A single
 * @c 0x00 byte decodes to the identity.
 *
 * @param in      Encoded point buffer.
 * @param insize  Length of @p in.
 * @param curve   Curve parameters.
 * @param out     Destination point (must be initialised).
 * @return @c TRUE on success; @c FALSE for malformed encoding,
 *         wrong size, or an off-curve point.
 */
R_API rboolean r_ecurve_point_from_uncompressed (const ruint8 * in,
    rsize insize, const REcurve * curve, REcurveAffinePoint * out);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_ECURVE_H__ */
