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
#ifndef __R_CRYPTO_ECC_H__
#define __R_CRYPTO_ECC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_crypto_ecc ECDSA / ECDH keys
 * @ingroup r_crypto_ec
 *
 * @brief @ref RCryptoKey wrappers for the short-Weierstrass curves
 * exposed by @ref r_ecurve - ECDSA signing keys plus ECDH
 * key-agreement keys.
 *
 * The curve math itself (named curves, point arithmetic, scalar
 * multiplication) lives in @ref r_ecurve. This header binds those
 * primitives to the polymorphic @ref RCryptoKey handle: callers
 * build an ECDSA or ECDH key, then either pass it to the generic
 * @c r_crypto_key_sign / @c _verify dispatch or use the explicit
 * @ref r_ecdh_compute_shared entry point.
 *
 * For Curve25519 / Curve448 use @ref r_xdh instead; for the EdDSA
 * signature variants use @ref r_ed25519 / @ref r_ed448. The keys
 * in this header cover the short-Weierstrass family
 * (secp256r1 / secp384r1 / secp521r1 / ...).
 *
 * @{
 */

/**
 * @file rlib/crypto/recc.h
 * @brief ECDSA and ECDH key construction over the short-Weierstrass
 * curves in @ref r_ecurve, plus the shared-secret computation.
 */

#include <rlib/rtypes.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/rkey.h>
#include <rlib/rrand.h>

R_BEGIN_DECLS

/** @brief Algorithm-name string used in @c RCryptoKey introspection. */
#define R_ECDSA_STR     "ECDSA"
/** @brief Algorithm-name string used in @c RCryptoKey introspection. */
#define R_ECDH_STR      "ECDH"

/**
 * @brief Build an ECDSA public key from a named curve and an encoded
 * affine point @c Q.
 *
 * @param curve    The short-Weierstrass curve (@ref REcurveID).
 * @param ecp      Encoded point (typically SEC 1 uncompressed
 *                 @c 0x04 || X || Y).
 * @param ecpsize  Length of @p ecp.
 */
R_API RCryptoKey * r_ecdsa_pub_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize) R_ATTR_MALLOC;

/**
 * @brief Build an ECDH public key from a named curve and an encoded
 * affine point @c Q.
 *
 * @param curve    The short-Weierstrass curve (@ref REcurveID).
 * @param ecp      Encoded point (SEC 1 uncompressed).
 * @param ecpsize  Length of @p ecp.
 */
R_API RCryptoKey * r_ecdh_pub_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize) R_ATTR_MALLOC;

/**
 * @brief Build an ECDSA private key from a named curve, public point
 * and private scalar.
 *
 * @param curve       The short-Weierstrass curve.
 * @param ecp         Encoded public point @c Q.
 * @param ecpsize     Length of @p ecp.
 * @param scalar      Big-endian private scalar @c d.
 * @param scalarsize  Length of @p scalar.
 */
R_API RCryptoKey * r_ecdsa_priv_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize) R_ATTR_MALLOC;

/**
 * @brief Build an ECDH private key from a named curve, public point
 * and private scalar.
 */
R_API RCryptoKey * r_ecdh_priv_key_new (REcurveID curve,
    rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize) R_ATTR_MALLOC;

/**
 * @brief Return the named curve @p key is parameterised on.
 */
R_API REcurveID r_ecc_key_get_curve (const RCryptoKey * key);

/**
 * @brief Return the raw private scalar bytes for an ECDSA or ECDH
 * private key.
 *
 * The pointer is owned by @p key (do not free). Returns @c FALSE for
 * public keys or if the scalar was never set.
 */
R_API rboolean r_ecc_priv_key_get_scalar (const RCryptoKey * key,
    const ruint8 ** scalar, rsize * scalarsize);

/**
 * @brief Generate a fresh ECDH keypair on a named curve.
 *
 * Picks a random @c d in @c [1, n-1] and derives @c Q = d * G.
 *
 * @param curve  The curve.
 * @param prng   Randomness source. Pass @c NULL to use a fresh
 *               system PRNG; any PRNG you supply must be
 *               cryptographically secure (@ref r_prng_new_crypto).
 */
R_API RCryptoKey * r_ecdh_priv_key_new_gen (REcurveID curve,
    RPrng * prng) R_ATTR_MALLOC;

/**
 * @brief Retrieve the affine public point @c Q for an ECDSA or ECDH key.
 *
 * @return @c FALSE if @p key doesn't carry a parsed point (e.g. an
 * ECDSA key built from an encoding the math layer can't yet decode).
 */
R_API rboolean r_ecc_key_get_q (const RCryptoKey * key, REcurveAffinePoint * q);

/**
 * @brief Compute the ECDH shared-secret X-coordinate.
 *
 * Computes @c (peer_pub.Q * priv.d).x and writes it as a
 * left-zero-padded big-endian byte string sized to the curve's
 * coord_bytes.
 *
 * The two keys must use the same named curve; the peer's point is
 * on-curve checked at this layer (it was validated at construction,
 * but private-key paths that derived @c Q internally also need to
 * refuse the identity).
 *
 * @param priv      Local private key.
 * @param peer_pub  Peer's public key.
 * @param out       Output buffer.
 * @param outsize   On entry, capacity of @p out; on success, updated
 *                  to the number of bytes written.
 */
R_API RCryptoResult r_ecdh_compute_shared (const RCryptoKey * priv,
    const RCryptoKey * peer_pub, ruint8 * out, rsize * outsize);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_ECC_H__ */

