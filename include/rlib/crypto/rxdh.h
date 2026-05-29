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
#ifndef __R_CRYPTO_XDH_H__
#define __R_CRYPTO_XDH_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/recurve-montgomery.h>
#include <rlib/crypto/rkey.h>
#include <rlib/rrand.h>

/**
 * @defgroup r_xdh X25519 / X448 key exchange
 * @ingroup r_crypto_ec
 * @brief Diffie-Hellman key exchange over the Montgomery curves
 * Curve25519 and Curve448 (RFC 7748).
 * @{
 */

/**
 * @file rlib/crypto/rxdh.h
 * @brief @c RCryptoKey wrapper for the X25519 / X448 Diffie-Hellman
 * key exchange of RFC 7748.
 *
 * Both curves share a single @c R_CRYPTO_ALGO_XDH algorithm tag and
 * the API surface here is parameterised on @c REcurveID
 * (@c R_ECURVE_ID_X25519 or @c R_ECURVE_ID_X448), mirroring how
 * @c r_ecdh_* in @c rlib/crypto/recc.h parameterises on the named
 * short-Weierstrass curve.
 *
 * Public keys carry the raw little-endian u-coordinate (32 bytes
 * for X25519, 56 bytes for X448) per RFC 7748 §5. Private keys
 * additionally carry the clamped scalar of the same size. Scalar
 * clamping per RFC 7748 §5 is applied inside the math layer's
 * ladder on every call, so callers may pass either pre-clamped or
 * raw secret bytes - both produce the same result.
 *
 * @c r_xdh_compute_shared rejects the all-zero shared u-coordinate
 * per RFC 7748 §6 (the small-subgroup result that TLS 1.3 §7.4.2
 * also mandates) so callers do not have to inspect the output bytes.
 */

R_BEGIN_DECLS

/** @brief Algorithm string tag for X25519 / X448 keys. */
#define R_XDH_STR       "XDH"

/**
 * @brief Construct an X25519 / X448 public key from its raw
 * u-coordinate bytes.
 *
 * @c pub_u_size must equal the curve's coordinate size (32 for
 * X25519, 56 for X448); otherwise the constructor fails.
 *
 * @param curve       Either @c R_ECURVE_ID_X25519 or @c R_ECURVE_ID_X448.
 * @param pub_u       Little-endian u-coordinate bytes.
 * @param pub_u_size  Length of @p pub_u in bytes.
 * @return Owning reference to a new public key, or @c NULL on bad
 *         curve / size mismatch / NULL input.
 */
R_API RCryptoKey * r_xdh_pub_key_new (REcurveID curve,
    rconstpointer pub_u, rsize pub_u_size) R_ATTR_MALLOC;

/**
 * @brief Construct an X25519 / X448 private key from both halves
 * (public u-coordinate and raw scalar).
 *
 * Both buffers must be exactly the curve's coordinate size. The
 * scalar is stored as-given; clamping happens on each ladder call,
 * so callers may pass pre-clamped or raw bytes interchangeably.
 *
 * @param curve         Either @c R_ECURVE_ID_X25519 or @c R_ECURVE_ID_X448.
 * @param pub_u         Little-endian public u-coordinate.
 * @param pub_u_size    Length of @p pub_u.
 * @param scalar        Little-endian private scalar (32 / 56 bytes).
 * @param scalarsize    Length of @p scalar.
 * @return Owning reference to a new private key, or @c NULL on bad
 *         curve / size mismatch / NULL input.
 */
R_API RCryptoKey * r_xdh_priv_key_new (REcurveID curve,
    rconstpointer pub_u, rsize pub_u_size,
    rconstpointer scalar, rsize scalarsize) R_ATTR_MALLOC;

/**
 * @brief Generate a fresh X25519 / X448 private key.
 *
 * Draws @c coord_bytes random bytes from @p prng (or a fresh system
 * PRNG when @p prng is @c NULL), clamps them per RFC 7748 §5, and
 * derives the public u-coordinate as @c ladder(scalar, basepoint).
 *
 * @param curve  Either @c R_ECURVE_ID_X25519 or @c R_ECURVE_ID_X448.
 * @param prng   PRNG to draw from; @c NULL to use the system PRNG. Any
 *               PRNG you supply must be cryptographically secure
 *               (@ref r_prng_new_crypto).
 * @return Owning reference to a new private key, or @c NULL on
 *         unsupported curve / PRNG failure / allocation failure.
 */
R_API RCryptoKey * r_xdh_priv_key_new_gen (REcurveID curve,
    RPrng * prng) R_ATTR_MALLOC;

/**
 * @brief Return the named curve carried by an X25519 / X448 key.
 *
 * @param key  XDH public or private key.
 * @return The key's curve id, or @c R_ECURVE_ID_NONE for a NULL or
 *         non-XDH key.
 */
R_API REcurveID r_xdh_key_get_curve (const RCryptoKey * key);

/**
 * @brief Borrow the raw u-coordinate bytes of an X25519 / X448 key.
 *
 * Works for both public and private keys (a private key knows its
 * matching public u). The returned pointer aliases the key's
 * internal storage and is valid for the key's lifetime.
 *
 * @param key   XDH public or private key.
 * @param pub_u Out-pointer for the u-coordinate buffer.
 * @param size  Out-pointer for the buffer length.
 * @return @c TRUE on success; @c FALSE on NULL inputs or non-XDH key.
 */
R_API rboolean r_xdh_key_get_pub_u (const RCryptoKey * key,
    const ruint8 ** pub_u, rsize * size);

/**
 * @brief Compute the X25519 / X448 shared secret.
 *
 * Runs the RFC 7748 §5 Montgomery ladder of the private scalar
 * against the peer's u-coordinate and writes the resulting
 * u-coordinate to @p out as little-endian bytes. The two keys must
 * use the same curve.
 *
 * Rejects the all-zero shared u-coordinate as @c R_CRYPTO_INVAL
 * per RFC 7748 §6 (the small-subgroup outcome). @c *outsize is
 * updated to the number of bytes written on success.
 *
 * @param priv      XDH private key.
 * @param peer_pub  Peer's XDH public key (must name the same curve).
 * @param out       Destination buffer.
 * @param outsize   In: @p out capacity. Out: bytes written.
 * @return @c R_CRYPTO_OK on success;
 *         @c R_CRYPTO_INVAL on NULL inputs or zero shared secret;
 *         @c R_CRYPTO_WRONG_TYPE on a non-XDH key or curve mismatch;
 *         @c R_CRYPTO_BUFFER_TOO_SMALL when @p out is undersized.
 */
R_API RCryptoResult r_xdh_compute_shared (const RCryptoKey * priv,
    const RCryptoKey * peer_pub, ruint8 * out, rsize * outsize);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_XDH_H__ */
