/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_DH_H__
#define __R_CRYPTO_DH_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_crypto_dh Diffie-Hellman (finite-field)
 * @ingroup r_crypto_key
 *
 * @brief Classic finite-field Diffie-Hellman key exchange over a
 * prime-modulus group: keypair construction, the standard named
 * MODP / FFDHE groups, and the shared-secret derivation.
 *
 * The keys here are @ref RCryptoKey handles wrapping @c (p, g, y)
 * for the public side and @c (p, g, y, x) for the private side.
 * Most callers want to use the named groups via
 * @ref r_dh_priv_key_new_gen_named, which pulls @c (p, g) from the
 * RFC tables; @ref r_dh_priv_key_new_gen takes caller-supplied
 * domain parameters for nonstandard groups.
 *
 * For modern elliptic-curve Diffie-Hellman use @ref r_xdh
 * (Curve25519 / Curve448); this module covers the finite-field
 * variant that legacy IKE, SSH and TLS still negotiate.
 *
 * @{
 */

/**
 * @file rlib/crypto/rdh.h
 * @brief Finite-field Diffie-Hellman: keypair construction, named
 * MODP / FFDHE groups and shared-secret derivation.
 */

#include <rlib/rtypes.h>
#include <rlib/format/rasn1.h>
#include <rlib/crypto/rkey.h>
#include <rlib/data/rmpint.h>
#include <rlib/rrand.h>

R_BEGIN_DECLS

/** @brief Algorithm-name string used in @c RCryptoKey introspection. */
#define R_DH_STR     "DH"

/**
 * @brief Named DH groups with standardised @c (p, g) parameters.
 *
 * All groups use @c g = 2. The @c MODP_* values come from RFC 3526
 * (general-purpose DH used by IKE and SSH); the @c FFDHE_* values
 * come from RFC 7919 (designed for TLS, with primes resistant to
 * Logjam-style precomputation).
 */
typedef enum {
  R_DH_GROUP_UNKNOWN = -1,
  R_DH_GROUP_MODP_2048 = 0,   /**< RFC 3526 group 14. */
  R_DH_GROUP_MODP_3072,       /**< RFC 3526 group 15. */
  R_DH_GROUP_MODP_4096,       /**< RFC 3526 group 16. */
  R_DH_GROUP_MODP_6144,       /**< RFC 3526 group 17. */
  R_DH_GROUP_MODP_8192,       /**< RFC 3526 group 18. */
  R_DH_GROUP_FFDHE_2048,      /**< RFC 7919. */
  R_DH_GROUP_FFDHE_3072,      /**< RFC 7919. */
  R_DH_GROUP_FFDHE_4096,      /**< RFC 7919. */
  R_DH_GROUP_FFDHE_6144,      /**< RFC 7919. */
  R_DH_GROUP_FFDHE_8192,      /**< RFC 7919. */
  R_DH_GROUP_COUNT
} RDhNamedGroup;

/**
 * @brief Initialise @p p and @p g with the parameters of a named group.
 *
 * The caller is responsible for clearing both @c rmpints. Returns
 * @c FALSE if @p group is @c R_DH_GROUP_UNKNOWN or out of range.
 */
R_API rboolean r_dh_named_group_get_params (RDhNamedGroup group,
    rmpint * p, rmpint * g);

/**
 * @brief Build a DH public key from @c rmpint components @c (p, g, y).
 */
R_API RCryptoKey * r_dh_pub_key_new (const rmpint * p, const rmpint * g,
    const rmpint * y) R_ATTR_MALLOC;

/**
 * @brief Build a DH public key from raw big-endian byte buffers.
 *
 * Convenience wrapper around @ref r_dh_pub_key_new.
 */
R_API RCryptoKey * r_dh_pub_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize) R_ATTR_MALLOC;

/**
 * @brief Build a DH private key from @c rmpint components @c (p, g, y, x).
 */
R_API RCryptoKey * r_dh_priv_key_new (const rmpint * p, const rmpint * g,
    const rmpint * y, const rmpint * x) R_ATTR_MALLOC;

/**
 * @brief Build a DH private key from raw big-endian byte buffers.
 *
 * Convenience wrapper around @ref r_dh_priv_key_new.
 */
R_API RCryptoKey * r_dh_priv_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize,
    rconstpointer x, rsize xsize) R_ATTR_MALLOC;

/**
 * @brief Decode a DH private key from an ASN.1 @c SEQUENCE
 * (version, p, g, x).
 *
 * Used by the PEM and X.509 import paths to materialise an
 * @ref RCryptoKey from a DER blob.
 */
R_API RCryptoKey * r_dh_priv_key_new_from_asn1 (RAsn1BinDecoder * dec,
    RAsn1BinTLV * tlv) R_ATTR_MALLOC;

/**
 * @brief Generate a fresh DH keypair in a caller-supplied group.
 *
 * Picks a random @c x in @c [2, p-2] and derives @c y = g^x mod p.
 *
 * @param p     Prime modulus.
 * @param g     Generator.
 * @param prng  Randomness source for sampling @c x; must be
 *              cryptographically secure — use @ref r_prng_new_crypto,
 *              not @ref r_prng_new_kiss / @ref r_prng_new_mt.
 */
R_API RCryptoKey * r_dh_priv_key_new_gen (const rmpint * p, const rmpint * g,
    RPrng * prng) R_ATTR_MALLOC;

/**
 * @brief Generate a fresh DH keypair in a standard named group.
 *
 * Convenience wrapper that loads @c (p, g) for @p group from the
 * RFC tables before calling @ref r_dh_priv_key_new_gen.
 */
R_API RCryptoKey * r_dh_priv_key_new_gen_named (RDhNamedGroup group,
    RPrng * prng) R_ATTR_MALLOC;

/** @brief Copy the prime modulus @c p into @p p. */
R_API rboolean r_dh_pub_key_get_p (const RCryptoKey * key, rmpint * p);
/** @brief Copy the generator @c g into @p g. */
R_API rboolean r_dh_pub_key_get_g (const RCryptoKey * key, rmpint * g);
/** @brief Copy the public value @c y = g^x mod p into @p y. */
R_API rboolean r_dh_pub_key_get_y (const RCryptoKey * key, rmpint * y);
/** @brief Copy the private value @c x into @p x. */
R_API rboolean r_dh_priv_key_get_x (const RCryptoKey * key, rmpint * x);

/**
 * @brief Compute the shared DH secret.
 *
 * Computes @c peer_pub.y ^ priv.x mod priv.p and writes it to @p out
 * as a left-zero-padded big-endian byte string sized to match @c p.
 *
 * The two keys must share the same @c (p, g) group; the peer's @c y
 * is range-checked to be in @c (1, p-1) before the exponentiation
 * so that small-subgroup attacks fail with @c R_CRYPTO_INVAL.
 *
 * @param priv      Local private key.
 * @param peer_pub  Peer's public key.
 * @param out       Output buffer.
 * @param outsize   On entry, capacity of @p out; on success, updated
 *                  to the number of bytes written.
 */
R_API RCryptoResult r_dh_compute_shared (const RCryptoKey * priv,
    const RCryptoKey * peer_pub, ruint8 * out, rsize * outsize);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_DH_H__ */
