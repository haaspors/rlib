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
#ifndef __R_CRYPTO_DSA_H__
#define __R_CRYPTO_DSA_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_crypto_dsa DSA (FIPS 186-4)
 * @ingroup r_crypto_key
 *
 * @brief Digital Signature Algorithm: keypair construction and the
 * sign / verify operations parameterised by an @ref RMsgDigestType.
 *
 * DSA is a finite-field signature scheme defined by FIPS 186-4. Like
 * @ref r_crypto_rsa, DSA keys are surfaced as @ref RCryptoKey
 * handles; the constructors here build that handle from already
 * parsed @c rmpint components, raw big-endian byte buffers, or an
 * ASN.1 TLV. @ref r_dsa_priv_key_new_gen generates a fresh keypair
 * at one of the FIPS-approved (L, N) sizes.
 *
 * For new protocols prefer @ref r_ed25519 / @ref r_ed448 EdDSA over
 * DSA: EdDSA is deterministic, side-channel friendly and does not
 * depend on per-signature randomness. DSA is documented here for
 * interop with existing systems that mandate it.
 *
 * @{
 */

/**
 * @file rlib/crypto/rdsa.h
 * @brief DSA (FIPS 186-4) key construction, signature and
 * verification.
 */

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>
#include <rlib/data/rmpint.h>

R_BEGIN_DECLS

/** @brief Algorithm-name string used in @c RCryptoKey introspection. */
#define R_DSA_STR     "DSA"

/**
 * @brief Build a DSA public key from just the public value @c y;
 * domain parameters @c (p, q, g) are left unset.
 *
 * Convenience for parsers that pull @c (p, q, g) from a separate
 * source (e.g. a certificate's AlgorithmIdentifier) and want to
 * attach them afterwards.
 */
#define r_dsa_pub_key_new(y)  r_dsa_pub_key_new_full (NULL, NULL, NULL, y)

/**
 * @brief Build a DSA public key from already-parsed @c rmpint
 * components @c (p, q, g, y).
 */
R_API RCryptoKey * r_dsa_pub_key_new_full (const rmpint * p, const rmpint * q,
    const rmpint * g, const rmpint * y) R_ATTR_MALLOC;

/**
 * @brief Build a DSA public key from raw big-endian byte buffers.
 *
 * Convenience wrapper that parses each component into an @c rmpint
 * before calling @ref r_dsa_pub_key_new_full.
 */
R_API RCryptoKey * r_dsa_pub_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer q, rsize qsize, rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize) R_ATTR_MALLOC;

/**
 * @brief Build a DSA private key from already-parsed @c rmpint
 * components @c (p, q, g, y, x).
 */
R_API RCryptoKey * r_dsa_priv_key_new (const rmpint * p, const rmpint * q,
    const rmpint * g, const rmpint * y, const rmpint * x) R_ATTR_MALLOC;

/**
 * @brief Build a DSA private key from raw big-endian byte buffers.
 *
 * Convenience wrapper around @ref r_dsa_priv_key_new.
 */
R_API RCryptoKey * r_dsa_priv_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer q, rsize qsize, rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize, rconstpointer x, rsize xsize) R_ATTR_MALLOC;

/**
 * @brief Decode a DSA private key from an ASN.1 PKCS#8 TLV.
 *
 * Used by the PEM and X.509 import paths (see @c rpem.h and
 * @c rx509.h) to materialise an @ref RCryptoKey from a DER blob.
 */
R_API RCryptoKey * r_dsa_priv_key_new_from_asn1 (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv) R_ATTR_MALLOC;

/**
 * @brief Generate a fresh DSA keypair.
 *
 * Follows FIPS 186-4 §A.1.1.2 (probable primes @c p and @c q),
 * §A.2.1 (generator @c g) and §B.1.2 (private @c x, public @c y).
 *
 * @param L     Modulus size in bits.
 * @param N     Subgroup-order size in bits.
 * @param prng  Randomness source.
 *
 * @c (L, N) must be one of the FIPS-approved size combinations:
 * @c (1024, 160), @c (2048, 224), @c (2048, 256) or @c (3072, 256).
 */
R_API RCryptoKey * r_dsa_priv_key_new_gen (rsize L, rsize N,
    RPrng * prng) R_ATTR_MALLOC;

/** @brief Copy the prime modulus @c p into @p p. */
R_API rboolean r_dsa_pub_key_get_p (const RCryptoKey * key, rmpint * p);
/** @brief Copy the subgroup order @c q into @p q. */
R_API rboolean r_dsa_pub_key_get_q (const RCryptoKey * key, rmpint * q);
/** @brief Copy the generator @c g into @p g. */
R_API rboolean r_dsa_pub_key_get_g (const RCryptoKey * key, rmpint * g);
/** @brief Copy the public value @c y = g^x mod p into @p y. */
R_API rboolean r_dsa_pub_key_get_y (const RCryptoKey * key, rmpint * y);
/** @brief Copy the private value @c x into @p x. */
R_API rboolean r_dsa_priv_key_get_x (const RCryptoKey * key, rmpint * x);

/**
 * @brief DSA sign over message bytes.
 *
 * Hashes @p msg with @p mdtype, then signs the resulting digest per
 * FIPS 186-4 §4.6. The signature is encoded as an ASN.1 DER
 * SEQUENCE OF @c (r, s) integers.
 */
R_API RCryptoResult r_dsa_sign_msg (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    rpointer sig, rsize * sigsize);

/**
 * @brief DSA sign over a precomputed digest.
 *
 * Same as @ref r_dsa_sign_msg but the caller supplies the
 * already-hashed value; @p mdtype identifies which digest produced
 * @p hash so its length matches @c N / 8.
 */
R_API RCryptoResult r_dsa_sign_msg_hash (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize);

/**
 * @brief DSA verify over message bytes.
 *
 * Hashes @p msg with @p mdtype, then checks the @c (r, s) signature
 * per FIPS 186-4 §4.7.
 */
R_API RCryptoResult r_dsa_verify_msg (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    rconstpointer sig, rsize sigsize);

/**
 * @brief DSA verify over a precomputed digest.
 *
 * Counterpart to @ref r_dsa_sign_msg_hash.
 */
R_API RCryptoResult r_dsa_verify_msg_with_hash (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_DSA_H__ */




