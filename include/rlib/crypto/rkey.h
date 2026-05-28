/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_KEY_H__
#define __R_CRYPTO_KEY_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/asn1/rasn1.h>
#include <rlib/rmsgdigest.h>
#include <rlib/rrand.h>
#include <rlib/rref.h>

/**
 * @defgroup r_crypto_key Asymmetric cryptographic keys
 * @ingroup r_crypto
 * @brief Generic @c RCryptoKey handle plus the metadata enums it
 * carries (key type, algorithm, error code) and the dispatched
 * encrypt / decrypt / sign / verify / export entry points.
 * @{
 */

/**
 * @file rlib/crypto/rkey.h
 * @brief Generic asymmetric-key handle dispatching to the
 * per-algorithm modules (RSA, DSA, ECDSA, ECDH, DH, XDH, EdDSA).
 *
 * Algorithm-specific modules (@c rlib/crypto/rrsa.h,
 * @c rlib/crypto/rdsa.h, @c rlib/crypto/recc.h, @c rlib/crypto/rdh.h,
 * @c rlib/crypto/rxdh.h, @c rlib/crypto/red25519.h,
 * @c rlib/crypto/red448.h) own the construction and the
 * algorithm-specific surface. This header provides the polymorphic
 * @c RCryptoKey type and the small set of operations that dispatch
 * by algorithm: type / strtype / bitsize accessors, encrypt /
 * decrypt / sign / verify, ASN.1 export / import, and SSH public
 * key import.
 *
 * Keys are reference-counted (@c r_crypto_key_ref / @c _unref);
 * destructors wipe key material with @c r_memclear_secure.
 */

R_BEGIN_DECLS

/**
 * @brief Asymmetric-key role (public or private half).
 */
typedef enum {
  R_CRYPTO_PUBLIC_KEY,    /**< @brief The key carries only the public half. */
  R_CRYPTO_PRIVATE_KEY,   /**< @brief The key carries the private half (and usually the matching public half). */
} RCryptoKeyType;

/**
 * @brief Algorithm identifier carried on every @c RCryptoKey.
 *
 * New algorithms are appended at the end; @c R_CRYPTO_ALGO_TYPE_COUNT
 * is a sentinel for "any new value goes before this".
 */
typedef enum {
  R_CRYPTO_ALGO_DH,             /**< @brief Finite-field Diffie-Hellman (RFC 7919 ffdhe, custom groups). */
  R_CRYPTO_ALGO_DSA,            /**< @brief Digital Signature Algorithm (FIPS 186-4). */
  R_CRYPTO_ALGO_ECDH,           /**< @brief Elliptic-curve Diffie-Hellman on a short-Weierstrass curve. */
  R_CRYPTO_ALGO_ECDSA,          /**< @brief Elliptic-curve DSA on a short-Weierstrass curve. */
  R_CRYPTO_ALGO_RSA,            /**< @brief RSA encryption / signing (PKCS#1). */
  R_CRYPTO_ALGO_XDH,            /**< @brief X25519 / X448 key exchange (RFC 7748). */
  R_CRYPTO_ALGO_ED25519,        /**< @brief Ed25519 EdDSA signing (RFC 8032 §5.1). */
  R_CRYPTO_ALGO_ED448,          /**< @brief Ed448 EdDSA signing (RFC 8032 §5.2). */
  R_CRYPTO_ALGO_TYPE_COUNT,     /**< @brief Number of valid algorithms. */
  /* aliases */
  R_CRYPTO_ALGO_DSS = R_CRYPTO_ALGO_DSA,  /**< @brief Backwards-compatibility alias for @c R_CRYPTO_ALGO_DSA. */
} RCryptoAlgorithm;

/**
 * @brief Result code returned from every dispatching @c RCryptoKey
 * operation.
 *
 * @c R_CRYPTO_OK is the only success value; everything else
 * conveys a specific failure mode the caller may want to
 * distinguish (in particular, sign-side @c R_CRYPTO_SIGN_FAILED is
 * distinct from verify-side @c R_CRYPTO_VERIFY_FAILED so the two
 * sides of an interactive protocol can branch cleanly).
 */
typedef enum {
  R_CRYPTO_OK                     = 0,    /**< @brief Operation succeeded. */
  R_CRYPTO_INVAL,                         /**< @brief Invalid input (NULL pointer, malformed encoding, etc.). */
  R_CRYPTO_NOT_AVAILABLE,                 /**< @brief Operation is not supported by this key / algorithm. */
  R_CRYPTO_BUFFER_TOO_SMALL,              /**< @brief Output buffer too small for the result. */
  R_CRYPTO_WRONG_TYPE,                    /**< @brief Wrong key type for the requested operation (e.g. signing with a public key). */
  R_CRYPTO_WRONG_SIZE,                    /**< @brief Operand size does not match the key's natural size. */
  R_CRYPTO_INVALID_PADDING,               /**< @brief Padding bytes failed validation (PKCS#1, OAEP, etc.). */
  R_CRYPTO_ENCRYPT_FAILED,                /**< @brief Encryption-side internal failure. */
  R_CRYPTO_DECRYPT_FAILED,                /**< @brief Decryption-side internal failure. */
  R_CRYPTO_HASH_FAILED,                   /**< @brief Internal hash / digest failure. */
  R_CRYPTO_SIGN_FAILED,                   /**< @brief Sign-side internal failure. */
  R_CRYPTO_VERIFY_FAILED,                 /**< @brief Signature verification rejected a well-formed input. */
  R_CRYPTO_ERROR                          /**< @brief Generic / catch-all failure. */
} RCryptoResult;

/** @brief Opaque polymorphic asymmetric-key handle. */
typedef struct RCryptoKey RCryptoKey;

/** @brief Increment the reference count on @p key. */
#define r_crypto_key_ref r_ref_ref
/** @brief Decrement the reference count on @p key; frees when it reaches zero. */
#define r_crypto_key_unref r_ref_unref

/**
 * @brief Return whether @p key carries the public or private half.
 */
R_API RCryptoKeyType r_crypto_key_get_type (const RCryptoKey * key);
/** @brief Shorthand for @c (r_crypto_key_get_type(key) == R_CRYPTO_PRIVATE_KEY). */
#define r_crypto_key_has_private_key(key) (r_crypto_key_get_type (key) == R_CRYPTO_PRIVATE_KEY)
/** @brief Return the algorithm identifier carried by @p key. */
R_API RCryptoAlgorithm r_crypto_key_get_algo (const RCryptoKey * key);
/** @brief Return the canonical string label for @p key's algorithm
 *  (e.g. @c "RSA", @c "ECDSA", @c "Ed25519"). */
R_API const rchar * r_crypto_key_get_strtype (const RCryptoKey * key);
/** @brief Return the natural bit size of @p key (modulus bits for
 *  RSA / DH, curve size for ECC, encoding size for EdDSA). */
R_API ruint r_crypto_key_get_bitsize (const RCryptoKey * key);

/**
 * @brief Encrypt @p data with @p key, writing the ciphertext to
 * @p out.
 *
 * Dispatches to the per-algorithm implementation; many algorithms
 * (DSA, ECDSA, DH, ECDH, EdDSA) don't support encryption and
 * return @c R_CRYPTO_NOT_AVAILABLE.
 *
 * @param key      Key to encrypt with.
 * @param prng     Optional PRNG for randomised padding (RSA-OAEP /
 *                 PKCS#1 v1.5). May be @c NULL where the algorithm
 *                 doesn't need one.
 * @param data     Plaintext.
 * @param size     Plaintext length.
 * @param out      Destination buffer.
 * @param outsize  In: capacity of @p out. Out: bytes written.
 */
R_API RCryptoResult r_crypto_key_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, rpointer out, rsize * outsize);
/**
 * @brief Inverse of @c r_crypto_key_encrypt: decrypt @p data with
 * @p key. Requires a private key.
 */
R_API RCryptoResult r_crypto_key_decrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, rpointer out, rsize * outsize);
/**
 * @brief Sign @p hash with @p key. The hash function used is
 * encoded by @p mdtype (e.g. @c R_MSG_DIGEST_TYPE_SHA256) and
 * folded into the signature where the algorithm needs it (e.g.
 * RSA-PKCS#1 v1.5). EdDSA is "pure" and treats @p hash as the
 * full message regardless of @p mdtype.
 */
R_API RCryptoResult r_crypto_key_sign (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize);
/** @brief Inverse of @c r_crypto_key_sign: verify @p sig against
 *  @p hash with @p key (which must be a public or private key
 *  whose algorithm matches the signature's). */
R_API RCryptoResult r_crypto_key_verify (const RCryptoKey * key, RMsgDigestType mdtype,
    rconstpointer hash, rsize hashsize, rconstpointer sig, rsize sigsize);
/**
 * @brief Export @p key to an ASN.1 encoder.
 *
 * Public keys export the SubjectPublicKeyInfo / per-algorithm
 * SEQUENCE; private keys export the corresponding
 * @c PrivateKeyInfo. Encoding is RFC 5208 / RFC 7468 compatible
 * where the algorithm specifies a wire format.
 */
R_API RCryptoResult r_crypto_key_to_asn1 (const RCryptoKey * key, RAsn1BinEncoder * enc);
/** @brief Shorthand alias for @c r_crypto_key_to_asn1. */
#define r_crypto_key_export r_crypto_key_to_asn1

/** @brief Load an SSH-format public key from @p file (RFC 4716). */
R_API RCryptoKey * r_crypto_key_import_ssh_public_key_file (const rchar * file);
/** @brief Like @c _import_ssh_public_key_file but parses from an
 *  in-memory buffer. */
R_API RCryptoKey * r_crypto_key_import_ssh_public_key (const rchar * data, rsize size);
/** @brief Decode a SubjectPublicKeyInfo (or per-algorithm public
 *  encoding) from @p dec into a fresh @c RCryptoKey. */
R_API RCryptoKey * r_crypto_key_from_asn1_public_key (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);
/** @brief Decode a PrivateKeyInfo (or per-algorithm private
 *  encoding) from @p dec into a fresh @c RCryptoKey. */
R_API RCryptoKey * r_crypto_key_from_asn1_private_key (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_KEY_H__ */
