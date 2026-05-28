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
#ifndef __R_CRYPTO_RSA_H__
#define __R_CRYPTO_RSA_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_crypto_rsa RSA
 * @ingroup r_crypto_key
 *
 * @brief RSA key construction, RSAES (encrypt/decrypt) and RSASSA
 * (sign/verify) under raw, OAEP and PKCS#1 v1.5 padding.
 *
 * RSA keys are surfaced as the generic @ref RCryptoKey handle from
 * @ref r_crypto_key. The @c r_rsa_pub_key_new / @c r_rsa_priv_key_new
 * family construct one from already-parsed @c rmpint components or
 * raw big-endian byte buffers; @c r_rsa_priv_key_new_gen generates a
 * fresh keypair via a caller-supplied PRNG. Once you have an
 * @ref RCryptoKey, encrypt / decrypt / sign / verify go through the
 * polymorphic @c r_crypto_key_* dispatch, or directly through the
 * scheme-specific entry points below.
 *
 * Three padding modes are supported:
 *
 *   - @c R_RSA_PADDING_PKCS1_V15 — RSAES-PKCS1-v1_5 (encrypt) and
 *     RSASSA-PKCS1-v1_5 (sign). Legacy compatibility; see security
 *     caveats on @ref r_rsa_pkcs1v1_5_decrypt below.
 *   - @c R_RSA_PADDING_PKCS1_V21 — RSAES-OAEP and RSASSA-PSS.
 *     Modern, preferred for new protocols.
 *   - Raw RSA — @ref r_rsa_raw_encrypt / @ref r_rsa_raw_decrypt
 *     expose textbook RSA. Do not use without your own padding;
 *     it is provided for protocol-level work that does its own
 *     framing (e.g. building TLS internals).
 *
 * @{
 */

/**
 * @file rlib/crypto/rrsa.h
 * @brief RSA key construction plus RSAES / RSASSA primitives under
 * raw, OAEP and PKCS#1 v1.5 padding.
 */

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>

#include <rlib/data/rmpint.h>

#include <rlib/rrand.h>

R_BEGIN_DECLS

/** @brief Algorithm-name string used in @c RCryptoKey introspection. */
#define R_RSA_STR     "RSA"

/**
 * @brief RSA padding mode selector.
 *
 * Stored on the @ref RCryptoKey and consulted by the polymorphic
 * @c r_crypto_key_encrypt / @c r_crypto_key_sign dispatch. The
 * scheme-specific @c r_rsa_*_encrypt / @c _sign / @c _verify entry
 * points ignore this field and use whichever padding their name
 * indicates.
 */
typedef enum {
  R_RSA_PADDING_UNKNOWN       = -1,
  R_RSA_PADDING_PKCS1_V15     = 0, /**< RSAES-PKCS1-v1_5 + RSASSA-PKCS1-v1_5. */
  R_RSA_PADDING_PKCS1_V21     = 1, /**< RSAES-OAEP + RSASSA-PSS. */
} RRsaPadding;

/**
 * @brief Build an RSA public key from already-parsed @c rmpint
 * components @c (n, e).
 */
R_API RCryptoKey * r_rsa_pub_key_new (const rmpint * n, const rmpint * e) R_ATTR_MALLOC;

/**
 * @brief Build an RSA public key from raw big-endian byte buffers.
 *
 * Convenience wrapper that parses @p n and @p e into @c rmpints
 * before calling @ref r_rsa_pub_key_new.
 */
R_API RCryptoKey * r_rsa_pub_key_new_binary (rconstpointer n, rsize nsize,
    rconstpointer e, rsize esize) R_ATTR_MALLOC;

/**
 * @brief Build an RSA private key from @c (n, e, d).
 *
 * The CRT components (@c p, @c q, @c dp, @c dq, @c qp) are left
 * unset; private operations will use the slower @c (n, d) path.
 * For CRT-accelerated keys use @ref r_rsa_priv_key_new_full.
 */
R_API RCryptoKey * r_rsa_priv_key_new (const rmpint * n, const rmpint * e,
    const rmpint * d) R_ATTR_MALLOC;

/**
 * @brief Build an RSA private key with the full CRT representation.
 *
 * @param ver  PKCS#1 version tag (typically 0).
 * @param n    Modulus.
 * @param e    Public exponent.
 * @param d    Private exponent.
 * @param p,q  Prime factors of @p n.
 * @param dp   @c d mod (p-1).
 * @param dq   @c d mod (q-1).
 * @param qp   @c q^-1 mod p (CRT coefficient).
 *
 * Components @c dp / @c dq / @c qp accelerate private operations via
 * the Chinese Remainder Theorem.
 */
R_API RCryptoKey * r_rsa_priv_key_new_full (rint32 ver,
    const rmpint * n, const rmpint * e, /* public part */
    const rmpint * d, const rmpint * p, const rmpint * q,
    const rmpint * dp, const rmpint * dq, const rmpint * qp) R_ATTR_MALLOC;

/**
 * @brief Build an RSA private key from raw big-endian @c (n, e, d) buffers.
 *
 * Convenience wrapper around @ref r_rsa_priv_key_new.
 */
R_API RCryptoKey * r_rsa_priv_key_new_binary (rconstpointer n, rsize nsize,
    rconstpointer e, rsize esize, rconstpointer d, rsize dsize) R_ATTR_MALLOC;

/**
 * @brief Decode an RSA private key from an ASN.1 RSAPrivateKey TLV
 * (PKCS#1 §A.1.2).
 *
 * Used by the PEM and X.509 import paths (see @c rpem.h and
 * @c rx509.h) to materialise an @ref RCryptoKey from a DER blob.
 */
R_API RCryptoKey * r_rsa_priv_key_new_from_asn1 (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv) R_ATTR_MALLOC;

/**
 * @brief Generate a fresh RSA keypair.
 *
 * @param bits  Modulus size in bits.
 * @param e     Public exponent (typically 65537).
 * @param prng  Randomness source used for prime sampling.
 * @return New @ref RCryptoKey carrying the full CRT representation,
 *         or @c NULL on failure.
 */
R_API RCryptoKey * r_rsa_priv_key_new_gen (rsize bits, ruint64 e,
    RPrng * prng) R_ATTR_MALLOC;


/** @brief Alias for @ref r_rsa_pub_key_get_padding; same field. */
#define r_rsa_priv_key_get_padding r_rsa_pub_key_get_padding
/** @brief Alias for @ref r_rsa_pub_key_set_padding; same field. */
#define r_rsa_priv_key_set_padding r_rsa_pub_key_set_padding

/**
 * @brief Set the @ref RRsaPadding selector that the polymorphic
 * dispatch (@c r_crypto_key_encrypt / @c _sign) uses for this key.
 */
R_API rboolean r_rsa_pub_key_set_padding (RCryptoKey * key, RRsaPadding padding);

/**
 * @brief Read back the @ref RRsaPadding selector previously stored
 * with @ref r_rsa_pub_key_set_padding.
 */
R_API RRsaPadding r_rsa_pub_key_get_padding (const RCryptoKey * key);

/** @brief Alias for @ref r_rsa_pub_key_get_e (public field). */
#define r_rsa_priv_key_get_e r_rsa_pub_key_get_e

/** @brief Copy the public exponent @c e into @p e. */
R_API rboolean r_rsa_pub_key_get_e (const RCryptoKey * key, rmpint * e);
/** @brief Copy the modulus @c n into @p n. */
R_API rboolean r_rsa_pub_key_get_n (const RCryptoKey * key, rmpint * n);
/** @brief Copy the private exponent @c d into @p d. */
R_API rboolean r_rsa_priv_key_get_d (const RCryptoKey * key, rmpint * d);
/** @brief Copy the prime factor @c p into @p p (CRT-representation keys). */
R_API rboolean r_rsa_priv_key_get_p (const RCryptoKey * key, rmpint * p);
/** @brief Copy the prime factor @c q into @p q (CRT-representation keys). */
R_API rboolean r_rsa_priv_key_get_q (const RCryptoKey * key, rmpint * q);
/** @brief Copy the CRT exponent @c dp = d mod (p-1) into @p dp. */
R_API rboolean r_rsa_priv_key_get_dp (const RCryptoKey * key, rmpint * dp);
/** @brief Copy the CRT exponent @c dq = d mod (q-1) into @p dq. */
R_API rboolean r_rsa_priv_key_get_dq (const RCryptoKey * key, rmpint * dq);
/** @brief Copy the CRT coefficient @c qp = q^-1 mod p into @p qp. */
R_API rboolean r_rsa_priv_key_get_qp (const RCryptoKey * key, rmpint * qp);


/**
 * @brief Textbook RSA encryption: @c out = m^e mod n.
 *
 * @warning No padding. Direct use is insecure for almost every
 * protocol - the same plaintext always encrypts to the same
 * ciphertext, and small messages can be recovered by cube-root.
 * Use OAEP (@ref r_rsa_oaep_encrypt) or PKCS#1 v1.5
 * (@ref r_rsa_pkcs1v1_5_encrypt) unless you're building padding
 * yourself.
 */
R_API RCryptoResult r_rsa_raw_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

/**
 * @brief Textbook RSA decryption: @c out = c^d mod n.
 *
 * @warning No padding-check. See the warning on @ref r_rsa_raw_encrypt.
 */
R_API RCryptoResult r_rsa_raw_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

/**
 * @brief RSAES-OAEP encryption (PKCS#1 v2.x).
 *
 * Authenticated, randomised padding. Preferred over PKCS#1 v1.5 for
 * any new protocol that needs RSA-based encryption.
 */
R_API RCryptoResult r_rsa_oaep_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

/**
 * @brief RSAES-OAEP decryption (PKCS#1 v2.x).
 */
R_API RCryptoResult r_rsa_oaep_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

/**
 * @brief RSAES-PKCS1-v1_5 encryption.
 *
 * Legacy. New protocols should prefer OAEP. Encryption is fine; the
 * danger is on the decrypt side - see the security note on
 * @ref r_rsa_pkcs1v1_5_decrypt.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

/**
 * @brief Variable-length PKCS#1 v1.5 decrypt.
 *
 * Returns distinct error codes for each padding-validation failure
 * mode and walks the PS field via an early-out loop. Both of those
 * signals are attacker-observable - the function is a Bleichenbacher
 * oracle when exposed to chosen-ciphertext input.
 *
 * @warning SAFE only for trusted-source ciphertexts (e.g. blob
 * decryption where you encrypted the data yourself and just need to
 * recover it).
 *
 * For network-facing decrypt (TLS-RSA premaster, JWE RSA1_5, S/MIME,
 * anything else where an attacker can submit ciphertexts and observe
 * accept / reject), use @ref r_rsa_pkcs1v1_5_decrypt_implicit, which
 * collapses every failure mode into a constant-time synthetic
 * message of caller-supplied length.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

/**
 * @brief RSAES-PKCS1-v1_5 decrypt with implicit rejection - the
 * standard Bleichenbacher / ROBOT / Marvin mitigation.
 *
 * Always writes @p out_size bytes to @p out and returns
 * @c R_CRYPTO_OK on any well-formed raw decrypt: the real plaintext
 * when padding is valid and the recovered message length matches
 * @p out_size, or a deterministic synthetic message derived from
 * the private key + ciphertext otherwise. The padding check and
 * the length scan are constant-time across every byte of the
 * recovered block, and success / failure share the same return
 * code and output length, so a network attacker can't distinguish
 * them.
 *
 * Callers that need to detect "ciphertext doesn't decrypt to what
 * the protocol expected" must do so at a higher layer (e.g. the
 * TLS Finished transcript check), never through return-code
 * inspection on this primitive.
 *
 * @param key       Private RSA key.
 * @param data      Ciphertext bytes.
 * @param size      Length of @p data, must equal the modulus byte length.
 * @param out       Destination for the recovered (or synthetic) message;
 *                  exactly @p out_size bytes are always written.
 * @param out_size  Must be in @c (0, k-11] where @c k is the modulus
 *                  byte length (the RSAES-PKCS1-v1_5 maximum-message
 *                  bound). Zero or larger values return
 *                  @c R_CRYPTO_WRONG_SIZE.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_decrypt_implicit (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize out_size);

/**
 * @brief RSASSA-PKCS1-v1_5 sign over message bytes.
 *
 * Hashes @p msg with @p mdtype, then signs the resulting digest.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_sign_msg (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    rpointer sig, rsize * sigsize);

/**
 * @brief RSASSA-PKCS1-v1_5 sign over a precomputed digest.
 *
 * Same as @ref r_rsa_pkcs1v1_5_sign_msg but the caller supplies the
 * already-hashed value; @p mdtype is still required so the PKCS#1
 * v1.5 DigestInfo prefix can be selected.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_sign_msg_hash (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize);

/**
 * @brief RSASSA-PKCS1-v1_5 sign over a precomputed digest without a
 * DigestInfo prefix.
 *
 * The signed payload is the raw hash bytes. Used by protocols that
 * frame DigestInfo at a higher layer (e.g. some TLS 1.0 / 1.1
 * profiles).
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_sign_hash (const RCryptoKey * key, RPrng * prng,
    rconstpointer hash, rsize hashsize, rpointer sig, rsize * sigsize);

/**
 * @brief RSASSA-PKCS1-v1_5 verify over message bytes.
 *
 * Hashes @p msg using whichever digest is encoded in the signature's
 * DigestInfo, then compares.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_verify_msg (const RCryptoKey * key,
    rconstpointer msg, rsize msgsize, rconstpointer sig, rsize sigsize);

/**
 * @brief RSASSA-PKCS1-v1_5 verify with a caller-specified digest type
 * over a precomputed hash.
 *
 * Used when the caller already hashed the message and knows which
 * @ref RMsgDigestType produced @p hash.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_verify_msg_with_hash (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize);

/**
 * @brief RSASSA-PKCS1-v1_5 verify of a raw-hash signature (no
 * DigestInfo).
 *
 * Counterpart to @ref r_rsa_pkcs1v1_5_sign_hash.
 */
R_API RCryptoResult r_rsa_pkcs1v1_5_verify_hash (const RCryptoKey * key,
    rconstpointer hash, rsize hashsize, rconstpointer sig, rsize sigsize);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_RSA_H__ */



