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
#ifndef __R_CRYPTO_ED448_H__
#define __R_CRYPTO_ED448_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>
#include <rlib/rrand.h>

/**
 * @defgroup r_ed448 Ed448 EdDSA
 * @ingroup r_crypto_ec
 * @brief Ed448 sign / verify per RFC 8032 §5.2.
 * @{
 */

/**
 * @file rlib/crypto/red448.h
 * @brief @c RCryptoKey wrapper for Ed448 sign / verify
 * (RFC 8032 §5.2).
 *
 * Ed448 is the deterministic EdDSA instantiation over edwards448
 * with SHAKE256 as the hash function: the per-signature nonce is
 * derived from a hash of the private key prefix and the message,
 * so signing does not consume a PRNG. The public key encodes to
 * 57 bytes and the signature to 114 bytes (@c R || @c S, both
 * little-endian).
 *
 * Private keys carry a 57-byte seed plus the cached clamped
 * scalar @c s and the @c prefix half derived once at key
 * construction via @c SHAKE256(seed, 114); the cached values let
 * the sign path skip the seed-hash setup on every call.
 *
 * RFC 8032 §5.2 takes a context parameter that gets folded into a
 * @c dom4(F, C) domain-separation prefix on every sign / verify
 * hash; this first cut hardcodes the empty context to match the
 * @c r_ed25519_sign signature, but the @c dom4(0, "") machinery is
 * in place to support exposing a caller-supplied context as a
 * small additive follow-up.
 *
 * Verification follows RFC 8032 §5.2.7 with the cofactored
 * equation @c [4]SB == [4]R + [4]kA. The @c S field of the
 * signature is rejected when it is not in the canonical range
 * @c [0, L); the public key is rejected on a non-canonical
 * encoding.
 */

R_BEGIN_DECLS

/** @brief Algorithm string tag for Ed448 keys. */
#define R_ED448_STR             "Ed448"

/** @brief Signature length in bytes. */
#define R_ED448_SIG_SIZE        114

/** @brief Public-key encoding length in bytes. */
#define R_ED448_PUB_KEY_SIZE    57

/** @brief Private-key seed length in bytes. */
#define R_ED448_SEED_SIZE       57

/**
 * @brief Construct an Ed448 public key from its raw 57-byte
 * encoding per RFC 8032 §5.2.2.
 *
 * The encoding must be canonical (the embedded @c y component
 * decodes to a value strictly less than the field prime, and the
 * resulting point lies on edwards448). The constructor decodes
 * once and caches the point internally so verify doesn't pay the
 * cost on every call.
 *
 * @param pub      57-byte little-endian encoding.
 * @param pubsize  Must be exactly @c R_ED448_PUB_KEY_SIZE.
 * @return Owning reference to a new public key, or @c NULL on
 *         NULL / size mismatch / non-canonical encoding.
 */
R_API RCryptoKey * r_ed448_pub_key_new (rconstpointer pub,
    rsize pubsize) R_ATTR_MALLOC;

/**
 * @brief Construct an Ed448 private key from a 57-byte seed.
 *
 * Per RFC 8032 §5.2.5 the seed is hashed once via @c SHAKE256 with
 * 114-byte output: the first 57 bytes are clamped to produce the
 * scalar @c s, and the second 57 bytes become the
 * deterministic-nonce @c prefix. The public key is derived as
 * @c encode(s * B). Both @c s, @c prefix, and the encoded public
 * key are cached on the returned key.
 *
 * @param seed      57-byte seed.
 * @param seedsize  Must be exactly @c R_ED448_SEED_SIZE.
 * @return Owning reference to a new private key, or @c NULL on
 *         NULL / size mismatch / allocation failure.
 */
R_API RCryptoKey * r_ed448_priv_key_new (rconstpointer seed,
    rsize seedsize) R_ATTR_MALLOC;

/**
 * @brief Generate a fresh Ed448 private key.
 *
 * Draws 57 random bytes from @p prng (or a fresh system PRNG when
 * @p prng is @c NULL) and feeds them through
 * @c r_ed448_priv_key_new.
 *
 * @param prng  PRNG to draw from; @c NULL to use the system PRNG. Any
 *              PRNG you supply must be cryptographically secure
 *              (@ref r_prng_new_crypto).
 * @return Owning reference to a new private key, or @c NULL on
 *         PRNG or allocation failure.
 */
R_API RCryptoKey * r_ed448_priv_key_new_gen (RPrng * prng) R_ATTR_MALLOC;

/**
 * @brief Borrow the 57-byte canonical public-key encoding of an
 * Ed448 key.
 *
 * Works for both public and private keys. The returned pointer
 * aliases the key's internal storage and is valid for the key's
 * lifetime.
 *
 * @param key   Ed448 public or private key.
 * @param pub   Out-pointer for the encoding buffer.
 * @param size  Out-pointer for the buffer length (always 57 on
 *              success).
 * @return @c TRUE on success; @c FALSE on NULL / non-Ed448 key.
 */
R_API rboolean r_ed448_key_get_pub (const RCryptoKey * key,
    const ruint8 ** pub, rsize * size);

/**
 * @brief Sign a message with an Ed448 private key.
 *
 * Produces a 114-byte deterministic signature per RFC 8032 §5.2.6
 * with empty context. The signature does not consume a PRNG.
 *
 * @param key      Ed448 private key.
 * @param msg      Message to sign.
 * @param msgsize  Message length.
 * @param sig      114-byte output buffer.
 * @param sigsize  In: capacity of @p sig. Out: bytes written
 *                 (always @c R_ED448_SIG_SIZE on success).
 * @return @c R_CRYPTO_OK on success;
 *         @c R_CRYPTO_INVAL on NULL inputs;
 *         @c R_CRYPTO_WRONG_TYPE on a non-Ed448 private key;
 *         @c R_CRYPTO_BUFFER_TOO_SMALL when @p sig is undersized.
 */
R_API RCryptoResult r_ed448_sign (const RCryptoKey * key,
    rconstpointer msg, rsize msgsize,
    ruint8 * sig, rsize * sigsize);

/**
 * @brief Verify an Ed448 signature.
 *
 * Implements the cofactored verify equation of RFC 8032 §5.2.7:
 * @c [4]SB == [4]R + [4]kA. Rejects non-canonical @c S (>= L) and
 * malformed @p sig.
 *
 * @param key      Ed448 public key.
 * @param msg      Message that was signed.
 * @param msgsize  Message length.
 * @param sig      Signature bytes.
 * @param sigsize  Must be exactly @c R_ED448_SIG_SIZE.
 * @return @c R_CRYPTO_OK on a valid signature;
 *         @c R_CRYPTO_VERIFY_FAILED on a well-formed signature
 *         that fails the verify equation;
 *         @c R_CRYPTO_INVAL on NULL inputs / size mismatch /
 *         malformed @c R / @c S / public key;
 *         @c R_CRYPTO_WRONG_TYPE on a non-Ed448 key.
 */
R_API RCryptoResult r_ed448_verify (const RCryptoKey * key,
    rconstpointer msg, rsize msgsize,
    rconstpointer sig, rsize sigsize);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_ED448_H__ */
