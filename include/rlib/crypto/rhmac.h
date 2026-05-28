/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_MAC_H__
#define __R_CRYPTO_MAC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_crypto_hmac HMAC (RFC 2104)
 * @ingroup r_crypto_hash
 *
 * @brief Keyed-Hash Message Authentication Code built on top of any
 * @ref r_msg_digest hash function.
 *
 * HMAC turns an unkeyed hash @c H into a keyed authenticator that
 * lets two parties sharing a secret detect tampering of an arbitrary
 * byte stream. The construction is:
 *
 *     HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
 *
 * with @c K' the secret key padded / hashed to the underlying
 * digest's block size. rlib accepts any @ref RMsgDigestType for @c H
 * (SHA-1, the SHA-2 family, ...); the cost of HMAC is roughly two
 * digest computations on top of the input length.
 *
 * Typical use mirrors @ref r_msg_digest's absorb / squeeze cycle:
 *
 * @code
 * RHmac * h = r_hmac_new (R_MSG_DIGEST_TYPE_SHA256, key, keysize);
 * r_hmac_update (h, msg, msgsize);
 * ruint8 tag[32];
 * r_hmac_get_data (h, tag, sizeof (tag), NULL);
 * r_hmac_free (h);
 * @endcode
 *
 * The receiver side uses @ref r_hmac_verify, which finalises and
 * compares against a known tag in constant time:
 *
 * @code
 * RHmac * h = r_hmac_new (R_MSG_DIGEST_TYPE_SHA256, key, keysize);
 * r_hmac_update (h, msg, msgsize);
 * if (!r_hmac_verify (h, expected_tag, sizeof (expected_tag)))
 *   reject ();
 * r_hmac_free (h);
 * @endcode
 *
 * @{
 */

/**
 * @file rlib/crypto/rhmac.h
 * @brief HMAC (RFC 2104) keyed message-authentication code built on
 * top of @ref r_msg_digest hash functions.
 */

#include <rlib/rtypes.h>
#include <rlib/crypto/rmsgdigest.h>

R_BEGIN_DECLS

/** @brief Opaque HMAC computation state. */
typedef struct RHmac       RHmac;

/**
 * @brief Create a new HMAC state keyed by @p key.
 *
 * @param type     Underlying hash function (any @ref RMsgDigestType).
 * @param key      Secret key bytes.
 * @param keysize  Length of @p key in bytes; may be larger or smaller
 *                 than the hash block size (RFC 2104 prescribes how
 *                 each case is handled).
 * @return New @c RHmac on success, or @c NULL if @p type is
 *         unsupported or allocation failed. Free with
 *         @ref r_hmac_free.
 */
R_API RHmac * r_hmac_new (RMsgDigestType type, rconstpointer key, rsize keysize) R_ATTR_MALLOC;

/** @brief Release an @c RHmac and zero its key material. */
R_API void r_hmac_free (RHmac * hmac);

/**
 * @brief Output tag size in bytes (matches the underlying digest size).
 */
R_API rsize r_hmac_size (const RHmac * hmac);

/**
 * @brief Reset the state so a fresh message can be authenticated with
 * the same key, without reallocating.
 */
R_API void r_hmac_reset (RHmac * hmac);

/**
 * @brief Absorb @p size bytes of message data into the HMAC.
 *
 * May be called repeatedly between @ref r_hmac_new / @ref r_hmac_reset
 * and the finalisation step. Returns @c FALSE if the HMAC has already
 * been finalised.
 */
R_API rboolean r_hmac_update (RHmac * hmac, rconstpointer data, rsize size);

/**
 * @brief Finalise and copy the HMAC tag into @p data.
 *
 * @param hmac  Computation state.
 * @param data  Output buffer.
 * @param size  Capacity of @p data; must be >= @ref r_hmac_size.
 * @param out   Optional out-parameter receiving the number of bytes
 *              written. Pass @c NULL to ignore.
 * @return @c TRUE on success. The state becomes finalised; further
 *         @ref r_hmac_update calls fail until @ref r_hmac_reset.
 */
R_API rboolean r_hmac_get_data (RHmac * hmac, ruint8 * data, rsize size, rsize * out);

/**
 * @brief Finalise and return the HMAC tag as a lowercase hex string.
 *
 * The string is allocated with @c r_malloc; the caller frees it with
 * @c r_free.
 */
R_API rchar * r_hmac_get_hex (RHmac * hmac);

/**
 * @brief Finalise and compare the HMAC tag against an expected value
 * in constant time.
 *
 * @param hmac          Computation state.
 * @param expected_tag  Tag to compare against.
 * @param tag_size      Number of bytes to compare. May be shorter
 *                      than @ref r_hmac_size for truncated-MAC
 *                      profiles (SRTP-80, SRTP-32, ...) but must not
 *                      exceed it.
 * @return @c TRUE iff the first @p tag_size bytes match.
 *
 * The compare uses @c r_memcmp_ct, so its timing reveals neither
 * which byte (if any) differed nor whether the verify failed early.
 */
R_API rboolean r_hmac_verify (RHmac * hmac,
    rconstpointer expected_tag, rsize tag_size);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_MAC_H__ */

