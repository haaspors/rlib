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
#ifndef __R_KDF_H__
#define __R_KDF_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rmsgdigest.h>

/**
 * @defgroup r_crypto_kdf Key derivation functions
 * @ingroup r_crypto
 * @brief Password-based key derivation.
 * @{
 */

/**
 * @file rlib/crypto/rkdf.h
 * @brief Key derivation functions.
 */

R_BEGIN_DECLS

/**
 * @brief PBKDF2 (RFC 8018 / PKCS#5 v2.1, section 5.2).
 *
 * Derive @p outlen key bytes from @p password and @p salt by iterating
 * an HMAC built on @p prf @p iterations times per output block.
 *
 * @param prf         Digest backing the HMAC PRF (e.g.
 *                    @c R_MSG_DIGEST_TYPE_SHA256). Extendable-output
 *                    functions are not valid PRFs.
 * @param password    Password bytes; may be empty but not @c NULL.
 * @param passlen     Length of @p password in bytes.
 * @param salt        Salt bytes; may be empty but not @c NULL.
 * @param saltlen     Length of @p salt in bytes.
 * @param iterations  Iteration count; must be at least 1.
 * @param out         Destination buffer for @p outlen derived bytes.
 * @param outlen      Number of key bytes to derive; must be > 0.
 * @return @c TRUE on success; @c FALSE on invalid arguments (a @c NULL
 *         pointer, zero @p iterations or @p outlen, or a @p prf with no
 *         fixed output size).
 */
R_API rboolean r_kdf_pbkdf2 (RMsgDigestType prf,
    const ruint8 * password, rsize passlen,
    const ruint8 * salt, rsize saltlen,
    ruint iterations, ruint8 * out, rsize outlen);

/**
 * @brief HKDF-Extract (RFC 5869, section 2.2).
 *
 * Compute the pseudorandom key @c PRK = @c HMAC-Hash(salt, IKM) from input
 * keying material @p ikm, condensing its entropy for @ref r_hkdf_expand.
 *
 * @param hash    Digest backing the HMAC (e.g. @c R_MSG_DIGEST_TYPE_SHA256).
 * @param salt    Optional salt; may be @c NULL (with @p saltlen 0), which is
 *                equivalent to a string of @c HashLen zeros.
 * @param saltlen Length of @p salt in bytes.
 * @param ikm     Input keying material; may be empty but not @c NULL.
 * @param ikmlen  Length of @p ikm in bytes.
 * @param prk     Destination for the PRK, exactly
 *                @ref r_msg_digest_type_size (@p hash) bytes.
 * @return @c TRUE on success; @c FALSE on invalid arguments (a required
 *         @c NULL pointer or a @p hash with no fixed output size).
 */
R_API rboolean r_hkdf_extract (RMsgDigestType hash,
    const ruint8 * salt, rsize saltlen,
    const ruint8 * ikm, rsize ikmlen, ruint8 * prk);

/**
 * @brief HKDF-Expand (RFC 5869, section 2.3).
 *
 * Expand a pseudorandom key @p prk (typically from @ref r_hkdf_extract) and an
 * optional @p info context into @p outlen output bytes.
 *
 * @param hash    Digest backing the HMAC; must match the one used to extract.
 * @param prk     Pseudorandom key; should be at least @c HashLen bytes.
 * @param prklen  Length of @p prk in bytes.
 * @param info    Optional context/application info; may be @c NULL (with
 *                @p infolen 0).
 * @param infolen Length of @p info in bytes.
 * @param out     Destination buffer for @p outlen bytes.
 * @param outlen  Number of bytes to derive; must be > 0 and at most
 *                @c 255 * @c HashLen.
 * @return @c TRUE on success; @c FALSE on invalid arguments (a required
 *         @c NULL pointer, zero or oversized @p outlen, or a @p hash with no
 *         fixed output size).
 */
R_API rboolean r_hkdf_expand (RMsgDigestType hash,
    const ruint8 * prk, rsize prklen,
    const ruint8 * info, rsize infolen, ruint8 * out, rsize outlen);

R_END_DECLS

/** @} */

#endif /* __R_KDF_H__ */
