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

R_END_DECLS

/** @} */

#endif /* __R_KDF_H__ */
