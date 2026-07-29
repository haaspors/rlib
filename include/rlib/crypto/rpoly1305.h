/* RLIB - Convenience library for useful things
 * Copyright (C) 2026  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_POLY1305_H__
#define __R_CRYPTO_POLY1305_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>

/**
 * @defgroup r_crypto_poly1305 Poly1305 (RFC 8439)
 * @ingroup r_crypto_symmetric
 * @brief The Poly1305 one-time message-authentication code.
 * @{
 */

/**
 * @file rlib/crypto/rpoly1305.h
 * @brief Poly1305 one-time authenticator primitive (RFC 8439).
 *
 * A minimal, allocation-free implementation of the Poly1305 MAC from
 * RFC 8439 §2.5: given a 32-byte one-time key it authenticates an
 * arbitrary-length message into a 16-byte tag.
 *
 * Poly1305 is a *one-time* MAC — each key must authenticate exactly one
 * message. It is not a general keyed-hash; for a reusable keyed
 * authenticator use @ref r_crypto_hmac. The intended construction is
 * ChaCha20-Poly1305 (RFC 8439 §2.8), which derives a fresh one-time key
 * per message from the ChaCha20 keystream; that AEAD is provided by
 * @ref r_cipher_chacha20_poly1305_new and layers on top of this
 * primitive.
 */

R_BEGIN_DECLS

/** @brief Poly1305 one-time key size in bytes. */
#define R_POLY1305_KEY_SIZE     32
/** @brief Poly1305 tag size in bytes. */
#define R_POLY1305_TAG_SIZE     16
/** @brief Poly1305 accumulator block size in bytes. */
#define R_POLY1305_BLOCK_SIZE   16

/**
 * @brief Compute the Poly1305 tag of @p msg under one-time @p key.
 *
 * Runs the RFC 8439 §2.5 authenticator over @p size bytes of @p msg and
 * writes the @ref R_POLY1305_TAG_SIZE tag to @p tag.
 *
 * @param tag   Destination for @ref R_POLY1305_TAG_SIZE tag bytes.
 * @param msg   Message to authenticate; may be @c NULL only if
 *              @p size is 0.
 * @param size  Number of message bytes.
 * @param key   32-byte (@ref R_POLY1305_KEY_SIZE) one-time key.
 *
 * @warning The key is single-use. Authenticating two different messages
 * under the same key lets an attacker forge tags.
 */
R_API void r_poly1305_mac (ruint8 tag[R_POLY1305_TAG_SIZE],
    const ruint8 * msg, rsize size, const ruint8 key[R_POLY1305_KEY_SIZE]);

R_END_DECLS

/** @} */ /* r_crypto_poly1305 group */

#endif /* __R_CRYPTO_POLY1305_H__ */
