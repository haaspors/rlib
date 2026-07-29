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
#ifndef __R_CRYPTO_CHACHA20POLY1305_H__
#define __R_CRYPTO_CHACHA20POLY1305_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rcipher.h>

/**
 * @defgroup r_crypto_chacha20poly1305 ChaCha20-Poly1305 AEAD (RFC 8439)
 * @ingroup r_crypto_symmetric
 * @brief The ChaCha20-Poly1305 authenticated cipher, plugged into the
 * @ref r_crypto_cipher AEAD interface.
 * @{
 */

/**
 * @file rlib/crypto/rchacha20poly1305.h
 * @brief ChaCha20-Poly1305 AEAD construction (RFC 8439 §2.8).
 *
 * Combines the ChaCha20 stream cipher (@ref r_crypto_chacha20) with the
 * Poly1305 one-time authenticator (@ref r_crypto_poly1305) into an AEAD
 * cipher exposed through the generic @ref r_crypto_cipher interface. A
 * per-message Poly1305 key is derived from ChaCha20 keystream block 0,
 * the plaintext is encrypted from block 1 on, and the tag covers the
 * AAD, the ciphertext and their lengths.
 *
 * The cipher is AEAD, so drive it through
 * @ref r_crypto_cipher_encrypt_aead / @ref r_crypto_cipher_decrypt_aead
 * (a 32-byte key, a 12-byte nonce and a 16-byte tag); the plain
 * @ref r_crypto_cipher_encrypt entry points reject it.
 */

R_BEGIN_DECLS

/** @brief ChaCha20-Poly1305 key size in bytes (256-bit). */
#define R_CHACHA20POLY1305_KEY_SIZE     32
/** @brief ChaCha20-Poly1305 nonce size in bytes (96-bit). */
#define R_CHACHA20POLY1305_NONCE_SIZE   12
/** @brief ChaCha20-Poly1305 tag size in bytes. */
#define R_CHACHA20POLY1305_TAG_SIZE     16

/**
 * @brief Create a ChaCha20-Poly1305 AEAD cipher instance for @p key.
 *
 * @param key  32-byte (@ref R_CHACHA20POLY1305_KEY_SIZE) key.
 * @return Cipher instance bound to the ChaCha20-Poly1305 descriptor;
 *         release with @c r_crypto_cipher_unref. @c NULL on allocation
 *         failure or a @c NULL key.
 */
R_API RCryptoCipher * r_cipher_chacha20_poly1305_new (const ruint8 * key) R_ATTR_MALLOC;

R_END_DECLS

/** @} */ /* r_crypto_chacha20poly1305 group */

#endif /* __R_CRYPTO_CHACHA20POLY1305_H__ */
