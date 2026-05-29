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
#ifndef __R_CRYPTO_CHACHA20_H__
#define __R_CRYPTO_CHACHA20_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

/**
 * @defgroup r_crypto_chacha20 ChaCha20 (RFC 8439)
 * @ingroup r_crypto_symmetric
 * @brief The ChaCha20 stream cipher core: a 64-byte block function and
 * a keystream-XOR helper.
 * @{
 */

/**
 * @file rlib/crypto/rchacha20.h
 * @brief ChaCha20 stream cipher primitive (RFC 8439).
 *
 * A minimal, allocation-free implementation of the ChaCha20 core from
 * RFC 8439: the 20-round block function and the keystream-XOR helper
 * built on it. It uses a 256-bit key, a 96-bit nonce and a 32-bit
 * block counter.
 *
 * This is the low-level cipher core, not an @c RCryptoCipher; it backs
 * @ref r_prng_new_crypto and is exposed so its output can be checked
 * directly against the RFC 8439 test vectors. For Poly1305
 * authentication or the negotiated-cipher interface, layer on top —
 * this header provides confidentiality only.
 */

R_BEGIN_DECLS

/** @brief ChaCha20 key size in bytes (256-bit). */
#define R_CHACHA20_KEY_SIZE     32
/** @brief ChaCha20 nonce size in bytes (96-bit, RFC 8439 layout). */
#define R_CHACHA20_NONCE_SIZE   12
/** @brief ChaCha20 keystream block size in bytes. */
#define R_CHACHA20_BLOCK_SIZE   64

/**
 * @brief Generate one 64-byte ChaCha20 keystream block.
 *
 * Runs the RFC 8439 §2.3 block function for the given @p key,
 * @p counter and @p nonce and writes the resulting
 * @ref R_CHACHA20_BLOCK_SIZE keystream bytes to @p out.
 *
 * @param out     Destination for @ref R_CHACHA20_BLOCK_SIZE bytes.
 * @param key     32-byte (@ref R_CHACHA20_KEY_SIZE) key.
 * @param counter Block counter; distinct counters yield distinct blocks.
 * @param nonce   12-byte (@ref R_CHACHA20_NONCE_SIZE) nonce.
 */
R_API void r_chacha20_block (ruint8 * out,
    const ruint8 * key, ruint32 counter, const ruint8 * nonce);

/**
 * @brief XOR @p size bytes of ChaCha20 keystream over @p src into @p dst.
 *
 * Encrypts or decrypts (the operation is its own inverse) @p size
 * bytes, generating keystream blocks starting at @p counter and
 * incrementing it per 64-byte block as in RFC 8439 §2.4. @p dst may
 * alias @p src for in-place operation.
 *
 * @param dst     Output buffer; at least @p size bytes.
 * @param src     Input buffer; at least @p size bytes. May alias @p dst.
 * @param size    Number of bytes to process.
 * @param key     32-byte (@ref R_CHACHA20_KEY_SIZE) key.
 * @param counter Initial block counter.
 * @param nonce   12-byte (@ref R_CHACHA20_NONCE_SIZE) nonce.
 *
 * @warning The block counter is 32-bit, so a single (@p key, @p nonce)
 * pair yields at most 2³² blocks — 256 GiB — of keystream. The counter
 * wraps silently past that point and the keystream repeats, which is
 * catastrophic for confidentiality; split larger streams across nonces.
 */
R_API void r_chacha20_xor (ruint8 * dst, const ruint8 * src, rsize size,
    const ruint8 * key, ruint32 counter, const ruint8 * nonce);

R_END_DECLS

/** @} */ /* r_crypto_chacha20 group */

#endif /* __R_CRYPTO_CHACHA20_H__ */
