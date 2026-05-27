/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_AES_H__
#define __R_CRYPTO_AES_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rcipher.h>

/**
 * @defgroup r_crypto_aes AES (FIPS 197)
 * @brief AES cipher (128 / 192 / 256-bit keys) across ECB, CBC, CTR,
 * CFB, OFB modes; built on the @c RCryptoCipher base.
 * @{
 */

/**
 * @file rlib/crypto/raes.h
 * @brief AES block cipher and modes of operation.
 *
 * Wraps the 128 / 192 / 256-bit AES cipher in the modes of operation
 * registered against @c RCryptoCipherInfo (ECB / CBC / CTR / CFB / OFB).
 * A construction helper picks the right per-bits / HW-accelerated
 * primitive once at @c r_cipher_aes_new and caches it on the cipher
 * instance; the registered @c enc / @c dec operations then dispatch
 * through that cached pointer per call.
 *
 * **Picking a constructor:**
 *  - @c r_cipher_aes_new (mode, bits, key) - generic.
 *  - @c r_cipher_aes_NNN_MMM_new (key)     - explicit (mode, key-size) form.
 *  - @c r_cipher_aes_new_from_hex          - convenience for tests / config.
 *
 * **HW dispatch:** on x86 with AES-NI or on AArch64 with the +crypto
 * extension, the per-block primitive runs in hardware; falls back to
 * a constant-time-ish table implementation otherwise. Selection is
 * automatic at construction.
 */

R_BEGIN_DECLS

/** @brief Canonical algorithm name for @c r_crypto_cipher_find_by_str. */
#define R_AES_STR           "AES"
/** @brief AES block size in bytes (16, regardless of key length). */
#define R_AES_BLOCK_BYTES   16

/**
 * @brief Create an AES cipher with explicit @p mode, @p bits, and @p key.
 *
 * @param mode  One of @c R_CRYPTO_CIPHER_MODE_ECB / CBC / CTR / CFB / OFB.
 * @param bits  128, 192, or 256.
 * @param key   @p bits / 8 key bytes.
 * @return Cipher instance, or @c NULL on invalid arguments.
 */
R_API RCryptoCipher * r_cipher_aes_new (RCryptoCipherMode mode, ruint bits, const ruint8 * key) R_ATTR_MALLOC;
/**
 * @brief Create an AES cipher with @p mode and a hex-encoded key.
 *
 * The key-bit size is inferred from the length of @p hexkey
 * (32 / 48 / 64 hex characters for 128 / 192 / 256 bits). Convenience
 * for tests and configuration files; production code should prefer
 * @c r_cipher_aes_new with raw bytes.
 */
R_API RCryptoCipher * r_cipher_aes_new_from_hex (RCryptoCipherMode mode, const rchar * hexkey) R_ATTR_MALLOC;

/**
 * @name Per-mode / per-size factories
 *
 * Each shorthand wraps @c r_cipher_aes_new with the matching mode and
 * key size. Use these when the cipher choice is fixed at compile time.
 * @{
 */
/** @brief Create an AES-128 ECB cipher. */
R_API RCryptoCipher * r_cipher_aes_128_ecb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-192 ECB cipher. */
R_API RCryptoCipher * r_cipher_aes_192_ecb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-256 ECB cipher. */
R_API RCryptoCipher * r_cipher_aes_256_ecb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-128 CBC cipher. */
R_API RCryptoCipher * r_cipher_aes_128_cbc_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-192 CBC cipher. */
R_API RCryptoCipher * r_cipher_aes_192_cbc_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-256 CBC cipher. */
R_API RCryptoCipher * r_cipher_aes_256_cbc_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-128 CTR cipher. */
R_API RCryptoCipher * r_cipher_aes_128_ctr_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-192 CTR cipher. */
R_API RCryptoCipher * r_cipher_aes_192_ctr_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-256 CTR cipher. */
R_API RCryptoCipher * r_cipher_aes_256_ctr_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-128 CFB cipher. */
R_API RCryptoCipher * r_cipher_aes_128_cfb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-192 CFB cipher. */
R_API RCryptoCipher * r_cipher_aes_192_cfb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-256 CFB cipher. */
R_API RCryptoCipher * r_cipher_aes_256_cfb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-128 OFB cipher. */
R_API RCryptoCipher * r_cipher_aes_128_ofb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-192 OFB cipher. */
R_API RCryptoCipher * r_cipher_aes_192_ofb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-256 OFB cipher. */
R_API RCryptoCipher * r_cipher_aes_256_ofb_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-128 GCM cipher (AEAD). */
R_API RCryptoCipher * r_cipher_aes_128_gcm_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-192 GCM cipher (AEAD). */
R_API RCryptoCipher * r_cipher_aes_192_gcm_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-256 GCM cipher (AEAD). */
R_API RCryptoCipher * r_cipher_aes_256_gcm_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-128 CCM cipher (AEAD). */
R_API RCryptoCipher * r_cipher_aes_128_ccm_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-192 CCM cipher (AEAD). */
R_API RCryptoCipher * r_cipher_aes_192_ccm_new (const ruint8 * key) R_ATTR_MALLOC;
/** @brief Create an AES-256 CCM cipher (AEAD). */
R_API RCryptoCipher * r_cipher_aes_256_ccm_new (const ruint8 * key) R_ATTR_MALLOC;
/** @} */


/**
 * @name Single-block ECB primitive
 *
 * Low-level access to one AES block encrypt / decrypt. Exposed for
 * callers that build their own mode of operation (e.g. KW, custom
 * KDFs); ordinary use should go through the mode-aware
 * @c r_crypto_cipher_encrypt entry point.
 * @{
 */
/**
 * @brief Encrypt one 16-byte block in ECB.
 *
 * @return @c TRUE on success.
 */
R_API rboolean r_cipher_aes_ecb_encrypt_block (const RCryptoCipher * cipher,
    ruint8 ciphertxt[R_AES_BLOCK_BYTES], const ruint8 plaintxt[R_AES_BLOCK_BYTES]);
/**
 * @brief Decrypt one 16-byte block in ECB.
 *
 * @return @c TRUE on success.
 */
R_API rboolean r_cipher_aes_ecb_decrypt_block (const RCryptoCipher * cipher,
    ruint8 plaintxt[R_AES_BLOCK_BYTES], const ruint8 ciphertxt[R_AES_BLOCK_BYTES]);
/** @} */

/**
 * @name Mode operations
 *
 * Each pair is registered against an @c RCryptoCipherInfo so the
 * generic @c r_crypto_cipher_encrypt / @c _decrypt dispatch via
 * @c info->enc / @c _dec for that mode. They are also exported here
 * for callers that already have a typed @c RCryptoCipher and want to
 * skip the lookup.
 *
 * @c CTR and @c OFB are self-inverse - encrypt and decrypt are the
 * same operation - so each is exposed once and the matching
 * @c _decrypt alias resolves to its @c _encrypt sibling.
 * @{
 */
/** @brief AES-ECB encrypt. */
R_API RCryptoCipherResult r_cipher_aes_ecb_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/** @brief AES-ECB decrypt. */
R_API RCryptoCipherResult r_cipher_aes_ecb_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);

/** @brief AES-CBC encrypt. */
R_API RCryptoCipherResult r_cipher_aes_cbc_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/** @brief AES-CBC decrypt. */
R_API RCryptoCipherResult r_cipher_aes_cbc_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);

/** @brief AES-CTR encrypt (also covers decrypt; see alias below). */
R_API RCryptoCipherResult r_cipher_aes_ctr_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/** @brief CTR is self-inverse; decrypt resolves to encrypt. */
#define r_cipher_aes_ctr_decrypt r_cipher_aes_ctr_encrypt

/** @brief AES-CFB encrypt. */
R_API RCryptoCipherResult r_cipher_aes_cfb_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/** @brief AES-CFB decrypt. */
R_API RCryptoCipherResult r_cipher_aes_cfb_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);

/** @brief AES-OFB encrypt (also covers decrypt; see alias below). */
R_API RCryptoCipherResult r_cipher_aes_ofb_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/** @brief OFB is self-inverse; decrypt resolves to encrypt. */
#define r_cipher_aes_ofb_decrypt r_cipher_aes_ofb_encrypt

/**
 * @brief AES-GCM authenticated encrypt.
 *
 * GCM = CTR-mode encryption plus GHASH over AAD || ciphertext for the
 * integrity tag. IV must be 12 bytes (96 bits, the recommended NIST
 * size); other IV lengths return @c R_CRYPTO_CIPHER_INVAL. Tag length
 * is 1..16 bytes; @c tagsize == 16 covers the full GMAC output.
 *
 * Buffers may alias for in-place operation. The @p iv is read-only
 * (GCM's counter is internal); the parameter is kept read-write for
 * signature symmetry with @c RCryptoCipherAeadOperation, but is not
 * modified.
 */
R_API RCryptoCipherResult r_cipher_aes_gcm_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);
/**
 * @brief AES-GCM authenticated decrypt with tag verification.
 *
 * Computes the expected tag over @p aad and @p data, then compares
 * (constant time) against @p tag. On mismatch returns
 * @c R_CRYPTO_CIPHER_AUTH_FAILED and leaves @p dst untouched.
 */
R_API RCryptoCipherResult r_cipher_aes_gcm_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);

/**
 * @brief AES-CCM authenticated encrypt (RFC 3610 / NIST SP 800-38C).
 *
 * CCM = CBC-MAC for integrity (over the formatted B0 / AAD / plaintext)
 * plus CTR-mode encryption. The nonce length @p ivsize must be 7..13
 * bytes; the resulting length-of-length field @c L = @c 15-ivsize
 * bounds the plaintext to fewer than @c 2^(8L) bytes (e.g. 64 KiB
 * at @c ivsize == 13, 16 MiB at @c ivsize == 12). Tag length must be
 * an even number in @c [4, 16].
 *
 * Buffers may alias for in-place operation; @p iv is read-only.
 */
R_API RCryptoCipherResult r_cipher_aes_ccm_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);
/**
 * @brief AES-CCM authenticated decrypt with tag verification.
 *
 * Unlike GCM (where the tag is over ciphertext), CCM's tag is over
 * plaintext, so verification requires decrypting first. On a tag
 * mismatch this function returns @c R_CRYPTO_CIPHER_AUTH_FAILED and
 * @p dst already contains the decrypted bytes; the caller must
 * discard @p dst on auth failure.
 */
R_API RCryptoCipherResult r_cipher_aes_ccm_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);
/** @} */

R_END_DECLS

/** @} */ /* r_crypto_aes group */

#endif /* __R_CRYPTO_AES_H__ */

