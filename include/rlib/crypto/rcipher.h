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
#ifndef __R_CRYPTO_CIPHER_H__
#define __R_CRYPTO_CIPHER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>

/**
 * @defgroup r_crypto_cipher Block / stream cipher base
 * @brief Algorithm-agnostic block / stream cipher interface; concrete
 * cipher families (AES, ARC4, ...) plug into it via @c RCryptoCipherInfo.
 * @{
 */

/**
 * @file rlib/crypto/rcipher.h
 * @brief Block / stream cipher base interface.
 *
 * Provides the algorithm- and mode-neutral surface every concrete
 * cipher (AES, ARC4, ...) registers against. A cipher is a reference-
 * counted @c RCryptoCipher whose @c info pointer carries the
 * algorithm + mode + key size + operation function pointers; concrete
 * families publish a static array of @c RCryptoCipherInfo entries (one
 * per algo/mode/bits triple) and a matching factory.
 *
 * **Usage:**
 *  - Look up an @c RCryptoCipherInfo by name or by tuple
 *    (@c r_crypto_cipher_find_by_str / @c _find_by_type), or take one
 *    from the algorithm-specific factory (e.g. @c r_cipher_aes_new).
 *  - Create the cipher with @c r_crypto_cipher_new (or the family's
 *    factory) - the new instance retains a borrowed pointer to @p info.
 *  - Encrypt / decrypt one buffer per call with
 *    @c r_crypto_cipher_encrypt / @c _decrypt. The @p iv argument is
 *    read-write; chained-mode callers reuse it to chain successive
 *    calls.
 *  - Release with @c r_crypto_cipher_unref.
 *
 * The base API is one-shot only - there is no incremental
 * @c init/update/final flow.
 */

R_BEGIN_DECLS

/** @brief Cipher algorithm identity (algorithm family, not mode or size). */
typedef enum {
  R_CRYPTO_CIPHER_ALGO_NONE = 0,
  R_CRYPTO_CIPHER_ALGO_NULL,        /**< Pass-through cipher (for negotiation / testing). */
  R_CRYPTO_CIPHER_ALGO_AES,         /**< AES (FIPS 197). */
  R_CRYPTO_CIPHER_ALGO_ARC4,        /**< RC4 stream cipher. */
  R_CRYPTO_CIPHER_ALGO_BLOWFISH,    /**< Blowfish. */
  R_CRYPTO_CIPHER_ALGO_DES,         /**< Single DES. */
  R_CRYPTO_CIPHER_ALGO_3DES,        /**< Triple DES. */
  R_CRYPTO_CIPHER_ALGO_CAMELLIA,    /**< Camellia. */
} RCryptoCipherAlgorithm;

/**
 * @brief Mode of operation for a block cipher (or stream-cipher marker).
 *
 * Combined with @c RCryptoCipherAlgorithm and a key-size in bits to
 * uniquely identify an @c RCryptoCipherInfo.
 */
typedef enum {
  R_CRYPTO_CIPHER_MODE_NONE = 0,
  R_CRYPTO_CIPHER_MODE_ECB,         /**< Electronic Code Book. */
  R_CRYPTO_CIPHER_MODE_CBC,         /**< Cipher Block Chaining. */
  R_CRYPTO_CIPHER_MODE_CFB,         /**< Cipher Feedback. */
  R_CRYPTO_CIPHER_MODE_OFB,         /**< Output Feedback. */
  R_CRYPTO_CIPHER_MODE_CTR,         /**< Counter mode. */
  R_CRYPTO_CIPHER_MODE_GCM,         /**< Galois / Counter Mode (AEAD; future). */
  R_CRYPTO_CIPHER_MODE_CCM,         /**< Counter with CBC-MAC (AEAD; future). */
  R_CRYPTO_CIPHER_MODE_STREAM,      /**< Generic stream cipher (no block boundary). */
} RCryptoCipherMode;

/** @brief Padding scheme for fixed-block modes that need to handle
 * the residual partial block. Independent of mode dispatch. */
typedef enum {
  R_CRYPTO_CIPHER_PADDING_NONE,         /**< No padding; complete blocks only. */
  R_CRYPTO_CIPHER_PADDING_PKCS7,        /**< PKCS#7 padding (RFC 5652). */
  R_CRYPTO_CIPHER_PADDING_X923,         /**< ANSI X9.23: zero bytes plus length. */
  R_CRYPTO_CIPHER_PADDING_ISO_7816_4,   /**< ISO/IEC 7816-4: 0x80 then zeros. */
  R_CRYPTO_CIPHER_PADDING_ZEROS,        /**< Zero bytes only (length must be known out-of-band). */
} RCryptoCipherPadding;

/** @brief Result code returned by cipher operations. */
typedef enum {
  R_CRYPTO_CIPHER_OK = 0,               /**< Operation succeeded. */
  R_CRYPTO_CIPHER_OOM,                  /**< Memory allocation failed. */
  R_CRYPTO_CIPHER_INVAL,                /**< Invalid argument (NULL, wrong size, etc.). */
  R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE,     /**< Input not a multiple of @c blocksize for a block mode. */
  R_CRYPTO_CIPHER_NEEDS_AEAD,           /**< Cipher mode is AEAD; use @c r_crypto_cipher_encrypt_aead. */
  R_CRYPTO_CIPHER_NOT_AEAD,             /**< Cipher mode is not AEAD; use @c r_crypto_cipher_encrypt. */
  R_CRYPTO_CIPHER_AUTH_FAILED,          /**< AEAD tag verification failed; plaintext must be discarded. */
} RCryptoCipherResult;

/** @brief Opaque cipher handle. */
typedef struct RCryptoCipher RCryptoCipher;

/**
 * @brief Operation function signature for one-shot encrypt / decrypt.
 *
 * @param cipher  Cipher instance.
 * @param dst     Output buffer; at least @p size bytes.
 * @param size    Bytes of @p data to process.
 * @param data    Input buffer; at least @p size bytes. May alias @p dst
 *                for in-place operation.
 * @param iv      Initialization vector / counter; read-write so chained
 *                modes can advance it for the next call. @c NULL is
 *                accepted only by modes that don't use an IV (ECB).
 * @param ivsize  Size of @p iv in bytes; must match @c info->ivsize.
 */
typedef RCryptoCipherResult (*RCryptoCipherOperation) (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/** @brief Encrypt operation alias for @c RCryptoCipherOperation. */
typedef RCryptoCipherOperation RCryptoCipherEncrypt;
/** @brief Decrypt operation alias for @c RCryptoCipherOperation. */
typedef RCryptoCipherOperation RCryptoCipherDecrypt;

/**
 * @brief Operation function signature for AEAD encrypt / decrypt.
 *
 * Same as @c RCryptoCipherOperation but adds the AEAD-specific
 * arguments: additional authenticated data (@p aad / @p aadsize) that
 * is included in the tag computation but not encrypted, and the
 * authentication tag (@p tag / @p tagsize). On encrypt the tag is
 * written; on decrypt it is read, verified, and the function returns
 * @c R_CRYPTO_CIPHER_AUTH_FAILED on mismatch.
 *
 * @param cipher   Cipher instance; must be an AEAD mode.
 * @param dst      Output buffer; at least @p size bytes.
 * @param size     Bytes of @p data to process.
 * @param data     Input buffer; at least @p size bytes. May alias @p dst.
 * @param aad      Additional authenticated data; may be @c NULL when
 *                 @p aadsize is 0.
 * @param aadsize  Bytes of @p aad to include in the tag computation.
 * @param iv       Nonce; size dictated by @c info->ivsize.
 * @param ivsize   Size of @p iv in bytes.
 * @param tag      Tag buffer; @c tagsize bytes. Written on encrypt,
 *                 read on decrypt.
 * @param tagsize  Tag size in bytes.
 */
typedef RCryptoCipherResult (*RCryptoCipherAeadOperation) (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);
/** @brief AEAD encrypt operation alias. */
typedef RCryptoCipherAeadOperation RCryptoCipherAeadEncrypt;
/** @brief AEAD decrypt operation alias. */
typedef RCryptoCipherAeadOperation RCryptoCipherAeadDecrypt;

/**
 * @brief Static descriptor for a (algo, mode, key-bits) triple.
 *
 * Concrete cipher families publish a const array of these and the
 * lookup functions resolve them by name or by tuple. The matching
 * @c r_<family>_new / @c r_crypto_cipher_new wires up the resulting
 * @c RCryptoCipher instance to one of these descriptors.
 */
typedef struct {
  const rchar *           strtype;     /**< Canonical name, e.g. @c "AES-128-CBC". */
  RCryptoCipherAlgorithm  type;        /**< Algorithm family. */
  RCryptoCipherMode       mode;        /**< Mode of operation. */
  ruint16                 keybits;     /**< Key size in bits. */
  rsize                   ivsize;      /**< Expected IV size in bytes (0 if N/A). */
  rsize                   blocksize;   /**< Native block size in bytes (1 for stream modes). */

  /**
   * Non-AEAD encrypt / decrypt operations. Filled for ECB / CBC / CTR
   * / CFB / OFB; left @c NULL for AEAD modes (GCM, CCM), whose
   * @c aead_enc / @c aead_dec slots carry the operations instead.
   */
  RCryptoCipherEncrypt    enc;         /**< Encrypt operation, or @c NULL on AEAD modes. */
  RCryptoCipherDecrypt    dec;         /**< Decrypt operation, or @c NULL on AEAD modes. */

  /**
   * AEAD encrypt / decrypt operations. Filled for GCM / CCM; left
   * @c NULL for non-AEAD modes. Exactly one of (@c enc, @c dec) and
   * (@c aead_enc, @c aead_dec) must be set per info entry.
   */
  RCryptoCipherAeadEncrypt aead_enc;   /**< AEAD encrypt operation, or @c NULL on non-AEAD modes. */
  RCryptoCipherAeadDecrypt aead_dec;   /**< AEAD decrypt operation, or @c NULL on non-AEAD modes. */
} RCryptoCipherInfo;

/**
 * @brief Concrete cipher instance.
 *
 * Concrete cipher families typically allocate a larger struct that
 * embeds @c RCryptoCipher at the top, so the @c info pointer indexes
 * into the family's static info array while the surrounding bytes
 * carry the family-specific state (key schedule, etc.).
 */
struct RCryptoCipher {
  RRef ref;                            /**< Reference counter. */
  const RCryptoCipherInfo * info;      /**< Borrowed descriptor for this instance. */
};

/**
 * @name Info lookup
 * @{
 */
/**
 * @brief Find a cipher descriptor by its canonical name (e.g. @c "AES-128-CBC").
 *
 * Case-insensitive; returns @c NULL if no registered cipher matches.
 */
R_API const RCryptoCipherInfo * r_crypto_cipher_find_by_str (const rchar * str);
/**
 * @brief Find a cipher descriptor by (algorithm, mode, key bits).
 *
 * @return Matching descriptor, or @c NULL if no cipher matches.
 */
R_API const RCryptoCipherInfo * r_crypto_cipher_find_by_type (
    RCryptoCipherAlgorithm algo, RCryptoCipherMode mode, ruint16 bits);
/** @} */

/**
 * @name Cipher lifecycle
 * @{
 */
/**
 * @brief Pass-through "null" cipher.
 *
 * Returns ciphertext == plaintext; used to fill a NULL slot in cipher-
 * suite negotiation and as a baseline for tests. No key is consumed.
 */
R_API RCryptoCipher * r_crypto_cipher_null_new (/* accept key */) R_ATTR_MALLOC;

/**
 * @brief Create a cipher instance for @p info using @p key.
 *
 * Dispatches to the algorithm family's factory; the returned cipher
 * is bound to @p info for its lifetime.
 *
 * @param info  Descriptor selected via @c _find_by_str / @c _find_by_type.
 * @param key   Key bytes; size dictated by @c info->keybits.
 * @return Cipher instance; release with @c r_crypto_cipher_unref.
 */
R_API RCryptoCipher * r_crypto_cipher_new (const RCryptoCipherInfo * info,
    const ruint8 * key) R_ATTR_MALLOC;
/** @brief Increment the cipher's refcount. */
#define r_crypto_cipher_ref r_ref_ref
/** @brief Decrement the cipher's refcount; frees when it reaches zero. */
#define r_crypto_cipher_unref r_ref_unref
/** @} */

/**
 * @brief Return @c TRUE if @p cipher is an AEAD mode (GCM / CCM).
 *
 * AEAD ciphers must be driven through @c r_crypto_cipher_encrypt_aead
 * / @c _decrypt_aead; non-AEAD ciphers through @c r_crypto_cipher_encrypt
 * / @c _decrypt. The base entry points reject the wrong family with
 * @c R_CRYPTO_CIPHER_NEEDS_AEAD / @c NOT_AEAD, so a runtime check is
 * a safety net rather than a requirement, but exposing this helper
 * lets callers branch on the contract without spelling out the mode.
 */
R_API rboolean r_crypto_cipher_is_aead (const RCryptoCipher * cipher);

/**
 * @name One-shot encrypt / decrypt
 *
 * For non-AEAD modes (ECB / CBC / CTR / CFB / OFB). An AEAD-moded
 * cipher rejects these entry points with
 * @c R_CRYPTO_CIPHER_NEEDS_AEAD; use the @c _aead variants instead.
 * @{
 */
/**
 * @brief Encrypt @p size bytes from @p data into @p dst.
 *
 * Buffers may alias for in-place operation. For block modes, @p size
 * must be a multiple of @c info->blocksize.
 *
 * @param cipher  Cipher instance; must not be an AEAD mode.
 * @param dst     Output buffer; at least @p size bytes.
 * @param size    Number of input bytes.
 * @param data    Input buffer; at least @p size bytes.
 * @param iv      Initialization vector / counter (read-write); chained
 *                modes update it in place.
 * @param ivsize  Size of @p iv; must match @c info->ivsize.
 */
R_API RCryptoCipherResult r_crypto_cipher_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/**
 * @brief Decrypt @p size bytes from @p data into @p dst.
 *
 * See @c r_crypto_cipher_encrypt for the buffer / IV contract.
 */
R_API RCryptoCipherResult r_crypto_cipher_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
/** @} */

/**
 * @name One-shot AEAD encrypt / decrypt
 *
 * For AEAD modes (GCM / CCM). A non-AEAD cipher rejects these entry
 * points with @c R_CRYPTO_CIPHER_NOT_AEAD; use @c r_crypto_cipher_encrypt
 * / @c _decrypt instead. Tag is detached (separate buffer from
 * @p dst); on decrypt, the function returns
 * @c R_CRYPTO_CIPHER_AUTH_FAILED on tag mismatch and the caller must
 * discard @p dst.
 * @{
 */
/**
 * @brief Authenticated encrypt with associated data.
 *
 * @param cipher   Cipher instance; must be an AEAD mode.
 * @param dst      Output ciphertext buffer; at least @p size bytes.
 * @param size     Plaintext length.
 * @param data     Plaintext; at least @p size bytes. May alias @p dst.
 * @param aad      Additional authenticated data (covered by the tag
 *                 but not encrypted); may be @c NULL when @p aadsize
 *                 is 0.
 * @param aadsize  AAD length in bytes.
 * @param iv       Nonce; size dictated by @c info->ivsize.
 * @param ivsize   Size of @p iv in bytes.
 * @param tag      Tag output buffer; @p tagsize bytes written.
 * @param tagsize  Requested tag size; mode-specific (e.g. 16 for GCM).
 */
R_API RCryptoCipherResult r_crypto_cipher_encrypt_aead (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);
/**
 * @brief Authenticated decrypt with associated data and tag verification.
 *
 * Same arguments as @c r_crypto_cipher_encrypt_aead, but @p tag is an
 * input (the expected tag) and is compared in constant time against
 * the value computed from @p data + @p aad. On mismatch, returns
 * @c R_CRYPTO_CIPHER_AUTH_FAILED; @p dst contents are undefined and
 * must be discarded.
 */
R_API RCryptoCipherResult r_crypto_cipher_decrypt_aead (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);
/** @} */

R_END_DECLS

/** @} */ /* r_crypto_cipher group */

#endif /* __R_CRYPTO_CIPHER_H__ */


