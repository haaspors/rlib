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

R_BEGIN_DECLS

typedef enum {
  R_CRYPTO_CIPHER_ALGO_NONE = 0,
  R_CRYPTO_CIPHER_ALGO_NULL,
  R_CRYPTO_CIPHER_ALGO_AES,
  R_CRYPTO_CIPHER_ALGO_ARC4,
  R_CRYPTO_CIPHER_ALGO_BLOWFISH,
  R_CRYPTO_CIPHER_ALGO_DES,
  R_CRYPTO_CIPHER_ALGO_3DES,
  R_CRYPTO_CIPHER_ALGO_CAMELLIA,
} RCryptoCipherAlgorithm;

typedef enum {
  R_CRYPTO_CIPHER_MODE_NONE = 0,
  R_CRYPTO_CIPHER_MODE_ECB,
  R_CRYPTO_CIPHER_MODE_CBC,
  R_CRYPTO_CIPHER_MODE_CFB,
  R_CRYPTO_CIPHER_MODE_OFB,
  R_CRYPTO_CIPHER_MODE_CTR,
  R_CRYPTO_CIPHER_MODE_GCM,
  R_CRYPTO_CIPHER_MODE_CCM,
  R_CRYPTO_CIPHER_MODE_STREAM,
} RCryptoCipherMode;

typedef enum {
  R_CRYPTO_CIPHER_PADDING_NONE,           /* complete blocks only */
  R_CRYPTO_CIPHER_PADDING_PKCS7,
  R_CRYPTO_CIPHER_PADDING_X923,           /* zeros and length     */
  R_CRYPTO_CIPHER_PADDING_ISO_7816_4,     /* ISO/IEC 7816-4       */
  R_CRYPTO_CIPHER_PADDING_ZEROS,
} RCryptoCipherPadding;

typedef enum {
  R_CRYPTO_CIPHER_OK = 0,
  R_CRYPTO_CIPHER_INVAL,
  R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE,
} RCryptoCipherResult;

typedef struct _RCryptoCipher RCryptoCipher;

typedef RCryptoCipherResult (*RCryptoCipherOperation) (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
typedef RCryptoCipherOperation RCryptoCipherEncrypt;
typedef RCryptoCipherOperation RCryptoCipherDecrypt;

typedef struct {
  const rchar *           strtype;
  RCryptoCipherAlgorithm  type;
  RCryptoCipherMode       mode;
  ruint16                 keybits;
  rsize                   ivsize;
  rsize                   blocksize;

  /* Cipher operations */
  RCryptoCipherEncrypt    enc;
  RCryptoCipherDecrypt    dec;
} RCryptoCipherInfo;

struct _RCryptoCipher {
  RRef ref;
  const RCryptoCipherInfo * info;
};

R_API const RCryptoCipherInfo * r_crypto_cipher_find_by_str (const rchar * str);
R_API const RCryptoCipherInfo * r_crypto_cipher_find_by_type (
    RCryptoCipherAlgorithm algo, RCryptoCipherMode mode, ruint16 bits);

R_API RCryptoCipher * r_crypto_cipher_null_new (/* accept key */) R_ATTR_MALLOC;

R_API RCryptoCipher * r_crypto_cipher_new (const RCryptoCipherInfo * info,
    const ruint8 * key) R_ATTR_MALLOC;
#define r_crypto_cipher_ref r_ref_ref
#define r_crypto_cipher_unref r_ref_unref

R_API RCryptoCipherResult r_crypto_cipher_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);
R_API RCryptoCipherResult r_crypto_cipher_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize);

R_END_DECLS

#endif /* __R_CRYPTO_CIPHER_H__ */


