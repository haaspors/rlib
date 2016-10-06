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
#ifndef __R_CRYPTO_CERT_H__
#define __R_CRYPTO_CERT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/crypto/rkey.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

typedef enum {
  R_CRYPTO_CERT_X509,
  R_CRYPTO_CERT_OPENPGP,
} RCryptoCertType;

typedef enum {
  R_CRYPTO_SIGN_ALGO_UNKNOWN =  0,
  R_CRYPTO_SIGN_ALGO_RSA_MD5,
  R_CRYPTO_SIGN_ALGO_RSA_SHA1,
  R_CRYPTO_SIGN_ALGO_RSA_SHA256,
  R_CRYPTO_SIGN_ALGO_RSA_SHA384,
  R_CRYPTO_SIGN_ALGO_RSA_SHA512,
  R_CRYPTO_SIGN_ALGO_RSA_SHA224,
  R_CRYPTO_SIGN_ALGO_DSA_SHA1,
} RCryptoSignAlgo;

typedef struct _RCryptoCert RCryptoCert;

R_API RCryptoCertType r_crypto_cert_get_type (const RCryptoCert * cert);
R_API const rchar * r_crypto_cert_get_strtype (const RCryptoCert * cert);
R_API const ruint8 * r_crypto_cert_get_signature (const RCryptoCert * cert,
    RCryptoSignAlgo * signalgo, rsize * signbits);
R_API ruint64 r_crypto_cert_get_valid_from (const RCryptoCert * cert);
R_API ruint64 r_crypto_cert_get_valid_to (const RCryptoCert * cert);
R_API RCryptoKey * r_crypto_cert_get_public_key (const RCryptoCert * cert);

#define r_crypto_cert_ref r_ref_ref
#define r_crypto_cert_unref r_ref_unref

R_END_DECLS

#endif /* __R_CRYPTO_CERT_H__ */

