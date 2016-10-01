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
#ifndef __R_CRYPTO_KEY_H__
#define __R_CRYPTO_KEY_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>
#include <rlib/asn1/rasn1.h>

R_BEGIN_DECLS

typedef enum {
  R_CRYPTO_PUBLIC_KEY,
  R_CRYPTO_PRIVATE_KEY,
} RCryptoKeyType;

typedef enum {
  R_CRYPTO_ALGO_DH,
  R_CRYPTO_ALGO_DSA,
  R_CRYPTO_ALGO_ECDH,
  R_CRYPTO_ALGO_ECDSA,
  R_CRYPTO_ALGO_RSA,
  R_CRYPTO_ALGO_TYPE_COUNT,
  /* aliases */
  R_CRYPTO_ALGO_DSS = R_CRYPTO_ALGO_DSA,
} RCryptoAlgorithm;

typedef struct _RCryptoKey RCryptoKey;

typedef rboolean (*RCryptoOperation) (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
typedef RCryptoOperation RCryptoEncrypt;
typedef RCryptoOperation RCryptoDecrypt;

struct _RCryptoKey {
  RRef ref;
  RCryptoKeyType type;
  RCryptoAlgorithm algo;
  const rchar * strtype;
};

#define r_crypto_key_ref r_ref_ref
#define r_crypto_key_unref r_ref_unref

R_API RCryptoKey * r_crypto_key_import_ssh_public_key_file (const rchar * file);
R_API RCryptoKey * r_crypto_key_import_ssh_public_key (const rchar * data, rsize size);
R_API RCryptoKey * r_crypto_key_from_asn1_public_key (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv);

R_END_DECLS

#endif /* __R_CRYPTO_KEY_H__ */

