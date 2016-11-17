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
#ifndef __R_CRYPTO_PRIVATE_H__
#define __R_CRYPTO_PRIVATE_H__

#if !defined(RLIB_COMPILATION)
#error "rcert-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>

#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rcert.h>

R_BEGIN_DECLS

typedef RCryptoResult (*RCryptoOperation) (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, rpointer, rsize * outsize);
typedef RCryptoResult (*RCryptoSign) (const RCryptoKey * key, RPrng * prng,
    RHashType hashtype, rconstpointer hash, rsize hashsize,
    rpointer, rsize * sigsize);
typedef RCryptoResult (*RCryptoVerify) (const RCryptoKey * key,
    RHashType hashtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize);
typedef RCryptoResult (*RCryptoKeyExportAsn1) (const RCryptoKey * key, RAsn1BinEncoder * enc);
typedef RCryptoResult (*RCryptoCertExportAsn1) (const RCryptoCert * cert, RAsn1BinEncoder * enc);

typedef struct {
  RCryptoAlgorithm algo;
  const rchar * strtype;

  RCryptoOperation encrypt;
  RCryptoOperation decrypt;
  RCryptoSign sign;
  RCryptoVerify verify;
  RCryptoKeyExportAsn1 export;
} RCryptoAlgoInfo;

struct _RCryptoKey {
  RRef ref;
  RCryptoKeyType type;
  ruint bits;

  const RCryptoAlgoInfo * algo;
};

struct _RCryptoCert {
  RRef ref;
  RCryptoCertType type;
  const rchar * strtype;

  RBuffer * certdata;

  ruint64 valid_from;     /* unix timestamp */
  ruint64 valid_to;       /* unix timestamp */
  RCryptoKey * pk;

  RHashType signalgo;
  ruint8 signhash[64];
  ruint8 * sign;
  rsize signbits;

  RCryptoCertExportAsn1 export;
};

R_API_HIDDEN void r_crypto_key_destroy (RCryptoKey * key);
R_API_HIDDEN void r_crypto_cert_destroy (RCryptoCert * cert);

R_END_DECLS

#endif /* __R_CRYPTO_PRIVATE_H__ */

