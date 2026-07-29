/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/crypto/rcipher.h>

R_BEGIN_DECLS

typedef RCryptoResult (*RCryptoOperation) (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, rpointer, rsize * outsize);
typedef RCryptoResult (*RCryptoSign) (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer, rsize * sigsize);
typedef RCryptoResult (*RCryptoVerify) (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
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

struct RCryptoKey {
  RRef ref;
  RCryptoKeyType type;
  ruint bits;

  const RCryptoAlgoInfo * algo;
};

struct RCryptoCert {
  RRef ref;
  RCryptoCertType type;
  const rchar * strtype;

  RBuffer * certdata;

  ruint64 valid_from;     /* unix timestamp */
  ruint64 valid_to;       /* unix timestamp */
  RCryptoKey * pk;

  RMsgDigestType signalgo;
  ruint8 signhash[64];
  ruint8 * tbs;           /* raw TBSCertificate; kept only for PureEdDSA (no pre-hash) */
  rsize tbssize;
  ruint8 * sign;
  rsize signbits;

  RCryptoCertExportAsn1 export;
};

R_API_HIDDEN void r_crypto_key_destroy (RCryptoKey * key);
R_API_HIDDEN void r_crypto_cert_destroy (RCryptoCert * cert);

/* Poly1305 incremental state (RFC 8439 §2.5), radix-2^26 accumulator.
 * The one-shot r_poly1305_mac is public; these hidden entry points let
 * the ChaCha20-Poly1305 AEAD feed the padded AAD / ciphertext / length
 * blocks without staging them in one contiguous buffer. */
typedef struct {
  ruint32 r[5];
  ruint32 h[5];
  ruint32 pad[4];
  rsize leftover;
  ruint8 buffer[16];
  ruint8 final;
} RPoly1305Ctx;

R_API_HIDDEN void r_poly1305_init (RPoly1305Ctx * ctx, const ruint8 key[32]);
R_API_HIDDEN void r_poly1305_update (RPoly1305Ctx * ctx, const ruint8 * m, rsize bytes);
R_API_HIDDEN void r_poly1305_finish (RPoly1305Ctx * ctx, ruint8 mac[16]);

R_API_HIDDEN RCryptoCipher * r_cipher_aes_new_with_info (const RCryptoCipherInfo * info, const ruint8 * key);
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_null_cipher;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ecb;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ecb;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ecb;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_128_cbc;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_192_cbc;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_256_cbc;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ctr;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ctr;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ctr;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_128_gcm;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_192_gcm;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_256_gcm;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ccm;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ccm;
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ccm;

R_API_HIDDEN RCryptoCipher * r_cipher_chacha20_poly1305_new_with_info (const RCryptoCipherInfo * info, const ruint8 * key);
R_API_HIDDEN extern const RCryptoCipherInfo g__r_crypto_cipher_chacha20_poly1305;

R_END_DECLS

#endif /* __R_CRYPTO_PRIVATE_H__ */

