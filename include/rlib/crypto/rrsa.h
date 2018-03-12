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
#ifndef __R_CRYPTO_RSA_H__
#define __R_CRYPTO_RSA_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>

#include <rlib/data/rmpint.h>

#include <rlib/rrand.h>

R_BEGIN_DECLS

#define R_RSA_STR     "RSA"

typedef enum {
  R_RSA_PADDING_UNKNOWN       = -1,
  R_RSA_PADDING_PKCS1_V15     = 0, /* RSAES-PKCS1-v1_5 and RSASSA-PKCS1-v1_5 */
  R_RSA_PADDING_PKCS1_V21     = 1, /* RSAES-OAEP and RSASSA-PSS */
} RRsaPadding;

R_API RCryptoKey * r_rsa_pub_key_new (const rmpint * n, const rmpint * e) R_ATTR_MALLOC;
R_API RCryptoKey * r_rsa_pub_key_new_binary (rconstpointer n, rsize nsize,
    rconstpointer e, rsize esize) R_ATTR_MALLOC;

R_API RCryptoKey * r_rsa_priv_key_new (const rmpint * n, const rmpint * e,
    const rmpint * d) R_ATTR_MALLOC;
R_API RCryptoKey * r_rsa_priv_key_new_full (rint32 ver,
    const rmpint * n, const rmpint * e, /* public part */
    const rmpint * d, const rmpint * p, const rmpint * q,
    const rmpint * dp, const rmpint * dq, const rmpint * qp) R_ATTR_MALLOC;
R_API RCryptoKey * r_rsa_priv_key_new_binary (rconstpointer n, rsize nsize,
    rconstpointer e, rsize esize, rconstpointer d, rsize dsize) R_ATTR_MALLOC;
R_API RCryptoKey * r_rsa_priv_key_new_from_asn1 (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv) R_ATTR_MALLOC;

R_API RCryptoKey * r_rsa_priv_key_new_gen (rsize bits, ruint64 e,
    RPrng * prng) R_ATTR_MALLOC;


#define r_rsa_priv_key_get_padding r_rsa_pub_key_get_padding
#define r_rsa_priv_key_set_padding r_rsa_pub_key_set_padding
R_API rboolean r_rsa_pub_key_set_padding (RCryptoKey * key, RRsaPadding padding);
R_API RRsaPadding r_rsa_pub_key_get_padding (const RCryptoKey * key);

#define r_rsa_priv_key_get_e r_rsa_pub_key_get_e
R_API rboolean r_rsa_pub_key_get_e (const RCryptoKey * key, rmpint * e);
R_API rboolean r_rsa_pub_key_get_n (const RCryptoKey * key, rmpint * n);
R_API rboolean r_rsa_priv_key_get_d (const RCryptoKey * key, rmpint * d);
R_API rboolean r_rsa_priv_key_get_p (const RCryptoKey * key, rmpint * p);
R_API rboolean r_rsa_priv_key_get_q (const RCryptoKey * key, rmpint * q);
R_API rboolean r_rsa_priv_key_get_dp (const RCryptoKey * key, rmpint * dp);
R_API rboolean r_rsa_priv_key_get_dq (const RCryptoKey * key, rmpint * dq);
R_API rboolean r_rsa_priv_key_get_qp (const RCryptoKey * key, rmpint * qp);


R_API RCryptoResult r_rsa_raw_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
R_API RCryptoResult r_rsa_raw_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

R_API RCryptoResult r_rsa_oaep_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
R_API RCryptoResult r_rsa_oaep_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

R_API RCryptoResult r_rsa_pkcs1v1_5_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
R_API RCryptoResult r_rsa_pkcs1v1_5_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
R_API RCryptoResult r_rsa_pkcs1v1_5_sign_msg (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    rpointer sig, rsize * sigsize);
R_API RCryptoResult r_rsa_pkcs1v1_5_sign_msg_hash (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize);
R_API RCryptoResult r_rsa_pkcs1v1_5_sign_hash (const RCryptoKey * key, RPrng * prng,
    rconstpointer hash, rsize hashsize, rpointer sig, rsize * sigsize);
R_API RCryptoResult r_rsa_pkcs1v1_5_verify_msg (const RCryptoKey * key,
    rconstpointer msg, rsize msgsize, rconstpointer sig, rsize sigsize);
R_API RCryptoResult r_rsa_pkcs1v1_5_verify_msg_with_hash (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize);
R_API RCryptoResult r_rsa_pkcs1v1_5_verify_hash (const RCryptoKey * key,
    rconstpointer hash, rsize hashsize, rconstpointer sig, rsize sigsize);

R_END_DECLS

#endif /* __R_CRYPTO_RSA_H__ */



