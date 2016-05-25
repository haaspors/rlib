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
#ifndef __R_CRYPTO_RSA_H__
#define __R_CRYPTO_RSA_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>
#include <rlib/rmpint.h>

R_BEGIN_DECLS

#define R_RSA_STR     "RSA"

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
R_API RCryptoKey * r_rsa_priv_key_new_from_asn1 (RAsn1BinDecoder * dec) R_ATTR_MALLOC;


#define r_rsa_pub_key_get_exponent  r_rsa_key_get_exponent
#define r_rsa_priv_key_get_exponent r_rsa_key_get_exponent
R_API rboolean r_rsa_key_get_exponent (RCryptoKey * key, rmpint * e);

R_API rboolean r_rsa_pub_key_get_modulus (RCryptoKey * key, rmpint * n);
R_API rboolean r_rsa_priv_key_get_modulus (RCryptoKey * key, rmpint * d);

R_API rboolean r_rsa_oaep_encrypt (RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
R_API rboolean r_rsa_oaep_decrypt (RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
R_API rboolean r_rsa_pkcs1v1_5_encrypt (RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);
R_API rboolean r_rsa_pkcs1v1_5_decrypt (RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize);

R_END_DECLS

#endif /* __R_CRYPTO_RSA_H__ */



