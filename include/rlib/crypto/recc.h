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
#ifndef __R_CRYPTO_ECC_H__
#define __R_CRYPTO_ECC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/crypto/rkey.h>

R_BEGIN_DECLS

#define R_ECDSA_STR     "ECDSA"
#define R_ECDH_STR      "ECDH"

typedef enum {
  R_EC_NAMED_CURVE_NONE                             = 0,
  R_EC_NAMED_CURVE_SECT163K1                        = 0x0001, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT163R1                        = 0x0002, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT163R2                        = 0x0003, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT193R1                        = 0x0004, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT193R2                        = 0x0005, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT233K1                        = 0x0006, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT233R1                        = 0x0007, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT239K1                        = 0x0008, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT283K1                        = 0x0009, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT283R1                        = 0x000a, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT409K1                        = 0x000b, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT409R1                        = 0x000c, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT571K1                        = 0x000d, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECT571R1                        = 0x000e, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP160K1                        = 0x000f, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP160R1                        = 0x0010, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP160R2                        = 0x0011, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP192K1                        = 0x0012, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP192R1                        = 0x0013, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP224K1                        = 0x0014, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP224R1                        = 0x0015, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP256K1                        = 0x0016, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP256R1                        = 0x0017, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP384R1                        = 0x0018, /* [RFC4492] */
  R_EC_NAMED_CURVE_SECP521R1                        = 0x0019, /* [RFC4492] */
  R_EC_NAMED_CURVE_BRAINPOOLP256R1                  = 0x001a, /* [RFC7027] */
  R_EC_NAMED_CURVE_BRAINPOOLP348R1                  = 0x001b, /* [RFC7027] */
  R_EC_NAMED_CURVE_BRAINPOOLP512R1                  = 0x001c, /* [RFC7027] */
  R_EC_NAMED_CURVE_X25519                           = 0x001d, /* [TLS1.3] */
  R_EC_NAMED_CURVE_X448                             = 0x001e, /* [TLS1.3] */
  R_EC_NAMED_CURVE_FFDHE2048                        = 0x0100, /* [RFC7919] */
  R_EC_NAMED_CURVE_FFDHE3072                        = 0x0101, /* [RFC7919] */
  R_EC_NAMED_CURVE_FFDHE4096                        = 0x0102, /* [RFC7919] */
  R_EC_NAMED_CURVE_FFDHE6144                        = 0x0103, /* [RFC7919] */
  R_EC_NAMED_CURVE_FFDHE8192                        = 0x0104, /* [RFC7919] */
  R_EC_NAMED_CURVE_ARBITRARY_EXPLICIT_PRIME_CURVES  = 0xff01, /* [RFC4492] */
  R_EC_NAMED_CURVE_ARBITRARY_EXPLICIT_CHAR2_CURVES  = 0xff02, /* [RFC4492] */
} REcNamedCurve;

R_API rboolean r_ecc_parse_named_curve (REcNamedCurve * curve,
    rconstpointer oid, rsize oidsize);

R_API RCryptoKey * r_ecdsa_pub_key_new (REcNamedCurve curve,
    rconstpointer ecp, rsize ecpsize) R_ATTR_MALLOC;
R_API RCryptoKey * r_ecdh_pub_key_new (REcNamedCurve curve,
    rconstpointer ecp, rsize ecpsize) R_ATTR_MALLOC;
R_API REcNamedCurve r_ecc_key_get_curve (const RCryptoKey * key);

R_END_DECLS

#endif /* __R_CRYPTO_ECC_H__ */

