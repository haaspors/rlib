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

#include "config.h"
#include "rcrypto-private.h"

#include <rlib/crypto/recc.h>

#include <rlib/asn1/roid.h>
#include <rlib/rmem.h>

typedef struct {
  RCryptoKey key;
  REcNamedCurve namedcurve;

  rsize ecpsize;
  ruint8 * ecp;
} REccPubKey;

typedef struct {
  REccPubKey pub;

  rsize scalarsize;
  ruint8 * scalar;
} REccPrivKey;

static void
r_ecc_pub_key_free (rpointer data)
{
  REccPubKey * key;

  if ((key = data) != NULL) {
    r_free (key->ecp);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

static void
r_ecdsa_pub_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo ecdsa_pub_key_info = {
    R_CRYPTO_ALGO_ECDSA, R_ECDSA_STR,
    NULL, NULL, NULL, NULL, NULL
  };

  r_ref_init (key, r_ecc_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = &ecdsa_pub_key_info;
  key->bits = bits;
}

RCryptoKey *
r_ecdsa_pub_key_new (REcNamedCurve curve, rconstpointer ecp, rsize ecpsize)
{
  REccPubKey * ret;

  if (ecp != NULL) {
    if ((ret = r_mem_new (REccPubKey)) != NULL) {
      ret->namedcurve = curve;
      ret->ecpsize = ecpsize;
      ret->ecp = r_memdup (ecp, ecpsize);
      r_ecdsa_pub_key_init (&ret->key, (ruint)(ecpsize * 8));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

static void
r_ecdh_pub_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo ecdh_pub_key_info = {
    R_CRYPTO_ALGO_ECDH, R_ECDH_STR,
    NULL, NULL, NULL, NULL, NULL
  };

  r_ref_init (key, r_ecc_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = &ecdh_pub_key_info;
  key->bits = bits;
}

RCryptoKey *
r_ecdh_pub_key_new (REcNamedCurve curve, rconstpointer ecp, rsize ecpsize)
{
  REccPubKey * ret;

  if (ecp != NULL) {
    if ((ret = r_mem_new (REccPubKey)) != NULL) {
      ret->namedcurve = curve;
      ret->ecpsize = ecpsize;
      ret->ecp = r_memdup (ecp, ecpsize);
      r_ecdh_pub_key_init (&ret->key, (ruint)(ecpsize * 8));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

REcNamedCurve
r_ecc_key_get_curve (const RCryptoKey * key)
{
  if (R_UNLIKELY (key == NULL)) return R_EC_NAMED_CURVE_NONE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ECDSA &&
        key->algo->algo != R_CRYPTO_ALGO_ECDH))
    return R_EC_NAMED_CURVE_NONE;

  return ((const REccPubKey *)key)->namedcurve;
}

static void
r_ecc_priv_key_free (rpointer data)
{
  REccPrivKey * key;

  if ((key = data) != NULL) {
    if (key->scalar != NULL) {
      r_memclear (key->scalar, key->scalarsize);
      r_free (key->scalar);
    }
    r_free (key->pub.ecp);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

static RCryptoKey *
r_ecc_priv_key_new_full (REcNamedCurve curve, RCryptoAlgorithm algo,
    const rchar * algo_str, rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize)
{
  REccPrivKey * ret;
  static const RCryptoAlgoInfo ecdsa_priv_key_info = {
    R_CRYPTO_ALGO_ECDSA, R_ECDSA_STR, NULL, NULL, NULL, NULL, NULL
  };
  static const RCryptoAlgoInfo ecdh_priv_key_info = {
    R_CRYPTO_ALGO_ECDH, R_ECDH_STR, NULL, NULL, NULL, NULL, NULL
  };

  if (scalar == NULL || scalarsize == 0) return NULL;

  if ((ret = r_mem_new (REccPrivKey)) != NULL) {
    ret->pub.namedcurve = curve;
    ret->pub.ecpsize = ecpsize;
    ret->pub.ecp = (ecp != NULL && ecpsize > 0) ? r_memdup (ecp, ecpsize) : NULL;
    ret->scalarsize = scalarsize;
    ret->scalar = r_memdup (scalar, scalarsize);

    r_ref_init (&ret->pub.key, r_ecc_priv_key_free);
    ret->pub.key.type = R_CRYPTO_PRIVATE_KEY;
    ret->pub.key.algo = (algo == R_CRYPTO_ALGO_ECDSA)
        ? &ecdsa_priv_key_info : &ecdh_priv_key_info;
    ret->pub.key.bits = (ruint) (scalarsize * 8);
    (void) algo_str;
  }

  return (RCryptoKey *) ret;
}

RCryptoKey *
r_ecdsa_priv_key_new (REcNamedCurve curve, rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize)
{
  return r_ecc_priv_key_new_full (curve, R_CRYPTO_ALGO_ECDSA, R_ECDSA_STR,
      ecp, ecpsize, scalar, scalarsize);
}

RCryptoKey *
r_ecdh_priv_key_new (REcNamedCurve curve, rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize)
{
  return r_ecc_priv_key_new_full (curve, R_CRYPTO_ALGO_ECDH, R_ECDH_STR,
      ecp, ecpsize, scalar, scalarsize);
}

rboolean
r_ecc_priv_key_get_scalar (const RCryptoKey * key,
    const ruint8 ** scalar, rsize * scalarsize)
{
  const REccPrivKey * priv;

  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ECDSA &&
        key->algo->algo != R_CRYPTO_ALGO_ECDH))
    return FALSE;

  priv = (const REccPrivKey *) key;
  if (scalar != NULL) *scalar = priv->scalar;
  if (scalarsize != NULL) *scalarsize = priv->scalarsize;
  return TRUE;
}

rboolean
r_ecc_parse_named_curve (REcNamedCurve * curve,
    rconstpointer oid, rsize oidsize)
{
  if (R_UNLIKELY (curve == NULL)) return FALSE;
  if (R_UNLIKELY (oid == NULL)) return FALSE;
  if (R_UNLIKELY (oidsize == 0)) return FALSE;

  if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP192R1))
    *curve = R_EC_NAMED_CURVE_SECP192R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP256R1))
    *curve = R_EC_NAMED_CURVE_SECP256R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP224R1))
    *curve = R_EC_NAMED_CURVE_SECP224R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP384R1))
    *curve = R_EC_NAMED_CURVE_SECP384R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP521R1))
    *curve = R_EC_NAMED_CURVE_SECP521R1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP192K1))
    *curve = R_EC_NAMED_CURVE_SECP192K1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP224K1))
    *curve = R_EC_NAMED_CURVE_SECP224K1;
  else if (r_asn1_oid_bin_equals (oid, oidsize, R_EC_GRP_OID_SECP256K1))
    *curve = R_EC_NAMED_CURVE_SECP256K1;
  else
    return FALSE;

  return TRUE;
}

