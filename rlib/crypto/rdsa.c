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
#include <rlib/crypto/rdsa.h>
#include <rlib/rmem.h>

typedef struct {
  RCryptoKey key;

  rmpint p;
  rmpint q;
  rmpint g;
  rmpint y;
} RDsaPubKey;

typedef struct {
  RDsaPubKey pub;

  rint32 ver;
  rmpint x;
} RDsaPrivKey;

static void
r_dsa_pub_key_free (rpointer data)
{
  RDsaPubKey * key;

  if ((key = data) != NULL) {
    r_mpint_clear (&key->p);
    r_mpint_clear (&key->q);
    r_mpint_clear (&key->g);
    r_mpint_clear (&key->y);
    r_free (key);
  }
}

static void
r_dsa_pub_key_init (RCryptoKey * key)
{
  r_ref_init (key, r_dsa_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = R_CRYPTO_ALGO_DSA;
  key->strtype = R_DSA_STR;
}

static void
r_dsa_priv_key_free (rpointer data)
{
  RDsaPrivKey * key;

  if ((key = data) != NULL) {
    r_mpint_clear (&key->x);
    r_dsa_pub_key_free (key);
  }
}

static void
r_dsa_priv_key_init (RCryptoKey * key)
{
  r_ref_init (key, r_dsa_priv_key_free);
  key->type = R_CRYPTO_PRIVATE_KEY;
  key->algo = R_CRYPTO_ALGO_DSA;
  key->strtype = R_DSA_STR;
}

RCryptoKey *
r_dsa_pub_key_new_full (const rmpint * p, const rmpint * q,
    const rmpint * g, const rmpint * y)
{
  RDsaPubKey * ret;

  if (y != NULL) {
    if ((ret = r_mem_new (RDsaPubKey)) != NULL) {
      r_dsa_pub_key_init (&ret->key);
      if (p != NULL)  r_mpint_init_copy (&ret->p, p);
      else            r_mpint_init (&ret->p);
      if (q != NULL)  r_mpint_init_copy (&ret->q, q);
      else            r_mpint_init (&ret->q);
      if (q != NULL)  r_mpint_init_copy (&ret->g, g);
      else            r_mpint_init (&ret->g);
      r_mpint_init_copy (&ret->y, y);
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dsa_pub_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer q, rsize qsize, rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize)
{
  RDsaPubKey * ret;

  if (p != NULL && psize > 0 && q != NULL && qsize > 0 &&
      g != NULL && gsize > 0 && y != NULL && ysize > 0) {
    if ((ret = r_mem_new (RDsaPubKey)) != NULL) {
      r_dsa_pub_key_init (&ret->key);
      r_mpint_init_binary (&ret->p, p, psize);
      r_mpint_init_binary (&ret->q, q, qsize);
      r_mpint_init_binary (&ret->g, g, gsize);
      r_mpint_init_binary (&ret->y, y, ysize);
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dsa_priv_key_new (const rmpint * p, const rmpint * q,
    const rmpint * g, const rmpint * y, const rmpint * x)
{
  RDsaPrivKey * ret;

  if (p != NULL && q != NULL && g != NULL && y != NULL && x != NULL) {
    if ((ret = r_mem_new (RDsaPrivKey)) != NULL) {
      r_dsa_priv_key_init (&ret->pub.key);
      r_mpint_init_copy (&ret->pub.p, p);
      r_mpint_init_copy (&ret->pub.q, q);
      r_mpint_init_copy (&ret->pub.g, g);
      r_mpint_init_copy (&ret->pub.y, y);
      r_mpint_init_copy (&ret->x, x);
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dsa_priv_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer q, rsize qsize, rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize, rconstpointer x, rsize xsize)
{
  RDsaPrivKey * ret;

  if (p != NULL && psize > 0 && q != NULL && qsize > 0 && g != NULL && gsize > 0 &&
      y != NULL && ysize > 0 && x != NULL && xsize > 0) {
    if ((ret = r_mem_new (RDsaPrivKey)) != NULL) {
      r_dsa_priv_key_init (&ret->pub.key);
      r_mpint_init_binary (&ret->pub.p, p, psize);
      r_mpint_init_binary (&ret->pub.q, q, qsize);
      r_mpint_init_binary (&ret->pub.g, g, gsize);
      r_mpint_init_binary (&ret->pub.y, y, ysize);
      r_mpint_init_binary (&ret->x, x, xsize);
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dsa_priv_key_new_from_asn1 (RAsn1BinDecoder * dec)
{
  RDsaPrivKey * ret;

  if ((ret = r_mem_new (RDsaPrivKey)) != NULL) {
    RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
    r_dsa_priv_key_init (&ret->pub.key);

    r_mpint_init (&ret->pub.p);
    r_mpint_init (&ret->pub.q);
    r_mpint_init (&ret->pub.g);
    r_mpint_init (&ret->pub.y);
    r_mpint_init (&ret->x);

    if (r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_into (dec, &tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer (&tlv, &ret->ver) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_mpint (&tlv, &ret->pub.p) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_mpint (&tlv, &ret->pub.q) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_mpint (&tlv, &ret->pub.g) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_mpint (&tlv, &ret->pub.y) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, &tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_mpint (&tlv, &ret->x) != R_ASN1_DECODER_OK) {
      r_crypto_key_unref ((RCryptoKey *)ret);
      ret = NULL;
    }
  }

  return (RCryptoKey *)ret;
}

rboolean
r_dsa_pub_key_get_p (RCryptoKey * key, rmpint * p)
{
  if (R_UNLIKELY (key == NULL || p == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (p, &((RDsaPubKey*)key)->p);
  return TRUE;
}

rboolean
r_dsa_pub_key_get_q (RCryptoKey * key, rmpint * q)
{
  if (R_UNLIKELY (key == NULL || q == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (q, &((RDsaPubKey*)key)->q);
  return TRUE;
}

rboolean
r_dsa_pub_key_get_g (RCryptoKey * key, rmpint * g)
{
  if (R_UNLIKELY (key == NULL || g == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (g, &((RDsaPubKey*)key)->g);
  return TRUE;
}

rboolean
r_dsa_pub_key_get_y (RCryptoKey * key, rmpint * y)
{
  if (R_UNLIKELY (key == NULL || y == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (y, &((RDsaPubKey*)key)->y);
  return TRUE;
}

rboolean
r_dsa_priv_key_get_x (RCryptoKey * key, rmpint * x)
{
  if (R_UNLIKELY (key == NULL || x == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo != R_CRYPTO_ALGO_DSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (x, &((RDsaPrivKey*)key)->x);
  return TRUE;
}

