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
#include <rlib/crypto/rrsa.h>
#include <rlib/crypto/rcrypto-private.h>

#include <rlib/rmem.h>

typedef struct {
  RCryptoKey key;
  RRsaPadding padding;

  rmpint n;
  rmpint e;
} RRsaPubKey;

typedef struct {
  RRsaPubKey pub;

  rint32 ver;

  rmpint d;
  rmpint p;
  rmpint q;

  rmpint dp;
  rmpint dq;
  rmpint qp;
} RRsaPrivKey;

static RCryptoResult
r_rsa_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  switch (((const RRsaPubKey *)key)->padding) {
    case R_RSA_PADDING_PKCS1_V15:
      return r_rsa_pkcs1v1_5_encrypt (key, prng, data, size, out, outsize);
    case R_RSA_PADDING_PKCS1_V21:
      /*return r_rsa_oaep_encrypt (key, prng, data, size, out, outsize);*/
    default:
      return R_CRYPTO_NOT_AVAILABLE;
  }
}

static RCryptoResult
r_rsa_decrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  (void) prng;

  switch (((const RRsaPubKey *)key)->padding) {
    case R_RSA_PADDING_PKCS1_V15:
      return r_rsa_pkcs1v1_5_decrypt (key, data, size, out, outsize);
    case R_RSA_PADDING_PKCS1_V21:
      /*return r_rsa_oaep_decrypt (key, data, size, out, outsize);*/
    default:
      return R_CRYPTO_NOT_AVAILABLE;
  }
}


static void
r_rsa_pub_key_free (rpointer data)
{
  RRsaPubKey * key;

  if ((key = data) != NULL) {
    r_mpint_clear (&key->n);
    r_mpint_clear (&key->e);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

static void
r_rsa_pub_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo rsa_pub_key_info = {
    R_CRYPTO_ALGO_RSA, R_RSA_STR,
    r_rsa_encrypt, r_rsa_decrypt, NULL, NULL
  };

  r_ref_init (key, r_rsa_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = &rsa_pub_key_info;
  key->bits = bits;
}

static void
r_rsa_priv_key_free (rpointer data)
{
  RRsaPrivKey * key;

  if ((key = data) != NULL) {
    r_mpint_clear (&key->d);
    r_mpint_clear (&key->p);
    r_mpint_clear (&key->q);
    r_mpint_clear (&key->dp);
    r_mpint_clear (&key->dq);
    r_mpint_clear (&key->qp);

    r_rsa_pub_key_free (data);
  }
}

static void
r_rsa_priv_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo rsa_priv_key_info = {
    R_CRYPTO_ALGO_RSA, R_RSA_STR,
    r_rsa_encrypt, r_rsa_decrypt, NULL, NULL
  };

  r_ref_init (key, r_rsa_priv_key_free);
  key->type = R_CRYPTO_PRIVATE_KEY;
  key->algo = &rsa_priv_key_info;
  key->bits = bits;
}

RCryptoKey *
r_rsa_pub_key_new (const rmpint * n, const rmpint * e)
{
  RRsaPubKey * ret;

  if (n != NULL && e != NULL) {
    if ((ret = r_mem_new (RRsaPubKey)) != NULL) {
      r_mpint_init_copy (&ret->n, n);
      r_mpint_init_copy (&ret->e, e);
      ret->padding = R_RSA_PADDING_PKCS1_V15;
      r_rsa_pub_key_init (&ret->key, r_mpint_bits_used (&ret->n));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_rsa_pub_key_new_binary (rconstpointer n, rsize nsize,
    rconstpointer e, rsize esize)
{
  RRsaPubKey * ret;

  if (n != NULL && nsize > 0 && e != NULL && esize > 0) {
    if ((ret = r_mem_new (RRsaPubKey)) != NULL) {
      r_mpint_init_binary (&ret->n, n, nsize);
      r_mpint_init_binary (&ret->e, e, esize);
      ret->padding = R_RSA_PADDING_PKCS1_V15;
      r_rsa_pub_key_init (&ret->key, r_mpint_bits_used (&ret->n));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_rsa_priv_key_new (const rmpint * n, const rmpint * e, const rmpint * d)
{
  RRsaPrivKey * ret;

  if (n != NULL && e != NULL && d != NULL) {
    if ((ret = r_mem_new0 (RRsaPrivKey)) != NULL) {
      r_mpint_init_copy (&ret->pub.n, n);
      r_mpint_init_copy (&ret->pub.e, e);
      r_mpint_init_copy (&ret->d, d);
      r_mpint_init (&ret->p);
      r_mpint_init (&ret->q);
      r_mpint_init (&ret->dp);
      r_mpint_init (&ret->dq);
      r_mpint_init (&ret->qp);
      ret->pub.padding = R_RSA_PADDING_PKCS1_V15;
      r_rsa_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.n));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_rsa_priv_key_new_full (rint32 ver, const rmpint * n, const rmpint * e,
    const rmpint * d, const rmpint * p, const rmpint * q,
    const rmpint * dp, const rmpint * dq, const rmpint * qp)
{
  RRsaPrivKey * ret;

  if (n != NULL && e != NULL && d != NULL) {
    if ((ret = r_mem_new (RRsaPrivKey)) != NULL) {
      ret->ver = ver;
      r_mpint_init_copy (&ret->pub.n, n);
      r_mpint_init_copy (&ret->pub.e, e);
      r_mpint_init_copy (&ret->d, d);
      if (p != NULL)  r_mpint_init_copy (&ret->p, p);
      else            r_mpint_init (&ret->p);
      if (q != NULL)  r_mpint_init_copy (&ret->q, q);
      else            r_mpint_init (&ret->q);
      if (dp != NULL) r_mpint_init_copy (&ret->dp, dp);
      else            r_mpint_init (&ret->dp);
      if (dq != NULL) r_mpint_init_copy (&ret->dq, dq);
      else            r_mpint_init (&ret->dq);
      if (qp != NULL) r_mpint_init_copy (&ret->qp, qp);
      else            r_mpint_init (&ret->qp);
      ret->pub.padding = R_RSA_PADDING_PKCS1_V15;
      r_rsa_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.n));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_rsa_priv_key_new_binary (rconstpointer n, rsize nsize,
    rconstpointer e, rsize esize, rconstpointer d, rsize dsize)
{
  RRsaPrivKey * ret;

  if (n != NULL && e != NULL && d != NULL) {
    if ((ret = r_mem_new0 (RRsaPrivKey)) != NULL) {
      r_mpint_init_binary (&ret->pub.n, n, nsize);
      r_mpint_init_binary (&ret->pub.e, e, esize);
      r_mpint_init_binary (&ret->d, d, dsize);
      r_mpint_init (&ret->p);
      r_mpint_init (&ret->q);
      r_mpint_init (&ret->dp);
      r_mpint_init (&ret->dq);
      r_mpint_init (&ret->qp);
      ret->pub.padding = R_RSA_PADDING_PKCS1_V15;
      r_rsa_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.n));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_rsa_priv_key_new_from_asn1 (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  RRsaPrivKey * ret;

  if ((ret = r_mem_new (RRsaPrivKey)) != NULL) {

    r_mpint_init (&ret->pub.n);
    r_mpint_init (&ret->pub.e);
    r_mpint_init (&ret->d);
    r_mpint_init (&ret->p);
    r_mpint_init (&ret->q);
    r_mpint_init (&ret->dp);
    r_mpint_init (&ret->dq);
    r_mpint_init (&ret->qp);

    if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_i32 (tlv, &ret->ver) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.n) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.e) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->d) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->p) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->q) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->dp) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->dq) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->qp) != R_ASN1_DECODER_OK) {
      r_crypto_key_unref ((RCryptoKey *)ret);
      ret = NULL;
    } else {
      ret->pub.padding = R_RSA_PADDING_PKCS1_V15;
      r_rsa_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.n));
    }
  }

  return (RCryptoKey *)ret;
}

rboolean
r_rsa_pub_key_set_padding (RCryptoKey * key, RRsaPadding padding)
{
  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;

  ((RRsaPubKey*)key)->padding = padding;
  return TRUE;
}

RRsaPadding
r_rsa_pub_key_get_padding (const RCryptoKey * key)
{
  if (R_UNLIKELY (key == NULL)) return R_RSA_PADDING_UNKNOWN;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_RSA_PADDING_UNKNOWN;

  return ((const RRsaPubKey*)key)->padding;
}

rboolean
r_rsa_pub_key_get_e (const RCryptoKey * key, rmpint * e)
{
  if (R_UNLIKELY (key == NULL || e == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;

  r_mpint_set (e, &((const RRsaPubKey*)key)->e);
  return TRUE;
}

rboolean
r_rsa_pub_key_get_n (const RCryptoKey * key, rmpint * n)
{
  if (R_UNLIKELY (key == NULL || n == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;

  r_mpint_set (n, &((const RRsaPubKey*)key)->n);
  return TRUE;
}

rboolean
r_rsa_priv_key_get_d (const RCryptoKey * key, rmpint * d)
{
  if (R_UNLIKELY (key == NULL || d == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (d, &((const RRsaPrivKey*)key)->d);
  return TRUE;
}

rboolean
r_rsa_priv_key_get_p (const RCryptoKey * key, rmpint * p)
{
  if (R_UNLIKELY (key == NULL || p == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (p, &((const RRsaPrivKey*)key)->p);
  return TRUE;
}

rboolean
r_rsa_priv_key_get_q (const RCryptoKey * key, rmpint * q)
{
  if (R_UNLIKELY (key == NULL || q == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (q, &((const RRsaPrivKey*)key)->q);
  return TRUE;
}

rboolean
r_rsa_priv_key_get_dp (const RCryptoKey * key, rmpint * dp)
{
  if (R_UNLIKELY (key == NULL || dp == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (dp, &((const RRsaPrivKey*)key)->dp);
  return TRUE;
}

rboolean
r_rsa_priv_key_get_dq (const RCryptoKey * key, rmpint * dq)
{
  if (R_UNLIKELY (key == NULL || dq == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (dq, &((const RRsaPrivKey*)key)->dq);
  return TRUE;
}

rboolean
r_rsa_priv_key_get_qp (const RCryptoKey * key, rmpint * qp)
{
  if (R_UNLIKELY (key == NULL || qp == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (qp, &((const RRsaPrivKey*)key)->qp);
  return TRUE;
}


static rboolean
r_rsa_raw_encrypt_internal (const RRsaPubKey * key,
    rconstpointer data, ruint8 * out, rsize size)
{
  rboolean ret;
  rsize k;
  rmpint c, m;

  k = r_mpint_digits_used (&key->n) * sizeof (rmpint_digit);
  if (size != k)
    return FALSE;

  r_mpint_init_binary (&m, data, size);
  if (r_mpint_iszero (&m)) {
    r_mpint_clear (&m);
    return FALSE;
  }

  r_mpint_init_size (&c, r_mpint_digits_used (&key->n));

  ret = r_mpint_expmod (&c, &m, &key->e, &key->n) &&
    r_mpint_to_binary_with_size (&c, out, k);

  r_mpint_clear (&m);
  r_mpint_clear (&c);
  return ret;
}

rboolean
r_rsa_raw_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  rboolean ret;

  (void) prng;

  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  if (R_UNLIKELY (data == NULL || out == NULL || outsize == NULL))
    return FALSE;

  if ((ret = r_rsa_raw_encrypt_internal ((const RRsaPubKey *)key, data, out, size)))
    *outsize = size;

  return ret;
}

static rboolean
r_rsa_raw_decrypt_internal (const RRsaPrivKey * key,
    rconstpointer data, ruint8 * out, rsize size)
{
  rboolean ret;
  rsize k;
  rmpint c, m;

  k = r_mpint_digits_used (&key->pub.n) * sizeof (rmpint_digit);
  if (size != k)
    return FALSE;

  r_mpint_init_binary (&c, data, size);
  if (r_mpint_iszero (&c)) {
    r_mpint_clear (&c);
    return FALSE;
  }

  r_mpint_init_size (&m, r_mpint_digits_used (&key->pub.n));

  /* FIXME: implement... faster mode when we have q, p, dQ, dP and qInv */
  ret = r_mpint_expmod (&m, &c, &key->d, &key->pub.n) &&
    r_mpint_to_binary_with_size (&m, out, k);

  r_mpint_clear (&m);
  r_mpint_clear (&c);
  return ret;
}

rboolean
r_rsa_raw_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  rboolean ret;

  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  if (R_UNLIKELY (data == NULL || out == NULL || outsize == NULL))
    return FALSE;

  if ((ret = r_rsa_raw_decrypt_internal ((const RRsaPrivKey*)key, data, out, size)))
    *outsize = size;

  return ret;
}

rboolean
r_rsa_pkcs1v1_5_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  rboolean ret;
  rsize k;
  ruint8 * ptr;

  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  if (R_UNLIKELY (prng == NULL)) return FALSE;
  if (R_UNLIKELY (data == NULL)) return FALSE;
  if (R_UNLIKELY (out == NULL || outsize == NULL)) return FALSE;

  k = r_mpint_digits_used (&((const RRsaPrivKey*)key)->pub.n) * sizeof (rmpint_digit);
  if (size > k - 11 || *outsize < k)
    return FALSE;

  ptr = out;
  *ptr++ = 0;
  *ptr++ = 2;
  /* FIXME: This should be pseudo random nonzero! */
  for (; ptr < out + k - (size+1); ptr++) *ptr = 0xff;
  *ptr++ = 0;
  r_memcpy (ptr, data, size);

  if ((ret = r_rsa_raw_encrypt_internal ((const RRsaPubKey *)key, out, out, k)))
    *outsize = k;

  return ret;
}

rboolean
r_rsa_pkcs1v1_5_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  rboolean ret;
  ruint8 * buffer;

  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  if (R_UNLIKELY (data == NULL || out == NULL || outsize == NULL))
    return FALSE;
  if (size != r_mpint_digits_used (&((const RRsaPrivKey*)key)->pub.n) * sizeof (rmpint_digit))
    return FALSE;

  buffer = (*outsize >= size) ? out : r_alloca (size);

  if ((ret = r_rsa_raw_decrypt_internal ((const RRsaPrivKey*)key, data, buffer, size))) {
    ruint8 * ptr;

    if (buffer[0] != 0 || buffer[1] != 2)
      return FALSE;

    ptr = buffer + 2;
    while (ptr < buffer + size && *ptr != 0) ptr++;

    ptr++;
    if (*outsize < size - (ptr - buffer))
      return FALSE;

    *outsize = size - (ptr - buffer);
    r_memmove (out, ptr, *outsize);
  }

  return ret;
}

