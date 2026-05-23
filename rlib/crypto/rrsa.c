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

#include "config.h"
#include "rcrypto-private.h"

#include <rlib/crypto/rrsa.h>

#include <rlib/crypto/rhmac.h>

#include <rlib/asn1/rasn1.h>
#include <rlib/asn1/roid.h>
#include <rlib/rmem.h>

#define R_RSA_EMSA_PKCS1        0x01
#define R_RSA_EME_PKCS1         0x02

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
    rconstpointer data, rsize size, rpointer out, rsize * outsize)
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
    rconstpointer data, rsize size, rpointer out, rsize * outsize)
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

static RCryptoResult
r_rsa_sign (const RCryptoKey * key, RPrng * prng, RMsgDigestType mdtype,
    rconstpointer hash, rsize hashsize, rpointer sig, rsize * sigsize)
{
  switch (((const RRsaPubKey *)key)->padding) {
    case R_RSA_PADDING_PKCS1_V15:
      return r_rsa_pkcs1v1_5_sign_msg_hash (key, prng,
          mdtype, hash, hashsize, sig, sigsize);
    case R_RSA_PADDING_PKCS1_V21:
      /*return r_rsa_oaep_sign_msg_hash (key, prng,
          mdtype, hash, hashsize, sig, sigsize);*/
    default:
      return R_CRYPTO_NOT_AVAILABLE;
  }
}

static RCryptoResult
r_rsa_verify (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize)
{
  switch (((const RRsaPubKey *)key)->padding) {
    case R_RSA_PADDING_PKCS1_V15:
      return r_rsa_pkcs1v1_5_verify_msg_with_hash (key, mdtype, hash, hashsize, sig, sigsize);
    case R_RSA_PADDING_PKCS1_V21:
      /*return r_rsa_oaep_decrypt (key, data, size, out, outsize);*/
    default:
      return R_CRYPTO_NOT_AVAILABLE;
  }
}

static RCryptoResult
r_rsa_pub_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  RCryptoResult ret = R_CRYPTO_ERROR;

  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {

    if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
      r_asn1_bin_encoder_add_oid_rawsz (enc, R_RSA_OID_RSA_ENCRYPTION);
      r_asn1_bin_encoder_add_null (enc);
      r_asn1_bin_encoder_end_constructed (enc);
    }

    if (r_asn1_bin_encoder_begin_bit_string (enc, 0) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
        const RRsaPubKey * pk = (const RRsaPubKey *)key;
        if (r_asn1_bin_encoder_add_integer_mpint (enc, &pk->n) == R_ASN1_ENCODER_OK &&
            r_asn1_bin_encoder_add_integer_mpint (enc, &pk->e) == R_ASN1_ENCODER_OK) {
          ret = R_CRYPTO_OK;
        }
        r_asn1_bin_encoder_end_constructed (enc);
      }
      r_asn1_bin_encoder_end_bit_string (enc);
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return ret;
}

static RCryptoResult
r_rsa_priv_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    const RRsaPrivKey * pk = (const RRsaPrivKey *)key;
    if (r_asn1_bin_encoder_add_integer_i32 (enc, pk->ver) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.n) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.e) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->d) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->p) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->q) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->dp) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->dq) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->qp) == R_ASN1_ENCODER_OK) {
      r_asn1_bin_encoder_end_constructed (enc);
      return R_CRYPTO_OK;
    }

    r_asn1_bin_encoder_end_constructed (enc); /* end and discard? */
  }

  return R_CRYPTO_ERROR;
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
    r_rsa_encrypt, r_rsa_decrypt, NULL, r_rsa_verify, r_rsa_pub_key_export,
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
    r_rsa_encrypt, r_rsa_decrypt, r_rsa_sign, r_rsa_verify, r_rsa_priv_key_export
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
      r_mpint_init_copy_secure (&ret->d, d);
      r_mpint_init_secure (&ret->p);
      r_mpint_init_secure (&ret->q);
      r_mpint_init_secure (&ret->dp);
      r_mpint_init_secure (&ret->dq);
      r_mpint_init_secure (&ret->qp);
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
      r_mpint_init_copy_secure (&ret->d, d);
      if (p != NULL)  r_mpint_init_copy_secure (&ret->p, p);
      else            r_mpint_init_secure (&ret->p);
      if (q != NULL)  r_mpint_init_copy_secure (&ret->q, q);
      else            r_mpint_init_secure (&ret->q);
      if (dp != NULL) r_mpint_init_copy_secure (&ret->dp, dp);
      else            r_mpint_init_secure (&ret->dp);
      if (dq != NULL) r_mpint_init_copy_secure (&ret->dq, dq);
      else            r_mpint_init_secure (&ret->dq);
      if (qp != NULL) r_mpint_init_copy_secure (&ret->qp, qp);
      else            r_mpint_init_secure (&ret->qp);
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
      r_mpint_init_binary_secure (&ret->d, d, dsize);
      r_mpint_init_secure (&ret->p);
      r_mpint_init_secure (&ret->q);
      r_mpint_init_secure (&ret->dp);
      r_mpint_init_secure (&ret->dq);
      r_mpint_init_secure (&ret->qp);
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
    r_mpint_init_secure (&ret->d);
    r_mpint_init_secure (&ret->p);
    r_mpint_init_secure (&ret->q);
    r_mpint_init_secure (&ret->dp);
    r_mpint_init_secure (&ret->dq);
    r_mpint_init_secure (&ret->qp);

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

RCryptoKey *
r_rsa_priv_key_new_gen (rsize bits, ruint64 e, RPrng * prng)
{
  RRsaPrivKey * ret;
  rmpint g, p_1, q_1, p_1mulq_1;

  if (R_UNLIKELY (bits < 128)) return NULL;
  if (R_UNLIKELY (e < 3)) return NULL;

  if ((ret = r_mem_new0 (RRsaPrivKey)) != NULL) {
    rboolean pq_gcd = FALSE;

    r_rsa_priv_key_init (&ret->pub.key, (ruint)bits);

    r_mpint_init (&ret->pub.e);
    r_mpint_set_u64 (&ret->pub.e, e);
    r_mpint_init (&ret->pub.n);
    r_mpint_init_secure (&ret->p);
    r_mpint_init_secure (&ret->q);

    /* g, p_1, q_1, p_1mulq_1 are derived from the primes p / q and so
     * are themselves secret. Mark them so the data buffers don't end
     * up in freed heap after this function returns. */
    r_mpint_init_secure (&g);
    r_mpint_init_secure (&p_1);
    r_mpint_init_secure (&q_1);
    r_mpint_init_secure (&p_1mulq_1);

    if (prng != NULL) {
      r_prng_ref (prng);
    } else if ((prng = r_rand_prng_new ()) == NULL) {
      /* No usable PRNG and the caller didn't supply one. Bail out
       * cleanly - the rest of the gen path relies on prng being
       * non-NULL, and proceeding with a NULL would just crash
       * inside r_mpint_gen_prime. */
      r_mpint_clear (&p_1mulq_1);
      r_mpint_clear (&q_1);
      r_mpint_clear (&p_1);
      r_mpint_clear (&g);
      r_crypto_key_unref ((RCryptoKey *)ret);
      return NULL;
    }

    /* Find two primes p and q where;
     * GCD (e, (p - 1) * (q - 1)) == 1
     */
    do {
      if (!r_mpint_gen_prime (&ret->p, bits / 2, prng))
        break;

      if (bits % 2) {
        if (!r_mpint_gen_prime (&ret->q, (bits / 2) + 1, prng))
          break;
      } else {
        if (!r_mpint_gen_prime (&ret->q, bits / 2, prng))
          break;
      }

      if (r_mpint_cmp (&ret->p, &ret->q) == 0)
        continue;
      if (!r_mpint_mul (&ret->pub.n, &ret->p, &ret->q))
        break;
       if (r_mpint_bits_used (&ret->pub.n) != bits)
        continue;

      if (!r_mpint_sub_i32 (&p_1, &ret->p, 1) ||
          !r_mpint_sub_i32 (&q_1, &ret->q, 1) ||
          !r_mpint_mul (&p_1mulq_1, &p_1, &q_1) ||
          !r_mpint_gcd (&g, &ret->pub.e, &p_1mulq_1))
        break;
    } while (!(pq_gcd = (r_mpint_cmp_i32 (&g, 1) == 0)));

    if (pq_gcd) {
      r_mpint_init_secure (&ret->d);
      r_mpint_init_secure (&ret->dp);
      r_mpint_init_secure (&ret->dq);
      r_mpint_init_secure (&ret->qp);

      r_mpint_invmod (&ret->qp, &ret->q, &ret->p);        /* qp = q^-1 mod p */
      r_mpint_invmod (&ret->d, &ret->pub.e, &p_1mulq_1);  /* d  = e^-1 mod ((p - 1) * (q - 1)) */
      r_mpint_mod (&ret->dp, &ret->d, &p_1);              /* dp = d mod (p - 1) */
      r_mpint_mod (&ret->dq, &ret->d, &q_1);              /* dq = d mod (q - 1) */
    } else {
      r_crypto_key_unref (ret);
      ret = NULL;
    }

    r_mpint_clear (&p_1mulq_1);
    r_mpint_clear (&q_1);
    r_mpint_clear (&p_1);
    r_mpint_clear (&g);

    r_prng_unref (prng);
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


static RCryptoResult
r_rsa_raw_encrypt_internal (const RRsaPubKey * key,
    rconstpointer data, ruint8 * out, rsize size)
{
  RCryptoResult ret;
  rsize k;
  rmpint c, m;

  k = r_mpint_digits_used (&key->n) * sizeof (rmpint_digit);
  if (size != k)
    return R_CRYPTO_INVAL;

  r_mpint_init_binary (&m, data, size);
  if (r_mpint_iszero (&m)) {
    r_mpint_clear (&m);
    return R_CRYPTO_WRONG_SIZE;
  }

  r_mpint_init_size (&c, r_mpint_digits_used (&key->n));

  ret = r_mpint_expmod (&c, &m, &key->e, &key->n) &&
    r_mpint_to_binary_with_size (&c, out, k);

  r_mpint_clear (&m);
  r_mpint_clear (&c);
  return ret ? R_CRYPTO_OK : R_CRYPTO_ENCRYPT_FAILED;
}

RCryptoResult
r_rsa_raw_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  RCryptoResult ret;

  (void) prng;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return R_CRYPTO_WRONG_TYPE;

  if (R_UNLIKELY (data == NULL || out == NULL || outsize == NULL))
    return R_CRYPTO_INVAL;

  if ((ret = r_rsa_raw_encrypt_internal ((const RRsaPubKey *)key, data, out, size)) == R_CRYPTO_OK)
    *outsize = size;

  return ret;
}

/* The actual c^d mod n step. Caller is responsible for blinding c before
 * the call and unblinding m after — keeping that logic separate keeps the
 * CRT/non-CRT dispatch readable. */
static rboolean
r_rsa_modexp_private (const RRsaPrivKey * key, const rmpint * c, rmpint * m)
{
  if (!r_mpint_iszero (&key->p) && !r_mpint_iszero (&key->q) &&
      !r_mpint_iszero (&key->dp) && !r_mpint_iszero (&key->dq) &&
      !r_mpint_iszero (&key->qp)) {
    /* CRT path: ~4x faster than computing c^d mod n directly.
     *   m1 = c^dp mod p
     *   m2 = c^dq mod q
     *   h  = (m1 - m2) * qInv mod p
     *   m  = m2 + h * q
     * r_mpint_mod treats inputs as unsigned, so reduce m2 mod p first
     * to keep (m1 - m2_p) in (-p, p) and add p once if it lands negative. */
    rmpint m1, m2, m2_p, h;
    rboolean ok;

    r_mpint_init (&m1);
    r_mpint_init (&m2);
    r_mpint_init (&m2_p);
    r_mpint_init (&h);

    ok = r_mpint_expmod (&m1, c, &key->dp, &key->p)
      && r_mpint_expmod (&m2, c, &key->dq, &key->q)
      && r_mpint_mod (&m2_p, &m2, &key->p)
      && r_mpint_sub (&h, &m1, &m2_p);
    if (ok && r_mpint_isneg (&h))
      ok = r_mpint_add (&h, &h, &key->p);
    ok = ok
      && r_mpint_mul (&h, &h, &key->qp)
      && r_mpint_mod (&h, &h, &key->p)
      && r_mpint_mul (m, &h, &key->q)
      && r_mpint_add (m, m, &m2);

    r_mpint_clear (&m1);
    r_mpint_clear (&m2);
    r_mpint_clear (&m2_p);
    r_mpint_clear (&h);
    return ok;
  } else {
    return r_mpint_expmod (m, c, &key->d, &key->pub.n);
  }
}

static RCryptoResult
r_rsa_raw_decrypt_internal (const RRsaPrivKey * key, RPrng * prng,
    rconstpointer data, ruint8 * out, rsize size)
{
  RCryptoResult ret;
  rsize k;
  rmpint c, m, r, r_inv, r_e;
  ruint8 * rbuf;
  rboolean own_prng = FALSE;
  rboolean ok;

  k = r_mpint_digits_used (&key->pub.n) * sizeof (rmpint_digit);
  if (size != k)
    return R_CRYPTO_INVAL;

  r_mpint_init_binary (&c, data, size);
  if (r_mpint_iszero (&c)) {
    r_mpint_clear (&c);
    return R_CRYPTO_WRONG_SIZE;
  }

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL) {
      r_mpint_clear (&c);
      return R_CRYPTO_ERROR;
    }
    own_prng = TRUE;
  }

  /* m ends up holding the plaintext; r / r_inv / r_e are the blinding
   * factor and its variants. None of those should linger in freed
   * heap after this function returns. */
  r_mpint_init_size (&m, r_mpint_digits_used (&key->pub.n));
  r_mpint_set_secure_clear (&m);
  r_mpint_init_secure (&r);
  r_mpint_init_secure (&r_inv);
  r_mpint_init_secure (&r_e);
  rbuf = r_alloca (size);

  /* RSA blinding: instead of computing m = c^d mod n directly — whose
   * timing would correlate with d — sample a random r in (0, n) with
   * gcd(r, n) = 1, compute c' = c * r^e mod n, run the private-key op
   * on c', then unblind via m = m' * r^-1 mod n. For random 2048-bit r
   * and n = p*q the gcd is essentially always 1, but we still iterate
   * until invmod succeeds rather than silently failing. */
  do {
    if (!r_prng_fill (prng, rbuf, size)) {
      ok = FALSE;
      goto done;
    }
    r_mpint_set_binary (&r, rbuf, size);
    r_mpint_mod (&r, &r, &key->pub.n);
  } while (r_mpint_iszero (&r) || !r_mpint_invmod (&r_inv, &r, &key->pub.n));

  ok = r_mpint_expmod (&r_e, &r, &key->pub.e, &key->pub.n)
    && r_mpint_mulmod (&c, &c, &r_e, &key->pub.n)
    && r_rsa_modexp_private (key, &c, &m)
    && r_mpint_mulmod (&m, &m, &r_inv, &key->pub.n)
    && r_mpint_to_binary_with_size (&m, out, k);

done:
  ret = ok ? R_CRYPTO_OK : R_CRYPTO_DECRYPT_FAILED;

  /* rbuf held raw PRNG output used to seed the blinding factor; the
   * blinding mpint itself is wiped via secure-clear above. */
  r_memclear_secure (rbuf, size);
  r_mpint_clear (&c);
  r_mpint_clear (&m);
  r_mpint_clear (&r);
  r_mpint_clear (&r_inv);
  r_mpint_clear (&r_e);
  if (own_prng)
    r_prng_unref (prng);

  return ret;
}

RCryptoResult
r_rsa_raw_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  RCryptoResult ret;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return R_CRYPTO_WRONG_TYPE;

  if (R_UNLIKELY (data == NULL || out == NULL || outsize == NULL))
    return R_CRYPTO_INVAL;

  if ((ret = r_rsa_raw_decrypt_internal ((const RRsaPrivKey*)key, NULL, data, out, size)) == R_CRYPTO_OK)
    *outsize = size;

  return ret;
}

RCryptoResult
r_rsa_pkcs1v1_5_encrypt (const RCryptoKey * key, RPrng * prng,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  RCryptoResult ret;
  rsize k;
  ruint8 * ptr;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return R_CRYPTO_WRONG_TYPE;

  if (R_UNLIKELY (prng == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (out == NULL || outsize == NULL)) return R_CRYPTO_INVAL;

  k = r_mpint_digits_used (&((const RRsaPrivKey*)key)->pub.n) * sizeof (rmpint_digit);
  if (size > k - 11 || *outsize < k)
    return R_CRYPTO_WRONG_SIZE;

  ptr = out;
  *ptr++ = 0x00;
  *ptr++ = R_RSA_EME_PKCS1;
  r_prng_fill_nonzero (prng, ptr, k - size - 3);
  ptr += k - size - 3;
  *ptr++ = 0x00;
  r_memcpy (ptr, data, size);

  if ((ret = r_rsa_raw_encrypt_internal ((const RRsaPubKey *)key, out, out, k)) == R_CRYPTO_OK)
    *outsize = k;

  return ret;
}

RCryptoResult
r_rsa_pkcs1v1_5_decrypt (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  RCryptoResult ret;
  ruint8 * buffer;
  rboolean scratch;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return R_CRYPTO_WRONG_TYPE;

  if (R_UNLIKELY (data == NULL || out == NULL || outsize == NULL))
    return R_CRYPTO_INVAL;
  if (size != r_mpint_digits_used (&((const RRsaPrivKey*)key)->pub.n) * sizeof (rmpint_digit))
    return R_CRYPTO_WRONG_SIZE;

  /* When out is big enough we decrypt straight into it; otherwise a
   * scratch alloca holds the padded plaintext until we strip the
   * PS / 0x00 separator and copy the message out. The scratch case
   * gets a secure wipe at the end - it's a full RSA plaintext (TLS
   * premaster secrets in particular) and shouldn't linger on the
   * popped stack frame. */
  scratch = (*outsize < size);
  buffer = scratch ? r_alloca (size) : out;

  if ((ret = r_rsa_raw_decrypt_internal ((const RRsaPrivKey*)key, NULL, data, buffer, size)) == R_CRYPTO_OK) {
    ruint8 * ptr;

    if (size < 11 || buffer[0] != 0x00 || buffer[1] != R_RSA_EME_PKCS1) {
      ret = R_CRYPTO_INVALID_PADDING;
      goto out_wipe;
    }

    ptr = buffer + 2;
    while (ptr < buffer + size && *ptr != 0) ptr++;

    if (ptr - buffer < 10 || ptr >= buffer + size) {
      ret = R_CRYPTO_INVALID_PADDING;
      goto out_wipe;
    }
    ptr++;

    if (*outsize < size - (ptr - buffer)) {
      ret = R_CRYPTO_BUFFER_TOO_SMALL;
      goto out_wipe;
    }

    *outsize = size - (ptr - buffer);
    r_memmove (out, ptr, *outsize);
  }

out_wipe:
  if (scratch)
    r_memclear_secure (buffer, size);
  return ret;
}

/* Branchless u32 equality: 0xFFFFFFFF if a == b, 0 otherwise.
 *
 *   x = a ^ b           is zero iff a == b
 *   y = x | (-x)        top bit set iff x != 0 (one of x or -x is non-zero
 *                       and has bit 31 set when interpreted as unsigned)
 *   d = y >> 31         maps to 0 (equal) or 1 (different)
 *   d - 1               wraps unsigned: 0xFFFFFFFF for equal, 0 for different
 *
 * No branches, no data-dependent timing. */
static inline ruint32
r_ct_u32_eq (ruint32 a, ruint32 b)
{
  ruint32 x = a ^ b;
  return (((x | ((~x) + 1u)) >> 31) - 1u);
}

/* Same shape, treating a single byte as a 32-bit value for mask
 * width. Returns 0xFFFFFFFF if a == b, 0 otherwise. */
static inline ruint32
r_ct_byte_eq (ruint8 a, ruint8 b)
{
  return r_ct_u32_eq ((ruint32)a, (ruint32)b);
}

/* Branchless u32 select: mask is the all-ones / all-zeros output of
 * one of the r_ct_*_eq helpers. */
static inline ruint32
r_ct_u32_select (ruint32 mask, ruint32 t, ruint32 f)
{
  return (mask & t) | ((~mask) & f);
}

/* HKDF-Expand-style stretching of HMAC-SHA256 (private exponent,
 * counter || ciphertext) into out_size bytes of deterministic
 * synthetic plaintext. Same (key, ciphertext) always produces the
 * same byte stream, so replaying a chosen ciphertext yields the
 * same output as before - an attacker can't tell whether the
 * apparent random data came from a padding failure or from a
 * different ciphertext that happened to decrypt to it. */
static rboolean
r_rsa_pkcs1v1_5_synthetic (const rmpint * d, rconstpointer ciphertext,
    rsize ct_size, ruint8 * out, rsize out_size)
{
  ruint8 * d_bytes;
  rsize d_size;
  RHmac * hmac;
  ruint8 block[32];
  rsize block_size;
  ruint8 counter;
  rsize emitted;
  rboolean ok = TRUE;

  d_size = r_mpint_bytes_used (d);
  if (R_UNLIKELY (d_size == 0))
    return FALSE;
  d_bytes = r_alloca (d_size);
  if (R_UNLIKELY (!r_mpint_to_binary_with_size (d, d_bytes, d_size))) {
    r_memclear_secure (d_bytes, d_size);
    return FALSE;
  }

  for (counter = 1, emitted = 0; emitted < out_size && ok; counter++) {
    block_size = sizeof (block);
    if ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA256, d_bytes, d_size)) == NULL) {
      ok = FALSE;
      break;
    }
    ok = r_hmac_update (hmac, &counter, sizeof (counter)) &&
         r_hmac_update (hmac, ciphertext, ct_size) &&
         r_hmac_get_data (hmac, block, sizeof (block), &block_size);
    r_hmac_free (hmac);
    if (ok) {
      rsize take = MIN (block_size, out_size - emitted);
      r_memcpy (out + emitted, block, take);
      emitted += take;
    }
  }

  r_memclear_secure (d_bytes, d_size);
  r_memclear_secure (block, sizeof (block));
  return ok;
}

RCryptoResult
r_rsa_pkcs1v1_5_decrypt_implicit (const RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize out_size)
{
  RCryptoResult ret;
  const RRsaPrivKey * pk;
  ruint8 * em;
  ruint8 * synth;
  rsize k, i;
  ruint32 valid;
  ruint32 zero_seen;
  ruint32 zero_pos;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (data == NULL || out == NULL)) return R_CRYPTO_INVAL;

  pk = (const RRsaPrivKey *)key;
  k = r_mpint_digits_used (&pk->pub.n) * sizeof (rmpint_digit);
  if (R_UNLIKELY (size != k)) return R_CRYPTO_WRONG_SIZE;
  /* PKCS#1 v1.5 requires |PS| >= 8 plus the 0x00 0x02 prefix and the
   * 0x00 separator, so the message can be at most k - 11 bytes. */
  if (R_UNLIKELY (out_size == 0 || out_size > k - 11))
    return R_CRYPTO_WRONG_SIZE;

  em = r_alloca (size);
  synth = r_alloca (out_size);

  /* Raw decrypt: out-of-range / zero ciphertexts surface as an error
   * here. Bleichenbacher candidates are always in [0, n), so this
   * doesn't expose a useful oracle - it's input validation, not a
   * padding check. */
  if ((ret = r_rsa_raw_decrypt_internal (pk, NULL, data, em, size)) != R_CRYPTO_OK) {
    r_memclear_secure (em, size);
    return ret;
  }

  if (!r_rsa_pkcs1v1_5_synthetic (&pk->d, data, size, synth, out_size)) {
    r_memclear_secure (em, size);
    return R_CRYPTO_ERROR;
  }

  /* Padding shape:
   *   em[0] == 0x00
   *   em[1] == 0x02
   *   em[2..k-1] = PS || 0x00 || M, |PS| >= 8
   * To match the requested out_size, the 0x00 separator must be at
   * position k - out_size - 1. The scan accumulates the position of
   * the FIRST 0x00 in em[2..k-1] using a once-set "zero_seen" mask;
   * a too-early zero (PS shorter than 8) trips the position check
   * against k - out_size - 1, which we enforced to be >= 10 above. */
  valid = r_ct_byte_eq (em[0], 0x00) & r_ct_byte_eq (em[1], R_RSA_EME_PKCS1);

  zero_seen = 0;
  zero_pos = 0;
  for (i = 2; i < size; i++) {
    ruint32 is_zero = r_ct_byte_eq (em[i], 0x00);
    ruint32 first_zero = is_zero & ~zero_seen;
    zero_pos = r_ct_u32_select (first_zero, (ruint32)i, zero_pos);
    zero_seen |= is_zero;
  }

  valid &= zero_seen;
  valid &= r_ct_u32_eq (zero_pos, (ruint32)(k - out_size - 1));

  /* Constant-time select: out[i] = valid ? em[k - out_size + i]
   *                                      : synth[i]. The load from
   * em is always at the same offset regardless of where the real
   * message would actually start, so a malformed em can't tilt the
   * memory-access pattern. */
  for (i = 0; i < out_size; i++) {
    ruint32 real_byte = (ruint32)em[k - out_size + i];
    ruint32 synth_byte = (ruint32)synth[i];
    out[i] = (ruint8)r_ct_u32_select (valid, real_byte, synth_byte);
  }

  r_memclear_secure (em, size);
  r_memclear_secure (synth, out_size);
  return R_CRYPTO_OK;
}

RCryptoResult
r_rsa_pkcs1v1_5_sign_msg (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    rpointer sig, rsize * sigsize)
{
  RMsgDigest * md;
  RCryptoResult ret;

  if (R_UNLIKELY (msg == NULL || msgsize == 0))
    return R_CRYPTO_INVAL;

  if ((md = r_msg_digest_new (mdtype)) != NULL) {
    rsize hashsize = r_msg_digest_size (md);
    ruint8 * hash = r_alloca (hashsize);

    if (r_msg_digest_update (md, msg, msgsize) && r_msg_digest_get_data (md, hash, hashsize, NULL)) {
      ret = r_rsa_pkcs1v1_5_sign_msg_hash (key, prng, mdtype, hash, hashsize, sig, sigsize);
    } else {
      ret = R_CRYPTO_HASH_FAILED;
    }

    r_msg_digest_free (md);
  } else {
    ret = R_CRYPTO_WRONG_TYPE;
  }

  return ret;
}

static rsize
r_rsa_oid_from_msg_digest (RMsgDigestType mdtype, ruint8 oid[16])
{
  switch (mdtype) {
    case R_MSG_DIGEST_TYPE_MD5: /* 1.2.840.113549.1.1.4  */
      r_memcpy (oid, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x04", 9);
      return 9;
    case R_MSG_DIGEST_TYPE_SHA1: /* 1.3.14.3.2.26  */
      r_memcpy (oid, "\x2b\x0e\x03\x02\x1a", 9);
      return 5;
    case R_MSG_DIGEST_TYPE_SHA256: /* 2.16.840.1.101.3.4.2.1  */
      r_memcpy (oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x01", 9);
      return 9;
    case R_MSG_DIGEST_TYPE_SHA384: /* 2.16.840.1.101.3.4.2.2  */
      r_memcpy (oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x02", 9);
      return 9;
    case R_MSG_DIGEST_TYPE_SHA512: /* 2.16.840.1.101.3.4.2.3  */
      r_memcpy (oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x03", 9);
      return 9;
    case R_MSG_DIGEST_TYPE_SHA224: /* 2.16.840.1.101.3.4.2.4  */
      r_memcpy (oid, "\x60\x86\x48\x01\x65\x03\x04\x02\x04", 9);
      return 9;
    default:
      break;
  }
  return 0;
}

RCryptoResult
r_rsa_pkcs1v1_5_sign_msg_hash (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize)
{
  RAsn1BinEncoder * enc;
  rsize k, oidsize, di_size;
  ruint8 * ptr, * di, oidbuf[16];
  RCryptoResult ret;

  (void) prng;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (hash == NULL || hashsize == 0 || sig == NULL || sigsize == NULL))
    return R_CRYPTO_INVAL;

  if (*sigsize < (k = r_crypto_key_get_bitsize (key) / 8))
    return R_CRYPTO_BUFFER_TOO_SMALL;
  if ((oidsize = r_rsa_oid_from_msg_digest (mdtype, oidbuf)) == 0)
    return R_CRYPTO_HASH_FAILED;

  /* Build the DER-encoded DigestInfo via the encoder so that we don't
   * silently break when hashsize+oidsize requires long-form lengths.
   *   DigestInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, digest OCTET STRING }
   *   AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL } */
  if ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)) == NULL)
    return R_CRYPTO_SIGN_FAILED;

  if (r_asn1_bin_encoder_begin_constructed (enc,
          R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE),
          0) != R_ASN1_ENCODER_OK ||
      r_asn1_bin_encoder_begin_constructed (enc,
          R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE),
          0) != R_ASN1_ENCODER_OK ||
      r_asn1_bin_encoder_add_raw (enc,
          R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OBJECT_IDENTIFIER),
          oidbuf, oidsize) != R_ASN1_ENCODER_OK ||
      r_asn1_bin_encoder_add_null (enc) != R_ASN1_ENCODER_OK ||
      r_asn1_bin_encoder_end_constructed (enc) != R_ASN1_ENCODER_OK ||
      r_asn1_bin_encoder_add_raw (enc,
          R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OCTET_STRING),
          hash, hashsize) != R_ASN1_ENCODER_OK ||
      r_asn1_bin_encoder_end_constructed (enc) != R_ASN1_ENCODER_OK) {
    r_asn1_bin_encoder_unref (enc);
    return R_CRYPTO_SIGN_FAILED;
  }

  di = r_asn1_bin_encoder_get_data (enc, &di_size);
  r_asn1_bin_encoder_unref (enc);
  if (di == NULL)
    return R_CRYPTO_SIGN_FAILED;

  if (R_UNLIKELY (di_size + 11 > k)) {
    r_free (di);
    return R_CRYPTO_BUFFER_TOO_SMALL;
  }

  *sigsize = k;
  ptr = sig;
  *ptr++ = 0x00;
  *ptr++ = R_RSA_EMSA_PKCS1;
  r_memset (ptr, 0xff, k - 3 - di_size);
  ptr += k - 3 - di_size;
  *ptr++ = 0x00;
  r_memcpy (ptr, di, di_size);
  r_free (di);

  if (r_rsa_raw_decrypt_internal ((const RRsaPrivKey *)key, prng, sig, sig, k) != R_CRYPTO_OK)
    ret = R_CRYPTO_SIGN_FAILED;
  else
    ret = R_CRYPTO_OK;
  return ret;
}

RCryptoResult
r_rsa_pkcs1v1_5_sign_hash (const RCryptoKey * key, RPrng * prng,
    rconstpointer hash, rsize hashsize, rpointer sig, rsize * sigsize)
{
  rsize k;
  ruint8 * ptr;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (hash == NULL || hashsize == 0 || sig == NULL || sigsize == NULL))
    return R_CRYPTO_INVAL;

  if (*sigsize < (k = r_crypto_key_get_bitsize (key) / 8))
    return R_CRYPTO_BUFFER_TOO_SMALL;
  if (R_UNLIKELY (hashsize + 3 > k))
    return R_CRYPTO_BUFFER_TOO_SMALL;

  *sigsize = k;
  ptr = sig;
  *ptr++ = 0x00;
  *ptr++ = R_RSA_EMSA_PKCS1;
  r_memset (ptr, 0xff, k - 3 - hashsize);
  ptr += k - 3 - hashsize;
  *ptr++ = 0x00;

  r_memcpy (ptr, hash, hashsize);

  if (r_rsa_raw_decrypt_internal ((const RRsaPrivKey *)key, prng, sig, sig, k) != R_CRYPTO_OK)
    return R_CRYPTO_SIGN_FAILED;
  return R_CRYPTO_OK;
}

RCryptoResult
r_rsa_pkcs1v1_5_verify_msg (const RCryptoKey * key,
    rconstpointer msg, rsize msgsize, rconstpointer sig, rsize sigsize)
{
  RCryptoResult ret;
  ruint8 * buffer;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;

  buffer = r_alloca (sigsize);

  if ((ret = r_rsa_raw_encrypt_internal ((const RRsaPubKey*)key, sig, buffer, sigsize)) == R_CRYPTO_OK) {
    ruint8 * ptr = buffer;
    RAsn1BinDecoder * dec;

    if (sigsize < 11 || *ptr++ != 0x00 || *ptr++ != R_RSA_EMSA_PKCS1)
      return R_CRYPTO_VERIFY_FAILED;

    while (ptr < buffer + sigsize && *ptr == 0xff) ptr++;
    if (ptr - buffer < 10 || ptr >= buffer + sigsize || *ptr++ != 0x00)
      return R_CRYPTO_VERIFY_FAILED;

    if ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, ptr, buffer + sigsize - ptr)) != NULL) {
      RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
      RMsgDigestType mdtype;

      if ((r_asn1_bin_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_tlv_parse_oid_to_msg_digest_type (&tlv, &mdtype) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_decoder_out (dec, &tlv) == R_ASN1_DECODER_OK)) {
        RMsgDigest * md;
        rsize hashsize;

        if ((md = r_msg_digest_new (mdtype)) == NULL) {
          /* FIXME: Support all hash types! */
          ret = R_CRYPTO_NOT_AVAILABLE;
        } else if ((hashsize = r_msg_digest_size (md)) == tlv.len) {
          ruint8 * hash = r_alloca (hashsize);
          ret = (r_msg_digest_update (md, msg, msgsize) &&
            r_msg_digest_get_data (md, hash, hashsize, NULL) &&
            r_memcmp (tlv.value, hash, hashsize) == 0) ? R_CRYPTO_OK : R_CRYPTO_VERIFY_FAILED;
        } else {
          ret = R_CRYPTO_WRONG_SIZE;
        }

        r_msg_digest_free (md);
      } else {
        ret = R_CRYPTO_VERIFY_FAILED;
      }

      r_asn1_bin_decoder_unref (dec);
    } else {
      ret = R_CRYPTO_VERIFY_FAILED;
    }
  }

  return ret;
}

RCryptoResult
r_rsa_pkcs1v1_5_verify_msg_with_hash (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize)
{
  RCryptoResult ret;
  ruint8 * buffer;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;

  buffer = r_alloca (sigsize);

  if ((ret = r_rsa_raw_encrypt_internal ((const RRsaPubKey*)key, sig, buffer, sigsize)) == R_CRYPTO_OK) {
    ruint8 * ptr = buffer;
    RAsn1BinDecoder * dec;

    if (sigsize < 11 || *ptr++ != 0x00 || *ptr++ != R_RSA_EMSA_PKCS1)
      return R_CRYPTO_VERIFY_FAILED;

    while (ptr < buffer + sigsize && *ptr == 0xff) ptr++;
    if (ptr - buffer < 10 || ptr >= buffer + sigsize || *ptr++ != 0x00)
      return R_CRYPTO_VERIFY_FAILED;

    if ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, ptr, buffer + sigsize - ptr)) != NULL) {
      RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
      RMsgDigestType md;

      if ((r_asn1_bin_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_tlv_parse_oid_to_msg_digest_type (&tlv, &md) == R_ASN1_DECODER_OK) &&
            (r_asn1_bin_decoder_out (dec, &tlv) == R_ASN1_DECODER_OK)) {
        if (mdtype != md)
          ret = R_CRYPTO_WRONG_TYPE;
        else if (hashsize != tlv.len)
          ret = R_CRYPTO_WRONG_SIZE;
        else if (r_memcmp (tlv.value, hash, hashsize) == 0)
          ret = R_CRYPTO_OK;
        else
          ret = R_CRYPTO_VERIFY_FAILED;
      } else {
        ret = R_CRYPTO_VERIFY_FAILED;
      }
      r_asn1_bin_decoder_unref (dec);
    } else {
      ret = R_CRYPTO_VERIFY_FAILED;
    }
  }

  return ret;
}

RCryptoResult
r_rsa_pkcs1v1_5_verify_hash (const RCryptoKey * key,
    rconstpointer hash, rsize hashsize, rconstpointer sig, rsize sigsize)
{
  RCryptoResult ret;
  ruint8 * buffer;

  if (R_UNLIKELY (key == NULL)) return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_RSA)) return R_CRYPTO_WRONG_TYPE;

  buffer = r_alloca (sigsize);

  if ((ret = r_rsa_raw_encrypt_internal ((const RRsaPubKey*)key, sig, buffer, sigsize)) == R_CRYPTO_OK) {
    ruint8 * ptr = buffer;

    if (sigsize < 11 || *ptr++ != 0x00 || *ptr++ != R_RSA_EMSA_PKCS1)
      return R_CRYPTO_VERIFY_FAILED;

    while (ptr < buffer + sigsize && *ptr == 0xff) ptr++;
    if (ptr - buffer < 10 || ptr >= buffer + sigsize || *ptr++ != 0x00)
      return R_CRYPTO_VERIFY_FAILED;

    if ((rsize) (buffer + sigsize - ptr) != hashsize)
      return R_CRYPTO_VERIFY_FAILED;
    ret = (r_memcmp (ptr, hash, hashsize) == 0) ? R_CRYPTO_OK : R_CRYPTO_VERIFY_FAILED;
  }

  return ret;
}

