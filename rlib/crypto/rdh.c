/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include <rlib/crypto/rdh.h>

#include <rlib/asn1/roid.h>
#include <rlib/rmem.h>

#include "rdh-groups.inc"

typedef struct {
  const ruint8 * p;
  rsize p_len;
  ruint8 g;
} RDhGroupParams;

static const RDhGroupParams g__dh_groups[R_DH_GROUP_COUNT] = {
  { rfc3526_group14_p, sizeof (rfc3526_group14_p), 2 },
  { rfc3526_group15_p, sizeof (rfc3526_group15_p), 2 },
  { rfc3526_group16_p, sizeof (rfc3526_group16_p), 2 },
  { rfc3526_group17_p, sizeof (rfc3526_group17_p), 2 },
  { rfc3526_group18_p, sizeof (rfc3526_group18_p), 2 },
  { rfc7919_ffdhe2048_p, sizeof (rfc7919_ffdhe2048_p), 2 },
  { rfc7919_ffdhe3072_p, sizeof (rfc7919_ffdhe3072_p), 2 },
  { rfc7919_ffdhe4096_p, sizeof (rfc7919_ffdhe4096_p), 2 },
  { rfc7919_ffdhe6144_p, sizeof (rfc7919_ffdhe6144_p), 2 },
  { rfc7919_ffdhe8192_p, sizeof (rfc7919_ffdhe8192_p), 2 },
};

typedef struct {
  RCryptoKey key;

  rmpint p;
  rmpint g;
  rmpint y;
} RDhPubKey;

typedef struct {
  RDhPubKey pub;

  rint32 ver;
  rmpint x;
} RDhPrivKey;

static void
r_dh_pub_key_free (rpointer data)
{
  RDhPubKey * key;

  if ((key = data) != NULL) {
    r_mpint_clear (&key->p);
    r_mpint_clear (&key->g);
    r_mpint_clear (&key->y);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

static RCryptoResult
r_dh_pub_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  RCryptoResult ret = R_CRYPTO_ERROR;
  const RDhPubKey * pk = (const RDhPubKey *)key;
  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);

  /* SubjectPublicKeyInfo ::= SEQUENCE {
   *   AlgorithmIdentifier { dhKeyAgreement, DHParameter { p, g } },
   *   BIT STRING (INTEGER y)  -- DHPublicKey, RFC 3279 / PKCS#3 */
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) != R_ASN1_ENCODER_OK)
    return ret;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    r_asn1_bin_encoder_add_oid_rawsz (enc, R_RSA_OID_DH_KEY_AGREEMENT);
    if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
      r_asn1_bin_encoder_add_integer_mpint (enc, &pk->p);
      r_asn1_bin_encoder_add_integer_mpint (enc, &pk->g);
      r_asn1_bin_encoder_end_constructed (enc);
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  if (r_asn1_bin_encoder_begin_bit_string (enc, 0) == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_integer_mpint (enc, &pk->y) == R_ASN1_ENCODER_OK)
      ret = R_CRYPTO_OK;
    r_asn1_bin_encoder_end_bit_string (enc);
  }

  r_asn1_bin_encoder_end_constructed (enc);
  return ret;
}

static RCryptoResult
r_dh_priv_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  /* Self-describing payload mirroring how rlib treats DSA: a single
   * SEQUENCE { ver, p, g, x } so the importer doesn't have to thread
   * (p, g) down from a wrapping AlgorithmIdentifier. */
  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    const RDhPrivKey * pk = (const RDhPrivKey *)key;
    if (r_asn1_bin_encoder_add_integer_i32 (enc, pk->ver) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.p) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.g) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->x) == R_ASN1_ENCODER_OK) {
      r_asn1_bin_encoder_end_constructed (enc);
      return R_CRYPTO_OK;
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return R_CRYPTO_ERROR;
}

static void
r_dh_pub_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo dh_pub_key_info = {
    R_CRYPTO_ALGO_DH, R_DH_STR,
    NULL, NULL, NULL, NULL, r_dh_pub_key_export
  };

  r_ref_init (key, r_dh_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = &dh_pub_key_info;
  key->bits = bits;
}

static void
r_dh_priv_key_free (rpointer data)
{
  RDhPrivKey * key;

  if ((key = data) != NULL) {
    r_mpint_clear (&key->x);
    r_dh_pub_key_free (key);
  }
}

static void
r_dh_priv_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo dh_priv_key_info = {
    R_CRYPTO_ALGO_DH, R_DH_STR,
    NULL, NULL, NULL, NULL, r_dh_priv_key_export
  };

  r_ref_init (key, r_dh_priv_key_free);
  key->type = R_CRYPTO_PRIVATE_KEY;
  key->algo = &dh_priv_key_info;
  key->bits = bits;
}

RCryptoKey *
r_dh_pub_key_new (const rmpint * p, const rmpint * g, const rmpint * y)
{
  RDhPubKey * ret;

  if (R_UNLIKELY (p == NULL || g == NULL || y == NULL))
    return NULL;

  if ((ret = r_mem_new (RDhPubKey)) != NULL) {
    r_mpint_init_copy (&ret->p, p);
    r_mpint_init_copy (&ret->g, g);
    r_mpint_init_copy (&ret->y, y);
    r_dh_pub_key_init (&ret->key, r_mpint_bits_used (&ret->p));
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dh_pub_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize)
{
  RDhPubKey * ret;

  if (R_UNLIKELY (p == NULL || psize == 0 || g == NULL || gsize == 0 ||
      y == NULL || ysize == 0))
    return NULL;

  if ((ret = r_mem_new (RDhPubKey)) != NULL) {
    r_mpint_init_binary (&ret->p, p, psize);
    r_mpint_init_binary (&ret->g, g, gsize);
    r_mpint_init_binary (&ret->y, y, ysize);
    r_dh_pub_key_init (&ret->key, r_mpint_bits_used (&ret->p));
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dh_priv_key_new (const rmpint * p, const rmpint * g,
    const rmpint * y, const rmpint * x)
{
  RDhPrivKey * ret;

  if (R_UNLIKELY (p == NULL || g == NULL || y == NULL || x == NULL))
    return NULL;

  if ((ret = r_mem_new (RDhPrivKey)) != NULL) {
    ret->ver = 0;
    r_mpint_init_copy (&ret->pub.p, p);
    r_mpint_init_copy (&ret->pub.g, g);
    r_mpint_init_copy (&ret->pub.y, y);
    r_mpint_init_copy_secure (&ret->x, x);
    r_dh_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.p));
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dh_priv_key_new_binary (rconstpointer p, rsize psize,
    rconstpointer g, rsize gsize,
    rconstpointer y, rsize ysize,
    rconstpointer x, rsize xsize)
{
  RDhPrivKey * ret;

  if (R_UNLIKELY (p == NULL || psize == 0 || g == NULL || gsize == 0 ||
      y == NULL || ysize == 0 || x == NULL || xsize == 0))
    return NULL;

  if ((ret = r_mem_new (RDhPrivKey)) != NULL) {
    ret->ver = 0;
    r_mpint_init_binary (&ret->pub.p, p, psize);
    r_mpint_init_binary (&ret->pub.g, g, gsize);
    r_mpint_init_binary (&ret->pub.y, y, ysize);
    r_mpint_init_binary_secure (&ret->x, x, xsize);
    r_dh_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.p));
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dh_priv_key_new_gen (const rmpint * p, const rmpint * g, RPrng * prng)
{
  RDhPrivKey * ret;
  rmpint p_2;
  rsize pbytes;
  ruint8 * xbuf;

  if (R_UNLIKELY (p == NULL || g == NULL))
    return NULL;
  if (R_UNLIKELY (r_mpint_cmp_i32 (p, 3) < 0))
    return NULL;

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL)
      return NULL;
  } else {
    r_prng_ref (prng);
  }

  if ((ret = r_mem_new (RDhPrivKey)) == NULL)
    goto out;

  ret->ver = 0;
  r_mpint_init_copy (&ret->pub.p, p);
  r_mpint_init_copy (&ret->pub.g, g);
  r_mpint_init (&ret->pub.y);
  r_mpint_init_secure (&ret->x);

  r_mpint_init (&p_2);
  r_mpint_sub_i32 (&p_2, p, 2);

  /* Draw x as a positive integer of the same byte length as p, then keep
   * resampling until 2 <= x <= p-2. With a fully-random sample on a real
   * group this loop converges immediately. */
  pbytes = (r_mpint_bits_used (p) + 7) / 8;
  xbuf = r_alloca (pbytes);

  for (;;) {
    if (!r_prng_fill (prng, xbuf, pbytes)) {
      r_dh_priv_key_free (ret);
      ret = NULL;
      r_mpint_clear (&p_2);
      goto out;
    }
    r_mpint_set_binary (&ret->x, xbuf, pbytes);
    if (r_mpint_cmp_i32 (&ret->x, 2) >= 0 && r_mpint_cmp (&ret->x, &p_2) <= 0)
      break;
  }

  if (!r_mpint_expmod (&ret->pub.y, &ret->pub.g, &ret->x, &ret->pub.p)) {
    r_dh_priv_key_free (ret);
    ret = NULL;
  } else {
    r_dh_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.p));
  }

  r_mpint_clear (&p_2);

out:
  r_prng_unref (prng);

  return (RCryptoKey *)ret;
}

rboolean
r_dh_pub_key_get_p (const RCryptoKey * key, rmpint * p)
{
  if (R_UNLIKELY (key == NULL || p == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DH)) return FALSE;

  r_mpint_set (p, &((const RDhPubKey *)key)->p);
  return TRUE;
}

rboolean
r_dh_pub_key_get_g (const RCryptoKey * key, rmpint * g)
{
  if (R_UNLIKELY (key == NULL || g == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DH)) return FALSE;

  r_mpint_set (g, &((const RDhPubKey *)key)->g);
  return TRUE;
}

rboolean
r_dh_pub_key_get_y (const RCryptoKey * key, rmpint * y)
{
  if (R_UNLIKELY (key == NULL || y == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DH)) return FALSE;

  r_mpint_set (y, &((const RDhPubKey *)key)->y);
  return TRUE;
}

rboolean
r_dh_priv_key_get_x (const RCryptoKey * key, rmpint * x)
{
  if (R_UNLIKELY (key == NULL || x == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DH)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (x, &((const RDhPrivKey *)key)->x);
  return TRUE;
}

RCryptoResult
r_dh_compute_shared (const RCryptoKey * priv, const RCryptoKey * peer_pub,
    ruint8 * out, rsize * outsize)
{
  const RDhPrivKey * me;
  const RDhPubKey * peer;
  rmpint shared, p_1;
  rsize pbytes;
  RCryptoResult ret;

  if (R_UNLIKELY (priv == NULL || peer_pub == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (out == NULL || outsize == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (priv->algo->algo != R_CRYPTO_ALGO_DH))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (peer_pub->algo->algo != R_CRYPTO_ALGO_DH))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (priv->type != R_CRYPTO_PRIVATE_KEY))
    return R_CRYPTO_WRONG_TYPE;

  me = (const RDhPrivKey *)priv;
  peer = (const RDhPubKey *)peer_pub;

  /* The two sides must share the same group; otherwise the shared secret
   * is meaningless and the modexp may even succeed silently. */
  if (r_mpint_cmp (&me->pub.p, &peer->p) != 0 ||
      r_mpint_cmp (&me->pub.g, &peer->g) != 0)
    return R_CRYPTO_WRONG_TYPE;

  pbytes = (r_mpint_bits_used (&me->pub.p) + 7) / 8;
  if (*outsize < pbytes)
    return R_CRYPTO_BUFFER_TOO_SMALL;

  /* Reject peer pubkeys that fall outside (1, p-1). These would either
   * trivially leak the secret (y in {0, 1, p-1}) or have to come from a
   * non-conformant party — drop them rather than compute. */
  r_mpint_init (&p_1);
  r_mpint_sub_i32 (&p_1, &me->pub.p, 1);
  if (r_mpint_cmp_i32 (&peer->y, 1) <= 0 || r_mpint_cmp (&peer->y, &p_1) >= 0) {
    r_mpint_clear (&p_1);
    return R_CRYPTO_INVAL;
  }
  r_mpint_clear (&p_1);

  r_mpint_init (&shared);
  if (!r_mpint_expmod (&shared, &peer->y, &me->x, &me->pub.p)) {
    ret = R_CRYPTO_ERROR;
  } else if (!r_mpint_to_binary_with_size (&shared, out, pbytes)) {
    ret = R_CRYPTO_ERROR;
  } else {
    *outsize = pbytes;
    ret = R_CRYPTO_OK;
  }
  r_mpint_clear (&shared);

  return ret;
}

RCryptoKey *
r_dh_priv_key_new_from_asn1 (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  RDhPrivKey * ret;

  if (R_UNLIKELY (dec == NULL || tlv == NULL))
    return NULL;
  if ((ret = r_mem_new (RDhPrivKey)) == NULL)
    return NULL;

  r_mpint_init (&ret->pub.p);
  r_mpint_init (&ret->pub.g);
  r_mpint_init (&ret->pub.y);
  r_mpint_init_secure (&ret->x);

  /* DHPrivateKey ::= SEQUENCE { ver INTEGER, p INTEGER, g INTEGER, x INTEGER }
   * Caller positioned the decoder at the wrapping SEQUENCE. */
  if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK ||
      r_asn1_bin_tlv_parse_integer_i32 (tlv, &ret->ver) != R_ASN1_DECODER_OK ||
      r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
      r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.p) != R_ASN1_DECODER_OK ||
      r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
      r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.g) != R_ASN1_DECODER_OK ||
      r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
      r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->x) != R_ASN1_DECODER_OK) {
    r_dh_priv_key_free (ret);
    return NULL;
  }

  /* Recover y from (g, x, p) so the caller has a complete key without
   * having to compute it themselves. */
  if (!r_mpint_expmod (&ret->pub.y, &ret->pub.g, &ret->x, &ret->pub.p)) {
    r_dh_priv_key_free (ret);
    return NULL;
  }

  r_dh_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.p));
  return (RCryptoKey *)ret;
}

rboolean
r_dh_named_group_get_params (RDhNamedGroup group, rmpint * p, rmpint * g)
{
  const RDhGroupParams * gp;

  if (R_UNLIKELY (group < 0 || group >= R_DH_GROUP_COUNT))
    return FALSE;
  if (R_UNLIKELY (p == NULL || g == NULL))
    return FALSE;

  gp = &g__dh_groups[group];
  r_mpint_init_binary (p, gp->p, gp->p_len);
  r_mpint_init (g);
  r_mpint_set_u32 (g, gp->g);
  return TRUE;
}

RCryptoKey *
r_dh_priv_key_new_gen_named (RDhNamedGroup group, RPrng * prng)
{
  rmpint p, g;
  RCryptoKey * ret;

  if (!r_dh_named_group_get_params (group, &p, &g))
    return NULL;
  ret = r_dh_priv_key_new_gen (&p, &g, prng);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
  return ret;
}
