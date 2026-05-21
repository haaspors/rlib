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

#include <rlib/crypto/rdsa.h>

#include <rlib/asn1/roid.h>
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
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

/* FIPS 186-4 §4.6: the integer z fed to the sign/verify equations is
 * formed from the leftmost min(N, outlen) bits of the message hash,
 * where N is the bit length of q. The mpint is assumed uninitialised
 * on entry. */
static void
r_dsa_hash_to_mpint (rmpint * z, const rmpint * q,
    const ruint8 * hash, rsize hashsize)
{
  ruint qbits = r_mpint_bits_used (q);
  rsize hashbits = hashsize * 8;
  rsize use_bits = qbits < hashbits ? qbits : hashbits;
  rsize use_bytes = (use_bits + 7) / 8;

  r_mpint_init_binary (z, hash, use_bytes);
  if ((use_bits & 7) != 0)
    r_mpint_shr (z, z, 8 - (use_bits & 7));
}

/* Decode Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } (RFC 3279
 * §2.2.2) from sig/sigsize. Caller owns r and s; both are initialised
 * here on success. */
static rboolean
r_dsa_decode_sig (rconstpointer sig, rsize sigsize, rmpint * r, rmpint * s)
{
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rboolean ok = FALSE;

  /* RFC 3279 §2.2.2 mandates DER. */
  if ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, sig, sigsize)) == NULL)
    return FALSE;

  /* DER requires INTEGERs in their minimum-byte form: a leading 0x00
   * is allowed only when the next byte has the high bit set (would
   * otherwise be interpreted as negative). Rejecting non-minimal
   * encoding closes a signature-malleability gap. */
#define MINIMAL_POS_INT(tlv) \
    ((tlv).len >= 1 && \
     !((tlv).len >= 2 && (tlv).value[0] == 0 && ((tlv).value[1] & 0x80) == 0))

  r_mpint_init (r);
  r_mpint_init (s);
  if (r_asn1_bin_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK &&
      R_ASN1_BIN_TLV_ID_TAG (&tlv) == R_ASN1_ID_SEQUENCE &&
      tlv.value + tlv.len == (const ruint8 *)sig + sigsize &&
      r_asn1_bin_decoder_into (dec, &tlv) == R_ASN1_DECODER_OK &&
      MINIMAL_POS_INT (tlv) &&
      r_asn1_bin_tlv_parse_integer_mpint (&tlv, r) == R_ASN1_DECODER_OK &&
      r_asn1_bin_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK &&
      MINIMAL_POS_INT (tlv) &&
      r_asn1_bin_tlv_parse_integer_mpint (&tlv, s) == R_ASN1_DECODER_OK &&
      r_asn1_bin_decoder_next (dec, &tlv) == R_ASN1_DECODER_EOC) {
    ok = TRUE;
  }
#undef MINIMAL_POS_INT
  r_asn1_bin_decoder_unref (dec);
  if (!ok) {
    r_mpint_clear (r);
    r_mpint_clear (s);
  }
  return ok;
}

static RCryptoResult
r_dsa_sign (const RCryptoKey * key, RPrng * prng, RMsgDigestType mdtype,
    rconstpointer hash, rsize hashsize, rpointer sig, rsize * sigsize)
{
  const RDsaPrivKey * pk = (const RDsaPrivKey *)key;
  rmpint k, kinv, r, s, z, xr;
  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  RAsn1BinEncoder * enc = NULL;
  ruint8 * sigbuf = NULL;
  rsize qbytes, kbytes, sigbufsize;
  ruint8 * kbuf;
  rboolean own_prng = FALSE;
  rboolean ok = FALSE;
  RCryptoResult ret;

  (void) mdtype;  /* DSA signs the raw hash; mdtype is purely informational. */

  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (hash == NULL || hashsize == 0))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (r_mpint_iszero (&pk->pub.p) || r_mpint_iszero (&pk->pub.q) ||
        r_mpint_iszero (&pk->pub.g) || r_mpint_iszero (&pk->x)))
    return R_CRYPTO_INVAL;

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL)
      return R_CRYPTO_ERROR;
    own_prng = TRUE;
  } else {
    r_prng_ref (prng);
  }

  /* Sample 64 extra bits beyond q before reducing — FIPS 186-4
   * Appendix B.2.1's "Extra Random Bits" technique. Reducing N+64
   * uniform bits modulo q drops the resulting bias on k from
   * (2^N - q)/2^N down to ~2^-64, which is cryptographically
   * negligible. The naive "sample N bits then reduce" approach skews
   * the low end of [1, q-1] in a way that leaks a fraction of a bit
   * per signature and stacks across many signatures. */
  qbytes = (r_mpint_bits_used (&pk->pub.q) + 7) / 8;
  kbytes = qbytes + 8;
  kbuf = r_alloca (kbytes);

  r_mpint_init (&k);
  r_mpint_init (&kinv);
  r_mpint_init (&r);
  r_mpint_init (&s);
  r_mpint_init (&xr);
  r_dsa_hash_to_mpint (&z, &pk->pub.q, hash, hashsize);

  for (;;) {
    do {
      if (!r_prng_fill (prng, kbuf, kbytes))
        goto cleanup;
      r_mpint_set_binary (&k, kbuf, kbytes);
      if (!r_mpint_mod (&k, &k, &pk->pub.q))
        goto cleanup;
    } while (r_mpint_iszero (&k));

    /* r = (g^k mod p) mod q; retry on the (negligible) chance r == 0. */
    if (!r_mpint_expmod (&r, &pk->pub.g, &k, &pk->pub.p) ||
        !r_mpint_mod (&r, &r, &pk->pub.q))
      goto cleanup;
    if (r_mpint_iszero (&r))
      continue;

    /* s = k^-1 * (z + x * r) mod q; retry on s == 0. */
    if (!r_mpint_invmod (&kinv, &k, &pk->pub.q) ||
        !r_mpint_mul (&xr, &pk->x, &r) ||
        !r_mpint_add (&xr, &xr, &z) ||
        !r_mpint_mul (&s, &kinv, &xr) ||
        !r_mpint_mod (&s, &s, &pk->pub.q))
      goto cleanup;
    if (!r_mpint_iszero (&s))
      break;
  }

  /* Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } */
  if ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)) == NULL)
    goto cleanup;
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) != R_ASN1_ENCODER_OK)
    goto cleanup;
  if (r_asn1_bin_encoder_add_integer_mpint (enc, &r) != R_ASN1_ENCODER_OK ||
      r_asn1_bin_encoder_add_integer_mpint (enc, &s) != R_ASN1_ENCODER_OK) {
    r_asn1_bin_encoder_end_constructed (enc);
    goto cleanup;
  }
  r_asn1_bin_encoder_end_constructed (enc);

  if ((sigbuf = r_asn1_bin_encoder_get_data (enc, &sigbufsize)) == NULL)
    goto cleanup;

  if (*sigsize < sigbufsize) {
    ret = R_CRYPTO_BUFFER_TOO_SMALL;
    goto cleanup_with_ret;
  }
  r_memcpy (sig, sigbuf, sigbufsize);
  *sigsize = sigbufsize;
  ok = TRUE;

cleanup:
  ret = ok ? R_CRYPTO_OK : R_CRYPTO_SIGN_FAILED;
cleanup_with_ret:
  r_free (sigbuf);
  if (enc != NULL) r_asn1_bin_encoder_unref (enc);
  r_mpint_clear (&k);
  r_mpint_clear (&kinv);
  r_mpint_clear (&r);
  r_mpint_clear (&s);
  r_mpint_clear (&xr);
  r_mpint_clear (&z);
  r_prng_unref (prng);
  (void) own_prng;
  return ret;
}

static RCryptoResult
r_dsa_verify (const RCryptoKey * key, RMsgDigestType mdtype,
    rconstpointer hash, rsize hashsize, rconstpointer sig, rsize sigsize)
{
  const RDsaPubKey * pk = (const RDsaPubKey *)key;
  rmpint r, s, z, w, u1, u2, gu1, yu2, v;
  RCryptoResult ret = R_CRYPTO_VERIFY_FAILED;

  (void) mdtype;

  if (R_UNLIKELY (hash == NULL || hashsize == 0 || sig == NULL || sigsize == 0))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (r_mpint_iszero (&pk->p) || r_mpint_iszero (&pk->q) ||
        r_mpint_iszero (&pk->g) || r_mpint_iszero (&pk->y)))
    return R_CRYPTO_INVAL;

  if (!r_dsa_decode_sig (sig, sigsize, &r, &s))
    return R_CRYPTO_VERIFY_FAILED;

  /* Reject 0 < r < q and 0 < s < q out-of-range signatures up front. */
  if (r_mpint_iszero (&r) || r_mpint_cmp (&r, &pk->q) >= 0 ||
      r_mpint_iszero (&s) || r_mpint_cmp (&s, &pk->q) >= 0)
    goto out;

  r_dsa_hash_to_mpint (&z, &pk->q, hash, hashsize);
  r_mpint_init (&w);
  r_mpint_init (&u1);
  r_mpint_init (&u2);
  r_mpint_init (&gu1);
  r_mpint_init (&yu2);
  r_mpint_init (&v);

  /* v = ((g^u1 * y^u2) mod p) mod q  where u1 = z*w, u2 = r*w, w = s^-1 mod q */
  if (r_mpint_invmod (&w, &s, &pk->q) &&
      r_mpint_mul (&u1, &z, &w) && r_mpint_mod (&u1, &u1, &pk->q) &&
      r_mpint_mul (&u2, &r, &w) && r_mpint_mod (&u2, &u2, &pk->q) &&
      r_mpint_expmod (&gu1, &pk->g, &u1, &pk->p) &&
      r_mpint_expmod (&yu2, &pk->y, &u2, &pk->p) &&
      r_mpint_mul (&v, &gu1, &yu2) &&
      r_mpint_mod (&v, &v, &pk->p) &&
      r_mpint_mod (&v, &v, &pk->q) &&
      r_mpint_cmp (&v, &r) == 0) {
    ret = R_CRYPTO_OK;
  }

  r_mpint_clear (&z);
  r_mpint_clear (&w);
  r_mpint_clear (&u1);
  r_mpint_clear (&u2);
  r_mpint_clear (&gu1);
  r_mpint_clear (&yu2);
  r_mpint_clear (&v);

out:
  r_mpint_clear (&r);
  r_mpint_clear (&s);
  return ret;
}

static RCryptoResult
r_dsa_pub_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  RCryptoResult ret = R_CRYPTO_ERROR;
  const RDsaPubKey * pk = (const RDsaPubKey *)key;
  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);

  /* SubjectPublicKeyInfo ::= SEQUENCE {
   *   AlgorithmIdentifier { dsaEncryption, Dss-Parms { p, q, g } },
   *   BIT STRING (INTEGER y)  -- DSAPublicKey, RFC 3279 §2.3.2 */
  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) != R_ASN1_ENCODER_OK)
    return ret;

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    r_asn1_bin_encoder_add_oid_rawsz (enc, R_X9CM_OID_DSA);
    if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
      r_asn1_bin_encoder_add_integer_mpint (enc, &pk->p);
      r_asn1_bin_encoder_add_integer_mpint (enc, &pk->q);
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
r_dsa_priv_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  /* Traditional OpenSSL DSAPrivateKey payload — a single self-describing
   *   SEQUENCE { ver, p, q, g, y, x }
   * matching the import side in r_dsa_priv_key_new_from_asn1. */
  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);

  if (r_asn1_bin_encoder_begin_constructed (enc, id, 0) == R_ASN1_ENCODER_OK) {
    const RDsaPrivKey * pk = (const RDsaPrivKey *)key;
    if (r_asn1_bin_encoder_add_integer_i32 (enc, pk->ver) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.p) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.q) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.g) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->pub.y) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_integer_mpint (enc, &pk->x) == R_ASN1_ENCODER_OK) {
      r_asn1_bin_encoder_end_constructed (enc);
      return R_CRYPTO_OK;
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  return R_CRYPTO_ERROR;
}

static void
r_dsa_pub_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo dsa_pub_key_info = {
    R_CRYPTO_ALGO_DSA, R_DSA_STR,
    NULL, NULL, NULL, r_dsa_verify, r_dsa_pub_key_export
  };

  r_ref_init (key, r_dsa_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = &dsa_pub_key_info;
  key->bits = bits;
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
r_dsa_priv_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo dsa_priv_key_info = {
    R_CRYPTO_ALGO_DSA, R_DSA_STR,
    NULL, NULL, r_dsa_sign, r_dsa_verify, r_dsa_priv_key_export
  };

  r_ref_init (key, r_dsa_priv_key_free);
  key->type = R_CRYPTO_PRIVATE_KEY;
  key->algo = &dsa_priv_key_info;
  key->bits = bits;
}

RCryptoKey *
r_dsa_pub_key_new_full (const rmpint * p, const rmpint * q,
    const rmpint * g, const rmpint * y)
{
  RDsaPubKey * ret;

  if (y != NULL) {
    if ((ret = r_mem_new (RDsaPubKey)) != NULL) {
      if (p != NULL)  r_mpint_init_copy (&ret->p, p);
      else            r_mpint_init (&ret->p);
      if (q != NULL)  r_mpint_init_copy (&ret->q, q);
      else            r_mpint_init (&ret->q);
      if (g != NULL)  r_mpint_init_copy (&ret->g, g);
      else            r_mpint_init (&ret->g);
      r_mpint_init_copy (&ret->y, y);
      r_dsa_pub_key_init (&ret->key, r_mpint_bits_used (&ret->y));
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
      r_mpint_init_binary (&ret->p, p, psize);
      r_mpint_init_binary (&ret->q, q, qsize);
      r_mpint_init_binary (&ret->g, g, gsize);
      r_mpint_init_binary (&ret->y, y, ysize);
      r_dsa_pub_key_init (&ret->key, r_mpint_bits_used (&ret->y));
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
      ret->ver = 0;
      r_mpint_init_copy (&ret->pub.p, p);
      r_mpint_init_copy (&ret->pub.q, q);
      r_mpint_init_copy (&ret->pub.g, g);
      r_mpint_init_copy (&ret->pub.y, y);
      r_mpint_init_copy (&ret->x, x);
      r_dsa_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.y));
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
      ret->ver = 0;
      r_mpint_init_binary (&ret->pub.p, p, psize);
      r_mpint_init_binary (&ret->pub.q, q, qsize);
      r_mpint_init_binary (&ret->pub.g, g, gsize);
      r_mpint_init_binary (&ret->pub.y, y, ysize);
      r_mpint_init_binary (&ret->x, x, xsize);
      r_dsa_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.y));
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_dsa_priv_key_new_from_asn1 (RAsn1BinDecoder * dec, RAsn1BinTLV * tlv)
{
  RDsaPrivKey * ret;

  if ((ret = r_mem_new (RDsaPrivKey)) != NULL) {
    r_mpint_init (&ret->pub.p);
    r_mpint_init (&ret->pub.q);
    r_mpint_init (&ret->pub.g);
    r_mpint_init (&ret->pub.y);
    r_mpint_init (&ret->x);

    if (r_asn1_bin_decoder_into (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_i32 (tlv, &ret->ver) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.p) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.q) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.g) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->pub.y) != R_ASN1_DECODER_OK ||
        r_asn1_bin_decoder_next (dec, tlv) != R_ASN1_DECODER_OK ||
        r_asn1_bin_tlv_parse_integer_mpint (tlv, &ret->x) != R_ASN1_DECODER_OK) {
      r_crypto_key_unref ((RCryptoKey *)ret);
      ret = NULL;
    } else {
      r_dsa_priv_key_init (&ret->pub.key, r_mpint_bits_used (&ret->pub.y));
    }
  }

  return (RCryptoKey *)ret;
}

rboolean
r_dsa_pub_key_get_p (const RCryptoKey * key, rmpint * p)
{
  if (R_UNLIKELY (key == NULL || p == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (p, &((RDsaPubKey*)key)->p);
  return TRUE;
}

rboolean
r_dsa_pub_key_get_q (const RCryptoKey * key, rmpint * q)
{
  if (R_UNLIKELY (key == NULL || q == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (q, &((RDsaPubKey*)key)->q);
  return TRUE;
}

rboolean
r_dsa_pub_key_get_g (const RCryptoKey * key, rmpint * g)
{
  if (R_UNLIKELY (key == NULL || g == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (g, &((RDsaPubKey*)key)->g);
  return TRUE;
}

rboolean
r_dsa_pub_key_get_y (const RCryptoKey * key, rmpint * y)
{
  if (R_UNLIKELY (key == NULL || y == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DSA)) return FALSE;

  r_mpint_set (y, &((RDsaPubKey*)key)->y);
  return TRUE;
}

rboolean
r_dsa_priv_key_get_x (const RCryptoKey * key, rmpint * x)
{
  if (R_UNLIKELY (key == NULL || x == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_DSA)) return FALSE;
  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY)) return FALSE;

  r_mpint_set (x, &((RDsaPrivKey*)key)->x);
  return TRUE;
}

/* Drive RMsgDigest from mdtype over (msg, msgsize), writing the digest
 * to a caller-supplied buffer (64 bytes is enough for SHA-512).
 * Returns the digest size on success, 0 on failure. */
static rsize
r_dsa_compute_hash (RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    ruint8 * hashbuf, rsize hashbuf_max)
{
  RMsgDigest * md;
  rsize hashsize;

  if ((md = r_msg_digest_new (mdtype)) == NULL)
    return 0;
  hashsize = r_msg_digest_size (md);
  if (hashsize == 0 || hashsize > hashbuf_max ||
      !r_msg_digest_update (md, msg, msgsize) ||
      !r_msg_digest_get_data (md, hashbuf, hashsize, NULL)) {
    r_msg_digest_free (md);
    return 0;
  }
  r_msg_digest_free (md);
  return hashsize;
}

RCryptoResult
r_dsa_sign_msg_hash (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize)
{
  /* The algo->sign callback already accepts a pre-computed hash; this
   * is just a name-symmetric shortcut to match the RSA shape. */
  return r_crypto_key_sign (key, prng, mdtype, hash, hashsize, sig, sigsize);
}

RCryptoResult
r_dsa_sign_msg (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    rpointer sig, rsize * sigsize)
{
  ruint8 hash[64];
  rsize hashsize;

  if (R_UNLIKELY (msg == NULL || msgsize == 0))
    return R_CRYPTO_INVAL;
  if ((hashsize = r_dsa_compute_hash (mdtype, msg, msgsize, hash, sizeof (hash))) == 0)
    return R_CRYPTO_HASH_FAILED;
  return r_crypto_key_sign (key, prng, mdtype, hash, hashsize, sig, sigsize);
}

RCryptoResult
r_dsa_verify_msg_with_hash (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize)
{
  return r_crypto_key_verify (key, mdtype, hash, hashsize, sig, sigsize);
}

RCryptoResult
r_dsa_verify_msg (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer msg, rsize msgsize,
    rconstpointer sig, rsize sigsize)
{
  ruint8 hash[64];
  rsize hashsize;

  if (R_UNLIKELY (msg == NULL || msgsize == 0))
    return R_CRYPTO_INVAL;
  if ((hashsize = r_dsa_compute_hash (mdtype, msg, msgsize, hash, sizeof (hash))) == 0)
    return R_CRYPTO_HASH_FAILED;
  return r_crypto_key_verify (key, mdtype, hash, hashsize, sig, sigsize);
}
