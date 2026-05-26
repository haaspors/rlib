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

#include <rlib/asn1/rasn1.h>
#include <rlib/asn1/roid.h>
#include <rlib/rmem.h>
#include <rlib/rrand.h>

/* ECC keys keep two parallel representations: the raw SEC 1 octet
 * string the key was constructed from (for ASN.1 round-trips and
 * fingerprinting), and a parsed (curve, Q[, d]) view used by the math
 * code paths. `has_math` says whether the parsed view is populated;
 * private keys with no accompanying public point still get curve + d
 * but no Q. */
typedef struct {
  RCryptoKey key;
  REcurveID namedcurve;

  REcurve curve;
  REcurveAffinePoint Q;
  rboolean has_math;

  rsize ecpsize;
  ruint8 * ecp;
} REccPubKey;

typedef struct {
  REccPubKey pub;

  rmpint d;
  rboolean has_d;

  rsize scalarsize;
  ruint8 * scalar;

  /* Mod-n Montgomery context cached for r_ecdsa_sign: precomputing the
   * ctx + R^2 + (n-2) Fermat exponent + d in Mont form means each
   * signature pays one fixed-iteration scalar-mul plus one CT
   * invmod_mont, with no per-call Mont setup. Populated by
   * r_ecdsa_priv_key_precompute_cache when the key is constructed as
   * an ECDSA key on a math-capable curve; has_ecdsa_cache flags that
   * setup succeeded. Unused for ECDH keys. */
  RMpintFEMontCtx ctx_n;
  RMpintFE mont_r_sq_n;
  RMpintFE n_minus_2_fe;
  RMpintFE d_M;
  ruint n_minus_2_bits;
  ruint n_bits;
  rboolean has_ecdsa_cache;
} REccPrivKey;

/* Forward declarations - the algo-info structs in the key-init helpers
 * below reference these, and the bodies live further down so the
 * cache-aware sign / verify code sits next to the cache populate. The
 * ASN.1 export wrappers are similarly forward-declared so all the
 * algo-info structs in the same compilation unit can name them. */
static RCryptoResult r_ecdsa_sign (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize);
static RCryptoResult r_ecdsa_verify (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize);
static RCryptoResult r_ecdsa_pub_key_export (const RCryptoKey * key,
    RAsn1BinEncoder * enc);
static RCryptoResult r_ecdsa_priv_key_export (const RCryptoKey * key,
    RAsn1BinEncoder * enc);
static RCryptoResult r_ecdh_pub_key_export (const RCryptoKey * key,
    RAsn1BinEncoder * enc);
static RCryptoResult r_ecdh_priv_key_export (const RCryptoKey * key,
    RAsn1BinEncoder * enc);

/* Priv-key algo-info tables. Hoisted to file scope so the two
 * construction paths (r_ecc_priv_key_new_full and r_ecdh_priv_key_new_gen)
 * pick up the same table without duplicating the definition. */
static const RCryptoAlgoInfo g_ecdsa_priv_key_info = {
  R_CRYPTO_ALGO_ECDSA, R_ECDSA_STR,
  NULL, NULL, r_ecdsa_sign, r_ecdsa_verify, r_ecdsa_priv_key_export
};
static const RCryptoAlgoInfo g_ecdh_priv_key_info = {
  R_CRYPTO_ALGO_ECDH, R_ECDH_STR,
  NULL, NULL, NULL, NULL, r_ecdh_priv_key_export
};

static void
r_ecc_pub_key_free (rpointer data)
{
  REccPubKey * key;

  if ((key = data) != NULL) {
    if (key->has_math) {
      r_ecurve_point_clear (&key->Q);
      r_ecurve_clear (&key->curve);
    }
    r_free (key->ecp);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

/* Decode `ecp` as a SEC 1 uncompressed point and validate it sits on
 * the named curve. Populates pub->curve / pub->Q / pub->has_math.
 * Returns FALSE if the curve is unsupported, the encoding is bad, or
 * the point isn't on the curve. */
static rboolean
r_ecc_pub_key_load_point (REccPubKey * pub, REcurveID curve,
    const ruint8 * ecp, rsize ecpsize)
{
  if (!r_ecurve_init (&pub->curve, curve))
    return FALSE;

  r_ecurve_point_init (&pub->Q);
  if (!r_ecurve_point_from_uncompressed (ecp, ecpsize, &pub->curve, &pub->Q)) {
    r_ecurve_point_clear (&pub->Q);
    r_ecurve_clear (&pub->curve);
    return FALSE;
  }

  pub->has_math = TRUE;
  return TRUE;
}

static void
r_ecdsa_pub_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo ecdsa_pub_key_info = {
    R_CRYPTO_ALGO_ECDSA, R_ECDSA_STR,
    NULL, NULL, NULL, r_ecdsa_verify, r_ecdsa_pub_key_export
  };

  r_ref_init (key, r_ecc_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = &ecdsa_pub_key_info;
  key->bits = bits;
}

RCryptoKey *
r_ecdsa_pub_key_new (REcurveID curve, rconstpointer ecp, rsize ecpsize)
{
  REccPubKey * ret;

  if (ecp == NULL || ecpsize == 0) return NULL;
  if ((ret = r_mem_new0 (REccPubKey)) == NULL) return NULL;
  if ((ret->ecp = r_memdup (ecp, ecpsize)) == NULL) {
    r_free (ret);
    return NULL;
  }

  ret->namedcurve = curve;
  ret->ecpsize = ecpsize;
  /* On-curve validation is best-effort here: ECDSA test fixtures may
   * pre-date the math layer or use encodings we don't support yet
   * (e.g. compressed). Keep the byte-only key around so existing
   * ASN.1 / cert tests keep loading, and let ECDSA-math consumers
   * check has_math when they need it. */
  r_ecc_pub_key_load_point (ret, curve, ecp, ecpsize);
  r_ecdsa_pub_key_init (&ret->key, (ruint)(ecpsize * 8));

  return (RCryptoKey *)ret;
}

static void
r_ecdh_pub_key_init (RCryptoKey * key, ruint bits)
{
  static const RCryptoAlgoInfo ecdh_pub_key_info = {
    R_CRYPTO_ALGO_ECDH, R_ECDH_STR,
    NULL, NULL, NULL, NULL, r_ecdh_pub_key_export
  };

  r_ref_init (key, r_ecc_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = &ecdh_pub_key_info;
  key->bits = bits;
}

RCryptoKey *
r_ecdh_pub_key_new (REcurveID curve, rconstpointer ecp, rsize ecpsize)
{
  REccPubKey * ret;

  if (ecp == NULL || ecpsize == 0) return NULL;
  if ((ret = r_mem_new0 (REccPubKey)) == NULL) return NULL;

  /* ECDH always uses the math layer for compute_shared, so the point
   * must parse and validate. */
  if (!r_ecc_pub_key_load_point (ret, curve, ecp, ecpsize)) {
    r_free (ret);
    return NULL;
  }
  if ((ret->ecp = r_memdup (ecp, ecpsize)) == NULL) {
    r_ecurve_point_clear (&ret->Q);
    r_ecurve_clear (&ret->curve);
    r_free (ret);
    return NULL;
  }

  ret->namedcurve = curve;
  ret->ecpsize = ecpsize;
  r_ecdh_pub_key_init (&ret->key, (ruint)(ecpsize * 8));

  return (RCryptoKey *)ret;
}

REcurveID
r_ecc_key_get_curve (const RCryptoKey * key)
{
  if (R_UNLIKELY (key == NULL)) return R_ECURVE_ID_NONE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ECDSA &&
        key->algo->algo != R_CRYPTO_ALGO_ECDH))
    return R_ECURVE_ID_NONE;

  return ((const REccPubKey *)key)->namedcurve;
}

static void
r_ecc_priv_key_free (rpointer data)
{
  REccPrivKey * key;

  if ((key = data) != NULL) {
    if (key->has_ecdsa_cache) {
      /* The cached Mont fields hold values derived from the secret d
       * (and the long-term curve order); wipe before freeing so they
       * don't linger on the heap after the key is released. */
      r_memclear_secure (&key->ctx_n, sizeof (key->ctx_n));
      r_memclear_secure (&key->mont_r_sq_n, sizeof (key->mont_r_sq_n));
      r_memclear_secure (&key->n_minus_2_fe, sizeof (key->n_minus_2_fe));
      r_memclear_secure (&key->d_M, sizeof (key->d_M));
    }
    if (key->has_d) {
      r_mpint_clear (&key->d);
    }
    if (key->pub.has_math) {
      r_ecurve_point_clear (&key->pub.Q);
      r_ecurve_clear (&key->pub.curve);
    }
    if (key->scalar != NULL) {
      r_memclear_secure (key->scalar, key->scalarsize);
      r_free (key->scalar);
    }
    r_free (key->pub.ecp);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

/* Load the scalar bytes into priv->d. When no explicit public point
 * is supplied, attempt r_ecurve_init on the named curve; if it
 * succeeds, derive Q = d * G so subsequent sign / verify / shared-
 * secret paths can use the parsed key without an out-of-line ecp
 * dance. derive_q_if_needed only controls the failure semantics
 * when the math layer can't load the curve: TRUE for ECDH (which
 * needs Q to do anything useful, so we refuse the construction),
 * FALSE for ECDSA (which keeps the lenient raw-bytes-only fallback
 * so ASN.1 / cert fixtures on unsupported curves still parse).
 * Range-checks d to [1, n-1] whenever math is available; returns
 * FALSE on a scalar that isn't a valid private key for the curve. */
static rboolean
r_ecc_priv_key_load_scalar (REccPrivKey * priv, REcurveID curve,
    const ruint8 * scalar, rsize scalarsize, rboolean derive_q_if_needed)
{
  r_mpint_init_secure (&priv->d);
  r_mpint_set_binary (&priv->d, scalar, scalarsize);

  if (priv->pub.has_math) {
    /* Public point already loaded; just range-check d against the
     * curve order that came with it. */
    if (r_mpint_cmp_i32 (&priv->d, 1) < 0 ||
        r_mpint_cmp (&priv->d, &priv->pub.curve.n) >= 0) {
      r_mpint_clear (&priv->d);
      return FALSE;
    }
    /* For ECDH (derive_q_if_needed == TRUE), also verify Q == d * G.
     * The caller has handed us both halves of a keypair and we have
     * everything we need to confirm they actually match - refusing
     * mismatched (ecp, scalar) inputs at construction beats deferring
     * the inconsistency to compute_shared. ECDSA stays lenient (we
     * accept whatever ASN.1 / cert decoders hand in). */
    if (derive_q_if_needed) {
      REcurveAffinePoint Qd;
      rboolean match;
      r_ecurve_point_init (&Qd);
      match = r_ecurve_point_scalar_mul (&Qd, &priv->d,
                  &priv->pub.curve.G, &priv->pub.curve) &&
              !Qd.is_infinity &&
              r_mpint_cmp (&Qd.x, &priv->pub.Q.x) == 0 &&
              r_mpint_cmp (&Qd.y, &priv->pub.Q.y) == 0;
      r_ecurve_point_clear (&Qd);
      if (!match) {
        r_mpint_clear (&priv->d);
        return FALSE;
      }
    }
  } else {
    /* No ecp was parsed. Try to load the math layer regardless of
     * algorithm; if the curve is supported, derive Q from d so the
     * subsequent sign / verify / compute_shared paths can use it.
     * For ECDH math is mandatory (a usable key requires Q); we
     * refuse the construction if init fails. For ECDSA we keep the
     * lenient fallback - some ASN.1 / cert tests carry keys on
     * curves the math layer can't yet decode, and those should
     * still parse as raw-d-only. */
    if (r_ecurve_init (&priv->pub.curve, curve)) {
      if (r_mpint_cmp_i32 (&priv->d, 1) < 0 ||
          r_mpint_cmp (&priv->d, &priv->pub.curve.n) >= 0) {
        r_ecurve_clear (&priv->pub.curve);
        r_mpint_clear (&priv->d);
        return FALSE;
      }
      r_ecurve_point_init (&priv->pub.Q);
      if (!r_ecurve_point_scalar_mul (&priv->pub.Q, &priv->d,
            &priv->pub.curve.G, &priv->pub.curve)) {
        r_ecurve_point_clear (&priv->pub.Q);
        r_ecurve_clear (&priv->pub.curve);
        r_mpint_clear (&priv->d);
        return FALSE;
      }
      priv->pub.has_math = TRUE;
    } else if (derive_q_if_needed) {
      r_mpint_clear (&priv->d);
      return FALSE;
    }
  }

  priv->has_d = TRUE;
  return TRUE;
}

/* Populate the per-key Mont-mod-n cache used by r_ecdsa_sign. Returns
 * FALSE if the math layer isn't loaded (unsupported curve, or no ecp
 * supplied at construction and the curve never got initialised) or
 * if the order n is even / oversized for the FE storage. The caller
 * sets pk->has_ecdsa_cache on success - if this returns FALSE the
 * key is still usable for things that don't need the cache (parsing,
 * ECDH, etc.), it just can't sign. */
static rboolean
r_ecdsa_priv_key_precompute_cache (REccPrivKey * pk)
{
  rmpint n_minus_2;
  RMpintFE d_fe;
  rboolean ok = FALSE;

  if (!pk->pub.has_math || !pk->has_d)
    return FALSE;

  if (!r_mpint_fe_mont_ctx_init (&pk->ctx_n, &pk->pub.curve.n))
    return FALSE;
  if (!r_mpint_fe_compute_r_squared (&pk->mont_r_sq_n, &pk->pub.curve.n,
        pk->ctx_n.n_digits))
    return FALSE;

  r_mpint_init (&n_minus_2);
  if (r_mpint_sub_i32 (&n_minus_2, &pk->pub.curve.n, 2)) {
    r_mpint_fe_from_mpint (&pk->n_minus_2_fe, &n_minus_2, pk->ctx_n.n_digits);
    pk->n_minus_2_bits = r_mpint_bits_used (&n_minus_2);
    pk->n_bits = r_mpint_bits_used (&pk->pub.curve.n);

    /* d is already range-checked to [1, n-1] by r_ecc_priv_key_load_scalar,
     * so the FE conversion + Mont lift below is well-defined. */
    r_mpint_fe_from_mpint (&d_fe, &pk->d, pk->ctx_n.n_digits);
    r_mpint_fe_mont_in (&pk->d_M, &d_fe, &pk->mont_r_sq_n, &pk->ctx_n);
    r_memclear_secure (&d_fe, sizeof (d_fe));
    ok = TRUE;
  }
  r_mpint_clear (&n_minus_2);
  return ok;
}

/* SEC 1 §4.1.4 step 5 / FIPS 186-4 §6.4: the integer e fed to the
 * sign / verify equations is formed from the leftmost min(N, hashlen)
 * bits of the message hash, where N is the bit length of n. Same
 * truncation rule DSA uses; rdsa.c carries a private copy of this
 * helper - kept local here so recc.c doesn't reach across the layer
 * for a one-screen utility that's unlikely to change. */
static void
r_ecdsa_hash_to_mpint (rmpint * e, const rmpint * n,
    const ruint8 * hash, rsize hashsize)
{
  ruint nbits = r_mpint_bits_used (n);
  rsize hashbits = hashsize * 8;
  rsize use_bits = nbits < hashbits ? nbits : hashbits;
  rsize use_bytes = (use_bits + 7) / 8;

  r_mpint_init_binary (e, hash, use_bytes);
  if ((use_bits & 7) != 0)
    r_mpint_shr (e, e, 8 - (use_bits & 7));
}

/* Decode Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
 * (RFC 5480 §2.2 references RFC 3279 §2.2.3 for the exact ASN.1 -
 * structurally identical to DSA's Dss-Sig-Value). DER-mandated;
 * minimum-byte INTEGER encoding is enforced to close a malleability
 * gap an unstrict decoder would open. */
static rboolean
r_ecdsa_decode_sig (rconstpointer sig, rsize sigsize, rmpint * r, rmpint * s)
{
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rboolean ok = FALSE;

  if ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, sig, sigsize)) == NULL)
    return FALSE;

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
r_ecdsa_sign (const RCryptoKey * key, RPrng * prng, RMsgDigestType mdtype,
    rconstpointer hash, rsize hashsize, rpointer sig, rsize * sigsize)
{
  const REccPrivKey * pk = (const REccPrivKey *)key;
  REcurveAffinePoint kG;
  rmpint k, r, s, e;
  RMpintFE k_fe, k_M, kinv_M, e_fe, e_M, r_fe, r_M;
  RMpintFE dr_M, er_M, s_M, s_fe;
  ruint8 id = R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  RAsn1BinEncoder * enc = NULL;
  ruint8 * sigbuf = NULL;
  rsize nbytes, kbytes, sigbufsize;
  ruint8 * kbuf;
  rboolean own_prng = FALSE;
  rboolean ok = FALSE;
  RCryptoResult ret;

  (void) mdtype;  /* ECDSA signs the raw hash; mdtype is informational. */

  if (R_UNLIKELY (key->type != R_CRYPTO_PRIVATE_KEY))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (hash == NULL || hashsize == 0 || sig == NULL || sigsize == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (!pk->has_ecdsa_cache))
    return R_CRYPTO_NOT_AVAILABLE;

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL)
      return R_CRYPTO_ERROR;
    own_prng = TRUE;
  } else {
    r_prng_ref (prng);
  }

  /* FIPS 186-4 Appendix B.5.1 "Extra Random Bits": sample N+64 uniform
   * bits and reduce mod n to drive the residual bias on k below 2^-64.
   * The naive "sample N bits then reduce" path skews the low end of
   * [1, n-1] and stacks across signatures - same fix DSA uses. */
  nbytes = (r_mpint_bits_used (&pk->pub.curve.n) + 7) / 8;
  kbytes = nbytes + 8;
  kbuf = r_alloca (kbytes);

  r_mpint_init_secure (&k);
  r_mpint_init (&r);
  r_mpint_init (&s);
  r_ecdsa_hash_to_mpint (&e, &pk->pub.curve.n, hash, hashsize);
  r_ecurve_point_init (&kG);

  /* e is loop-invariant (no dependency on k) so the FE / Mont lift is
   * a once-off above the retry. */
  r_mpint_fe_from_mpint (&e_fe, &e, pk->ctx_n.n_digits);
  r_mpint_fe_mont_in (&e_M, &e_fe, &pk->mont_r_sq_n, &pk->ctx_n);

  for (;;) {
    do {
      if (!r_prng_fill (prng, kbuf, kbytes))
        goto cleanup;
      r_mpint_set_binary (&k, kbuf, kbytes);
      if (!r_mpint_mod (&k, &k, &pk->pub.curve.n))
        goto cleanup;
    } while (r_mpint_iszero (&k));

    /* r = x-coordinate of k*G mod n. The CT scalar-mul iterates a
     * fixed bit count (curve order's bit length + 1) regardless of
     * k's actual value, so the timing doesn't leak k's bit length. */
    if (!r_ecurve_point_scalar_mul (&kG, &k, &pk->pub.curve.G, &pk->pub.curve))
      goto cleanup;
    if (kG.is_infinity)
      continue;
    if (!r_mpint_mod (&r, &kG.x, &pk->pub.curve.n))
      goto cleanup;
    if (r_mpint_iszero (&r))
      continue;

    /* CT s = k^-1 * (e + d*r) mod n. Fermat inversion via the FE
     * primitives so k^-1 doesn't leak; same shape as the DSA s
     * computation (with d / n / e replacing x / q / z). */
    r_mpint_fe_from_mpint (&k_fe, &k, pk->ctx_n.n_digits);
    r_mpint_fe_from_mpint (&r_fe, &r, pk->ctx_n.n_digits);
    r_mpint_fe_mont_in (&k_M, &k_fe, &pk->mont_r_sq_n, &pk->ctx_n);
    r_mpint_fe_mont_in (&r_M, &r_fe, &pk->mont_r_sq_n, &pk->ctx_n);
    r_mpint_fe_invmod_mont (&kinv_M, &k_M, &pk->n_minus_2_fe,
        pk->n_minus_2_bits, &pk->mont_r_sq_n, &pk->ctx_n);
    r_mpint_fe_mul_mont (&dr_M, &pk->d_M, &r_M, &pk->ctx_n);
    r_mpint_fe_add (&er_M, &e_M, &dr_M, &pk->ctx_n);
    r_mpint_fe_mul_mont (&s_M, &kinv_M, &er_M, &pk->ctx_n);
    r_mpint_fe_mont_out (&s_fe, &s_M, &pk->ctx_n);
    if (!r_mpint_fe_to_mpint (&s, &s_fe, pk->ctx_n.n_digits))
      goto cleanup;
    if (!r_mpint_iszero (&s))
      break;
  }

  /* Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER } */
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
  r_mpint_clear (&r);
  r_mpint_clear (&s);
  r_mpint_clear (&e);
  r_ecurve_point_clear (&kG);
  /* Inline-storage FE temporaries derived from k live on the stack
   * and would survive the function frame until overwritten; wipe
   * them explicitly. The key-cached fields (ctx_n / mont_r_sq_n /
   * n_minus_2_fe / d_M) stay with the key and get wiped in
   * r_ecc_priv_key_free. */
  r_memclear_secure (&k_fe, sizeof (k_fe));
  r_memclear_secure (&k_M, sizeof (k_M));
  r_memclear_secure (&kinv_M, sizeof (kinv_M));
  r_memclear_secure (&e_fe, sizeof (e_fe));
  r_memclear_secure (&e_M, sizeof (e_M));
  r_memclear_secure (&r_fe, sizeof (r_fe));
  r_memclear_secure (&r_M, sizeof (r_M));
  r_memclear_secure (&dr_M, sizeof (dr_M));
  r_memclear_secure (&er_M, sizeof (er_M));
  r_memclear_secure (&s_M, sizeof (s_M));
  r_memclear_secure (&s_fe, sizeof (s_fe));
  r_prng_unref (prng);
  (void) own_prng;
  return ret;
}

static RCryptoResult
r_ecdsa_verify (const RCryptoKey * key, RMsgDigestType mdtype,
    rconstpointer hash, rsize hashsize, rconstpointer sig, rsize sigsize)
{
  /* The pub key carries the curve / generator / Q. Priv keys also
   * route through here (RCryptoAlgoInfo::verify is shared on both
   * info structs), so cast through the pub view either way. */
  const REccPubKey * pk = (const REccPubKey *)key;
  rmpint r, s, e, w, u1, u2, x_mod_n;
  REcurveAffinePoint u1G, u2Q, P;
  RCryptoResult ret = R_CRYPTO_VERIFY_FAILED;

  (void) mdtype;

  if (R_UNLIKELY (hash == NULL || hashsize == 0 || sig == NULL || sigsize == 0))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (!pk->has_math))
    return R_CRYPTO_NOT_AVAILABLE;
  if (R_UNLIKELY (pk->Q.is_infinity))
    return R_CRYPTO_VERIFY_FAILED;

  if (!r_ecdsa_decode_sig (sig, sigsize, &r, &s))
    return R_CRYPTO_VERIFY_FAILED;

  /* Range check: r, s in [1, n-1]. */
  if (r_mpint_cmp_i32 (&r, 1) < 0 || r_mpint_cmp (&r, &pk->curve.n) >= 0 ||
      r_mpint_cmp_i32 (&s, 1) < 0 || r_mpint_cmp (&s, &pk->curve.n) >= 0)
    goto out;

  r_ecdsa_hash_to_mpint (&e, &pk->curve.n, hash, hashsize);
  r_mpint_init (&w);
  r_mpint_init (&u1);
  r_mpint_init (&u2);
  r_mpint_init (&x_mod_n);
  r_ecurve_point_init (&u1G);
  r_ecurve_point_init (&u2Q);
  r_ecurve_point_init (&P);

  /* P = u1*G + u2*Q where u1 = e*w, u2 = r*w, w = s^-1 mod n. Valid
   * iff P is finite and P.x mod n == r. Variable-time throughout -
   * all inputs are public so no CT requirement. */
  if (r_mpint_invmod (&w, &s, &pk->curve.n) &&
      r_mpint_mul (&u1, &e, &w) && r_mpint_mod (&u1, &u1, &pk->curve.n) &&
      r_mpint_mul (&u2, &r, &w) && r_mpint_mod (&u2, &u2, &pk->curve.n) &&
      r_ecurve_point_scalar_mul (&u1G, &u1, &pk->curve.G, &pk->curve) &&
      r_ecurve_point_scalar_mul (&u2Q, &u2, &pk->Q, &pk->curve) &&
      r_ecurve_point_add (&P, &u1G, &u2Q, &pk->curve) &&
      !P.is_infinity &&
      r_mpint_mod (&x_mod_n, &P.x, &pk->curve.n) &&
      r_mpint_cmp (&x_mod_n, &r) == 0) {
    ret = R_CRYPTO_OK;
  }

  r_mpint_clear (&e);
  r_mpint_clear (&w);
  r_mpint_clear (&u1);
  r_mpint_clear (&u2);
  r_mpint_clear (&x_mod_n);
  r_ecurve_point_clear (&u1G);
  r_ecurve_point_clear (&u2Q);
  r_ecurve_point_clear (&P);

out:
  r_mpint_clear (&r);
  r_mpint_clear (&s);
  return ret;
}

/* ---- ASN.1 export (RFC 5480 SubjectPublicKeyInfo for pub keys,
 * RFC 5958 OneAsymmetricKey + RFC 5915 ECPrivateKey for priv keys).
 * ECDSA and ECDH differ only in the AlgorithmIdentifier OID; share
 * one helper per side, dispatch on the OID. ---- */

/* Emit an OID TLV with an explicit byte length. The library's
 * r_asn1_bin_encoder_add_oid_rawsz uses strlen, which truncates
 * mid-OID for any OID containing an embedded NUL (which several of
 * the ECC curve OIDs do: SECP224R1 / 384R1 / 521R1 / 192K1 / 224K1
 * / 256K1 all have \x00 in their encoding). */
static RAsn1EncoderStatus
r_ecc_encoder_add_oid (RAsn1BinEncoder * enc, const ruint8 * oid, rsize size)
{
  ruint8 id_oid = R_ASN1_ID (R_ASN1_ID_UNIVERSAL,
      R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OBJECT_IDENTIFIER);
  return r_asn1_bin_encoder_add_raw (enc, id_oid, oid, size);
}

static RCryptoResult
r_ecc_pub_key_export_with_algo_oid (const RCryptoKey * key,
    RAsn1BinEncoder * enc, const ruint8 * algo_oid, rsize algo_oid_size)
{
  const REccPubKey * pk = (const REccPubKey *)key;
  ruint8 id_seq = R_ASN1_ID (R_ASN1_ID_UNIVERSAL,
      R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  const ruint8 * curve_oid;
  rsize curve_oid_size;
  RCryptoResult ret = R_CRYPTO_ERROR;

  if (R_UNLIKELY (pk->ecp == NULL || pk->ecpsize == 0))
    return R_CRYPTO_NOT_AVAILABLE;
  if ((curve_oid = r_ecurve_oid_from_id (pk->namedcurve, &curve_oid_size)) == NULL)
    return R_CRYPTO_NOT_AVAILABLE;

  /* SubjectPublicKeyInfo ::= SEQUENCE {
   *   algorithm AlgorithmIdentifier { algo_oid, named-curve OID },
   *   subjectPublicKey BIT STRING (SEC 1 uncompressed point bytes) } */
  if (r_asn1_bin_encoder_begin_constructed (enc, id_seq, 0) != R_ASN1_ENCODER_OK)
    return R_CRYPTO_ERROR;
  if (r_asn1_bin_encoder_begin_constructed (enc, id_seq, 0) == R_ASN1_ENCODER_OK) {
    if (r_ecc_encoder_add_oid (enc, algo_oid, algo_oid_size) == R_ASN1_ENCODER_OK &&
        r_ecc_encoder_add_oid (enc, curve_oid, curve_oid_size) == R_ASN1_ENCODER_OK) {
      r_asn1_bin_encoder_end_constructed (enc);
      if (r_asn1_bin_encoder_add_bit_string_raw (enc, pk->ecp, pk->ecpsize)
          == R_ASN1_ENCODER_OK)
        ret = R_CRYPTO_OK;
    } else {
      r_asn1_bin_encoder_end_constructed (enc);
    }
  }
  r_asn1_bin_encoder_end_constructed (enc);
  return ret;
}

#define R_ECC_OID_LITERAL(macro)  ((const ruint8 *)(macro)), (sizeof (macro) - 1)

static RCryptoResult
r_ecdsa_pub_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  return r_ecc_pub_key_export_with_algo_oid (key, enc,
      R_ECC_OID_LITERAL (R_X9_62_OID_EC_PUB_KEY));
}

static RCryptoResult
r_ecdh_pub_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  return r_ecc_pub_key_export_with_algo_oid (key, enc,
      R_ECC_OID_LITERAL (R_CERTICOM_OID_ECDH_PUB_KEY));
}

/* Build the inner ECPrivateKey SEQUENCE (RFC 5915) for the given
 * private key into a fresh DER buffer. Caller r_free's *buf on
 * success. The optional [0] curve OID is omitted (the outer
 * PKCS#8 AlgorithmIdentifier already carries it, which is what the
 * matching decoder reads); the optional [1] BIT STRING pubkey is
 * included when the key's ecp bytes are available, so external
 * libraries that need it round-trip the full payload. */
static rboolean
r_ecc_build_ec_private_key_der (const REccPrivKey * pk,
    ruint8 ** buf, rsize * size)
{
  RAsn1BinEncoder * inner;
  ruint8 id_seq = R_ASN1_ID (R_ASN1_ID_UNIVERSAL,
      R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  ruint8 id_octet = R_ASN1_ID (R_ASN1_ID_UNIVERSAL,
      R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OCTET_STRING);
  ruint8 id_ctx1_constructed = R_ASN1_ID (R_ASN1_ID_CONTEXT,
      R_ASN1_ID_CONSTRUCTED, 1);
  rboolean ok = FALSE;

  *buf = NULL;
  *size = 0;
  if ((inner = r_asn1_bin_encoder_new (R_ASN1_DER)) == NULL)
    return FALSE;

  if (r_asn1_bin_encoder_begin_constructed (inner, id_seq, 0)
      == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_integer_i32 (inner, 1) == R_ASN1_ENCODER_OK &&
        r_asn1_bin_encoder_add_raw (inner, id_octet,
            pk->scalar, pk->scalarsize) == R_ASN1_ENCODER_OK) {
      ok = TRUE;
      if (pk->pub.ecp != NULL && pk->pub.ecpsize > 0) {
        if (r_asn1_bin_encoder_begin_constructed (inner,
                id_ctx1_constructed, 0) == R_ASN1_ENCODER_OK) {
          if (r_asn1_bin_encoder_add_bit_string_raw (inner,
                  pk->pub.ecp, pk->pub.ecpsize) != R_ASN1_ENCODER_OK)
            ok = FALSE;
          r_asn1_bin_encoder_end_constructed (inner);
        } else {
          ok = FALSE;
        }
      }
    }
    r_asn1_bin_encoder_end_constructed (inner);
  }

  if (ok) {
    *buf = r_asn1_bin_encoder_get_data (inner, size);
    if (*buf == NULL) ok = FALSE;
  }
  r_asn1_bin_encoder_unref (inner);
  return ok;
}

static RCryptoResult
r_ecc_priv_key_export_with_algo_oid (const RCryptoKey * key,
    RAsn1BinEncoder * enc, const ruint8 * algo_oid, rsize algo_oid_size)
{
  const REccPrivKey * pk = (const REccPrivKey *)key;
  ruint8 id_seq = R_ASN1_ID (R_ASN1_ID_UNIVERSAL,
      R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE);
  ruint8 id_octet = R_ASN1_ID (R_ASN1_ID_UNIVERSAL,
      R_ASN1_ID_PRIMITIVE, R_ASN1_ID_OCTET_STRING);
  const ruint8 * curve_oid;
  rsize curve_oid_size;
  ruint8 * ecprivkey_der = NULL;
  rsize ecprivkey_der_size = 0;
  RCryptoResult ret = R_CRYPTO_ERROR;

  if (R_UNLIKELY (pk->scalar == NULL || pk->scalarsize == 0))
    return R_CRYPTO_NOT_AVAILABLE;
  if ((curve_oid = r_ecurve_oid_from_id (pk->pub.namedcurve,
          &curve_oid_size)) == NULL)
    return R_CRYPTO_NOT_AVAILABLE;
  if (!r_ecc_build_ec_private_key_der (pk, &ecprivkey_der, &ecprivkey_der_size))
    return R_CRYPTO_ERROR;

  /* OneAsymmetricKey ::= SEQUENCE {
   *   version INTEGER (0),
   *   privateKeyAlgorithm AlgorithmIdentifier { algo_oid, named-curve OID },
   *   privateKey OCTET STRING (DER-encoded ECPrivateKey) } */
  if (r_asn1_bin_encoder_begin_constructed (enc, id_seq, 0)
      == R_ASN1_ENCODER_OK) {
    if (r_asn1_bin_encoder_add_integer_i32 (enc, 0) == R_ASN1_ENCODER_OK) {
      if (r_asn1_bin_encoder_begin_constructed (enc, id_seq, 0)
          == R_ASN1_ENCODER_OK) {
        if (r_ecc_encoder_add_oid (enc, algo_oid, algo_oid_size)
                == R_ASN1_ENCODER_OK &&
            r_ecc_encoder_add_oid (enc, curve_oid, curve_oid_size)
                == R_ASN1_ENCODER_OK) {
          r_asn1_bin_encoder_end_constructed (enc);
          if (r_asn1_bin_encoder_add_raw (enc, id_octet,
                  ecprivkey_der, ecprivkey_der_size) == R_ASN1_ENCODER_OK)
            ret = R_CRYPTO_OK;
        } else {
          r_asn1_bin_encoder_end_constructed (enc);
        }
      }
    }
    r_asn1_bin_encoder_end_constructed (enc);
  }

  r_free (ecprivkey_der);
  return ret;
}

static RCryptoResult
r_ecdsa_priv_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  return r_ecc_priv_key_export_with_algo_oid (key, enc,
      R_ECC_OID_LITERAL (R_X9_62_OID_EC_PUB_KEY));
}

static RCryptoResult
r_ecdh_priv_key_export (const RCryptoKey * key, RAsn1BinEncoder * enc)
{
  return r_ecc_priv_key_export_with_algo_oid (key, enc,
      R_ECC_OID_LITERAL (R_CERTICOM_OID_ECDH_PUB_KEY));
}

static RCryptoKey *
r_ecc_priv_key_new_full (REcurveID curve, RCryptoAlgorithm algo,
    rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize)
{
  REccPrivKey * ret;
  const rboolean is_ecdh = (algo == R_CRYPTO_ALGO_ECDH);

  if (scalar == NULL || scalarsize == 0) return NULL;
  if ((ret = r_mem_new0 (REccPrivKey)) == NULL) return NULL;

  ret->pub.namedcurve = curve;

  if (ecp != NULL && ecpsize > 0) {
    if (!r_ecc_pub_key_load_point (&ret->pub, curve, ecp, ecpsize)) {
      /* Public point given but unparseable: strict for ECDH, lenient
       * for ECDSA (same reason as the pub-key constructor). */
      if (is_ecdh)
        goto fail;
    }
    if ((ret->pub.ecp = r_memdup (ecp, ecpsize)) == NULL)
      goto fail;
    ret->pub.ecpsize = ecpsize;
  }

  if (!r_ecc_priv_key_load_scalar (ret, curve, scalar, scalarsize, is_ecdh))
    goto fail;

  if ((ret->scalar = r_memdup (scalar, scalarsize)) == NULL)
    goto fail;
  ret->scalarsize = scalarsize;

  r_ref_init (&ret->pub.key, r_ecc_priv_key_free);
  ret->pub.key.type = R_CRYPTO_PRIVATE_KEY;
  ret->pub.key.algo = is_ecdh ? &g_ecdh_priv_key_info : &g_ecdsa_priv_key_info;
  ret->pub.key.bits = (ruint) (scalarsize * 8);

  /* For ECDSA keys with the math layer loaded, populate the mod-n
   * Mont cache so r_ecdsa_sign skips the per-call setup. Failure
   * here doesn't fail the construction - keys without the cache are
   * still useful for parsing / round-tripping / verifying, they just
   * can't sign. The cache also doesn't apply to ECDH keys at all. */
  if (!is_ecdh && ret->pub.has_math) {
    if (r_ecdsa_priv_key_precompute_cache (ret))
      ret->has_ecdsa_cache = TRUE;
  }

  return (RCryptoKey *) ret;

fail:
  if (ret->has_d) r_mpint_clear (&ret->d);
  if (ret->pub.has_math) {
    r_ecurve_point_clear (&ret->pub.Q);
    r_ecurve_clear (&ret->pub.curve);
  }
  r_free (ret->pub.ecp);
  r_free (ret);
  return NULL;
}

RCryptoKey *
r_ecdsa_priv_key_new (REcurveID curve, rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize)
{
  return r_ecc_priv_key_new_full (curve, R_CRYPTO_ALGO_ECDSA,
      ecp, ecpsize, scalar, scalarsize);
}

RCryptoKey *
r_ecdh_priv_key_new (REcurveID curve, rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize)
{
  return r_ecc_priv_key_new_full (curve, R_CRYPTO_ALGO_ECDH,
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
r_ecc_key_get_q (const RCryptoKey * key, REcurveAffinePoint * q)
{
  const REccPubKey * pub;

  if (R_UNLIKELY (key == NULL || q == NULL)) return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ECDSA &&
        key->algo->algo != R_CRYPTO_ALGO_ECDH))
    return FALSE;

  pub = (const REccPubKey *) key;
  if (!pub->has_math) return FALSE;
  r_ecurve_point_copy (q, &pub->Q);
  return TRUE;
}

RCryptoKey *
r_ecdh_priv_key_new_gen (REcurveID curve, RPrng * prng)
{
  REccPrivKey * ret = NULL;
  REcurve params;
  rmpint d;
  REcurveAffinePoint Q;
  ruint8 * dbuf;
  ruint8 * ecpbuf;
  ruint8 * ecpcopy = NULL;
  ruint8 * scalarbuf = NULL;
  rsize dbytes, ecpsize;

  if (!r_ecurve_init (&params, curve))
    return NULL;

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL) {
      r_ecurve_clear (&params);
      return NULL;
    }
  } else {
    r_prng_ref (prng);
  }

  /* d carries the private scalar; mark it secure so the buffer it
   * ends up backing in the key (we hand it off by struct copy below)
   * is wiped when the key is freed. The flag survives the struct
   * copy. */
  r_mpint_init_secure (&d);
  r_ecurve_point_init (&Q);

  /* Sample d in [1, n-1] by drawing a fresh integer of the same byte
   * length as n and rejecting samples outside the half-open range.
   * For real curves with n close to a power of two this loop
   * converges immediately. */
  dbytes = (r_mpint_bits_used (&params.n) + 7) / 8;
  dbuf = r_alloca (dbytes);
  for (;;) {
    if (!r_prng_fill (prng, dbuf, dbytes))
      goto fail;
    r_mpint_set_binary (&d, dbuf, dbytes);
    if (r_mpint_cmp_i32 (&d, 1) >= 0 && r_mpint_cmp (&d, &params.n) < 0)
      break;
  }

  if (!r_ecurve_point_scalar_mul (&Q, &d, &params.G, &params))
    goto fail;

  /* Serialise Q to a fresh SEC 1 uncompressed buffer for the byte
   * representation that mirrors the externally-supplied key paths. */
  ecpsize = 1 + 2 * params.coord_bytes;
  ecpbuf = r_alloca (ecpsize);
  if (!r_ecurve_point_to_uncompressed (&Q, &params, ecpbuf, &ecpsize))
    goto fail;

  if ((ecpcopy = r_memdup (ecpbuf, ecpsize)) == NULL)
    goto fail;
  if ((scalarbuf = r_malloc (dbytes)) == NULL)
    goto fail;
  if (!r_mpint_to_binary_with_size (&d, scalarbuf, dbytes))
    goto fail;

  if ((ret = r_mem_new0 (REccPrivKey)) == NULL)
    goto fail;

  ret->pub.namedcurve = curve;
  /* Move the parsed curve / Q into the key rather than re-parsing. */
  ret->pub.curve = params;
  ret->pub.Q = Q;
  ret->pub.has_math = TRUE;
  ret->pub.ecpsize = ecpsize;
  ret->pub.ecp = ecpcopy;

  /* Move d into the key. Also record the big-endian byte form so
   * r_ecc_priv_key_get_scalar continues to work uniformly. */
  ret->d = d;
  ret->has_d = TRUE;
  ret->scalarsize = dbytes;
  ret->scalar = scalarbuf;

  r_ref_init (&ret->pub.key, r_ecc_priv_key_free);
  ret->pub.key.type = R_CRYPTO_PRIVATE_KEY;
  ret->pub.key.algo = &g_ecdh_priv_key_info;
  ret->pub.key.bits = (ruint) (dbytes * 8);

  r_memclear_secure (dbuf, dbytes);
  r_prng_unref (prng);
  return (RCryptoKey *) ret;

fail:
  r_memclear_secure (dbuf, dbytes);
  if (scalarbuf != NULL) {
    r_memclear_secure (scalarbuf, dbytes);
    r_free (scalarbuf);
  }
  r_free (ecpcopy);
  r_ecurve_point_clear (&Q);
  r_mpint_clear (&d);
  r_ecurve_clear (&params);
  r_prng_unref (prng);
  return NULL;
}

RCryptoResult
r_ecdh_compute_shared (const RCryptoKey * priv, const RCryptoKey * peer_pub,
    ruint8 * out, rsize * outsize)
{
  const REccPrivKey * me;
  const REccPubKey * peer;
  REcurveAffinePoint shared;
  RCryptoResult ret = R_CRYPTO_ERROR;

  if (R_UNLIKELY (priv == NULL || peer_pub == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (out == NULL || outsize == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (priv->algo->algo != R_CRYPTO_ALGO_ECDH ||
        peer_pub->algo->algo != R_CRYPTO_ALGO_ECDH))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (priv->type != R_CRYPTO_PRIVATE_KEY ||
        peer_pub->type != R_CRYPTO_PUBLIC_KEY))
    return R_CRYPTO_WRONG_TYPE;

  me = (const REccPrivKey *) priv;
  peer = (const REccPubKey *) peer_pub;

  if (!me->has_d || !me->pub.has_math || !peer->has_math)
    return R_CRYPTO_ERROR;
  /* Both sides must agree on the curve; otherwise the multiplication
   * happens in the wrong group and the "shared secret" is gibberish. */
  if (me->pub.namedcurve != peer->namedcurve)
    return R_CRYPTO_WRONG_TYPE;

  /* Defence in depth against invalid-curve attacks: even though the
   * key constructor validated Q at parse time, re-check that the
   * peer's point still sits on our curve and isn't the identity.
   * Note: every curve currently shipped by recurve has cofactor 1, so
   * on-curve implies in the prime-order subgroup. Adding any curve
   * with h>1 (e.g. sect163k1, edwards25519) means this also needs a
   * subgroup check: n * Q_peer == O. */
  if (peer->Q.is_infinity)
    return R_CRYPTO_INVAL;
  if (!r_ecurve_point_is_on_curve (&peer->Q, &me->pub.curve))
    return R_CRYPTO_INVAL;

  if (*outsize < me->pub.curve.coord_bytes)
    return R_CRYPTO_BUFFER_TOO_SMALL;

  r_ecurve_point_init (&shared);
  if (!r_ecurve_point_scalar_mul (&shared, &me->d, &peer->Q, &me->pub.curve))
    goto cleanup;
  /* d * Q == infinity means peer chose a point of order dividing d -
   * shouldn't happen with a real Q in the prime-order subgroup, but
   * refuse rather than emit an all-zero secret. */
  if (shared.is_infinity) {
    ret = R_CRYPTO_INVAL;
    goto cleanup;
  }

  if (!r_mpint_to_binary_with_size (&shared.x, out, me->pub.curve.coord_bytes))
    goto cleanup;

  *outsize = me->pub.curve.coord_bytes;
  ret = R_CRYPTO_OK;

cleanup:
  r_ecurve_point_clear (&shared);
  return ret;
}
