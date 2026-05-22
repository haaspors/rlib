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

#include <rlib/rmem.h>

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
} REccPrivKey;

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
    NULL, NULL, NULL, NULL, NULL
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
    NULL, NULL, NULL, NULL, NULL
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

/* Load the scalar bytes into priv->d and, if no explicit public point
 * was supplied but the curve is known and the caller wants it,
 * derive Q = d * G so ECDH private keys minted from "just the scalar"
 * still expose a usable public point. Range-checks d to [1, n-1] in
 * both branches; returns FALSE on a scalar that isn't a valid private
 * key for the curve. */
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
  } else if (derive_q_if_needed) {
    /* ECDH path with no public point on hand: we need real math.
     * Refuse outright if the curve isn't supported by the math layer
     * (returning a parsable-but-useless key would just defer the
     * failure to compute_shared). */
    if (!r_ecurve_init (&priv->pub.curve, curve)) {
      r_mpint_clear (&priv->d);
      return FALSE;
    }
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
  }
  /* else: ECDSA path with no public point - keep d as raw bytes only
   * so existing ASN.1 / cert tests using encodings the math layer
   * can't yet decode keep loading. */

  priv->has_d = TRUE;
  return TRUE;
}

static RCryptoKey *
r_ecc_priv_key_new_full (REcurveID curve, RCryptoAlgorithm algo,
    rconstpointer ecp, rsize ecpsize,
    rconstpointer scalar, rsize scalarsize)
{
  REccPrivKey * ret;
  static const RCryptoAlgoInfo ecdsa_priv_key_info = {
    R_CRYPTO_ALGO_ECDSA, R_ECDSA_STR, NULL, NULL, NULL, NULL, NULL
  };
  static const RCryptoAlgoInfo ecdh_priv_key_info = {
    R_CRYPTO_ALGO_ECDH, R_ECDH_STR, NULL, NULL, NULL, NULL, NULL
  };
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
  ret->pub.key.algo = is_ecdh ? &ecdh_priv_key_info : &ecdsa_priv_key_info;
  ret->pub.key.bits = (ruint) (scalarsize * 8);

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
  static const RCryptoAlgoInfo ecdh_priv_key_info = {
    R_CRYPTO_ALGO_ECDH, R_ECDH_STR, NULL, NULL, NULL, NULL, NULL
  };

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
  ret->pub.key.algo = &ecdh_priv_key_info;
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
