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

#include <rlib/crypto/rxdh.h>

#include <rlib/rmem.h>
#include <rlib/rrand.h>

/* RFC 7748 §5: X25519 u and scalar are 32 bytes, X448 are 56. The
 * fixed-size storage in the key struct accommodates both - the actual
 * "live" length per key is curve->coord_bytes. */
#define R_XDH_MAX_COORD_BYTES   56

typedef struct {
  RCryptoKey key;
  REcurveID curve_id;
  REcurveMontgomery curve;
  rsize coord_bytes;
  ruint8 pub_u[R_XDH_MAX_COORD_BYTES];
} RXdhPubKey;

typedef struct {
  RXdhPubKey pub;
  ruint8 scalar[R_XDH_MAX_COORD_BYTES];
} RXdhPrivKey;

static rsize
r_xdh_coord_bytes_for (REcurveID curve)
{
  switch (curve) {
    case R_ECURVE_ID_X25519: return 32;
    case R_ECURVE_ID_X448:   return 56;
    default:                 return 0;
  }
}

static void
r_xdh_pub_key_free (rpointer data)
{
  RXdhPubKey * key;

  if ((key = data) != NULL) {
    r_ecurve_montgomery_clear (&key->curve);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

static void
r_xdh_priv_key_free (rpointer data)
{
  RXdhPrivKey * key;

  if ((key = data) != NULL) {
    r_memclear_secure (key->scalar, sizeof (key->scalar));
    r_ecurve_montgomery_clear (&key->pub.curve);
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

/* Pub and priv share the same algo-info table: XDH offers no
 * encrypt / decrypt / sign / verify / export operations through the
 * generic RCryptoKey vtable - all of its surface lives behind the
 * dedicated r_xdh_* functions in this module. */
static const RCryptoAlgoInfo g_xdh_key_info = {
  R_CRYPTO_ALGO_XDH, R_XDH_STR,
  NULL, NULL, NULL, NULL, NULL
};

RCryptoKey *
r_xdh_pub_key_new (REcurveID curve, rconstpointer pub_u, rsize pub_u_size)
{
  RXdhPubKey * ret;
  rsize coord_bytes;

  if (R_UNLIKELY (pub_u == NULL)) return NULL;
  if ((coord_bytes = r_xdh_coord_bytes_for (curve)) == 0) return NULL;
  if (pub_u_size != coord_bytes) return NULL;

  if ((ret = r_mem_new0 (RXdhPubKey)) == NULL) return NULL;
  if (!r_ecurve_montgomery_init (&ret->curve, curve)) {
    r_free (ret);
    return NULL;
  }

  ret->curve_id = curve;
  ret->coord_bytes = coord_bytes;
  r_memcpy (ret->pub_u, pub_u, coord_bytes);

  r_ref_init (&ret->key, r_xdh_pub_key_free);
  ret->key.type = R_CRYPTO_PUBLIC_KEY;
  ret->key.algo = &g_xdh_key_info;
  ret->key.bits = (ruint)(coord_bytes * 8);

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_xdh_priv_key_new (REcurveID curve, rconstpointer pub_u, rsize pub_u_size,
    rconstpointer scalar, rsize scalarsize)
{
  RXdhPrivKey * ret;
  rsize coord_bytes;

  if (R_UNLIKELY (pub_u == NULL || scalar == NULL)) return NULL;
  if ((coord_bytes = r_xdh_coord_bytes_for (curve)) == 0) return NULL;
  if (pub_u_size != coord_bytes || scalarsize != coord_bytes) return NULL;

  if ((ret = r_mem_new0 (RXdhPrivKey)) == NULL) return NULL;
  if (!r_ecurve_montgomery_init (&ret->pub.curve, curve)) {
    r_free (ret);
    return NULL;
  }

  ret->pub.curve_id = curve;
  ret->pub.coord_bytes = coord_bytes;
  r_memcpy (ret->pub.pub_u, pub_u, coord_bytes);
  r_memcpy (ret->scalar, scalar, coord_bytes);

  r_ref_init (&ret->pub.key, r_xdh_priv_key_free);
  ret->pub.key.type = R_CRYPTO_PRIVATE_KEY;
  ret->pub.key.algo = &g_xdh_key_info;
  ret->pub.key.bits = (ruint)(coord_bytes * 8);

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_xdh_priv_key_new_gen (REcurveID curve, RPrng * prng)
{
  ruint8 scalar[R_XDH_MAX_COORD_BYTES];
  ruint8 pub_u[R_XDH_MAX_COORD_BYTES];
  ruint8 basepoint[R_XDH_MAX_COORD_BYTES];
  REcurveMontgomery curve_params;
  RCryptoKey * key = NULL;
  rsize coord_bytes;

  if ((coord_bytes = r_xdh_coord_bytes_for (curve)) == 0) return NULL;

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL) return NULL;
  } else {
    r_prng_ref (prng);
  }

  if (!r_prng_fill (prng, scalar, coord_bytes))
    goto cleanup;

  /* Derive the public u-coordinate from the random scalar against
   * the base-point. The ladder clamps internally so storing the
   * unclamped random scalar still gives the correct public key. */
  if (!r_ecurve_montgomery_init (&curve_params, curve))
    goto cleanup;
  r_memset (basepoint, 0, sizeof (basepoint));
  basepoint[0] = (curve == R_ECURVE_ID_X25519) ? 9u : 5u;
  if (!r_ecurve_montgomery_ladder (pub_u, scalar, basepoint, &curve_params)) {
    r_ecurve_montgomery_clear (&curve_params);
    goto cleanup;
  }
  r_ecurve_montgomery_clear (&curve_params);

  key = r_xdh_priv_key_new (curve, pub_u, coord_bytes, scalar, coord_bytes);

cleanup:
  r_memclear_secure (scalar, sizeof (scalar));
  r_prng_unref (prng);
  return key;
}

REcurveID
r_xdh_key_get_curve (const RCryptoKey * key)
{
  if (R_UNLIKELY (key == NULL)) return R_ECURVE_ID_NONE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_XDH))
    return R_ECURVE_ID_NONE;
  return ((const RXdhPubKey *)key)->curve_id;
}

rboolean
r_xdh_key_get_pub_u (const RCryptoKey * key, const ruint8 ** pub_u, rsize * size)
{
  const RXdhPubKey * k;

  if (R_UNLIKELY (key == NULL || pub_u == NULL || size == NULL))
    return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_XDH))
    return FALSE;

  k = (const RXdhPubKey *)key;
  *pub_u = k->pub_u;
  *size = k->coord_bytes;
  return TRUE;
}

RCryptoResult
r_xdh_compute_shared (const RCryptoKey * priv, const RCryptoKey * peer_pub,
    ruint8 * out, rsize * outsize)
{
  const RXdhPrivKey * me;
  const RXdhPubKey * peer;

  if (R_UNLIKELY (priv == NULL || peer_pub == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (out == NULL || outsize == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (priv->algo->algo != R_CRYPTO_ALGO_XDH ||
        peer_pub->algo->algo != R_CRYPTO_ALGO_XDH))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (priv->type != R_CRYPTO_PRIVATE_KEY ||
        peer_pub->type != R_CRYPTO_PUBLIC_KEY))
    return R_CRYPTO_WRONG_TYPE;

  me = (const RXdhPrivKey *)priv;
  peer = (const RXdhPubKey *)peer_pub;

  if (me->pub.curve_id != peer->curve_id)
    return R_CRYPTO_WRONG_TYPE;
  if (*outsize < me->pub.coord_bytes)
    return R_CRYPTO_BUFFER_TOO_SMALL;

  /* The math layer surfaces the RFC 7748 §6 zero-shared check via
   * its return value, so we don't have to inspect out. */
  if (!r_ecurve_montgomery_ladder (out, me->scalar, peer->pub_u, &me->pub.curve))
    return R_CRYPTO_INVAL;

  *outsize = me->pub.coord_bytes;
  return R_CRYPTO_OK;
}
