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

#include <rlib/crypto/red25519.h>

#include <rlib/crypto/recurve-edwards.h>
#include <rlib/rmem.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/rrand.h>

/* L (the prime-order subgroup of edwards25519) as BE bytes for use
 * with r_mpint_init_binary. */
static const ruint8 ed25519_L_be[32] = {
  0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
  0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
};

typedef struct {
  RCryptoKey key;
  REcurveEdwards curve;
  ruint8 pub_enc[R_ED25519_PUB_KEY_SIZE];
  REcurveEdwardsPoint A;        /* Pre-decoded public point. */
} REd25519PubKey;

typedef struct {
  REd25519PubKey pub;
  ruint8 seed[R_ED25519_SEED_SIZE];
  ruint8 s_buf[32];             /* Clamped scalar, LE. */
  ruint8 prefix[32];            /* SHA-512(seed)[32..63]. */
} REd25519PrivKey;

/* ---- Forward declarations for the algo-info table ------------------- */

static RCryptoResult r_ed25519_sign_vt (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize);
static RCryptoResult r_ed25519_verify_vt (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize);

static const RCryptoAlgoInfo g_ed25519_pub_key_info = {
  R_CRYPTO_ALGO_ED25519, R_ED25519_STR,
  NULL, NULL, NULL, r_ed25519_verify_vt, NULL
};
static const RCryptoAlgoInfo g_ed25519_priv_key_info = {
  R_CRYPTO_ALGO_ED25519, R_ED25519_STR,
  NULL, NULL, r_ed25519_sign_vt, r_ed25519_verify_vt, NULL
};

/* ---- LE-byte helpers ------------------------------------------------ */

static void
r_ed25519_le_to_mpint (rmpint * mp, const ruint8 * le, rsize n)
{
  ruint8 be[64];
  rsize i;
  for (i = 0; i < n; i++)
    be[i] = le[n - 1 - i];
  r_mpint_init_binary (mp, be, n);
  r_memclear_secure (be, sizeof (be));
}

static rboolean
r_ed25519_mpint_to_le_bytes (ruint8 * out, rsize n, const rmpint * mp)
{
  rsize i;
  for (i = 0; i < n; i++)
    out[i] = (ruint8)(r_mpint_get_digit (mp, (ruint32)(i / 4))
        >> ((i % 4) * 8));
  return TRUE;
}

/* SHA-512 in one shot. dst must hold 64 bytes. parts is a NULL-terminated
 * array of (ptr, size) pairs to feed into the digest. */
typedef struct { const ruint8 * data; rsize size; } RSha512Part;

static rboolean
r_ed25519_sha512 (ruint8 * dst, const RSha512Part * parts, rsize nparts)
{
  RMsgDigest * md = r_msg_digest_new_sha512 ();
  rsize i, n;
  rboolean ok = FALSE;
  if (md == NULL) return FALSE;
  for (i = 0; i < nparts; i++) {
    if (parts[i].size == 0) continue;
    if (!r_msg_digest_update (md, parts[i].data, parts[i].size))
      goto cleanup;
  }
  if (!r_msg_digest_get_data (md, dst, 64, &n) || n != 64)
    goto cleanup;
  ok = TRUE;
cleanup:
  r_msg_digest_free (md);
  return ok;
}

/* Reduce a 64-byte little-endian hash to an mpint mod L. */
static rboolean
r_ed25519_hash_to_scalar (rmpint * out, const ruint8 * hash64,
    const rmpint * L)
{
  rmpint t;
  rboolean ok;
  r_ed25519_le_to_mpint (&t, hash64, 64);
  ok = r_mpint_mod (out, &t, L);
  r_mpint_clear (&t);
  return ok;
}

/* ---- Key lifecycle -------------------------------------------------- */

static void
r_ed25519_pub_key_free (rpointer data)
{
  REd25519PubKey * key;
  if ((key = data) != NULL) {
    r_ecurve_edwards_clear (&key->curve);
    r_memclear_secure (&key->A, sizeof (key->A));
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

static void
r_ed25519_priv_key_free (rpointer data)
{
  REd25519PrivKey * key;
  if ((key = data) != NULL) {
    r_memclear_secure (key->seed, sizeof (key->seed));
    r_memclear_secure (key->s_buf, sizeof (key->s_buf));
    r_memclear_secure (key->prefix, sizeof (key->prefix));
    r_ecurve_edwards_clear (&key->pub.curve);
    r_memclear_secure (&key->pub.A, sizeof (key->pub.A));
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

RCryptoKey *
r_ed25519_pub_key_new (rconstpointer pub, rsize pubsize)
{
  REd25519PubKey * ret;

  if (R_UNLIKELY (pub == NULL || pubsize != R_ED25519_PUB_KEY_SIZE))
    return NULL;
  if ((ret = r_mem_new0 (REd25519PubKey)) == NULL) return NULL;
  if (!r_ecurve_edwards_init (&ret->curve, R_ECURVE_ID_X25519)) {
    r_free (ret);
    return NULL;
  }
  if (!r_ecurve_edwards_point_decode (&ret->A, pub, &ret->curve)) {
    r_ecurve_edwards_clear (&ret->curve);
    r_free (ret);
    return NULL;
  }
  r_memcpy (ret->pub_enc, pub, R_ED25519_PUB_KEY_SIZE);

  r_ref_init (&ret->key, r_ed25519_pub_key_free);
  ret->key.type = R_CRYPTO_PUBLIC_KEY;
  ret->key.algo = &g_ed25519_pub_key_info;
  ret->key.bits = 255;

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_ed25519_priv_key_new (rconstpointer seed, rsize seedsize)
{
  REd25519PrivKey * ret;
  ruint8 h[64];
  RSha512Part part;
  REcurveEdwardsPoint A;

  if (R_UNLIKELY (seed == NULL || seedsize != R_ED25519_SEED_SIZE))
    return NULL;
  if ((ret = r_mem_new0 (REd25519PrivKey)) == NULL) return NULL;
  if (!r_ecurve_edwards_init (&ret->pub.curve, R_ECURVE_ID_X25519)) {
    r_free (ret);
    return NULL;
  }

  r_memcpy (ret->seed, seed, R_ED25519_SEED_SIZE);

  /* h = SHA-512(seed). */
  part.data = ret->seed; part.size = R_ED25519_SEED_SIZE;
  if (!r_ed25519_sha512 (h, &part, 1))
    goto fail;

  /* s_buf = clamp(h[0..31]); prefix = h[32..63]. */
  r_memcpy (ret->s_buf, h, 32);
  ret->s_buf[0] &= 0xf8;
  ret->s_buf[31] &= 0x7f;
  ret->s_buf[31] |= 0x40;
  r_memcpy (ret->prefix, h + 32, 32);

  /* A = s * B; cache encoded form. */
  r_ecurve_edwards_point_scalar_mul (&A, ret->s_buf, 32, 255,
      &ret->pub.curve.B, &ret->pub.curve);
  if (!r_ecurve_edwards_point_encode (ret->pub.pub_enc, &A, &ret->pub.curve))
    goto fail;
  r_ecurve_edwards_point_copy (&ret->pub.A, &A);

  r_ref_init (&ret->pub.key, r_ed25519_priv_key_free);
  ret->pub.key.type = R_CRYPTO_PRIVATE_KEY;
  ret->pub.key.algo = &g_ed25519_priv_key_info;
  ret->pub.key.bits = 255;

  r_memclear_secure (h, sizeof (h));
  r_memclear_secure (&A, sizeof (A));
  return (RCryptoKey *)ret;

fail:
  r_memclear_secure (h, sizeof (h));
  r_memclear_secure (&A, sizeof (A));
  r_memclear_secure (ret->seed, sizeof (ret->seed));
  r_memclear_secure (ret->s_buf, sizeof (ret->s_buf));
  r_memclear_secure (ret->prefix, sizeof (ret->prefix));
  r_ecurve_edwards_clear (&ret->pub.curve);
  r_free (ret);
  return NULL;
}

RCryptoKey *
r_ed25519_priv_key_new_gen (RPrng * prng)
{
  ruint8 seed[R_ED25519_SEED_SIZE];
  RCryptoKey * key = NULL;

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL) return NULL;
  } else {
    r_prng_ref (prng);
  }
  if (r_prng_fill (prng, seed, sizeof (seed)))
    key = r_ed25519_priv_key_new (seed, sizeof (seed));

  r_memclear_secure (seed, sizeof (seed));
  r_prng_unref (prng);
  return key;
}

rboolean
r_ed25519_key_get_pub (const RCryptoKey * key, const ruint8 ** pub,
    rsize * size)
{
  if (R_UNLIKELY (key == NULL || pub == NULL || size == NULL))
    return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ED25519))
    return FALSE;
  *pub = ((const REd25519PubKey *)key)->pub_enc;
  *size = R_ED25519_PUB_KEY_SIZE;
  return TRUE;
}

/* ---- Sign / verify ----------------------------------------------------- */

RCryptoResult
r_ed25519_sign (const RCryptoKey * key, rconstpointer msg, rsize msgsize,
    ruint8 * sig, rsize * sigsize)
{
  const REd25519PrivKey * priv;
  rmpint L, r_mp, k_mp, s_mp, S_mp;
  ruint8 hash64[64];
  ruint8 R_enc[32];
  RSha512Part parts[3];
  REcurveEdwardsPoint R_pt;
  RCryptoResult ret = R_CRYPTO_ERROR;

  if (R_UNLIKELY (key == NULL || sig == NULL || sigsize == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (msg == NULL && msgsize != 0))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ED25519 ||
        key->type != R_CRYPTO_PRIVATE_KEY))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (*sigsize < R_ED25519_SIG_SIZE))
    return R_CRYPTO_BUFFER_TOO_SMALL;

  priv = (const REd25519PrivKey *)key;

  r_mpint_init_binary (&L, ed25519_L_be, sizeof (ed25519_L_be));
  r_mpint_init (&r_mp);
  r_mpint_init (&k_mp);
  r_mpint_init (&s_mp);
  r_mpint_init (&S_mp);

  /* r = SHA-512(prefix || msg) mod L. */
  parts[0].data = priv->prefix; parts[0].size = 32;
  parts[1].data = msg;          parts[1].size = msgsize;
  if (!r_ed25519_sha512 (hash64, parts, 2))
    goto cleanup;
  if (!r_ed25519_hash_to_scalar (&r_mp, hash64, &L))
    goto cleanup;

  /* R = r * B; encode. r_mp's byte width is the working width for the
   * scalar multiplication. */
  {
    ruint8 r_le[32];
    if (!r_ed25519_mpint_to_le_bytes (r_le, 32, &r_mp))
      goto cleanup;
    r_ecurve_edwards_point_scalar_mul (&R_pt, r_le, 32, 255,
        &priv->pub.curve.B, &priv->pub.curve);
    r_memclear_secure (r_le, sizeof (r_le));
  }
  if (!r_ecurve_edwards_point_encode (R_enc, &R_pt, &priv->pub.curve))
    goto cleanup;

  /* k = SHA-512(R || A || msg) mod L. */
  parts[0].data = R_enc;            parts[0].size = 32;
  parts[1].data = priv->pub.pub_enc; parts[1].size = 32;
  parts[2].data = msg;               parts[2].size = msgsize;
  if (!r_ed25519_sha512 (hash64, parts, 3))
    goto cleanup;
  if (!r_ed25519_hash_to_scalar (&k_mp, hash64, &L))
    goto cleanup;

  /* S = (r + k * s) mod L. */
  r_ed25519_le_to_mpint (&s_mp, priv->s_buf, 32);
  if (!r_mpint_mul (&S_mp, &k_mp, &s_mp))
    goto cleanup;
  if (!r_mpint_add (&S_mp, &S_mp, &r_mp))
    goto cleanup;
  if (!r_mpint_mod (&S_mp, &S_mp, &L))
    goto cleanup;

  r_memcpy (sig, R_enc, 32);
  if (!r_ed25519_mpint_to_le_bytes (sig + 32, 32, &S_mp))
    goto cleanup;
  *sigsize = R_ED25519_SIG_SIZE;
  ret = R_CRYPTO_OK;

cleanup:
  r_memclear_secure (hash64, sizeof (hash64));
  r_memclear_secure (&R_pt, sizeof (R_pt));
  r_mpint_clear (&L);
  r_mpint_clear (&r_mp);
  r_mpint_clear (&k_mp);
  r_mpint_clear (&s_mp);
  r_mpint_clear (&S_mp);
  return ret;
}

RCryptoResult
r_ed25519_verify (const RCryptoKey * key, rconstpointer msg, rsize msgsize,
    rconstpointer sig, rsize sigsize)
{
  const REd25519PubKey * pub;
  const ruint8 * sb;
  rmpint L, S_mp, k_mp;
  ruint8 hash64[64];
  RSha512Part parts[3];
  REcurveEdwardsPoint R_pt, kA_pt, lhs_pt, rhs_pt;
  RCryptoResult ret = R_CRYPTO_ERROR;

  if (R_UNLIKELY (key == NULL || sig == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (msg == NULL && msgsize != 0))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (sigsize != R_ED25519_SIG_SIZE))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ED25519 ||
        key->type != R_CRYPTO_PUBLIC_KEY))
    return R_CRYPTO_WRONG_TYPE;

  pub = (const REd25519PubKey *)key;
  sb = sig;

  /* Decode R. */
  if (!r_ecurve_edwards_point_decode (&R_pt, sb, &pub->curve))
    return R_CRYPTO_INVAL;

  /* Decode S, reject S >= L. */
  r_mpint_init_binary (&L, ed25519_L_be, sizeof (ed25519_L_be));
  r_ed25519_le_to_mpint (&S_mp, sb + 32, 32);
  r_mpint_init (&k_mp);
  if (r_mpint_ucmp (&S_mp, &L) >= 0) {
    ret = R_CRYPTO_INVAL;
    goto cleanup;
  }

  /* k = SHA-512(R || A || msg) mod L. */
  parts[0].data = sb;             parts[0].size = 32;
  parts[1].data = pub->pub_enc;   parts[1].size = 32;
  parts[2].data = msg;            parts[2].size = msgsize;
  if (!r_ed25519_sha512 (hash64, parts, 3))
    goto cleanup;
  if (!r_ed25519_hash_to_scalar (&k_mp, hash64, &L))
    goto cleanup;

  /* Compute [S]B and R + [k]A; compare projectively after cofactor
   * multiplication ([8]SB == [8]R + [8]kA). The cofactor 8 is three
   * doublings on each side. */
  {
    ruint8 S_le[32], k_le[32];
    if (!r_ed25519_mpint_to_le_bytes (S_le, 32, &S_mp) ||
        !r_ed25519_mpint_to_le_bytes (k_le, 32, &k_mp))
      goto cleanup;
    r_ecurve_edwards_point_scalar_mul (&lhs_pt, S_le, 32, 253,
        &pub->curve.B, &pub->curve);
    r_ecurve_edwards_point_scalar_mul (&kA_pt, k_le, 32, 253,
        &pub->A, &pub->curve);
    r_memclear_secure (S_le, sizeof (S_le));
    r_memclear_secure (k_le, sizeof (k_le));
  }
  r_ecurve_edwards_point_add (&rhs_pt, &R_pt, &kA_pt, &pub->curve);

  /* Apply cofactor: lhs = 8*lhs, rhs = 8*rhs. */
  r_ecurve_edwards_point_dbl (&lhs_pt, &lhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&lhs_pt, &lhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&lhs_pt, &lhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&rhs_pt, &rhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&rhs_pt, &rhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&rhs_pt, &rhs_pt, &pub->curve);

  ret = r_ecurve_edwards_point_equal (&lhs_pt, &rhs_pt, &pub->curve)
      ? R_CRYPTO_OK : R_CRYPTO_VERIFY_FAILED;

cleanup:
  r_memclear_secure (hash64, sizeof (hash64));
  r_memclear_secure (&R_pt, sizeof (R_pt));
  r_memclear_secure (&kA_pt, sizeof (kA_pt));
  r_memclear_secure (&lhs_pt, sizeof (lhs_pt));
  r_memclear_secure (&rhs_pt, sizeof (rhs_pt));
  r_mpint_clear (&L);
  r_mpint_clear (&S_mp);
  r_mpint_clear (&k_mp);
  return ret;
}

/* Generic-vtable adapters. Ed25519 is "pure" (consumes the full
 * message, not a pre-digest), so the mdtype / hash / hashsize args
 * are interpreted as msg / msgsize. The RCryptoAlgoInfo vtable's
 * sign / verify signature predates this distinction; we accept any
 * mdtype and treat the byte buffer as the message. */
static RCryptoResult
r_ed25519_sign_vt (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize)
{
  (void)prng;
  (void)mdtype;
  return r_ed25519_sign (key, hash, hashsize, sig, sigsize);
}

static RCryptoResult
r_ed25519_verify_vt (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize)
{
  (void)mdtype;
  return r_ed25519_verify (key, hash, hashsize, sig, sigsize);
}
