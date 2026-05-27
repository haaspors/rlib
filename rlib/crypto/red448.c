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

#include <rlib/crypto/red448.h>

#include <rlib/crypto/recurve-edwards.h>
#include <rlib/rmem.h>
#include <rlib/rmsgdigest.h>
#include <rlib/rrand.h>

/* L (the prime-order subgroup of edwards448) as BE bytes for use
 * with r_mpint_init_binary. */
static const ruint8 ed448_L_be[56] = {
  0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0x7c, 0xca, 0x23, 0xe9,
  0xc4, 0x4e, 0xdb, 0x49, 0xae, 0xd6, 0x36, 0x90,
  0x21, 0x6c, 0xc2, 0x72, 0x8d, 0xc5, 0x8f, 0x55,
  0x23, 0x78, 0xc2, 0x92, 0xab, 0x58, 0x44, 0xf3,
};

/* dom4(F=0, C="") per RFC 8032 §5.2:
 *   "SigEd448" || octet(F) || octet(|C|) || C
 * For pure Ed448 with no context: 8 ASCII bytes + 0x00 + 0x00. */
static const ruint8 ed448_dom4_empty[10] = {
  'S', 'i', 'g', 'E', 'd', '4', '4', '8', 0x00, 0x00,
};

typedef struct {
  RCryptoKey key;
  REcurveEdwards curve;
  ruint8 pub_enc[R_ED448_PUB_KEY_SIZE];
  REcurveEdwardsPoint A;        /* Pre-decoded public point. */
} REd448PubKey;

typedef struct {
  REd448PubKey pub;
  ruint8 seed[R_ED448_SEED_SIZE];
  ruint8 s_buf[57];             /* Clamped scalar, LE. */
  ruint8 prefix[57];            /* SHAKE256(seed, 114)[57..113]. */
} REd448PrivKey;

/* ---- Forward declarations for the vtable -------------------------- */

static RCryptoResult r_ed448_sign_vt (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize);
static RCryptoResult r_ed448_verify_vt (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize);

static const RCryptoAlgoInfo g_ed448_pub_key_info = {
  R_CRYPTO_ALGO_ED448, R_ED448_STR,
  NULL, NULL, NULL, r_ed448_verify_vt, NULL
};
static const RCryptoAlgoInfo g_ed448_priv_key_info = {
  R_CRYPTO_ALGO_ED448, R_ED448_STR,
  NULL, NULL, r_ed448_sign_vt, r_ed448_verify_vt, NULL
};

/* ---- LE / hash helpers ------------------------------------------ */

static void
r_ed448_le_to_mpint (rmpint * mp, const ruint8 * le, rsize n)
{
  ruint8 be[128];
  rsize i;
  for (i = 0; i < n; i++)
    be[i] = le[n - 1 - i];
  r_mpint_init_binary (mp, be, n);
  r_memclear_secure (be, sizeof (be));
}

static rboolean
r_ed448_mpint_to_le_bytes (ruint8 * out, rsize n, const rmpint * mp)
{
  rsize i;
  for (i = 0; i < n; i++)
    out[i] = (ruint8)(r_mpint_get_digit (mp, (ruint32)(i / 4))
        >> ((i % 4) * 8));
  return TRUE;
}

typedef struct { const ruint8 * data; rsize size; } RShakePart;

/* SHAKE256(parts...) -> @outsize bytes at @dst. */
static rboolean
r_ed448_shake256 (ruint8 * dst, rsize outsize,
    const RShakePart * parts, rsize nparts)
{
  RMsgDigest * md = r_msg_digest_new_shake256 ();
  rsize i;
  rboolean ok = FALSE;
  if (md == NULL) return FALSE;
  for (i = 0; i < nparts; i++) {
    if (parts[i].size == 0) continue;
    if (!r_msg_digest_update (md, parts[i].data, parts[i].size))
      goto cleanup;
  }
  ok = r_msg_digest_squeeze (md, dst, outsize);
cleanup:
  r_msg_digest_free (md);
  return ok;
}

/* Reduce a 114-byte LE hash to an mpint mod L. */
static rboolean
r_ed448_hash_to_scalar (rmpint * out, const ruint8 * hash114,
    const rmpint * L)
{
  rmpint t;
  rboolean ok;
  r_ed448_le_to_mpint (&t, hash114, 114);
  ok = r_mpint_mod (out, &t, L);
  r_mpint_clear (&t);
  return ok;
}

/* ---- Key lifecycle ------------------------------------------------- */

static void
r_ed448_pub_key_free (rpointer data)
{
  REd448PubKey * key;
  if ((key = data) != NULL) {
    r_ecurve_edwards_clear (&key->curve);
    r_memclear_secure (&key->A, sizeof (key->A));
    r_crypto_key_destroy ((RCryptoKey *)key);
    r_free (key);
  }
}

static void
r_ed448_priv_key_free (rpointer data)
{
  REd448PrivKey * key;
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
r_ed448_pub_key_new (rconstpointer pub, rsize pubsize)
{
  REd448PubKey * ret;

  if (R_UNLIKELY (pub == NULL || pubsize != R_ED448_PUB_KEY_SIZE))
    return NULL;
  if ((ret = r_mem_new0 (REd448PubKey)) == NULL) return NULL;
  if (!r_ecurve_edwards_init (&ret->curve, R_ECURVE_ID_X448)) {
    r_free (ret);
    return NULL;
  }
  if (!r_ecurve_edwards_point_decode (&ret->A, pub, &ret->curve)) {
    r_ecurve_edwards_clear (&ret->curve);
    r_free (ret);
    return NULL;
  }
  r_memcpy (ret->pub_enc, pub, R_ED448_PUB_KEY_SIZE);

  r_ref_init (&ret->key, r_ed448_pub_key_free);
  ret->key.type = R_CRYPTO_PUBLIC_KEY;
  ret->key.algo = &g_ed448_pub_key_info;
  ret->key.bits = 448;

  return (RCryptoKey *)ret;
}

RCryptoKey *
r_ed448_priv_key_new (rconstpointer seed, rsize seedsize)
{
  REd448PrivKey * ret;
  ruint8 h[114];
  RShakePart part;
  REcurveEdwardsPoint A;

  if (R_UNLIKELY (seed == NULL || seedsize != R_ED448_SEED_SIZE))
    return NULL;
  if ((ret = r_mem_new0 (REd448PrivKey)) == NULL) return NULL;
  if (!r_ecurve_edwards_init (&ret->pub.curve, R_ECURVE_ID_X448)) {
    r_free (ret);
    return NULL;
  }

  r_memcpy (ret->seed, seed, R_ED448_SEED_SIZE);

  /* h = SHAKE256(seed, 114). */
  part.data = ret->seed; part.size = R_ED448_SEED_SIZE;
  if (!r_ed448_shake256 (h, sizeof (h), &part, 1))
    goto fail;

  /* Clamp per RFC 8032 §5.2.5:
   *  - s_buf[0] &= 0xfc       (clear low 2 bits)
   *  - s_buf[56] = 0          (clear top byte)
   *  - s_buf[55] |= 0x80      (set bit 7 of byte 55 = bit 447)
   * prefix = h[57..113]. */
  r_memcpy (ret->s_buf, h, 57);
  ret->s_buf[0] &= 0xfcu;
  ret->s_buf[56] = 0;
  ret->s_buf[55] |= 0x80u;
  r_memcpy (ret->prefix, h + 57, 57);

  /* A = s * B; cache encoded form. */
  r_ecurve_edwards_point_scalar_mul (&A, ret->s_buf, 57, 448,
      &ret->pub.curve.B, &ret->pub.curve);
  if (!r_ecurve_edwards_point_encode (ret->pub.pub_enc, &A, &ret->pub.curve))
    goto fail;
  r_ecurve_edwards_point_copy (&ret->pub.A, &A);

  r_ref_init (&ret->pub.key, r_ed448_priv_key_free);
  ret->pub.key.type = R_CRYPTO_PRIVATE_KEY;
  ret->pub.key.algo = &g_ed448_priv_key_info;
  ret->pub.key.bits = 448;

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
r_ed448_priv_key_new_gen (RPrng * prng)
{
  ruint8 seed[R_ED448_SEED_SIZE];
  RCryptoKey * key = NULL;

  if (prng == NULL) {
    if ((prng = r_rand_prng_new ()) == NULL) return NULL;
  } else {
    r_prng_ref (prng);
  }
  if (r_prng_fill (prng, seed, sizeof (seed)))
    key = r_ed448_priv_key_new (seed, sizeof (seed));

  r_memclear_secure (seed, sizeof (seed));
  r_prng_unref (prng);
  return key;
}

rboolean
r_ed448_key_get_pub (const RCryptoKey * key, const ruint8 ** pub,
    rsize * size)
{
  if (R_UNLIKELY (key == NULL || pub == NULL || size == NULL))
    return FALSE;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ED448))
    return FALSE;
  *pub = ((const REd448PubKey *)key)->pub_enc;
  *size = R_ED448_PUB_KEY_SIZE;
  return TRUE;
}

/* ---- Sign / verify ------------------------------------------------- */

RCryptoResult
r_ed448_sign (const RCryptoKey * key, rconstpointer msg, rsize msgsize,
    ruint8 * sig, rsize * sigsize)
{
  const REd448PrivKey * priv;
  rmpint L, r_mp, k_mp, s_mp, S_mp;
  ruint8 hash114[114];
  ruint8 R_enc[57];
  RShakePart parts[5];
  REcurveEdwardsPoint R_pt;
  RCryptoResult ret = R_CRYPTO_ERROR;

  if (R_UNLIKELY (key == NULL || sig == NULL || sigsize == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (msg == NULL && msgsize != 0))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ED448 ||
        key->type != R_CRYPTO_PRIVATE_KEY))
    return R_CRYPTO_WRONG_TYPE;
  if (R_UNLIKELY (*sigsize < R_ED448_SIG_SIZE))
    return R_CRYPTO_BUFFER_TOO_SMALL;

  priv = (const REd448PrivKey *)key;

  r_mpint_init_binary (&L, ed448_L_be, sizeof (ed448_L_be));
  r_mpint_init (&r_mp);
  r_mpint_init (&k_mp);
  r_mpint_init (&s_mp);
  r_mpint_init (&S_mp);

  /* r = SHAKE256(dom4(0,"") || prefix || msg, 114) mod L. */
  parts[0].data = ed448_dom4_empty; parts[0].size = sizeof (ed448_dom4_empty);
  parts[1].data = priv->prefix;     parts[1].size = 57;
  parts[2].data = msg;              parts[2].size = msgsize;
  if (!r_ed448_shake256 (hash114, sizeof (hash114), parts, 3))
    goto cleanup;
  if (!r_ed448_hash_to_scalar (&r_mp, hash114, &L))
    goto cleanup;

  /* R = r * B; encode. */
  {
    ruint8 r_le[57];
    if (!r_ed448_mpint_to_le_bytes (r_le, 57, &r_mp))
      goto cleanup;
    r_ecurve_edwards_point_scalar_mul (&R_pt, r_le, 57, 448,
        &priv->pub.curve.B, &priv->pub.curve);
    r_memclear_secure (r_le, sizeof (r_le));
  }
  if (!r_ecurve_edwards_point_encode (R_enc, &R_pt, &priv->pub.curve))
    goto cleanup;

  /* k = SHAKE256(dom4(0,"") || R || A || msg, 114) mod L. */
  parts[0].data = ed448_dom4_empty;  parts[0].size = sizeof (ed448_dom4_empty);
  parts[1].data = R_enc;             parts[1].size = 57;
  parts[2].data = priv->pub.pub_enc; parts[2].size = R_ED448_PUB_KEY_SIZE;
  parts[3].data = msg;               parts[3].size = msgsize;
  if (!r_ed448_shake256 (hash114, sizeof (hash114), parts, 4))
    goto cleanup;
  if (!r_ed448_hash_to_scalar (&k_mp, hash114, &L))
    goto cleanup;

  /* S = (r + k * s) mod L. */
  r_ed448_le_to_mpint (&s_mp, priv->s_buf, 57);
  if (!r_mpint_mul (&S_mp, &k_mp, &s_mp))
    goto cleanup;
  if (!r_mpint_add (&S_mp, &S_mp, &r_mp))
    goto cleanup;
  if (!r_mpint_mod (&S_mp, &S_mp, &L))
    goto cleanup;

  r_memcpy (sig, R_enc, 57);
  if (!r_ed448_mpint_to_le_bytes (sig + 57, 57, &S_mp))
    goto cleanup;
  *sigsize = R_ED448_SIG_SIZE;
  ret = R_CRYPTO_OK;

cleanup:
  r_memclear_secure (hash114, sizeof (hash114));
  r_memclear_secure (&R_pt, sizeof (R_pt));
  r_mpint_clear (&L);
  r_mpint_clear (&r_mp);
  r_mpint_clear (&k_mp);
  r_mpint_clear (&s_mp);
  r_mpint_clear (&S_mp);
  return ret;
}

RCryptoResult
r_ed448_verify (const RCryptoKey * key, rconstpointer msg, rsize msgsize,
    rconstpointer sig, rsize sigsize)
{
  const REd448PubKey * pub;
  const ruint8 * sb;
  rmpint L, S_mp, k_mp;
  ruint8 hash114[114];
  RShakePart parts[4];
  REcurveEdwardsPoint R_pt, kA_pt, lhs_pt, rhs_pt;
  RCryptoResult ret = R_CRYPTO_ERROR;

  if (R_UNLIKELY (key == NULL || sig == NULL))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (msg == NULL && msgsize != 0))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (sigsize != R_ED448_SIG_SIZE))
    return R_CRYPTO_INVAL;
  if (R_UNLIKELY (key->algo->algo != R_CRYPTO_ALGO_ED448 ||
        key->type != R_CRYPTO_PUBLIC_KEY))
    return R_CRYPTO_WRONG_TYPE;

  pub = (const REd448PubKey *)key;
  sb = sig;

  /* Decode R. */
  if (!r_ecurve_edwards_point_decode (&R_pt, sb, &pub->curve))
    return R_CRYPTO_INVAL;

  r_mpint_init_binary (&L, ed448_L_be, sizeof (ed448_L_be));
  r_ed448_le_to_mpint (&S_mp, sb + 57, 57);
  r_mpint_init (&k_mp);
  if (r_mpint_ucmp (&S_mp, &L) >= 0) {
    ret = R_CRYPTO_INVAL;
    goto cleanup;
  }

  /* k = SHAKE256(dom4 || R || A || msg, 114) mod L. */
  parts[0].data = ed448_dom4_empty;  parts[0].size = sizeof (ed448_dom4_empty);
  parts[1].data = sb;                parts[1].size = 57;
  parts[2].data = pub->pub_enc;      parts[2].size = R_ED448_PUB_KEY_SIZE;
  parts[3].data = msg;               parts[3].size = msgsize;
  if (!r_ed448_shake256 (hash114, sizeof (hash114), parts, 4))
    goto cleanup;
  if (!r_ed448_hash_to_scalar (&k_mp, hash114, &L))
    goto cleanup;

  /* Compute [S]B and R + [k]A; apply cofactor 4 to both sides
   * ([4]SB == [4]R + [4]kA per RFC 8032 §5.2.7). Cofactor 4 is
   * two doublings. */
  {
    ruint8 S_le[57], k_le[57];
    if (!r_ed448_mpint_to_le_bytes (S_le, 57, &S_mp) ||
        !r_ed448_mpint_to_le_bytes (k_le, 57, &k_mp))
      goto cleanup;
    r_ecurve_edwards_point_scalar_mul (&lhs_pt, S_le, 57, 446,
        &pub->curve.B, &pub->curve);
    r_ecurve_edwards_point_scalar_mul (&kA_pt, k_le, 57, 446,
        &pub->A, &pub->curve);
    r_memclear_secure (S_le, sizeof (S_le));
    r_memclear_secure (k_le, sizeof (k_le));
  }
  r_ecurve_edwards_point_add (&rhs_pt, &R_pt, &kA_pt, &pub->curve);

  r_ecurve_edwards_point_dbl (&lhs_pt, &lhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&lhs_pt, &lhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&rhs_pt, &rhs_pt, &pub->curve);
  r_ecurve_edwards_point_dbl (&rhs_pt, &rhs_pt, &pub->curve);

  ret = r_ecurve_edwards_point_equal (&lhs_pt, &rhs_pt, &pub->curve)
      ? R_CRYPTO_OK : R_CRYPTO_VERIFY_FAILED;

cleanup:
  r_memclear_secure (hash114, sizeof (hash114));
  r_memclear_secure (&R_pt, sizeof (R_pt));
  r_memclear_secure (&kA_pt, sizeof (kA_pt));
  r_memclear_secure (&lhs_pt, sizeof (lhs_pt));
  r_memclear_secure (&rhs_pt, sizeof (rhs_pt));
  r_mpint_clear (&L);
  r_mpint_clear (&S_mp);
  r_mpint_clear (&k_mp);
  return ret;
}

/* Generic vtable adapters - same shape as Ed25519. */
static RCryptoResult
r_ed448_sign_vt (const RCryptoKey * key, RPrng * prng,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rpointer sig, rsize * sigsize)
{
  (void)prng;
  (void)mdtype;
  return r_ed448_sign (key, hash, hashsize, sig, sigsize);
}

static RCryptoResult
r_ed448_verify_vt (const RCryptoKey * key,
    RMsgDigestType mdtype, rconstpointer hash, rsize hashsize,
    rconstpointer sig, rsize sigsize)
{
  (void)mdtype;
  return r_ed448_verify (key, hash, hashsize, sig, sigsize);
}
