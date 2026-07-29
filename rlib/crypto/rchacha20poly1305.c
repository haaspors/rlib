/* RLIB - Convenience library for useful things
 * Copyright (C) 2026  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/crypto/rchacha20poly1305.h>

#include "rcrypto-private.h"

#include <rlib/crypto/rchacha20.h>
#include <rlib/crypto/rpoly1305.h>
#include <rlib/rmem.h>

/* ChaCha20-Poly1305 AEAD per RFC 8439 §2.8. The cipher just carries the
 * 256-bit key; the per-message one-time Poly1305 key is derived from
 * ChaCha20 keystream block 0 and the payload is encrypted from block 1
 * onward. */

typedef struct {
  RCryptoCipher cipher;
  ruint8 key[R_CHACHA20POLY1305_KEY_SIZE];
} RChaCha20Poly1305Cipher;

static RCryptoCipherResult r_cipher_chacha20_poly1305_encrypt (
    const RCryptoCipher * cipher, ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize, ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);
static RCryptoCipherResult r_cipher_chacha20_poly1305_decrypt (
    const RCryptoCipher * cipher, ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize, ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize);

const RCryptoCipherInfo g__r_crypto_cipher_chacha20_poly1305 = { "CHACHA20-POLY1305",
  R_CRYPTO_CIPHER_ALGO_CHACHA20, R_CRYPTO_CIPHER_MODE_POLY1305, 256, 12, 1,
  NULL, NULL,
  r_cipher_chacha20_poly1305_encrypt, r_cipher_chacha20_poly1305_decrypt
};

static void
r_cipher_chacha20_poly1305_free (rpointer data)
{
  r_memclear_secure (data, sizeof (RChaCha20Poly1305Cipher));
  r_free (data);
}

RCryptoCipher *
r_cipher_chacha20_poly1305_new_with_info (const RCryptoCipherInfo * info,
    const ruint8 * key)
{
  RChaCha20Poly1305Cipher * ret;

  if (R_UNLIKELY (key == NULL)) return NULL;

  if ((ret = r_mem_new (RChaCha20Poly1305Cipher)) != NULL) {
    r_ref_init (ret, r_cipher_chacha20_poly1305_free);
    ret->cipher.info = info;
    r_memcpy (ret->key, key, R_CHACHA20POLY1305_KEY_SIZE);
  }

  return (RCryptoCipher *) ret;
}

RCryptoCipher *
r_cipher_chacha20_poly1305_new (const ruint8 * key)
{
  return r_cipher_chacha20_poly1305_new_with_info (
      &g__r_crypto_cipher_chacha20_poly1305, key);
}

/* Poly1305 over AAD || pad16 || ciphertext || pad16 || le64(aadlen) ||
 * le64(ctlen), keyed by the one-time @p polykey (RFC 8439 §2.8). */
static void
r_chacha20_poly1305_tag (ruint8 tag[R_POLY1305_TAG_SIZE],
    const ruint8 polykey[R_POLY1305_KEY_SIZE],
    rconstpointer aad, rsize aadsize, const ruint8 * ct, rsize ctsize)
{
  static const ruint8 zeropad[16] = { 0 };
  RPoly1305Ctx ctx;
  ruint8 lengths[16];

  r_poly1305_init (&ctx, polykey);

  if (aadsize > 0) {
    r_poly1305_update (&ctx, aad, aadsize);
    if ((aadsize % 16) != 0)
      r_poly1305_update (&ctx, zeropad, 16 - (aadsize % 16));
  }
  if (ctsize > 0) {
    r_poly1305_update (&ctx, ct, ctsize);
    if ((ctsize % 16) != 0)
      r_poly1305_update (&ctx, zeropad, 16 - (ctsize % 16));
  }

  r_store_le64 (&lengths[0], (ruint64) aadsize);
  r_store_le64 (&lengths[8], (ruint64) ctsize);
  r_poly1305_update (&ctx, lengths, sizeof (lengths));

  r_poly1305_finish (&ctx, tag);
}

/* Derive the one-time Poly1305 key: the first 32 bytes of ChaCha20
 * keystream block 0 (counter 0). */
static void
r_chacha20_poly1305_derive_key (ruint8 polykey[R_POLY1305_KEY_SIZE],
    const ruint8 * key, const ruint8 * nonce)
{
  ruint8 block[R_CHACHA20_BLOCK_SIZE];

  r_chacha20_block (block, key, 0, nonce);
  r_memcpy (polykey, block, R_POLY1305_KEY_SIZE);
  r_memclear_secure (block, sizeof (block));
}

static RCryptoCipherResult
r_cipher_chacha20_poly1305_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize)
{
  const RChaCha20Poly1305Cipher * cc;
  ruint8 polykey[R_POLY1305_KEY_SIZE];

  if (R_UNLIKELY (cipher == NULL || iv == NULL || tag == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (size > 0 && (data == NULL || dst == NULL)))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (aadsize > 0 && aad == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_CHACHA20POLY1305_NONCE_SIZE))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (tagsize == 0 || tagsize > R_POLY1305_TAG_SIZE))
    return R_CRYPTO_CIPHER_INVAL;

  cc = (const RChaCha20Poly1305Cipher *) cipher;

  r_chacha20_poly1305_derive_key (polykey, cc->key, iv);

  /* Payload keystream starts at block counter 1. */
  if (size > 0)
    r_chacha20_xor (dst, data, size, cc->key, 1, iv);

  {
    ruint8 tagcomputed[R_POLY1305_TAG_SIZE];
    r_chacha20_poly1305_tag (tagcomputed, polykey, aad, aadsize, dst, size);
    r_memcpy (tag, tagcomputed, tagsize);
    r_memclear_secure (tagcomputed, sizeof (tagcomputed));
  }

  r_memclear_secure (polykey, sizeof (polykey));
  return R_CRYPTO_CIPHER_OK;
}

static RCryptoCipherResult
r_cipher_chacha20_poly1305_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize)
{
  const RChaCha20Poly1305Cipher * cc;
  ruint8 polykey[R_POLY1305_KEY_SIZE];
  ruint8 tagcomputed[R_POLY1305_TAG_SIZE];
  rboolean authok;

  if (R_UNLIKELY (cipher == NULL || iv == NULL || tag == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (size > 0 && (data == NULL || dst == NULL)))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (aadsize > 0 && aad == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_CHACHA20POLY1305_NONCE_SIZE))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (tagsize == 0 || tagsize > R_POLY1305_TAG_SIZE))
    return R_CRYPTO_CIPHER_INVAL;

  cc = (const RChaCha20Poly1305Cipher *) cipher;

  r_chacha20_poly1305_derive_key (polykey, cc->key, iv);

  /* Authenticate the ciphertext before releasing any plaintext, so a
   * forged record never surfaces to the caller. The compare is
   * constant-time. */
  r_chacha20_poly1305_tag (tagcomputed, polykey, aad, aadsize, data, size);
  authok = r_memcmp_ct (tagcomputed, tag, tagsize) == 0;
  r_memclear_secure (tagcomputed, sizeof (tagcomputed));
  if (!authok) {
    r_memclear_secure (polykey, sizeof (polykey));
    return R_CRYPTO_CIPHER_AUTH_FAILED;
  }

  if (size > 0)
    r_chacha20_xor (dst, data, size, cc->key, 1, iv);

  r_memclear_secure (polykey, sizeof (polykey));
  return R_CRYPTO_CIPHER_OK;
}
