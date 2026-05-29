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
#include "rprng-private.h"

#include <rlib/crypto/rchacha20.h>
#include <rlib/rmem.h>

#include <stdlib.h>

/* ChaCha20 DRBG with fast key erasure, after D. J. Bernstein's
 * "fast-key-erasure random-number generators" (and the same construction
 * as OpenBSD/Linux arc4random). Each refill runs ChaCha20 over zeros with
 * the current key; the first 32 keystream bytes become the next key (so the
 * key that produced any output is immediately destroyed -> forward secrecy)
 * and the remainder is handed out. The pool is reseeded from the OS entropy
 * source on creation and after R_PRNG_CRYPTO_RESEED output bytes. */

#define R_PRNG_CRYPTO_KEY_SIZE      R_CHACHA20_KEY_SIZE
#define R_PRNG_CRYPTO_OUT_SIZE      256
#define R_PRNG_CRYPTO_RESEED        (1024 * 1024)

typedef struct {
  ruint8  key[R_PRNG_CRYPTO_KEY_SIZE];
  ruint8  out[R_PRNG_CRYPTO_OUT_SIZE];
  rsize   outpos;             /* next unused byte in out[] */
  rsize   since_reseed;       /* output bytes produced since last reseed */
} RPrngCryptoState;

/* Pull fresh OS entropy and fold it into the key. Aborts on entropy
 * failure rather than continuing with a stale/predictable key. */
static void
r_prng_crypto_reseed (RPrngCryptoState * st)
{
  ruint8 seed[R_PRNG_CRYPTO_KEY_SIZE];
  rsize i;

  if (R_UNLIKELY (!r_rand_entropy_fill (seed, sizeof (seed))))
    abort ();

  for (i = 0; i < sizeof (st->key); i++)
    st->key[i] ^= seed[i];

  r_memclear_secure (seed, sizeof (seed));
  st->since_reseed = 0;
}

static void
r_prng_crypto_refill (RPrngCryptoState * st)
{
  static const ruint8 nonce[R_CHACHA20_NONCE_SIZE] = { 0, };
  ruint8 ks[R_PRNG_CRYPTO_KEY_SIZE + R_PRNG_CRYPTO_OUT_SIZE];

  if (st->since_reseed >= R_PRNG_CRYPTO_RESEED)
    r_prng_crypto_reseed (st);

  /* Keystream = ChaCha20(key) over zeros; first block of input is zero so
   * xor yields raw keystream. */
  r_memclear (ks, sizeof (ks));
  r_chacha20_xor (ks, ks, sizeof (ks), st->key, 0, nonce);

  r_memcpy (st->key, ks, R_PRNG_CRYPTO_KEY_SIZE);            /* erase old key */
  r_memcpy (st->out, ks + R_PRNG_CRYPTO_KEY_SIZE, R_PRNG_CRYPTO_OUT_SIZE);
  r_memclear_secure (ks, sizeof (ks));

  st->outpos = 0;
  st->since_reseed += R_PRNG_CRYPTO_OUT_SIZE;
}

static ruint64
r_prng_crypto_get (RPrng * prng)
{
  RPrngCryptoState * st = (RPrngCryptoState *) prng->data;
  ruint64 ret;

  if (st->outpos + sizeof (ret) > R_PRNG_CRYPTO_OUT_SIZE)
    r_prng_crypto_refill (st);

  r_memcpy (&ret, st->out + st->outpos, sizeof (ret));
  st->outpos += sizeof (ret);

  return ret;
}

static void
r_prng_crypto_free (rpointer data)
{
  RPrng * prng = data;
  RPrngCryptoState * st = (RPrngCryptoState *) prng->data;

  r_memclear_secure (st, sizeof (*st));
  r_free (prng);
}

RPrng *
r_prng_new_crypto (void)
{
  RPrng * ret;

  if ((ret = r_prng_new (r_prng_crypto_get, sizeof (RPrngCryptoState))) != NULL) {
    RPrngCryptoState * st = (RPrngCryptoState *) ret->data;

    r_memclear (st, sizeof (*st));
    /* Force a reseed + refill on the first draw. */
    st->since_reseed = R_PRNG_CRYPTO_RESEED;
    st->outpos = R_PRNG_CRYPTO_OUT_SIZE;

    /* r_prng_new initialised the ref with r_free; swap in a destructor
     * that wipes the key material first. */
    r_ref_init (ret, r_prng_crypto_free);
  }

  return ret;
}
