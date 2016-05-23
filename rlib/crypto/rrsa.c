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
#include <rlib/crypto/rrsa.h>
#include <rlib/rmem.h>

typedef struct {
  RCryptoKey key;

  rmpint n;
  rmpint e;
} RRsaPubKey;

typedef struct {
  RCryptoKey key;

  rmpint n;
  rmpint e;
  rmpint d;
  rmpint p;
  rmpint q;
} RRsaPrivKey;

static void
r_rsa_pub_key_free (rpointer data)
{
  RRsaPubKey * key;

  if ((key = data) != NULL) {
    r_mpint_clear (&key->n);
    r_mpint_clear (&key->e);
    r_free (key);
  }
}

static void
r_rsa_pub_key_init (RCryptoKey * key)
{
  r_ref_init (key, r_rsa_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = R_CRYPTO_ALGO_RSA;
  key->strtype = R_RSA_STR;
}

RCryptoKey *
r_rsa_pub_key_new (const rmpint * n, const rmpint * e)
{
  RRsaPubKey * ret;

  if (n != NULL && e != NULL) {
    if ((ret = r_mem_new (RRsaPubKey)) != NULL) {
      r_rsa_pub_key_init (&ret->key);
      r_mpint_init_copy (&ret->n, n);
      r_mpint_init_copy (&ret->e, e);
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
      r_rsa_pub_key_init (&ret->key);
      r_mpint_init_binary (&ret->n, n, nsize);
      r_mpint_init_binary (&ret->e, e, esize);
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}

rboolean
r_rsa_pub_key_get_exponent (RCryptoKey * key, rmpint * e)
{
  if (key != NULL && e != NULL &&
      key->type == R_CRYPTO_PUBLIC_KEY && key->algo == R_CRYPTO_ALGO_RSA) {
    r_mpint_set (e, &((RRsaPubKey *)key)->e);
    return TRUE;
  }

  return FALSE;
}

rboolean
r_rsa_pub_key_get_modulus (RCryptoKey * key, rmpint * n)
{
  if (key != NULL && n != NULL &&
      key->type == R_CRYPTO_PUBLIC_KEY && key->algo == R_CRYPTO_ALGO_RSA) {
    r_mpint_set (n, &((RRsaPubKey *)key)->n);
    return TRUE;
  }

  return FALSE;
}

rboolean
r_rsa_pub_key_encrypt (RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  if (R_UNLIKELY (key == NULL || data == NULL || size == 0 ||
        out == NULL || outsize == NULL || *outsize == 0))
    return FALSE;

  /* TODO: implment... */
  return FALSE;
}

rboolean
r_rsa_pub_key_decrypt (RCryptoKey * key,
    rconstpointer data, rsize size, ruint8 * out, rsize * outsize)
{
  if (R_UNLIKELY (key == NULL || data == NULL || size == 0 ||
        out == NULL || outsize == NULL || *outsize == 0))
    return FALSE;

  /* TODO: implment... */
  return FALSE;
}

