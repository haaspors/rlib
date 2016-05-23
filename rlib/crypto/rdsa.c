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
#include <rlib/crypto/rdsa.h>
#include <rlib/rmem.h>

typedef struct {
  RCryptoKey key;

  rmpint p;
  rmpint q;
  rmpint g;
  rmpint y;
} RDsaPubKey;

typedef struct {
  RCryptoKey key;

  rmpint p;
  rmpint q;
  rmpint g;
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
    r_free (key);
  }
}

static void
r_dsa_pub_key_init (RCryptoKey * key)
{
  r_ref_init (key, r_dsa_pub_key_free);
  key->type = R_CRYPTO_PUBLIC_KEY;
  key->algo = R_CRYPTO_ALGO_DSA;
  key->strtype = R_DSA_STR;
}

RCryptoKey *
r_dsa_pub_key_new (const rmpint * p, const rmpint * q,
    const rmpint * g, const rmpint * y)
{
  RDsaPubKey * ret;

  if (p != NULL && q != NULL && g != NULL && y != NULL) {
    if ((ret = r_mem_new (RDsaPubKey)) != NULL) {
      r_dsa_pub_key_init (&ret->key);
      r_mpint_init_copy (&ret->p, p);
      r_mpint_init_copy (&ret->q, q);
      r_mpint_init_copy (&ret->g, g);
      r_mpint_init_copy (&ret->y, y);
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
      r_dsa_pub_key_init (&ret->key);
      r_mpint_init_binary (&ret->p, p, psize);
      r_mpint_init_binary (&ret->q, q, qsize);
      r_mpint_init_binary (&ret->g, g, gsize);
      r_mpint_init_binary (&ret->y, y, ysize);
    }
  } else {
    ret = NULL;
  }

  return (RCryptoKey *)ret;
}


