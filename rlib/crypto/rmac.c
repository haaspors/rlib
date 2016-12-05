/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/crypto/rmac.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

struct _RHmac {
  RHash * inner;
  RHash * outer;
  ruint32 * keyblock;
  rsize blocksize;
};

RHmac *
r_hmac_new (RHashType type, rconstpointer key, rsize keysize)
{
  RHmac * hmac;

  if ((hmac = r_mem_new (RHmac)) != NULL) {
    hmac->inner = r_hash_new (type);
    hmac->outer = r_hash_new (type);
    hmac->blocksize = r_hash_blocksize (hmac->inner);
    hmac->keyblock = r_malloc0 (hmac->blocksize);

    if (hmac->inner == NULL || hmac->outer == NULL ||
        hmac->blocksize == 0 || hmac->keyblock == NULL) {
      r_hmac_free (hmac);
      return NULL;
    }

    if (keysize > hmac->blocksize) {
      r_hash_update (hmac->inner, key, keysize);
      r_hash_get_data (hmac->inner, (ruint8 *)hmac->keyblock, &keysize);
    } else {
      r_memcpy (hmac->keyblock, key, keysize);
    }

    r_hmac_reset (hmac);
  }

  return hmac;
}

void
r_hmac_free (RHmac * hmac)
{
  if (hmac != NULL) {
    r_hash_free (hmac->inner);
    r_hash_free (hmac->outer);
    r_free (hmac->keyblock);
    r_free (hmac);
  }
}

rsize
r_hmac_size (const RHmac * hmac)
{
  return r_hash_size (hmac->inner);
}

void
r_hmac_reset (RHmac * hmac)
{
  rsize i;
  ruint32 * block = r_alloca (hmac->blocksize);

  r_hash_reset (hmac->inner);
  r_hash_reset (hmac->outer);

  for (i = 0; i < hmac->blocksize / sizeof (ruint32); i++)
    block[i] = hmac->keyblock[i] ^ 0x36363636;
  r_hash_update (hmac->inner, block, hmac->blocksize);

  for (i = 0; i < hmac->blocksize / sizeof (ruint32); i++)
    block[i] = hmac->keyblock[i] ^ 0x5c5c5c5c;
  r_hash_update (hmac->outer, block, hmac->blocksize);
}


rboolean
r_hmac_update (RHmac * hmac, rconstpointer data, rsize size)
{
  if (hmac != NULL)
    return r_hash_update (hmac->inner, data, size);

  return FALSE;
}

rboolean
r_hmac_get_data (RHmac * hmac, ruint8 * data, rsize * size)
{
  rsize isize;

  if (R_UNLIKELY (hmac == NULL || data == NULL || size == NULL))
    return FALSE;

  isize = *size;
  if (r_hash_get_data (hmac->inner, data, &isize) &&
      r_hash_update (hmac->outer, data, isize))
    return r_hash_get_data (hmac->outer, data, size);

  return FALSE;
}

rchar *
r_hmac_get_hex (RHmac * hmac)
{
  ruint8 * data;
  rsize size;

  if (hmac != NULL && (size = r_hash_blocksize (hmac->inner)) > 0 &&
      (data = r_alloca (size)) != NULL && r_hmac_get_data (hmac, data, &size))
    return r_str_mem_hex (data, size);

  return NULL;
}

