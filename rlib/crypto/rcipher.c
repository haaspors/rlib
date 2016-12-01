/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/crypto/rcrypto-private.h>


static RCryptoCipherResult
r_crypto_cipher_null_func (const RCryptoCipher * cipher,
    ruint8 * iv, rconstpointer data, rsize size, ruint8 * out)
{
  (void) cipher;
  (void) iv;

  if (out != data)
    r_memmove (out, data, size);

  return R_CRYPTO_CIPHER_OK;
}

const RCryptoCipherInfo g__r_crypto_null_cipher = { "NULL",
  R_CRYPTO_CIPHER_ALGO_NULL, R_CRYPTO_CIPHER_MODE_STREAM, 0, 0, 1,
  r_crypto_cipher_null_func, r_crypto_cipher_null_func
};

const RCryptoCipherInfo * g__r_crypto_ciphers[] = {
  &g__r_crypto_null_cipher,
  &g__r_crypto_cipher_aes_128_ecb,
  &g__r_crypto_cipher_aes_192_ecb,
  &g__r_crypto_cipher_aes_256_ecb,
  &g__r_crypto_cipher_aes_128_cbc,
  &g__r_crypto_cipher_aes_192_cbc,
  &g__r_crypto_cipher_aes_256_cbc,
  NULL
};

RCryptoCipher *
r_crypto_cipher_null_new ()
{
  RCryptoCipher * ret;

  if ((ret = r_mem_new (RCryptoCipher)) != NULL) {
    r_ref_init (ret, r_free);
    ret->info = &g__r_crypto_null_cipher;
  }

  return ret;
}

RCryptoCipher *
r_crypto_cipher_new (const RCryptoCipherInfo * info, const ruint8 * key)
{
  if (R_UNLIKELY (info == NULL)) return NULL;

  switch (info->type) {
    case R_CRYPTO_CIPHER_ALGO_NULL:
      return r_crypto_cipher_null_new ();
    case R_CRYPTO_CIPHER_ALGO_AES:
      return r_cipher_aes_new_with_info (info, key);
    default:
      break;
  }

  return NULL;
}

RCryptoCipherResult
r_crypto_cipher_encrypt (const RCryptoCipher * cipher,
    ruint8 * iv, rconstpointer data, rsize size, ruint8 * out)
{
  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  return cipher->info->enc (cipher, iv, data, size, out);
}

RCryptoCipherResult
r_crypto_cipher_decrypt (const RCryptoCipher * cipher,
    ruint8 * iv, rconstpointer data, rsize size, ruint8 * out)
{
  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  return cipher->info->dec (cipher, iv, data, size, out);
}

