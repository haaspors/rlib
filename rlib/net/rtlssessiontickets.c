/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rtlssessiontickets-private.h"

#include <rlib/crypto/raes.h>
#include <rlib/crypto/rcipher.h>

#include <rlib/rmem.h>
#include <rlib/rrand.h>

#define R_TLS_STK_KEY_NAME_SIZE   16
#define R_TLS_STK_KEY_SIZE        16
#define R_TLS_STK_NONCE_SIZE      12
#define R_TLS_STK_TAG_SIZE        16

struct RTLSSessionTicketKeys {
  RRef ref;
  ruint8 key_name[R_TLS_STK_KEY_NAME_SIZE];
  ruint8 key[R_TLS_STK_KEY_SIZE];
};

static void
r_tls_session_ticket_keys_free (RTLSSessionTicketKeys * keys)
{
  r_memclear_secure (keys->key, sizeof (keys->key));
  r_free (keys);
}

RTLSSessionTicketKeys *
r_tls_session_ticket_keys_new (void)
{
  RTLSSessionTicketKeys * ret;

  if ((ret = r_mem_new (RTLSSessionTicketKeys)) != NULL) {
    if (!r_rand_entropy_fill (ret->key_name, sizeof (ret->key_name)) ||
        !r_rand_entropy_fill (ret->key, sizeof (ret->key))) {
      r_memclear_secure (ret->key, sizeof (ret->key));
      r_free (ret);
      return NULL;
    }
    r_ref_init (ret, r_tls_session_ticket_keys_free);
  }

  return ret;
}

rboolean
r_tls_session_ticket_keys_seal (RTLSSessionTicketKeys * keys,
    const ruint8 * plain, rsize plainlen, ruint8 ** out, rsize * outlen)
{
  RCryptoCipher * cipher;
  ruint8 * ticket, * nonce, * ct, * tag;
  rsize ticketlen = R_TLS_STK_KEY_NAME_SIZE + R_TLS_STK_NONCE_SIZE +
      plainlen + R_TLS_STK_TAG_SIZE;
  RCryptoCipherResult cr;

  if (R_UNLIKELY (keys == NULL)) return FALSE;

  if ((cipher = r_cipher_aes_128_gcm_new (keys->key)) == NULL)
    return FALSE;
  if ((ticket = r_malloc (ticketlen)) == NULL) {
    r_crypto_cipher_unref (cipher);
    return FALSE;
  }

  r_memcpy (ticket, keys->key_name, R_TLS_STK_KEY_NAME_SIZE);
  nonce = ticket + R_TLS_STK_KEY_NAME_SIZE;
  ct = nonce + R_TLS_STK_NONCE_SIZE;
  tag = ct + plainlen;

  if (!r_rand_entropy_fill (nonce, R_TLS_STK_NONCE_SIZE)) {
    r_crypto_cipher_unref (cipher);
    r_free (ticket);
    return FALSE;
  }

  /* The key_name is authenticated (AAD) but not encrypted: it travels in the
   * clear so the open side can pick the right key before decrypting. */
  cr = r_crypto_cipher_encrypt_aead (cipher, ct, plainlen, plain,
      keys->key_name, R_TLS_STK_KEY_NAME_SIZE, nonce, R_TLS_STK_NONCE_SIZE,
      tag, R_TLS_STK_TAG_SIZE);
  r_crypto_cipher_unref (cipher);

  if (cr != R_CRYPTO_CIPHER_OK) {
    r_free (ticket);
    return FALSE;
  }

  *out = ticket;
  *outlen = ticketlen;
  return TRUE;
}

rboolean
r_tls_session_ticket_keys_open (RTLSSessionTicketKeys * keys,
    const ruint8 * ticket, rsize len, ruint8 * plain_out, rsize cap,
    rsize * plainlen_out)
{
  RCryptoCipher * cipher;
  const ruint8 * nonce, * ct, * tag;
  rsize plainlen;
  RCryptoCipherResult cr;

  if (R_UNLIKELY (keys == NULL)) return FALSE;
  if (len < R_TLS_SESSION_TICKET_SEAL_OVERHEAD)
    return FALSE;
  plainlen = len - R_TLS_SESSION_TICKET_SEAL_OVERHEAD;
  if (plainlen > cap)
    return FALSE;
  /* Reject tickets sealed under a different key before touching the cipher. */
  if (r_memcmp (ticket, keys->key_name, R_TLS_STK_KEY_NAME_SIZE) != 0)
    return FALSE;

  nonce = ticket + R_TLS_STK_KEY_NAME_SIZE;
  ct = nonce + R_TLS_STK_NONCE_SIZE;
  tag = ct + plainlen;

  if ((cipher = r_cipher_aes_128_gcm_new (keys->key)) == NULL)
    return FALSE;
  cr = r_crypto_cipher_decrypt_aead (cipher, plain_out, plainlen, ct,
      keys->key_name, R_TLS_STK_KEY_NAME_SIZE,
      (ruint8 *) nonce, R_TLS_STK_NONCE_SIZE, (ruint8 *) tag, R_TLS_STK_TAG_SIZE);
  r_crypto_cipher_unref (cipher);

  if (cr != R_CRYPTO_CIPHER_OK)
    return FALSE;

  *plainlen_out = plainlen;
  return TRUE;
}
