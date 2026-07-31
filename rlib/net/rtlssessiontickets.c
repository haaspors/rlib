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

#include <rlib/concurrency/rthreads.h>
#include <rlib/rmem.h>
#include <rlib/rrand.h>

#define R_TLS_STK_KEY_NAME_SIZE   16
#define R_TLS_STK_KEY_SIZE        16
#define R_TLS_STK_NONCE_SIZE      12
#define R_TLS_STK_TAG_SIZE        16
/* The active key plus this many recent keys are retained, so a rotation does
 * not invalidate tickets sealed under the keys it replaces. */
#define R_TLS_STK_KEYS_MAX        3

/* Recent accepted 0-RTT ClientHellos remembered for anti-replay, and the cap on
 * the identifier (a PSK binder, at most one hash long). */
#define R_TLS_STK_STRIKE_MAX      256
#define R_TLS_STK_STRIKE_ID_MAX   64

typedef struct {
  ruint8 key_name[R_TLS_STK_KEY_NAME_SIZE];
  ruint8 key[R_TLS_STK_KEY_SIZE];
} RTLSSessionTicketKey;

typedef struct {
  ruint8 id[R_TLS_STK_STRIKE_ID_MAX];
  ruint8 idlen;                             /* 0 marks a free slot */
  RClockTime expiry;
} RTLSStrikeEntry;

struct RTLSSessionTicketKeys {
  RRef ref;
  /* Guards the key set (seal / open take the read lock, rotate the write lock)
   * and the strike register (write lock). The store is shared across servers
   * (and so potentially threads). */
  RRWMutex lock;
  rsize count;                              /* valid keys, 1..R_TLS_STK_KEYS_MAX */
  RTLSSessionTicketKey keys[R_TLS_STK_KEYS_MAX];  /* keys[0] is the active key */
  rsize strike_count;                       /* high-water mark of used strike slots */
  RTLSStrikeEntry strikes[R_TLS_STK_STRIKE_MAX];
};

static rboolean
r_tls_session_ticket_key_generate (RTLSSessionTicketKey * key)
{
  if (!r_rand_entropy_fill (key->key_name, sizeof (key->key_name)) ||
      !r_rand_entropy_fill (key->key, sizeof (key->key))) {
    r_memclear_secure (key->key, sizeof (key->key));
    return FALSE;
  }
  return TRUE;
}

static void
r_tls_session_ticket_keys_free (RTLSSessionTicketKeys * keys)
{
  rsize i;
  for (i = 0; i < R_TLS_STK_KEYS_MAX; i++)
    r_memclear_secure (keys->keys[i].key, sizeof (keys->keys[i].key));
  r_rwmutex_clear (&keys->lock);
  r_free (keys);
}

RTLSSessionTicketKeys *
r_tls_session_ticket_keys_new (void)
{
  RTLSSessionTicketKeys * ret;

  if ((ret = r_mem_new0 (RTLSSessionTicketKeys)) != NULL) {
    if (!r_tls_session_ticket_key_generate (&ret->keys[0])) {
      r_free (ret);
      return NULL;
    }
    ret->count = 1;
    r_rwmutex_init (&ret->lock);
    r_ref_init (ret, r_tls_session_ticket_keys_free);
  }

  return ret;
}

rboolean
r_tls_session_ticket_keys_rotate (RTLSSessionTicketKeys * keys)
{
  RTLSSessionTicketKey fresh;
  rsize i;

  if (R_UNLIKELY (keys == NULL)) return FALSE;
  if (!r_tls_session_ticket_key_generate (&fresh))
    return FALSE;

  r_rwmutex_wrlock (&keys->lock);
  /* Age the oldest key out (scrubbed) and shift the rest down, then promote the
   * fresh key to active. */
  if (keys->count == R_TLS_STK_KEYS_MAX)
    r_memclear_secure (keys->keys[R_TLS_STK_KEYS_MAX - 1].key,
        sizeof (keys->keys[R_TLS_STK_KEYS_MAX - 1].key));
  else
    keys->count++;
  for (i = keys->count - 1; i > 0; i--)
    keys->keys[i] = keys->keys[i - 1];
  keys->keys[0] = fresh;
  r_rwmutex_wrunlock (&keys->lock);

  r_memclear_secure (fresh.key, sizeof (fresh.key));
  return TRUE;
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

  if ((ticket = r_malloc (ticketlen)) == NULL)
    return FALSE;

  nonce = ticket + R_TLS_STK_KEY_NAME_SIZE;
  ct = nonce + R_TLS_STK_NONCE_SIZE;
  tag = ct + plainlen;

  if (!r_rand_entropy_fill (nonce, R_TLS_STK_NONCE_SIZE)) {
    r_free (ticket);
    return FALSE;
  }

  /* Seal under the active key (keys[0]). The key_name is authenticated (AAD)
   * but not encrypted: it travels in the clear so the open side can pick the
   * right key before decrypting. */
  r_rwmutex_rdlock (&keys->lock);
  r_memcpy (ticket, keys->keys[0].key_name, R_TLS_STK_KEY_NAME_SIZE);
  if ((cipher = r_cipher_aes_128_gcm_new (keys->keys[0].key)) != NULL) {
    cr = r_crypto_cipher_encrypt_aead (cipher, ct, plainlen, plain,
        keys->keys[0].key_name, R_TLS_STK_KEY_NAME_SIZE,
        nonce, R_TLS_STK_NONCE_SIZE, tag, R_TLS_STK_TAG_SIZE);
    r_crypto_cipher_unref (cipher);
  } else {
    cr = R_CRYPTO_CIPHER_OOM;
  }
  r_rwmutex_rdunlock (&keys->lock);

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
  rsize plainlen, i;
  RCryptoCipherResult cr = R_CRYPTO_CIPHER_AUTH_FAILED;

  if (R_UNLIKELY (keys == NULL)) return FALSE;
  if (len < R_TLS_SESSION_TICKET_SEAL_OVERHEAD)
    return FALSE;
  plainlen = len - R_TLS_SESSION_TICKET_SEAL_OVERHEAD;
  if (plainlen > cap)
    return FALSE;

  nonce = ticket + R_TLS_STK_KEY_NAME_SIZE;
  ct = nonce + R_TLS_STK_NONCE_SIZE;
  tag = ct + plainlen;

  /* Find the key whose key_name the ticket carries -- the active key or one of
   * the recent keys still retained after a rotation -- then decrypt with it. */
  r_rwmutex_rdlock (&keys->lock);
  for (i = 0; i < keys->count; i++) {
    if (r_memcmp (ticket, keys->keys[i].key_name, R_TLS_STK_KEY_NAME_SIZE) != 0)
      continue;
    if ((cipher = r_cipher_aes_128_gcm_new (keys->keys[i].key)) != NULL) {
      cr = r_crypto_cipher_decrypt_aead (cipher, plain_out, plainlen, ct,
          keys->keys[i].key_name, R_TLS_STK_KEY_NAME_SIZE,
          (ruint8 *) nonce, R_TLS_STK_NONCE_SIZE, (ruint8 *) tag, R_TLS_STK_TAG_SIZE);
      r_crypto_cipher_unref (cipher);
    }
    break;
  }
  r_rwmutex_rdunlock (&keys->lock);

  if (cr != R_CRYPTO_CIPHER_OK)
    return FALSE;

  *plainlen_out = plainlen;
  return TRUE;
}

rboolean
r_tls_session_ticket_keys_strike (RTLSSessionTicketKeys * keys,
    const ruint8 * id, rsize idlen, RClockTime now, RClockTime expiry)
{
  rsize i, free_slot = R_TLS_STK_STRIKE_MAX, oldest = 0;
  rboolean fresh = TRUE;

  /* An identifier we cannot store is treated as a replay: better to refuse 0-RTT
   * than to accept a flight we cannot remember. */
  if (id == NULL || idlen == 0 || idlen > R_TLS_STK_STRIKE_ID_MAX)
    return FALSE;

  r_rwmutex_wrlock (&keys->lock);
  for (i = 0; i < keys->strike_count; i++) {
    RTLSStrikeEntry * e = &keys->strikes[i];
    if (e->idlen == 0 || e->expiry <= now) {   /* free or expired: reclaim */
      e->idlen = 0;
      if (free_slot == R_TLS_STK_STRIKE_MAX)
        free_slot = i;
      continue;
    }
    if (e->idlen == idlen && r_memcmp (e->id, id, idlen) == 0) {
      fresh = FALSE;                            /* seen within the window: replay */
      break;
    }
    if (e->expiry < keys->strikes[oldest].expiry)
      oldest = i;
  }
  if (fresh) {
    RTLSStrikeEntry * e;
    if (free_slot != R_TLS_STK_STRIKE_MAX)
      e = &keys->strikes[free_slot];
    else if (keys->strike_count < R_TLS_STK_STRIKE_MAX)
      e = &keys->strikes[keys->strike_count++];
    else
      e = &keys->strikes[oldest];              /* full: evict soonest-to-expire */
    r_memcpy (e->id, id, idlen);
    e->idlen = (ruint8) idlen;
    e->expiry = expiry;
  }
  r_rwmutex_wrunlock (&keys->lock);
  return fresh;
}
