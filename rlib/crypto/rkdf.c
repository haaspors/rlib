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
#include <rlib/crypto/rkdf.h>

#include <rlib/crypto/rhmac.h>
#include <rlib/rmem.h>

#define R_KDF_MAX_HASH    64    /* SHA-512 output, the largest PRF here */

rboolean
r_kdf_pbkdf2 (RMsgDigestType prf, const ruint8 * password, rsize passlen,
    const ruint8 * salt, rsize saltlen, ruint iterations,
    ruint8 * out, rsize outlen)
{
  RHmac * hmac;
  rsize hlen, done = 0;
  ruint block = 1;

  hlen = r_msg_digest_type_size (prf);
  if (R_UNLIKELY (password == NULL || salt == NULL || out == NULL ||
        outlen == 0 || iterations == 0 || hlen == 0 || hlen > R_KDF_MAX_HASH))
    return FALSE;

  if ((hmac = r_hmac_new (prf, password, passlen)) == NULL)
    return FALSE;

  while (done < outlen) {
    /* T_block = U_1 ^ U_2 ^ ... ^ U_iterations, with
     * U_1 = PRF(P, salt || INT32BE(block)) and U_j = PRF(P, U_{j-1}). */
    ruint8 u[R_KDF_MAX_HASH], t[R_KDF_MAX_HASH];
    ruint8 be[4];
    rsize i, n;
    ruint j;

    be[0] = (ruint8) (block >> 24);
    be[1] = (ruint8) (block >> 16);
    be[2] = (ruint8) (block >> 8);
    be[3] = (ruint8) block;

    r_hmac_reset (hmac);
    if (!r_hmac_update (hmac, salt, saltlen) ||
        !r_hmac_update (hmac, be, sizeof (be)) ||
        !r_hmac_get_data (hmac, u, sizeof (u), NULL))
      goto fail;
    r_memcpy (t, u, hlen);

    for (j = 1; j < iterations; j++) {
      r_hmac_reset (hmac);
      if (!r_hmac_update (hmac, u, hlen) ||
          !r_hmac_get_data (hmac, u, sizeof (u), NULL))
        goto fail;
      for (i = 0; i < hlen; i++)
        t[i] ^= u[i];
    }

    n = (outlen - done < hlen) ? outlen - done : hlen;
    r_memcpy (out + done, t, n);
    done += n;
    block++;

    r_memclear_secure (u, sizeof (u));
    r_memclear_secure (t, sizeof (t));
    continue;

fail:
    r_memclear_secure (u, sizeof (u));
    r_memclear_secure (t, sizeof (t));
    r_hmac_free (hmac);
    return FALSE;
  }

  r_hmac_free (hmac);
  return TRUE;
}

rboolean
r_hkdf_extract (RMsgDigestType hash, const ruint8 * salt, rsize saltlen,
    const ruint8 * ikm, rsize ikmlen, ruint8 * prk)
{
  static const ruint8 empty[1] = { 0 };
  RHmac * hmac;
  rsize hlen = r_msg_digest_type_size (hash);
  rboolean ok;

  if (R_UNLIKELY (ikm == NULL || prk == NULL || hlen == 0 ||
        hlen > R_KDF_MAX_HASH || (salt == NULL && saltlen != 0)))
    return FALSE;

  /* PRK = HMAC-Hash(salt, IKM). An empty/absent salt is HashLen zeros, which
   * HMAC's key zero-padding produces from a zero-length key. */
  if ((hmac = r_hmac_new (hash, (salt != NULL) ? salt : empty, saltlen)) == NULL)
    return FALSE;
  ok = r_hmac_update (hmac, ikm, ikmlen) &&
       r_hmac_get_data (hmac, prk, hlen, NULL);
  r_hmac_free (hmac);
  return ok;
}

rboolean
r_hkdf_expand (RMsgDigestType hash, const ruint8 * prk, rsize prklen,
    const ruint8 * info, rsize infolen, ruint8 * out, rsize outlen)
{
  RHmac * hmac;
  rsize hlen = r_msg_digest_type_size (hash);
  rsize done = 0, tlen = 0;
  ruint8 t[R_KDF_MAX_HASH];
  ruint8 counter = 0;
  rboolean ok = TRUE;

  if (R_UNLIKELY (prk == NULL || out == NULL || outlen == 0 || hlen == 0 ||
        hlen > R_KDF_MAX_HASH || (info == NULL && infolen != 0)))
    return FALSE;
  if (R_UNLIKELY (outlen > 255 * hlen))     /* RFC 5869: L <= 255*HashLen */
    return FALSE;

  if ((hmac = r_hmac_new (hash, prk, prklen)) == NULL)
    return FALSE;

  while (done < outlen) {
    rsize n;

    /* T(i) = HMAC-Hash(PRK, T(i-1) | info | i), T(0) empty, i from 1. */
    counter++;
    r_hmac_reset (hmac);
    if ((tlen != 0 && !r_hmac_update (hmac, t, tlen)) ||
        (infolen != 0 && !r_hmac_update (hmac, info, infolen)) ||
        !r_hmac_update (hmac, &counter, 1) ||
        !r_hmac_get_data (hmac, t, sizeof (t), NULL)) {
      ok = FALSE;
      break;
    }
    tlen = hlen;
    n = (outlen - done < hlen) ? outlen - done : hlen;
    r_memcpy (out + done, t, n);
    done += n;
  }

  r_memclear_secure (t, sizeof (t));
  r_hmac_free (hmac);
  return ok;
}
