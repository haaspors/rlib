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
#include <rlib/net/proto/rtls12.h>
#include "rtls-private.h"

#include <rlib/crypto/rhmac.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/rmem.h>

#include <stdarg.h>

rboolean
r_tls_prf_and_hash_for (RMsgDigestType hash, RTLSPrfFunc * prf, RMsgDigest ** hshash)
{
  switch (hash) {
    case R_MSG_DIGEST_TYPE_SHA256:
      *prf = r_tls_1_2_prf_sha256;
      *hshash = r_sha256_new ();
      break;
    case R_MSG_DIGEST_TYPE_SHA384:
      *prf = r_tls_1_2_prf_sha384;
      *hshash = r_sha384_new ();
      break;
    default:
      return FALSE;
  }

  return *hshash != NULL;
}

static RTLSError
r_tls_1_2_prf (RMsgDigestType type, ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, va_list args)
{
  ruint8 * seed;
  rsize seedsize;
  RHmac * hmac;
  RTLSError ret;

  if (R_UNLIKELY (dst == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (secret == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (secsize == 0)) return R_TLS_ERROR_INVAL;

  if (R_UNLIKELY ((seed = r_memdup_aggv (&seedsize, args)) == NULL))
    return R_TLS_ERROR_OOM;

  if ((hmac = r_hmac_new (type, secret, secsize)) != NULL) {
    const rsize mdsize = r_msg_digest_type_size (type);
    ruint8 * scratch = r_alloca (mdsize);
    rsize size;

    r_hmac_update (hmac, seed, seedsize);
    r_hmac_get_data (hmac, scratch, mdsize, &size); /* = A(1) */

    while (dsize > mdsize) {
      r_hmac_reset (hmac);
      r_hmac_update (hmac, scratch, mdsize); /* A(i - 1) */
      r_hmac_update (hmac, seed, seedsize);
      r_hmac_get_data (hmac, dst, mdsize, &size);
      dst += size;
      dsize -= size;

      r_hmac_reset (hmac);
      r_hmac_update (hmac, scratch, mdsize); /* A(i - 1) */
      r_hmac_get_data (hmac, scratch, mdsize, &size); /* = A(i) */
    }

    if (dsize > 0) {
      r_hmac_reset (hmac);
      r_hmac_update (hmac, scratch, mdsize); /* A(i - 1) */
      r_hmac_update (hmac, seed, seedsize);
      r_hmac_get_data (hmac, scratch, mdsize, &size);
      r_memcpy (dst, scratch, dsize);
    }

    ret = R_TLS_ERROR_OK;

    r_memclear (scratch, mdsize);
    r_hmac_free (hmac);
  } else {
    ret = R_TLS_ERROR_OOM;
  }

  r_free (seed);
  return ret;
}

RTLSError
r_tls_1_2_prf_sha224 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...)
{
  va_list args;
  RTLSError ret;

  va_start (args, secsize);
  ret = r_tls_1_2_prf (R_MSG_DIGEST_TYPE_SHA224, dst, dsize, secret, secsize, args);
  va_end (args);

  return ret;
}

RTLSError
r_tls_1_2_prf_sha256 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...)
{
  va_list args;
  RTLSError ret;

  va_start (args, secsize);
  ret = r_tls_1_2_prf (R_MSG_DIGEST_TYPE_SHA256, dst, dsize, secret, secsize, args);
  va_end (args);

  return ret;
}

RTLSError
r_tls_1_2_prf_sha384 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...)
{
  va_list args;
  RTLSError ret;

  va_start (args, secsize);
  ret = r_tls_1_2_prf (R_MSG_DIGEST_TYPE_SHA384, dst, dsize, secret, secsize, args);
  va_end (args);

  return ret;
}

RTLSError
r_tls_1_2_prf_sha512 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...)
{
  va_list args;
  RTLSError ret;

  va_start (args, secsize);
  ret = r_tls_1_2_prf (R_MSG_DIGEST_TYPE_SHA512, dst, dsize, secret, secsize, args);
  va_end (args);

  return ret;
}
