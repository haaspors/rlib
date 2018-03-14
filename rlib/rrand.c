/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

#include <rlib/rbase64.h>
#include <rlib/rmem.h>
#include <rlib/rtime.h>

#if defined (R_OS_WIN32)
#include <wincrypt.h>
#elif defined (R_OS_UNIX)
#include <rlib/file/rfile.h>
#endif

ruint64
r_rand_entropy_u64 (void)
{
  ruint64 ret;
#if defined (R_OS_WIN32)
  HCRYPTPROV hCryptProv = (HCRYPTPROV)NULL;

  if (CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
    BOOL res = CryptGenRandom (hCryptProv, sizeof (ret), (BYTE *)&ret);

    CryptReleaseContext (hCryptProv, 0);
    if (res)
      return ret;
  }
#elif defined (R_OS_UNIX)
  RFile * devurand;

  if ((devurand = r_file_open ("/dev/urandom", "rb")) != NULL) {
    rsize res = 0;

    r_file_read (devurand, &ret, sizeof (ruint64), &res);
    r_file_unref (devurand);

    if (res == sizeof (ruint64))
      return ret;
  }
#endif

  return r_time_get_ts_monotonic ();
}

ruint32
r_rand_entropy_u32 (void)
{
  ruint32 ret;
#if defined (R_OS_WIN32)
  HCRYPTPROV hCryptProv = (HCRYPTPROV)NULL;

  if (CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
    BOOL res = CryptGenRandom (hCryptProv, sizeof (ret), (BYTE *)&ret);

    CryptReleaseContext (hCryptProv, 0);
    if (res)
      return ret;
  }
#elif defined (R_OS_UNIX)
  RFile * devurand;

  if ((devurand = r_file_open ("/dev/urandom", "rb")) != NULL) {
    rsize res = 0;

    r_file_read (devurand, &ret, sizeof (ruint32), &res);
    r_file_unref (devurand);

    if (res == sizeof (ruint32))
      return ret;
  }
#endif

  return (ruint32)(r_time_get_ts_monotonic () & RUINT32_MAX);
}

RPrng *
r_prng_new (RPrngGetFunc func, rsize size)
{
  RPrng * ret;

  if ((ret = r_malloc (sizeof (RPrng) + size)) != NULL) {
    r_ref_init (ret, r_free);
    ret->get = func;
  }

  return ret;
}

ruint64
r_prng_get_u64 (RPrng * prng)
{
  return prng->get (prng);
}

rboolean
r_prng_fill (RPrng * prng, ruint8 * buf, rsize size)
{
  static const rsize inc = sizeof (ruint64);

  if (R_UNLIKELY (prng == NULL)) return FALSE;
  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (size == 0)) return FALSE;

  for (; size >= inc; buf += inc, size -= inc)
    *((ruint64*)buf) = r_prng_get_u64 (prng);
  if (size > 0) {
    ruint64 v = r_prng_get_u64 (prng);
    r_memcpy (buf, &v, size);
  }

  return TRUE;
}

rboolean
r_prng_fill_nonzero (RPrng * prng, ruint8 * buf, rsize size)
{
  rboolean ret;

  if ((ret = r_prng_fill (prng, buf, size))) {
    rsize i;
    for (i = 0; i < size; i++) {
      while (R_UNLIKELY (buf[i] == 0))
        buf[i] = (ruint8)r_prng_get_u64 (prng);
    }
  }

  return ret;
}

rboolean
r_prng_fill_base64 (RPrng * prng, rchar * buf, rsize size)
{
  ruint64 scratch[3];

  if (R_UNLIKELY (prng == NULL)) return FALSE;
  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (size == 0)) return FALSE;

  while (size >= sizeof (ruint64) * 4) {
    scratch[0] = r_prng_get_u64 (prng);
    scratch[1] = r_prng_get_u64 (prng);
    scratch[2] = r_prng_get_u64 (prng);

    if (r_base64_encode (buf, size, scratch, sizeof (scratch)) != sizeof (ruint64) * 4)
      return FALSE;

    buf += sizeof (ruint64) * 4;
    size -= sizeof (ruint64) * 4;
  }

  if (size > 0) {
    rchar tmp[sizeof (ruint64) * 4];
    scratch[0] = r_prng_get_u64 (prng);
    scratch[1] = r_prng_get_u64 (prng);
    scratch[2] = r_prng_get_u64 (prng);

    if (r_base64_encode (tmp, sizeof (tmp), scratch, sizeof (scratch)) != sizeof (tmp))
      return FALSE;
    r_memcpy (buf, tmp, size);
  }

  return TRUE;
}

