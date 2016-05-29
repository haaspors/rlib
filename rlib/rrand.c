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
#include <rlib/rprng-private.h>
#include <rlib/rmem.h>
#include <rlib/rtime.h>
#ifdef R_OS_UNIX
#include <stdio.h>
#include <errno.h>
#endif

ruint64
r_rand_entropy_u64 (void)
{
  ruint64 ret;
#if defined (R_OS_WIN32)
  HCRYPTPROV hCryptProv = NULL;

  if (CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
    BOOL res = CryptGenRandom (hCryptProv, sizeof (ret), (BYTE *)&ret);

    CryptReleaseContext (hCryptProv, 0);
    if (res)
      return ret;
  }
#elif defined (R_OS_UNIX)
  FILE * devuranad;
  size_t res;

  do {
    devuranad = fopen ("/dev/urandom", "rb");
  } while (R_UNLIKELY (devuranad == NULL && errno == EINTR));

  do {
    res = fread (&ret, sizeof (ret), 1, devuranad);
  } while (R_UNLIKELY (errno == EINTR));

  if (res == 1)
    return ret;
#endif

  return r_time_get_ts_monotonic ();
}

ruint32
r_rand_entropy_u32 (void)
{
  ruint32 ret;
#if defined (R_OS_WIN32)
  HCRYPTPROV hCryptProv = NULL;

  if (CryptAcquireContext (&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
    BOOL res = CryptGenRandom (hCryptProv, sizeof (ret), (BYTE *)&ret);

    CryptReleaseContext (hCryptProv, 0);
    if (res)
      return ret;
  }
#elif defined (R_OS_UNIX)
  FILE * devuranad;
  size_t res;

  do {
    devuranad = fopen ("/dev/urandom", "rb");
  } while (R_UNLIKELY (devuranad == NULL && errno == EINTR));

  do {
    res = fread (&ret, sizeof (ret), 1, devuranad);
  } while (R_UNLIKELY (errno == EINTR));

  if (res == 1)
    return ret;
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

