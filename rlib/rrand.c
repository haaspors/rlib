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
#include <rlib/rrand.h>
#include <rlib/rmem.h>
#include <rlib/rtime.h>

struct _RPrng {
  ruint64 x, y, z, c;
};

RPrng *
r_rand_prng_new (void)
{
  ruint64 x = r_time_get_ts_monotonic ();
  ruint64 y = r_time_get_ts_monotonic () * 69069;
  ruint64 c = r_time_get_uptime ();
  ruint64 z = r_time_get_ts_monotonic ();

  return r_rand_prng_new_with_seed (x, y, (z * z), (c * c));
}

RPrng *
r_rand_prng_new_with_seed (ruint64 x, ruint64 y, ruint64 z, ruint64 c)
{
  RPrng * ret = NULL;

  if ((ret = r_mem_new (RPrng)) != NULL) {
    ret->x = x;
    ret->y = y;
    ret->z = z;
    ret->c = c;
  }

  return ret;
}

void
r_rand_prng_free (RPrng * prng)
{
  r_free (prng);
}

ruint64
r_rand_prng_get (RPrng * prng)
{
  ruint64 t;

  /* KISS algorith by the wonderful George Marsaglia
   * posted on the sci.math mailing list 2009-02-28 */

  /* Calculate Multiply-With-Carry (MWC), period (2^121+2^63-1) */
  /* #define MWC (t=(x<<58)+c, c=(x>>6), x+=t, c+=(x<t), x)     */
  t = (prng->x << 58) + prng->c;
  prng->c = prng->x >> 6;
  prng->x += t;
  prng->c += (prng->x < t);

  /* Calculate Xorshift (XSH), period 2^64-1          */
  /* #define XSH (y^=(y<<13), y^=(y>>17), y^=(y<<43)) */
  prng->y ^= (prng->y << 13);
  prng->y ^= (prng->y >> 17);
  prng->y ^= (prng->y << 43);

  /* Calculate Congruential (CNG), period 2^64 */
  /* #define CNG (z=6906969069LL*z+1234567) */
  prng->z = RUINT64_CONSTANT (6906969069) * prng->z + 1234567;

  /* #define KISS = (MWC + XSH + CNG) */
  return prng->x + prng->y + prng->z;
}


