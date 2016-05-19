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

#define R_PRNG_KISS_X(prng) (prng)->data.u64[0]
#define R_PRNG_KISS_Y(prng) (prng)->data.u64[1]
#define R_PRNG_KISS_Z(prng) (prng)->data.u64[2]
#define R_PRNG_KISS_C(prng) (prng)->data.u64[3]

static ruint64
r_prng_kiss_get (RPrng * prng)
{
  ruint64 t;

  /* KISS algorith by the wonderful George Marsaglia
   * posted on the sci.math mailing list 2009-02-28 */

  /* Calculate Multiply-With-Carry (MWC), period (2^121+2^63-1) */
  /* #define MWC (t=(x<<58)+c, c=(x>>6), x+=t, c+=(x<t), x)     */
  t = (R_PRNG_KISS_X (prng) << 58) + R_PRNG_KISS_C (prng);
  R_PRNG_KISS_C (prng) = R_PRNG_KISS_X (prng) >> 6;
  R_PRNG_KISS_X (prng) += t;
  R_PRNG_KISS_C (prng) += (R_PRNG_KISS_X (prng) < t);

  /* Calculate Xorshift (XSH), period 2^64-1          */
  /* #define XSH (y^=(y<<13), y^=(y>>17), y^=(y<<43)) */
  R_PRNG_KISS_Y (prng) ^= (R_PRNG_KISS_Y (prng) << 13);
  R_PRNG_KISS_Y (prng) ^= (R_PRNG_KISS_Y (prng) >> 17);
  R_PRNG_KISS_Y (prng) ^= (R_PRNG_KISS_Y (prng) << 43);

  /* Calculate Congruential (CNG), period 2^64 */
  /* #define CNG (z=6906969069LL*z+1234567) */
  R_PRNG_KISS_Z (prng) = RUINT64_CONSTANT (6906969069) * R_PRNG_KISS_Z (prng) + 1234567;

  /* #define KISS = (MWC + XSH + CNG) */
  return R_PRNG_KISS_X (prng) + R_PRNG_KISS_Y (prng) + R_PRNG_KISS_Z (prng);
}

RPrng *
r_prng_new_kiss (void)
{
  ruint64 x = r_rand_entropy_u64 ();
  ruint64 y = r_rand_entropy_u64 () * 69069;
  ruint64 c = r_rand_entropy_u64 ();
  ruint64 z = r_rand_entropy_u64 ();

  return r_prng_new_kiss_with_seed (x, y, (z * z), (c * c));
}

RPrng *
r_prng_new_kiss_with_seed (ruint64 x, ruint64 y, ruint64 z, ruint64 c)
{
  RPrng * ret;

  if ((ret = r_prng_new (r_prng_kiss_get, 4 * sizeof (ruint64))) != NULL) {
    R_PRNG_KISS_X (ret) = x;
    R_PRNG_KISS_Y (ret) = y;
    R_PRNG_KISS_Z (ret) = z;
    R_PRNG_KISS_C (ret) = c;
  }

  return ret;
}

