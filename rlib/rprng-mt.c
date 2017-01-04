/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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

/* mt19937 - 64bit version */

#define RPRNG_MT_SIZE         312
#define RPRNG_MT_DATA(prng)   (prng)->data.u64
#define RPRNG_MT_INDEX(prng)  (prng)->data.u64[RPRNG_MT_SIZE]

static ruint64
r_prng_mt_get (RPrng * prng)
{
  ruint64 ret;

  if (RPRNG_MT_INDEX (prng) >= RPRNG_MT_SIZE) {
    int i;
    static const ruint64 magic[] = {
      RUINT64_CONSTANT (0),
      RUINT64_CONSTANT (0xB5026F5AA96619E9)
    };

    for (i = 1; i < RPRNG_MT_SIZE - 1; i++) {
      ret = (RPRNG_MT_DATA (prng)[i] & RUINT64_CONSTANT (0xFFFFFFFF80000000)) |
        (RPRNG_MT_DATA (prng)[(i + 1) % RPRNG_MT_SIZE] & RUINT64_CONSTANT (0x7FFFFFFF));

      RPRNG_MT_DATA (prng)[i] = RPRNG_MT_DATA (prng)[(i + (RPRNG_MT_SIZE / 2)) % RPRNG_MT_SIZE];
      RPRNG_MT_DATA (prng)[i] ^= ret >> 1;
      RPRNG_MT_DATA (prng)[i] ^= magic[(int)(ret & RUINT64_CONSTANT (1))];
    }

    RPRNG_MT_INDEX (prng) = 0;
  }

  ret = RPRNG_MT_DATA (prng)[RPRNG_MT_INDEX (prng)++];
  ret ^= (ret >> 29) & RUINT64_CONSTANT (0x5555555555555555);
  ret ^= (ret << 17) & RUINT64_CONSTANT (0x71D67FFFEDA60000);
  ret ^= (ret << 37) & RUINT64_CONSTANT (0xFFF7EEE000000000);
  ret ^= (ret >> 43);
  return ret;
}

RPrng *
r_prng_new_mt (void)
{
  return r_prng_new_mt_with_seed (r_rand_entropy_u64 ());
}

RPrng *
r_prng_new_mt_with_seed (ruint64 seed)
{
  RPrng * ret;
  const rsize size = (RPRNG_MT_SIZE + 1) * sizeof (ruint64);

  if ((ret = r_prng_new (r_prng_mt_get, size)) != NULL) {
    int i;
    RPRNG_MT_INDEX (ret) = RPRNG_MT_SIZE;
    RPRNG_MT_DATA (ret)[0] = seed;
    for (i = 1; i < RPRNG_MT_SIZE; i++) {
      RPRNG_MT_DATA (ret)[i] = RUINT64_CONSTANT (6364136223846793005) *
        (RPRNG_MT_DATA (ret)[i-1] ^ (RPRNG_MT_DATA (ret)[i-1] >> 62)) + i;
    }
  }

  return ret;
}

RPrng *
r_prng_new_mt_with_seed_array (const ruint64 * array, rsize size)
{
  RPrng * ret;

  if ((ret = r_prng_new_mt_with_seed (RUINT64_CONSTANT (19650218))) != NULL) {
    ruint64 i, j, k;

    k = MAX (RPRNG_MT_SIZE, size);
    for (i = 1, j = 0; k > 0; k--) {
      RPRNG_MT_DATA (ret)[i] = (RPRNG_MT_DATA (ret)[i] ^
          ((RPRNG_MT_DATA (ret)[i-1] ^ (RPRNG_MT_DATA (ret)[i-1] >> 62)) *
           RUINT64_CONSTANT (3935559000370003845))) + array[j] + j;
      if (++i >= RPRNG_MT_SIZE) {
        RPRNG_MT_DATA (ret)[0] = RPRNG_MT_DATA (ret)[RPRNG_MT_SIZE - 1];
        i = 1;
      }
      if (++j >= size)
        j = 0;
    }
    for (k = RPRNG_MT_SIZE - 1; k > 0; k--) {
        RPRNG_MT_DATA (ret)[i] = (RPRNG_MT_DATA (ret)[i] ^
            ((RPRNG_MT_DATA (ret)[i-1] ^ (RPRNG_MT_DATA (ret)[i-1] >> 62)) *
             RUINT64_CONSTANT (2862933555777941757))) - i;
        if (++i >= RPRNG_MT_SIZE) {
          RPRNG_MT_DATA (ret)[0] = RPRNG_MT_DATA (ret)[RPRNG_MT_SIZE - 1];
          i = 1;
        }
    }

    RPRNG_MT_DATA (ret)[0] = 1ULL << 63;
  }

  return ret;
}

