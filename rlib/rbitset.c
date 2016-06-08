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
#include <rlib/rbitset.h>

#define R_BSWORD_BYTES    (sizeof (rbsword))
#define R_BSWORD_BITS     (sizeof (rbsword) * 8)
#define RBSWORD_MAX       RUINT64_MAX
#define RBSWORD_POPCOUNT  RUINT64_POPCOUNT
#define RBSWORD_CLZ       RUINT64_CLZ
#define RBSWORD_CTZ       RUINT64_CTZ
#define RBSWORD_CONSTANT  RUINT64_CONSTANT
#define R_BITSET_BIT_IDX(bit) ((bit) / R_BSWORD_BITS)
#define R_BITSET_BIT_POS(bit) ((bit) % R_BSWORD_BITS)
#define R_BITSET_BIT_MASK(bit) (RBSWORD_CONSTANT (1) << R_BITSET_BIT_POS (bit))

rboolean
r_bitset_set_bit (RBitset * bitset, rsize bit, rboolean set)
{
  rbsword mask;
  rsize idx;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bit >= bitset->bsize)) return FALSE;

  idx = R_BITSET_BIT_IDX (bit);
  mask = R_BITSET_BIT_MASK (bit);

  if (set)
    bitset->bits[idx] |= mask;
  else
    bitset->bits[idx] &= ~mask;

  return TRUE;
}

rboolean
r_bitset_set_bits (RBitset * bitset,
    const rsize * bits, rsize count, rboolean set)
{
  rboolean ret = TRUE;
  rsize i;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bits == NULL)) return FALSE;

  for (i = 0; i < count; i++) {
    if (R_UNLIKELY (!r_bitset_set_bit (bitset, bits[i], set)))
      ret = FALSE;
  }

  return ret;
}

rboolean
r_bitset_set_all (RBitset * bitset, rboolean set)
{
  rbsword mask;
  rsize size;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  size = _R_BITSET_BITS_SIZE (bitset->bsize);
  mask = RBSWORD_MAX >> (R_BSWORD_BITS - (bitset->bsize % R_BSWORD_BITS));
  r_memset (bitset->bits, set ? 0xFF : 0, size);
  bitset->bits[(size / sizeof (rbsword)) - 1] &= mask;

  return TRUE;
}

rboolean
r_bitset_is_bit_set (const RBitset * bitset, rsize bit)
{
  rsize idx = R_BITSET_BIT_IDX (bit);
  rbsword mask = R_BITSET_BIT_MASK (bit);

  return bitset->bits[idx] & mask ? TRUE : FALSE;
}

rsize
r_bitset_popcount (const RBitset * bitset)
{
  rsize ret, i;
  rsize words = _R_BITSET_BITS_SIZE (bitset->bsize) / sizeof (rbsword);

  for (ret = i = 0; i < words; i++)
    ret += RBSWORD_POPCOUNT (bitset->bits[i]);

  return ret;
}

void
r_bitset_foreach (const RBitset * bitset, rboolean set,
    RBitsetFunc func, rpointer user)
{
  rsize i, j, bit;
  rsize wcount = (bitset->bsize / R_BSWORD_BITS) + 1;
  rbsword mask;

  if (set) {
    for (i = bit = 0; i < wcount; bit = ++i * sizeof (rbsword) * 8) {
      rsize bitmax = R_BSWORD_BITS - RBSWORD_CLZ (bitset->bits[i]);
      for (j = RBSWORD_CTZ (bitset->bits[i]), bit += j, mask = RBSWORD_CONSTANT (1) << j;
          j < bitmax && bit < bitset->bsize;
          j++, bit++, mask <<= 1) {
        if (bitset->bits[i] & mask)
          func (bit, user);
      }
    }
  } else {
    for (i = bit = 0; i < wcount; i++) {
      for (j = 0, mask = RBSWORD_CONSTANT (1);
          j < R_BSWORD_BITS && bit < bitset->bsize;
          j++, bit++, mask <<= 1) {
        if ((bitset->bits[i] & mask) == 0)
          func (bit, user);
      }
    }
  }
}

