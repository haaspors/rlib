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
#define R_BITSET_WORDS(bs)   (_R_BITSET_BITS_SIZE ((bs)->bsize) / R_BSWORD_BYTES)
#define R_BITSET_BIT_IDX(bit) ((bit) / R_BSWORD_BITS)
#define R_BITSET_BIT_POS(bit) ((bit) % R_BSWORD_BITS)
#define R_BITSET_BIT_MASK(bit) (RBSWORD_CONSTANT (1) << R_BITSET_BIT_POS (bit))
#define R_BITSET_CLAMP(bs) (bs)->bits[R_BITSET_WORDS (bs) - 1] &= \
  (RBSWORD_MAX >> (R_BSWORD_BITS - ((bs)->bsize % R_BSWORD_BITS)))


rboolean
r_bitset_copy (RBitset * dest, const RBitset * src)
{
  rsize i, words;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (src == NULL)) return FALSE;
  if (R_UNLIKELY (dest == src)) return TRUE;
  if (R_UNLIKELY (dest->bsize < src->bsize)) return FALSE;

  words = R_BITSET_WORDS (src);
  for (i = 0; i < words; i++)
    dest->bits[i] = src->bits[i];
  words = R_BITSET_WORDS (dest);
  for (; i < words; i++)
    dest->bits[i] = 0;

  return TRUE;
}

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
  rsize size;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  size = _R_BITSET_BITS_SIZE (bitset->bsize);
  r_memset (bitset->bits, set ? 0xFF : 0, size);
  R_BITSET_CLAMP (bitset);

  return TRUE;
}

rboolean
r_bitset_shr (RBitset * bitset, ruint count)
{
  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  if (count < bitset->bsize) {
    rsize i, words = R_BITSET_WORDS (bitset);
    ruint d = count / R_BSWORD_BITS;
    count %= R_BSWORD_BITS;

    for (i = 0; i < words - d - 1; i++) {
      bitset->bits[i] = (bitset->bits[i + d] >> count) |
        (bitset->bits[i + d + 1] << (R_BSWORD_BITS - count));
    }
    bitset->bits[i] = bitset->bits[i + d] >> count;
    for (i++; i < words; i++)
      bitset->bits[i] = 0;
  } else {
    r_bitset_set_all (bitset, FALSE);
  }

  return TRUE;
}

rboolean
r_bitset_shl (RBitset * bitset, ruint count)
{
  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  if (count < bitset->bsize) {
    rsize i, words = R_BITSET_WORDS (bitset);
    ruint j, d = count / R_BSWORD_BITS;
    count %= R_BSWORD_BITS;
    for (i = words - d; i > 1; i--) {
      bitset->bits[i - 1 + d] = bitset->bits[i - 1] << count |
        bitset->bits[i - 2] >> (R_BSWORD_BITS - count);
    }
    bitset->bits[d] = bitset->bits[0] << count;
    for (j = 0; j < d; j++)
      bitset->bits[j] = 0;
    R_BITSET_CLAMP (bitset);
  } else {
    r_bitset_set_all (bitset, FALSE);
  }

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
  rsize ret, i, words;

  if (R_UNLIKELY (bitset == NULL)) return 0;

  words = R_BITSET_WORDS (bitset);;
  for (ret = i = 0; i < words; i++)
    ret += RBSWORD_POPCOUNT (bitset->bits[i]);

  return ret;
}

void
r_bitset_foreach (const RBitset * bitset, rboolean set,
    RBitsetFunc func, rpointer user)
{
  rsize i, j, bit;
  rsize words = R_BITSET_WORDS (bitset);
  rbsword mask;

  if (set) {
    for (i = bit = 0; i < words; bit = ++i * sizeof (rbsword) * 8) {
      rsize bitmax = R_BSWORD_BITS - RBSWORD_CLZ (bitset->bits[i]);
      for (j = RBSWORD_CTZ (bitset->bits[i]), bit += j, mask = RBSWORD_CONSTANT (1) << j;
          j < bitmax && bit < bitset->bsize;
          j++, bit++, mask <<= 1) {
        if (bitset->bits[i] & mask)
          func (bit, user);
      }
    }
  } else {
    for (i = bit = 0; i < words; i++) {
      for (j = 0, mask = RBSWORD_CONSTANT (1);
          j < R_BSWORD_BITS && bit < bitset->bsize;
          j++, bit++, mask <<= 1) {
        if ((bitset->bits[i] & mask) == 0)
          func (bit, user);
      }
    }
  }
}

rboolean
r_bitset_or (RBitset * dest, const RBitset * a, const RBitset * b)
{
  const RBitset * c;
  rsize words, i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (a == NULL)) return FALSE;
  if (R_UNLIKELY (b == NULL)) return FALSE;

  if (R_UNLIKELY (dest->bsize < a->bsize)) return FALSE;
  if (R_UNLIKELY (dest->bsize < b->bsize)) return FALSE;

  if (dest == a) {
    if (dest == b) return TRUE;
    c = b;
  } else if (dest == b) {
    c = a;
  } else {
    r_bitset_copy (dest, a);
    c = b;
  }

  words = R_BITSET_WORDS (c);
  for (i = 0; i < words; i++)
    dest->bits[i] |= c->bits[i];

  return TRUE;
}

rboolean
r_bitset_xor (RBitset * dest, const RBitset * a, const RBitset * b)
{
  const RBitset * c;
  rsize words, i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (a == NULL)) return FALSE;
  if (R_UNLIKELY (b == NULL)) return FALSE;

  if (R_UNLIKELY (dest->bsize < a->bsize)) return FALSE;
  if (R_UNLIKELY (dest->bsize < b->bsize)) return FALSE;

  if (dest == a) {
    if (dest == b) return TRUE;
    c = b;
  } else if (dest == b) {
    c = a;
  } else {
    r_bitset_copy (dest, a);
    c = b;
  }

  words = R_BITSET_WORDS (c);
  for (i = 0; i < words; i++)
    dest->bits[i] ^= c->bits[i];
  words = R_BITSET_WORDS (dest);
  for (; i < words; i++)
    dest->bits[i] = 0;

  return TRUE;
}

rboolean
r_bitset_and (RBitset * dest, const RBitset * a, const RBitset * b)
{
  const RBitset * c;
  rsize words, i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (a == NULL)) return FALSE;
  if (R_UNLIKELY (b == NULL)) return FALSE;

  if (R_UNLIKELY (dest->bsize < a->bsize)) return FALSE;
  if (R_UNLIKELY (dest->bsize < b->bsize)) return FALSE;

  if (dest == a) {
    if (dest == b) return TRUE;
    c = b;
  } else if (dest == b) {
    c = a;
  } else {
    r_bitset_copy (dest, a);
    c = b;
  }

  words = R_BITSET_WORDS (c);
  for (i = 0; i < words; i++)
    dest->bits[i] &= c->bits[i];
  words = R_BITSET_WORDS (dest);
  for (; i < words; i++)
    dest->bits[i] = 0;

  return TRUE;
}

rboolean
r_bitset_not (RBitset * dest, const RBitset * src)
{
  rsize words, i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (src == NULL)) return FALSE;
  if (R_UNLIKELY (dest->bsize < src->bsize)) return FALSE;

  words = R_BITSET_WORDS (src);
  for (i = 0; i < words - 1; i++)
    dest->bits[i] = ~src->bits[i];
  dest->bits[i] = ~src->bits[i] & RBSWORD_MAX >> (R_BSWORD_BITS - (src->bsize % R_BSWORD_BITS));

  words = R_BITSET_WORDS (dest);
  for (i++; i < words; i++)
    dest->bits[i] = 0;

  return TRUE;
}

