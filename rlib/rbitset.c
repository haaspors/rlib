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
#include <rlib/rstr.h>
#include <rlib/rfile.h>

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
#define R_BITSET_CLAMP(bs) \
  if (((bs)->words * R_BSWORD_BITS) != (bs)->bits) { \
    (bs)->data[(bs)->words - 1] &= (RBSWORD_CONSTANT (1) << (bs)->bits) - 1; \
  }

RBitset *
r_bitset_new_from_binary (rconstpointer data, rsize size)
{
  RBitset * ret;

  if (r_bitset_init_heap (ret, size * 8)) {
    const ruint8 * src = data;
    ruint8 * dst;

#if R_BYTE_ORDER == R_LITTLE_ENDIAN
    dst = (ruint8 *)(rpointer)ret->data;
    while (size-- > 0)
      dst[size] = *src++;
#else
    dst = (ruint8 *)(rpointer)&ret->data[ret->words - 1];
    size %= R_BSWORD_BYTES;
    while (size > 0)
      dst[R_BSWORD_BYTES - 1 - size--] = *src++;
    dst -= R_BSWORD_BYTES;
    while (dst >= (ruint8 *)(rpointer)ret->data) {
      r_memcpy (dst, src, R_BSWORD_BYTES);
      src -= R_BSWORD_BYTES;
      dst -= R_BSWORD_BYTES;
    }
#endif
  }

  return ret;
}

rboolean
r_bitset_copy (RBitset * dest, const RBitset * src)
{
  rsize i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (src == NULL)) return FALSE;
  if (R_UNLIKELY (dest == src)) return TRUE;
  if (R_UNLIKELY (dest->bits < src->bits)) return FALSE;

  for (i = 0; i < src->words; i++)
    dest->data[i] = src->data[i];
  for (; i < dest->words; i++)
    dest->data[i] = 0;

  return TRUE;
}

rboolean
r_bitset_set_bit (RBitset * bitset, rsize bit, rboolean set)
{
  rbsword mask;
  rsize idx;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bit >= bitset->bits)) return FALSE;

  idx = R_BITSET_BIT_IDX (bit);
  mask = R_BITSET_BIT_MASK (bit);

  if (set)
    bitset->data[idx] |= mask;
  else
    bitset->data[idx] &= ~mask;

  return TRUE;
}

rboolean
r_bitset_set_bits (RBitset * bitset,
    const rsize * data, rsize count, rboolean set)
{
  rboolean ret = TRUE;
  rsize i;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (data == NULL)) return FALSE;

  for (i = 0; i < count; i++) {
    if (R_UNLIKELY (!r_bitset_set_bit (bitset, data[i], set)))
      ret = FALSE;
  }

  return ret;
}

rboolean
r_bitset_set_all (RBitset * bitset, rboolean set)
{
  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  r_memset (bitset->data, set ? 0xFF : 0, sizeof (rbsword) * bitset->words);
  R_BITSET_CLAMP (bitset);

  return TRUE;
}

rboolean
r_bitset_set_n_bits_at (RBitset * bitset, rsize n, rsize bit, rboolean set)
{
  static const ruint64 v64 = RUINT64_MAX;
  static const ruint32 v32 = RUINT32_MAX;
  static const ruint16 v16 = RUINT16_MAX;
  static const ruint8  v8  = RUINT8_MAX;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bit + n > bitset->bits)) return FALSE;

  while (n > 64) {
    if (!r_bitset_set_u64_at (bitset, v64, bit))
      return FALSE;
    n -= 64; bit += 64;
  }
  while (n > 32) {
    if (!r_bitset_set_u32_at (bitset, v32, bit))
      return FALSE;
    n -= 32; bit += 32;
  }
  while (n > 16) {
    if (!r_bitset_set_u16_at (bitset, v16, bit))
      return FALSE;
    n -= 16; bit += 16;
  }
  while (n > 8) {
    if (!r_bitset_set_u8_at (bitset, v8, bit))
      return FALSE;
    n -= 8; bit += 8;
  }
  while (n--) {
    if (!r_bitset_set_bit (bitset, bit + n, set))
      return FALSE;
  }

  return TRUE;
}

rboolean
r_bitset_set_u8_at (RBitset * bitset, ruint8 u8, rsize bit)
{
  ruint d;
  rbsword w = (rbsword)u8;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bit + 8 > bitset->bits)) return FALSE;

  d = R_BITSET_BIT_IDX (bit);
  bit = R_BITSET_BIT_POS (bit);

  bitset->data[d] |= w << bit;
  if (bit > R_BSWORD_BITS - 8)
    bitset->data[d + 1] |= w >> (R_BSWORD_BITS - bit);

  return TRUE;
}

rboolean
r_bitset_set_u16_at (RBitset * bitset, ruint16 u16, rsize bit)
{
  ruint d;
  rbsword w = (rbsword)u16;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bit + 16 > bitset->bits)) return FALSE;

  d = R_BITSET_BIT_IDX (bit);
  bit = R_BITSET_BIT_POS (bit);

  bitset->data[d] |= w << bit;
  if (bit > R_BSWORD_BITS - 16)
    bitset->data[d + 1] |= w >> (R_BSWORD_BITS - bit);

  return TRUE;
}

rboolean
r_bitset_set_u32_at (RBitset * bitset, ruint32 u32, rsize bit)
{
  ruint d;
  rbsword w = (rbsword)u32;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bit + 32 > bitset->bits)) return FALSE;

  d = R_BITSET_BIT_IDX (bit);
  bit = R_BITSET_BIT_POS (bit);

  bitset->data[d] |= w << bit;
  if (bit > R_BSWORD_BITS - 32)
    bitset->data[d + 1] |= w >> (R_BSWORD_BITS - bit);

  return TRUE;
}

rboolean
r_bitset_set_u64_at (RBitset * bitset, ruint64 u64, rsize bit)
{
  ruint d;
  rbsword w = (rbsword)u64;

  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (bit + 64 > bitset->bits)) return FALSE;

  d = R_BITSET_BIT_IDX (bit);
  bit = R_BITSET_BIT_POS (bit);

  bitset->data[d] |= w << bit;
  if (bit > R_BSWORD_BITS - 64)
    bitset->data[d + 1] |= w >> (R_BSWORD_BITS - bit);

  return TRUE;
}

rboolean
r_bitset_set_from_human_readable (RBitset * bitset,
    const rchar * str, rsize * bits)
{
  int pos, c;
  ruint v1, v2;

  if (bits) *bits = 0;
  if (R_UNLIKELY (bitset == NULL)) return FALSE;
  if (R_UNLIKELY (str == NULL)) return FALSE;

  for (pos = 0; str[pos] != 0;) {
    c = 0;
    if (r_strscanf (&str[pos], "%u %n", &v1, &c) == 1) {
      if (R_UNLIKELY (!r_bitset_set_bit (bitset, v1, TRUE)))
        return FALSE;
      if (bits) *bits += 1;
      pos += c;
    } else {
      return FALSE;
    }

    c = 0;
    if (r_strscanf (&str[pos], "- %u %n", &v2, &c) == 1) {
      rsize n = v2 - v1;
      if (v1 > v2)
        return FALSE;
      if (R_UNLIKELY (!r_bitset_set_n_bits_at (bitset, n, v1 + 1, TRUE)))
        return FALSE;
      if (bits) *bits += n;
      pos += c;
    }
    if (str[pos] == ',')
      pos++;
  }

  return TRUE;
}

rboolean
r_bitset_set_from_human_readable_file (RBitset * bitset,
    const rchar * file, rsize * bits)
{
  ruint v1, v2;
  RFile * f;
  rsize actual;

  if (bits) *bits = 0;
  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  if ((f = r_file_open (file, "r")) == NULL)
    return FALSE;

  while (TRUE) {
    if (r_file_scanf (f, "%u ,", &actual, &v1) == R_FILE_ERROR_OK && actual == 1) {
      if (R_UNLIKELY (!r_bitset_set_bit (bitset, v1, TRUE)))
        return FALSE;
      if (bits) *bits += 1;
    } else {
      break;
    }

    if (r_file_scanf (f, "- %u ,", &actual, &v2) == R_FILE_ERROR_OK && actual == 1) {
      rsize n = v2 - v1;
      if (v1 > v2)
        return FALSE;
      if (R_UNLIKELY (!r_bitset_set_n_bits_at (bitset, n, v1 + 1, TRUE)))
        return FALSE;
      if (bits) *bits += n;
    }
  }

  r_file_unref (f);
  return TRUE;
}

rboolean
r_bitset_shr (RBitset * bitset, ruint count)
{
  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  if (count < bitset->bits) {
    rsize i;
    ruint d;

    d = R_BITSET_BIT_IDX (count);
    count = R_BITSET_BIT_POS (count);
    for (i = 0; i < bitset->words - d - 1; i++) {
      bitset->data[i] = (bitset->data[i + d] >> count) |
        (bitset->data[i + d + 1] << (R_BSWORD_BITS - count));
    }
    bitset->data[i] = bitset->data[i + d] >> count;
    for (i++; i < bitset->words; i++)
      bitset->data[i] = 0;

    return TRUE;
  }

  return r_bitset_set_all (bitset, FALSE);
}

rboolean
r_bitset_shl (RBitset * bitset, ruint count)
{
  if (R_UNLIKELY (bitset == NULL)) return FALSE;

  if (count < bitset->bits) {
    rsize i;
    ruint j, d;

    d = R_BITSET_BIT_IDX (count);
    count = R_BITSET_BIT_POS (count);
    for (i = bitset->words - d; i > 1; i--) {
      bitset->data[i - 1 + d] = bitset->data[i - 1] << count |
        bitset->data[i - 2] >> (R_BSWORD_BITS - count);
    }
    bitset->data[d] = bitset->data[0] << count;
    for (j = 0; j < d; j++)
      bitset->data[j] = 0;
    R_BITSET_CLAMP (bitset);

    return TRUE;
  }

  return r_bitset_set_all (bitset, FALSE);
}

ruint8
r_bitset_get_u8_at  (const RBitset * bitset, rsize bit)
{
  ruint8 ret;
  rsize i, p;

  if (R_UNLIKELY (bitset == NULL)) return 0;
  if (R_UNLIKELY (bit >= bitset->bits)) return 0;

  i = R_BITSET_BIT_IDX (bit);
  p = R_BITSET_BIT_POS (bit);

  ret = bitset->data[i] >> p;
  if (p + 8 > R_BSWORD_BITS && i + 1 < bitset->words) {
    ret |= (bitset->data[i + 1] << (R_BSWORD_BITS - p)) & RUINT8_MAX;
  }

  return ret;
}

ruint16
r_bitset_get_u16_at (const RBitset * bitset, rsize bit)
{
  ruint16 ret;
  rsize i, p;

  if (R_UNLIKELY (bitset == NULL)) return 0;
  if (R_UNLIKELY (bit >= bitset->bits)) return 0;

  i = R_BITSET_BIT_IDX (bit);
  p = R_BITSET_BIT_POS (bit);

  ret = bitset->data[i] >> p;
  if (p + 16 > R_BSWORD_BITS && i+1 < bitset->words) {
    ret |= (bitset->data[i + 1] << (R_BSWORD_BITS - p)) & RUINT16_MAX;
  }

  return ret;
}

ruint32
r_bitset_get_u32_at (const RBitset * bitset, rsize bit)
{
  ruint32 ret;
  rsize i, p;

  if (R_UNLIKELY (bitset == NULL)) return 0;
  if (R_UNLIKELY (bit >= bitset->bits)) return 0;

  i = R_BITSET_BIT_IDX (bit);
  p = R_BITSET_BIT_POS (bit);

  ret = bitset->data[i] >> p;
  if (p + 32 > R_BSWORD_BITS && i+1 < bitset->words) {
    ret |= (bitset->data[i + 1] << (R_BSWORD_BITS - p)) & RUINT32_MAX;
  }

  return ret;
}

ruint64
r_bitset_get_u64_at (const RBitset * bitset, rsize bit)
{
  ruint64 ret;
  rsize i, p;

  if (R_UNLIKELY (bitset == NULL)) return 0;
  if (R_UNLIKELY (bit >= bitset->bits)) return 0;

  i = R_BITSET_BIT_IDX (bit);
  p = R_BITSET_BIT_POS (bit);

  ret = bitset->data[i] >> p;
  if (p + 64 > R_BSWORD_BITS && i+1 < bitset->words) {
    ret |= (bitset->data[i + 1] << (R_BSWORD_BITS - p)) & RUINT64_MAX;
  }

  return ret;
}

rboolean
r_bitset_is_bit_set (const RBitset * bitset, rsize bit)
{
  rsize idx = R_BITSET_BIT_IDX (bit);
  rbsword mask = R_BITSET_BIT_MASK (bit);

  return bitset->data[idx] & mask ? TRUE : FALSE;
}

rsize
r_bitset_popcount (const RBitset * bitset)
{
  rsize ret, i;

  if (R_UNLIKELY (bitset == NULL)) return 0;

  for (ret = i = 0; i < bitset->words; i++)
    ret += RBSWORD_POPCOUNT (bitset->data[i]);

  return ret;
}

rsize
r_bitset_clz (const RBitset * bitset)
{
  rsize ret, i, rem;

  if (R_UNLIKELY (bitset == NULL)) return 0;

  ret = 0;
  for (i = bitset->words; i > 1 && bitset->data[i - 1] == 0; i--)
    ret += R_BSWORD_BITS;
  ret += RBSWORD_CLZ (bitset->data[i - 1]);

  if ((rem = bitset->bits % R_BSWORD_BITS) > 0)
    ret -= (R_BSWORD_BITS - rem);

  return ret;
}

rsize
r_bitset_ctz (const RBitset * bitset)
{
  rsize ret, i;

  if (R_UNLIKELY (bitset == NULL)) return 0;

  ret = 0;
  for (i = 0; i < bitset->words - 1 && bitset->data[i] == 0; i++)
    ret += R_BSWORD_BITS;

  ret += RBSWORD_CTZ (bitset->data[i]);
  return MIN (ret, bitset->bits);
}

void
r_bitset_foreach (const RBitset * bitset, rboolean set,
    RBitsetFunc func, rpointer user)
{
  rsize i, j, bit;
  rbsword mask;

  if (set) {
    for (i = bit = 0; i < bitset->words; bit = ++i * sizeof (rbsword) * 8) {
      rsize bitmax;
      if (bitset->data[i] == 0) continue;
      bitmax = R_BSWORD_BITS - RBSWORD_CLZ (bitset->data[i]);
      for (j = RBSWORD_CTZ (bitset->data[i]), bit += j, mask = RBSWORD_CONSTANT (1) << j;
          j < bitmax && bit < bitset->bits;
          j++, bit++, mask <<= 1) {
        if (bitset->data[i] & mask)
          func (bit, user);
      }
    }
  } else {
    for (i = bit = 0; i < bitset->words; i++) {
      for (j = 0, mask = RBSWORD_CONSTANT (1);
          j < R_BSWORD_BITS && bit < bitset->bits;
          j++, bit++, mask <<= 1) {
        if ((bitset->data[i] & mask) == 0)
          func (bit, user);
      }
    }
  }
}

rboolean
r_bitset_or (RBitset * dest, const RBitset * a, const RBitset * b)
{
  const RBitset * c;
  rsize i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (a == NULL)) return FALSE;
  if (R_UNLIKELY (b == NULL)) return FALSE;

  if (R_UNLIKELY (dest->bits < a->bits)) return FALSE;
  if (R_UNLIKELY (dest->bits < b->bits)) return FALSE;

  if (dest == a) {
    if (dest == b) return TRUE;
    c = b;
  } else if (dest == b) {
    c = a;
  } else {
    r_bitset_copy (dest, a);
    c = b;
  }

  for (i = 0; i < c->words; i++)
    dest->data[i] |= c->data[i];

  return TRUE;
}

rboolean
r_bitset_xor (RBitset * dest, const RBitset * a, const RBitset * b)
{
  const RBitset * c;
  rsize i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (a == NULL)) return FALSE;
  if (R_UNLIKELY (b == NULL)) return FALSE;

  if (R_UNLIKELY (dest->bits < a->bits)) return FALSE;
  if (R_UNLIKELY (dest->bits < b->bits)) return FALSE;

  if (dest == a) {
    if (dest == b) return TRUE;
    c = b;
  } else if (dest == b) {
    c = a;
  } else {
    r_bitset_copy (dest, a);
    c = b;
  }

  for (i = 0; i < c->words; i++)
    dest->data[i] ^= c->data[i];
  for (; i < dest->words; i++)
    dest->data[i] = 0;

  return TRUE;
}

rboolean
r_bitset_and (RBitset * dest, const RBitset * a, const RBitset * b)
{
  const RBitset * c;
  rsize i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (a == NULL)) return FALSE;
  if (R_UNLIKELY (b == NULL)) return FALSE;

  if (R_UNLIKELY (dest->bits < a->bits)) return FALSE;
  if (R_UNLIKELY (dest->bits < b->bits)) return FALSE;

  if (dest == a) {
    if (dest == b) return TRUE;
    c = b;
  } else if (dest == b) {
    c = a;
  } else {
    r_bitset_copy (dest, a);
    c = b;
  }

  for (i = 0; i < c->words; i++)
    dest->data[i] &= c->data[i];
  for (; i < dest->words; i++)
    dest->data[i] = 0;

  return TRUE;
}

rboolean
r_bitset_not (RBitset * dest, const RBitset * src)
{
  rsize i;

  if (R_UNLIKELY (dest == NULL)) return FALSE;
  if (R_UNLIKELY (src == NULL)) return FALSE;
  if (R_UNLIKELY (dest->bits < src->bits)) return FALSE;

  for (i = 0; i < src->words - 1; i++)
    dest->data[i] = ~src->data[i];
  dest->data[i] = ~src->data[i] & RBSWORD_MAX >> (R_BSWORD_BITS - (src->bits % R_BSWORD_BITS));

  for (i++; i < dest->words; i++)
    dest->data[i] = 0;

  return TRUE;
}

rchar *
r_bitset_to_human_readable (const RBitset * bitset)
{
  rchar * ret;
  rssize size, sp = 0;

  if (R_UNLIKELY (bitset == NULL)) return NULL;

  size = 32;
  if ((ret = r_malloc (size)) != NULL) {
    rsize i, j;
    for (i = 0; i < bitset->bits; i++) {
      if (r_bitset_is_bit_set (bitset, i)) {
        rchar tmp[32];
        int tmpsize;

        j = i;
        while (i+1 < bitset->bits && r_bitset_is_bit_set (bitset, i+1)) i++;
        if (sp > 0)
          ret[sp++] = ',';

        if (i == j)
          tmpsize = r_snprintf (tmp, 32, "%"RSIZE_FMT, i);
        else
          tmpsize = r_snprintf (tmp, 32, "%"RSIZE_FMT"-%"RSIZE_FMT, j, i);

        if (sp > size - tmpsize) {
          size += 32;
          ret = r_realloc (ret, size);
        }

        r_strncpy (&ret[sp], tmp, tmpsize);
        sp += tmpsize;
      }
    }

    ret[sp] = 0;
  }

  return ret;
}

