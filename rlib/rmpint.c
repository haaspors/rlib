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
#include <rlib/rmpint.h>
#include "rmpint_private.h"
#include <rlib/rascii.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

void
r_mpint_ensure_digits (rmpint * mpi, ruint16 digits)
{
  digits += RMPINT_DEF_DIGITS - 1;
  digits &= ~(RMPINT_DEF_DIGITS - 1);
  if (digits <= mpi->dig_alloc)
    return;

  mpi->dig_alloc = digits;
  mpi->data = r_realloc (mpi->data, digits * sizeof (rmpint_digit));
  r_memset (&mpi->data[mpi->dig_used], 0,
      (digits - mpi->dig_used) * sizeof (rmpint_digit));
}

void
r_mpint_init_size (rmpint * mpi, ruint16 digits)
{
  r_memset (mpi, 0, sizeof (rmpint));
  r_mpint_ensure_digits (mpi, MAX (digits, RMPINT_DEF_DIGITS));
}

void
r_mpint_init_binary (rmpint * mpi, rconstpointer data, rsize size)
{
  const ruint8 * src = data;
  ruint8 * dst;
  ruint16 digits = (size + sizeof (rmpint_digit) - 1) / sizeof (rmpint_digit);
  r_mpint_init_size (mpi, digits);
  mpi->dig_used = digits;

#if R_BYTE_ORDER == R_LITTLE_ENDIAN
  dst = (ruint8 *)(rpointer)mpi->data;
  while (size-- > 0)
    dst[size] = *src++;
#else
  dst = (ruint8 *)(rpointer)&mpi->data[digits - 1];
  switch (size % sizeof (rmpint_digit)) {
#if 0 /*sizeof (rmpint_digit) >= 8*/
    case 7: dst[sizeof (rmpint_digit) - 7] = *src++;
    case 6: dst[sizeof (rmpint_digit) - 6] = *src++;
    case 5: dst[sizeof (rmpint_digit) - 5] = *src++;
    case 4: dst[sizeof (rmpint_digit) - 4] = *src++;
#endif
#if 1 /*sizeof (rmpint_digit) >= 4*/
    case 3: dst[sizeof (rmpint_digit) - 3] = *src++;
    case 2: dst[sizeof (rmpint_digit) - 2] = *src++;
#endif
    case 1: dst[sizeof (rmpint_digit) - 1] = *src++;
  };
  dst -= sizeof (rmpint_digit);
  while (dst >= (ruint8 *)(rpointer)mpi->data) {
    r_memcpy (dst, src, sizeof (rmpint_digit));
    src -= sizeof (rmpint_digit);
    dst -= sizeof (rmpint_digit);
  }
#endif
  r_mpint_clamp (mpi);
}

void
r_mpint_init_str (rmpint * mpi, const rchar * str, const rchar ** endptr,
    ruint base)
{
  const rchar * ptr;

  r_mpint_init (mpi);

  if (endptr != NULL)
    *endptr = str;

  ptr = r_str_lwstrip (str);
  if (R_UNLIKELY (*ptr == 0))
    goto beach;

  if ((mpi->sign = (*ptr == '-')) || *ptr == '+')
    ptr++;

  if (*ptr == '0') {
    ptr++;
    if ((base == 0 || base == 16) && (*ptr == 'X' || *ptr == 'x')) {
      if (!r_ascii_isxdigit (ptr[1]))
        goto beach;
      base = 16;
      ptr++;
    } else if (base == 0) {
      if (*ptr < '0' || *ptr > '7')
        goto beach;
      base = 8;
    }
  } else if (base == 0) {
    base = 10;
  }

  while (*ptr != 0) {
    rchar c;

    if (r_ascii_isdigit (*ptr))       c = *ptr - '0';
    else if (r_ascii_islower (*ptr))  c = 10 + *ptr - 'a';
    else if (r_ascii_isupper (*ptr))  c = 10 + *ptr - 'A';
    else break;

    if ((ruint)c >= base)
      break;

    if (!r_mpint_mul_u32 (mpi, mpi, base) ||
        !r_mpint_add_u32 (mpi, mpi, (ruint)c))
      break;
    ptr++;
  }

beach:
  if (endptr != NULL)
    *endptr = ptr;
}

void
r_mpint_init_copy (rmpint * dst, const rmpint * src)
{
  r_memcpy (dst, src, sizeof (rmpint));
  dst->data = r_memdup (src->data, src->dig_alloc * sizeof (rmpint_digit));
}

void
r_mpint_clear (rmpint * mpi)
{
  r_free (mpi->data);
  r_memset (mpi, 0, sizeof (rmpint));
}

ruint8 *
r_mpint_to_binary (const rmpint * mpi, rsize * size)
{
  ruint8 * ret;

  if (R_LIKELY (mpi != NULL)) {
    rsize len = mpi->dig_used * sizeof (rmpint_digit);

    if ((ret = r_malloc (len)) != NULL) {
      ruint8 * src, * dst = ret;

#if R_BYTE_ORDER == R_LITTLE_ENDIAN
      src = (ruint8 *)(rpointer)mpi->data;

      while (len > 0 && src[len - 1] == 0)
        len--;
      while (len-- > 0)
        *dst++ = src[len];
#else
      if (mpi->dig_used > 0) {
        rsize i = 0;
        src = (ruint8 *)(rpointer)&mpi->data[mpi->dig_used - 1];

        while (i < sizeof (rmpint_digit) && src[i] == 0)
          i++;
        for (; i < sizeof (rmpint_digit); i++)
          *dst++ = src[i];

        if (mpi->dig_used > 1) {
          for (i = mpi->dig_used - 2; i > 0; i--, dst += sizeof (rmpint_digit))
            r_memcpy (dst, &mpi->data[i], sizeof (rmpint_digit));
        }
      }
#endif

      if (size != NULL)
        *size = dst - ret;
    }
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_mpint_to_str (const rmpint * mpi)
{
  rchar * ret;
  const int base = 16;
  const int bc = 4;
  const rchar prefix[] = "0x";

  /* This only supports base with power of two */
  if (mpi != NULL) {
    if ((ret = r_mem_new_n (rchar, 4 + mpi->dig_used * sizeof (rmpint_digit) * 2)) != NULL) {
      rchar * ptr = ret;
      if (R_LIKELY (mpi->dig_used > 0)) {
        rsize j, i = mpi->dig_used;

        ptr = r_stpcpy (ptr, prefix);
        while (i-- > 0) {
          rmpint_digit digit = r_mpint_get_digit (mpi, i);
          for (j = sizeof (rmpint_digit) * 8; j > 0; j -= bc) {
            ruint8 bits = (digit >> (j - bc)) & (base - 1);

            if (bits <= 9)
              *ptr++ = '0' + bits;
            else
              *ptr++ = 'a' - 10 + bits;
          }
        }
      }
      *ptr++ = 0;
    }
  } else {
    ret = NULL;
  }

  return ret;
}

void
r_mpint_zero (rmpint * mpi)
{
  mpi->dig_used = 0;
  mpi->sign = 0;
  r_memset (mpi->data, 0, mpi->dig_alloc * sizeof (rmpint_digit));
}

void
r_mpint_set (rmpint * mpi, const rmpint * b)
{
  mpi->sign = b->sign;
  mpi->dig_used = b->dig_used;
  r_mpint_ensure_digits (mpi, b->dig_used);
  r_memcpy (mpi->data, b->data, mpi->dig_used * sizeof (rmpint_digit));
}

void
r_mpint_set_i32 (rmpint * mpi, rint32 value)
{
  r_memset (&mpi->data[1], 0, (mpi->dig_alloc - 1) * sizeof (rmpint_digit));
  mpi->dig_used = value != 0 ? 1 : 0;
  if ((mpi->sign = (value < 0)) == 0)
    mpi->data[0] = (ruint32)value;
  else
    mpi->data[0] = (ruint32)-value;
}

void
r_mpint_set_u32 (rmpint * mpi, ruint32 value)
{
  mpi->data[0] = value;
  r_memset (&mpi->data[1], 0, (mpi->dig_alloc - 1) * sizeof (rmpint_digit));
  mpi->dig_used = value != 0 ? 1 : 0;
  mpi->sign = 0;
}

ruint32
r_mpint_ctz (const rmpint * mpi)
{
  ruint16 i;

  for (i = 0; i < mpi->dig_used && r_mpint_get_digit (mpi, i) == 0; i++);
  return i * sizeof (rmpint_digit) * 8 + RUINT32_CTZ (r_mpint_get_digit (mpi, i));
}

int
r_mpint_cmp (const rmpint * a, const rmpint * b)
{
  int sa, sb;

  if (R_UNLIKELY (a == b)) return 0;
  if (R_UNLIKELY (a == NULL)) return -1;
  if (R_UNLIKELY (b == NULL)) return 1;

  if ((sa = r_mpint_isneg (a)) != (sb = r_mpint_isneg (b)))
    return sb - sa;
  if (a->dig_used != b->dig_used)
    return (int)a->dig_used - (int)b->dig_used;

  if (a->dig_used > 0) {
    ruint16 i;

    for (i = a->dig_used; i > 0; i--) {
      rint64 c = (rint64)a->data[i - 1] - (rint64)b->data[i - 1];
      if (c != 0)
        return c > 0 ? 1 : -1;
    }
  }
  return 0;
}

int
r_mpint_ucmp (const rmpint * a, const rmpint * b)
{
  if (R_UNLIKELY (a == b)) return 0;
  if (R_UNLIKELY (a == NULL)) return -1;
  if (R_UNLIKELY (b == NULL)) return 1;

  if (a->dig_used != b->dig_used)
    return (int)a->dig_used - (int)b->dig_used;

  if (a->dig_used > 0) {
    ruint16 i;
    for (i = a->dig_used; i > 0; i--) {
      rint64 c = (rint64)a->data[i - 1] - (rint64)b->data[i - 1];
      if (c != 0)
        return c > 0 ? 1 : -1;
    }
  }
  return 0;
}

int
r_mpint_cmp_i32 (const rmpint * a, rint32 b)
{
  rmpint mpi;
  rmpint_digit digit;

  mpi.dig_alloc = 0;
  mpi.data = &digit;
  if (b > 0) {
    mpi.sign = 0;
    mpi.dig_used = 1;
    digit = (rmpint_digit)b;
  } else if (b < 0) {
    mpi.sign = 1;
    mpi.dig_used = 1;
    digit = (rmpint_digit)-b;
  } else {
    mpi.sign = 0;
    mpi.dig_used = 0;
    digit = (rmpint_digit)b;
  }

  return r_mpint_cmp (a, &mpi);
}

int
r_mpint_ucmp_u32 (const rmpint * a, ruint32 b)
{
  rint64 c;

  if (R_UNLIKELY (a == NULL)) return -1;

  if (b == 0)
    return (int)a->dig_used;
  if (a->dig_used != 1)
    return (int)a->dig_used - 1;
  if ((c = (rint64)a->data[0] - (rint64)b) != 0)
    return c > 0 ? 1 : -1;
  return 0;
}

rboolean
r_mpint_add_unsigned (rmpint * dst, const rmpint * a, const rmpint * b)
{
  rmpint_word w;
  const rmpint * add;
  ruint16 i, max;

  max = MAX (a->dig_used, b->dig_used);
  r_mpint_ensure_digits (dst, max + 1);

  if (dst == a) {
    add = b;
  } else if (dst == b) {
    add = a;
  } else if (a->dig_used >= b->dig_used) {
    r_mpint_set (dst, b);
    add = a;
  } else {
    r_mpint_set (dst, a);
    add = b;
  }

  for (i = 0, w = 0; i < add->dig_used; i++) {
    w +=  ((rmpint_word)r_mpint_get_digit (dst, i)) +
          ((rmpint_word)r_mpint_get_digit (add, i));
    dst->data[i] = (rmpint_digit)w;
    w >>= sizeof (rmpint_digit) * 8;
  }
  for (; i < dst->dig_used; i++) {
    w += ((rmpint_word)r_mpint_get_digit (dst, i));
    dst->data[i] = (rmpint_digit)w;
    w >>= sizeof (rmpint_digit) * 8;
  }
  if (w > 0) dst->data[i++] = w;
  dst->dig_used = i;
  r_memset (&dst->data[dst->dig_used], 0,
      (dst->dig_alloc - dst->dig_used) * sizeof (rmpint_digit));

  return TRUE;
}

/* NOTE: a MUST be bigger than b */
rboolean
r_mpint_sub_unsigned (rmpint * dst, const rmpint * a, const rmpint * b)
{
  rmpint_word w;
  ruint16 i;

  r_mpint_ensure_digits (dst, a->dig_used + 1);

  for (i = 0, w = 0; i < b->dig_used; i++) {
    w = ((rmpint_word)r_mpint_get_digit (a, i)) -
        ((rmpint_word)r_mpint_get_digit (b, i)) - w;
    dst->data[i] = w;
    w = (w >> (sizeof (rmpint_digit) * 8)) & 1;
  }

  for (; i < a->dig_used; i++) {
    w = ((rmpint_word)r_mpint_get_digit (a, i)) - w;
    dst->data[i] = w;
    w = (w >> (sizeof (rmpint_digit) * 8)) & 1;
  }

  dst->dig_used = i;
  r_memset (&dst->data[i], 0, (dst->dig_alloc - i) * sizeof (rmpint_digit));
  r_mpint_clamp (dst);

  return TRUE;
}

rboolean
r_mpint_add (rmpint * dst, const rmpint * a, const rmpint * b)
{
  if (R_UNLIKELY (dst == NULL || a == NULL || b == NULL))
    return FALSE;

  if (a->sign == b->sign) {
    /* -a + -b = -(a + b) */
    /* +a + +b = +(a + b) */
    return r_mpint_add_unsigned (dst, a, b);
  } else if (r_mpint_ucmp (a, b) < 0) {
    /* -a + +b = +(b - a) === -1 + +2 = +1 */
    /* +a + -b = -(b - a) === +1 + -2 = -1 */
    dst->sign = b->sign;
    return r_mpint_sub_unsigned (dst, b, a);
  } else {
    /* -a + +b = -(a - b) === -2 + +1 = -1 */
    /* +a + -b = +(a - b) === +2 + -1 = +1 */
    dst->sign = a->sign;
    return r_mpint_sub_unsigned (dst, a, b);
  }
}

rboolean
r_mpint_add_i32 (rmpint * dst, const rmpint * a, rint32 b)
{
  if (b < 0)
    return r_mpint_sub_u32 (dst, a, (ruint32)-b);
  return r_mpint_add_u32 (dst, a, (ruint32)b);
}

rboolean
r_mpint_add_u32 (rmpint * dst, const rmpint * a, ruint32 b)
{
  rmpint mpi;
  mpi.dig_alloc = 0;
  mpi.dig_used = 1;
  mpi.sign = 0;
  mpi.data = &b;

  return r_mpint_add_unsigned (dst, a, &mpi);
}

rboolean
r_mpint_sub (rmpint * dst, const rmpint * a, const rmpint * b)
{
  if (R_UNLIKELY (dst == NULL || a == NULL || b == NULL))
    return FALSE;

  if (a->sign != b->sign) {
    /* -a - +b = -(a + b) */
    /* +a - -b = +(a + b) */
    dst->sign = a->sign;
    return r_mpint_add_unsigned (dst, a, b);
  } else if (r_mpint_ucmp (a, b) > 0) {
    /* -a - -b = -(a - b) === -2 - -1 = -1 */
    /* +a - +b = +(a - b) === +2 - +1 = +1 */
    dst->sign = a->sign;
    return r_mpint_sub_unsigned (dst, a, b);
  } else {
    /* -a - -b = +(b - a) === -1 - -2 = +1 */
    /* +a - +b = -(b - a) === +1 - +2 = -1 */
    dst->sign = a->sign == 0 ? 1 : 0;
    return r_mpint_sub_unsigned (dst, b, a);
  }
}

rboolean
r_mpint_sub_i32 (rmpint * dst, const rmpint * a, rint32 b)
{
  if (b < 0)
    return r_mpint_add_u32 (dst, a, (ruint32)-b);
  return r_mpint_sub_u32 (dst, a, (ruint32)b);
}

rboolean
r_mpint_sub_u32 (rmpint * dst, const rmpint * a, ruint32 b)
{
  rmpint mpi;
  mpi.dig_alloc = 0;
  mpi.dig_used = 1;
  mpi.sign = 0;
  mpi.data = &b;

  return r_mpint_sub (dst, a, &mpi);
}

rboolean
r_mpint_shl (rmpint * dst, const rmpint * a, ruint32 bits)
{
  ruint16 i, d = bits / (sizeof (rmpint_digit) * 8);
  bits = bits % (sizeof (rmpint_digit) * 8);

  if (bits == 0)
    return r_mpint_shl_digit (dst, a, d);

  if (R_UNLIKELY (dst == NULL || a == NULL)) {
    return FALSE;
  } else if (a->dig_used == 0) {
    if (dst != a)
      r_mpint_zero (dst);
    return TRUE;
  }

  r_mpint_ensure_digits (dst, a->dig_used + d + 1);
  dst->data[a->dig_used + d] =
    a->data[a->dig_used - 1] >> (sizeof (rmpint_digit) * 8 - bits);
  for (i = a->dig_used; i > 1; i--) {
    dst->data[i - 1 + d] =
      a->data[i - 1] << bits |
      a->data[i - 2] >> (sizeof (rmpint_digit) * 8 - bits);
  }
  dst->data[d] = a->data[0] << bits;

  r_memset (dst->data, 0, d * sizeof (rmpint_digit));
  dst->dig_used = a->dig_used + d + 1;
  r_mpint_clamp (dst);
  return TRUE;
}

rboolean
r_mpint_shr (rmpint * dst, const rmpint * a, ruint32 bits)
{
  ruint16 i, d = bits / (sizeof (rmpint_digit) * 8);
  bits = bits % (sizeof (rmpint_digit) * 8);

  if (bits == 0)
    return r_mpint_shr_digit (dst, a, d);

  if (R_UNLIKELY (dst == NULL || a == NULL)) {
    return FALSE;
  } else if (a->dig_used == 0) {
    if (dst != a)
      r_mpint_zero (dst);
    return TRUE;
  }

  r_mpint_ensure_digits (dst, a->dig_used - d);
  for (i = 0; i < a->dig_used - 1; i++) {
    dst->data[i] = a->data[i + d] >> bits |
      a->data[i + d + 1] << (sizeof (rmpint_digit) * 8 - bits);
  }
  dst->data[i] = a->data[i + d] >> bits;

  dst->dig_used = a->dig_used - d;
  r_mpint_clamp (dst);
  return TRUE;
}

rboolean
r_mpint_shl_digit (rmpint * dst, const rmpint * a, ruint16 d)
{
  if (R_UNLIKELY (dst == NULL || a == NULL)) {
    return FALSE;
  } else if (a->dig_used == 0) {
    if (dst != a)
      r_mpint_zero (dst);
    return TRUE;
  }

  r_mpint_ensure_digits (dst, a->dig_used + d);

  if (dst == a) {
    r_memmove (&dst->data[d], a->data, a->dig_used * sizeof (rmpint_digit));
  } else {
    if (dst->dig_alloc > a->dig_alloc)
      r_memset (&dst->data[a->dig_alloc], 0, dst->dig_alloc - a->dig_alloc);

    r_memcpy (&dst->data[d], a->data, a->dig_used * sizeof (rmpint_digit));
  }

  r_memset (dst->data, 0, d * sizeof (rmpint_digit));
  dst->dig_used = a->dig_used + d;
  return TRUE;
}

rboolean
r_mpint_shr_digit (rmpint * dst, const rmpint * a, ruint16 d)
{
  if (R_UNLIKELY (dst == NULL || a == NULL))
    return FALSE;

  r_mpint_ensure_digits (dst, a->dig_used - d);
  dst->dig_used = a->dig_used - d;

  if (dst == a)
    r_memmove (a->data, &dst->data[d], dst->dig_used * sizeof (rmpint_digit));
  else
    r_memcpy (dst->data, &a->data[d], dst->dig_used * sizeof (rmpint_digit));

  r_memset (&dst->data[dst->dig_used], 0, dst->dig_alloc - dst->dig_used);
  return TRUE;
}

/* Based on Paul G. Combas algorithm/method */
rboolean
r_mpint_mul (rmpint * dst, const rmpint * a, const rmpint * b)
{
  rint32 ix, iy, iz, tx, ty;
  ruint16 used;
  rmpint * tmp, * out;
  rmpint_word w, acc, c;

  if (R_UNLIKELY (dst == NULL || a == NULL || b == NULL))
    return FALSE;

  used = a->dig_used + b->dig_used;
  if (R_UNLIKELY (used < a->dig_used || used < b->dig_used))
    return FALSE;

  /* FIXME: Add specific comba versions for 1024 and 2048 bits multiplications */
#if 0
  if (a->dig_used == 16 && b->dig_used == 16)
    return r_mpint_mul_comba16 (dst, a, b);
  if (a->dig_used == 32 && b->dig_used == 32)
    return r_mpint_mul_comba32 (dst, a, b);
#endif

  if (a == dst || b == dst) {
    tmp = r_mem_newa (rmpint);
    r_mpint_init_size (tmp, used);
    out = tmp;
  } else {
    tmp = NULL;
    r_mpint_ensure_digits (dst, used);
    out = dst;
  }

  for (ix = 0, acc = 0; ix < used; ix++) {
    ty = MIN (ix, b->dig_used - 1);
    tx = ix - ty;

    iy = MIN (a->dig_used - tx, ty + 1);
    for (iz = 0, c = 0; iz < iy; iz++) {
      /* acc += a * b  (c used as carry) */
      w = (rmpint_word)acc +
        ((rmpint_word)r_mpint_get_digit (a, tx + iz)) *
        ((rmpint_word)r_mpint_get_digit (b, ty - iz));
      if (w < acc) c++;
      acc = w;
    }

    out->data[ix] = acc;
    acc = c << (sizeof (rmpint_digit) * 8) | acc >> sizeof (rmpint_digit) * 8;
  }

  out->sign = a->sign ^ b->sign;
  out->dig_used = used;
  r_mpint_clamp (out);

  if (tmp != NULL) {
    r_mpint_set (dst, tmp);
    r_mpint_clear (tmp);
  }

  return TRUE;
}

rboolean
r_mpint_mul_i32 (rmpint * dst, const rmpint * a, rint32 b)
{
  if (dst != a)
    r_mpint_set (dst, a);
  if (b == 0) {
    return TRUE;
  } else if (b < 0) {
    dst->sign = (dst->sign == 0);
    return r_mpint_mul_u32 (dst, dst, (ruint32)-b);
  } else {
    return r_mpint_mul_u32 (dst, dst, (ruint32)b);
  }
}

rboolean
r_mpint_mul_u32 (rmpint * dst, const rmpint * a, ruint32 b)
{
  rmpint_word w;
  ruint16 i;

  r_mpint_ensure_digits (dst, a->dig_used + 1);
  for (i = 0, w = 0; i < a->dig_used; i++) {
    w += ((rmpint_word)r_mpint_get_digit (a, i)) * ((rmpint_word)b);
    dst->data[i] = (rmpint_digit)w;
    w >>= sizeof (rmpint_digit) * 8;
  }
  if (w > 0) dst->data[i++] = w;
  r_memset (&dst->data[i], 0, (dst->dig_alloc - i) * sizeof (rmpint_digit));
  dst->dig_used = i;
  dst->sign = a->sign;

  return TRUE;
}

/* Based on Handbook of Applied Cryptography (HAC) 14.2.5 (p.598) */
rboolean
r_mpint_div (rmpint * q, rmpint * r, const rmpint * n, const rmpint * d)
{
  rmpint x, y, qtmp, *qp, tmp1, tmp2;
  int cmp;
  ruint norm, bits;
  ruint16 i, nn, tt;

  if (R_UNLIKELY (n == NULL || d == NULL))
    return FALSE;
  if (R_UNLIKELY (q == NULL && r == NULL))
    return FALSE;
  if (r_mpint_iszero (d))
    return FALSE;

  if ((cmp = r_mpint_ucmp (n, d)) < 0) {
    if (q != NULL) r_mpint_zero (q);
    if (r != NULL) r_mpint_set (r, n);
    return TRUE;
  } else if (cmp == 0) {
    if (q != NULL) r_mpint_set_u32 (q, 1);
    if (r != NULL) r_mpint_zero (r);
    return TRUE;
  }

  r_mpint_init (&tmp1);
  r_mpint_init (&tmp2);
  r_mpint_init_copy (&x, n);
  r_mpint_init_size (&y, r_mpint_digits_used (d) * 3);

  bits = r_mpint_bits_used (d);
  if ((norm = bits % (sizeof (rmpint_digit) * 8)) < sizeof (rmpint_digit) * 8 - 1) {
    norm = sizeof (rmpint_digit) * 8 - 1 - norm;
    r_mpint_shl (&y, d, norm);
    r_mpint_shl (&x, &x, norm);
  } else {
    r_mpint_set (&y, d);
    norm = 0;
  }

  x.sign = y.sign = 0;
  nn = r_mpint_digits_used (&x) - 1;
  tt = r_mpint_digits_used (&y) - 1;

  if (q != NULL) {
    r_mpint_ensure_digits (q, nn - tt + 1);
    qp = q;
  } else {
    r_mpint_init_size (&qtmp, nn - tt + 1);
    qp = &qtmp;
  }
  qp->dig_used = nn - tt + 1;
  qp->sign = n->sign ^ d->sign;

  /* step 2 */
  r_mpint_shl_digit (&tmp1, &y, nn - tt);
  while (r_mpint_ucmp (&x, &tmp1) >= 0) {
    qp->data[nn - tt]++;
    r_mpint_sub_unsigned (&x, &x, &tmp1);
  }

  /* Step 3 */
  for (i = nn; i > tt; i--) {
    rmpint_word w;
    rmpint_digit * qit;

    if (i > r_mpint_digits_used (&x)) continue;

    /* Step 3.1 */
    qit = &qp->data[i - tt - 1];
    if (r_mpint_get_digit (&x, i) == r_mpint_get_digit (&y, tt)) {
      w = (rmpint_digit)((((rmpint_word)1) << sizeof (rmpint_digit) * 8) - 1);
    } else {
      w = ((rmpint_word) x.data[i]) << sizeof (rmpint_digit) * 8;
      w |= ((rmpint_word) x.data[i - 1]);
      w /= ((rmpint_word) y.data[tt]);
    }
    *qit = (rmpint_digit)w;

    /* Step 3.2 */
    tmp2.data[0] = (i > 1) ? x.data[i - 2] : 0;
    tmp2.data[1] = (i > 0) ? x.data[i - 1] : 0;
    tmp2.data[2] = x.data[i];
    tmp2.dig_used = 3;
    r_mpint_clamp (&tmp2);
    while (TRUE) {
      r_mpint_zero (&tmp1);
      tmp1.data[0] = (tt > 0) ? y.data[tt - 1] : 0;
      tmp1.data[1] = y.data[tt];
      tmp1.dig_used = 2;
      r_mpint_mul_u32 (&tmp1, &tmp1, *qit);

      r_mpint_clamp (&tmp1);
      if (r_mpint_ucmp (&tmp1, &tmp2) <= 0)
        break;
      (*qit)--;
    }

    /* Step 3.3 */
    r_mpint_mul_u32 (&tmp1, &y, *qit);
    r_mpint_shl_digit (&tmp1, &tmp1, i - tt - 1);
    r_mpint_sub (&x, &x, &tmp1);

    /* Step 3.4 */
    if (x.sign == 1) {
      r_mpint_shl_digit (&tmp1, &y, i - tt - 1);
      r_mpint_add (&x, &x, &tmp1);
      (*qit)--;
    }
  }

  r_mpint_clamp (qp);

  if (r != NULL) {
    r_mpint_clamp (&x);
    r_mpint_shr (r, &x, norm);
    r->sign = n->sign;
  }

  r_mpint_clear (&tmp1);
  r_mpint_clear (&tmp2);
  r_mpint_clear (&x);
  r_mpint_clear (&y);
  if (qp == &qtmp)
    r_mpint_clear (&qtmp);

  return TRUE;
}

rboolean
r_mpint_div_i32 (rmpint * q, rmpint * r, const rmpint * n, rint32 d)
{
  rmpint mpi;
  rmpint_digit digit;

  if (d == 0)
    return FALSE;

  mpi.dig_alloc = 0;
  mpi.dig_used = 1;
  mpi.data = &digit;
  if (d >= 0) {
    mpi.sign = 0;
    digit = d;
  } else {
    mpi.sign = 1;
    digit = -d;
  }

  return r_mpint_div (q, r, n, &mpi);
}

rboolean
r_mpint_div_u32 (rmpint * q, rmpint * r, const rmpint * n, ruint32 d)
{
  rmpint mpi;

  if (d == 0)
    return FALSE;

  mpi.dig_alloc = 0;
  mpi.dig_used = 1;
  mpi.sign = 0;
  mpi.data = &d;

  return r_mpint_div (q, r, n, &mpi);
}

rboolean
r_mpint_exp (rmpint * dst, const rmpint * b, ruint16 e)
{
  rmpint s;
  rboolean ret;

  if (R_UNLIKELY (dst == NULL || b == NULL))
    return FALSE;

  if (e == 0) {
    r_mpint_set_u32 (dst, 1);
    return TRUE;
  }

  r_mpint_init_copy (&s, b);
  r_mpint_set_u32 (dst, 1);

  for (; e > 1; e >>= 1) {
    if (e & 1)
      r_mpint_mul (dst, &s, dst);
    r_mpint_mul (&s, &s, &s);
  }

  ret = r_mpint_mul (dst, dst, &s);
  r_mpint_clear (&s);
  return ret;
}

static void
r_mpint_gcd_internal (rmpint * u, rmpint * v,
    rmpint * a, rmpint * b, rmpint * c, rmpint * d)
{
  rmpint x, y;

  r_mpint_init_copy (&x, u);
  r_mpint_init_copy (&y, v);

  do {
    /* Step 4 */
    while (r_mpint_iseven (u)) {
      r_mpint_shr (u, u, 1);

      if (r_mpint_isodd (a) || r_mpint_isodd (b)) {
        r_mpint_add (a, a, &y);
        r_mpint_sub (b, b, &x);
      }
      r_mpint_shr (a, a, 1);
      r_mpint_shr (b, b, 1);
    }
    /* Step 5 */
    while (r_mpint_iseven (v)) {
      r_mpint_shr (v, v, 1);

      if (r_mpint_isodd (c) || r_mpint_isodd (d)) {
        r_mpint_add (c, c, &y);
        r_mpint_sub (d, d, &x);
      }
      r_mpint_shr (c, c, 1);
      r_mpint_shr (d, d, 1);
    }
    /* Step 6 */
    if (r_mpint_ucmp (u, v) >= 0) {
      r_mpint_sub (u, u, v);
      r_mpint_sub (a, a, c);
      r_mpint_sub (b, b, d);
    } else {
      r_mpint_sub (v, v, u);
      r_mpint_sub (c, c, a);
      r_mpint_sub (d, d, b);
    }
  } while (!r_mpint_iszero (u));

  r_mpint_clear (&x);
  r_mpint_clear (&y);
}

static rboolean
r_mpint_invmod_even (rmpint * dst, const rmpint * a, const rmpint * m)
{
  rmpint u, v, A, B, C, D;

  if (R_UNLIKELY (dst == NULL || a == NULL))
    return FALSE;
  if (R_UNLIKELY (r_mpint_iseven (a))) {
    r_mpint_zero (dst);
    return TRUE;
  }

  r_mpint_init (&u);
  if (!r_mpint_mod (&u, a, m)) {
    r_mpint_clear (&u);
    return FALSE;
  } else if (R_UNLIKELY (r_mpint_iseven (&u))) {
    r_mpint_clear (&u);
    r_mpint_zero (dst);
    return TRUE;
  }

  r_mpint_init_copy (&v, m);

  r_mpint_init (&A);
  r_mpint_init (&B);
  r_mpint_init (&C);
  r_mpint_init (&D);
  r_mpint_set_u32 (&A, 1);
  r_mpint_set_u32 (&D, 1);

  r_mpint_gcd_internal (&u, &v, &A, &B, &C, &D);
  if (r_mpint_digits_used (&v) != 1 || r_mpint_get_digit (&v, 0) != 1) {
    r_mpint_zero (dst);
  } else {
    while (C.sign != 0)               r_mpint_add (&C, &C, m);
    while (r_mpint_ucmp (&C, m) > 0)  r_mpint_sub (&C, &C, m);

    r_mpint_set (dst, &C);
  }

  r_mpint_clear (&u);
  r_mpint_clear (&v);
  r_mpint_clear (&A);
  r_mpint_clear (&B);
  r_mpint_clear (&C);
  r_mpint_clear (&D);
  return TRUE;
}

static rboolean
r_mpint_invmod_odd (rmpint * dst, const rmpint * a, const rmpint * m)
{
  rmpint u, v, B, D;
  ruint16 sign;

  if (R_UNLIKELY (dst == NULL || a == NULL))
    return FALSE;

  r_mpint_init_copy (&u, m);
  r_mpint_init_copy (&v, a);
  v.sign = 0;
  r_mpint_init (&B);
  r_mpint_init (&D);
  r_mpint_set_u32 (&D, 1);

  do {
    while (r_mpint_iseven (&u)) {
      r_mpint_shr (&u, &u, 1);
      if (r_mpint_isodd (&B))
        r_mpint_sub (&B, &B, m);
      r_mpint_shr (&B, &B, 1);
    }
    while (r_mpint_iseven (&v)) {
      r_mpint_shr (&v, &v, 1);
      if (r_mpint_isodd (&D))
        r_mpint_sub (&D, &D, m);
      r_mpint_shr (&D, &D, 1);
    }

    if (r_mpint_ucmp (&u, &v) >= 0) {
      r_mpint_sub (&u, &u, &v);
      r_mpint_sub (&B, &B, &D);
    } else {
      r_mpint_sub (&v, &v, &u);
      r_mpint_sub (&D, &D, &B);
    }
  } while (!r_mpint_iszero (&u));

  if (r_mpint_digits_used (&v) != 1 || r_mpint_get_digit (&v, 0) != 1) {
    r_mpint_zero (dst);
  } else {
    while (D.sign != 0)
      r_mpint_add (&D, &D, m);

    sign = a->sign;
    r_mpint_set (dst, &D);
    dst->sign = sign;
  }

  r_mpint_clear (&u);
  r_mpint_clear (&v);
  r_mpint_clear (&B);
  r_mpint_clear (&D);
  return TRUE;
}

rboolean
r_mpint_invmod (rmpint * dst, const rmpint * a, const rmpint * m)
{
  if (R_UNLIKELY (m == NULL || m->sign != 0 || r_mpint_iszero (m)))
    return FALSE;

  return r_mpint_isodd (m) ?
    r_mpint_invmod_odd (dst, a, m) : r_mpint_invmod_even (dst, a, m);
}

rboolean
r_mpint_expmod (rmpint * dst, const rmpint * b, const rmpint * e, const rmpint * m)
{
  rmpint R[2];
  rmpint_digit mp;
  ruint16 didx, bidx;

  if (R_UNLIKELY (dst == NULL || b == NULL || e == NULL || m == NULL))
    return FALSE;

  if (!r_mpint_montgomery_setup (&mp, m))
     return FALSE;

  r_mpint_init (&R[0]);
  r_mpint_init (&R[1]);

  if (!r_mpint_montgomery_normalize (&R[0], m))
    goto expmod_failed;

  if (r_mpint_ucmp (b, m) > 0)
     r_mpint_mod (&R[1], b, m);
  else
     r_mpint_set (&R[1], b);
  if (!r_mpint_mulmod (&R[1], &R[1], &R[0], m))
    goto expmod_failed;

  /* For loops iterates all bits from msb to lsb */
  for (didx = r_mpint_digits_used (e); didx > 0; didx--) {
    rmpint_digit dig = r_mpint_get_digit (e, didx - 1);
    for (bidx = 0; bidx < sizeof (rmpint_digit) * 8; bidx++) {
      rmpint_digit bit = (dig >> (sizeof (rmpint_digit) * 8 - 1)) & 1;
      dig <<= 1;

      /* Do this for all bits */
      if (!r_mpint_mul (&R[bit^1], &R[0], &R[1]) ||
          !r_mpint_montgomery_reduce (&R[bit^1], m, mp))
        goto expmod_failed;
      if (!r_mpint_mul (&R[bit], &R[bit], &R[bit]) ||
          !r_mpint_montgomery_reduce (&R[bit], m, mp))
        goto expmod_failed;
    }
  }

  if (!r_mpint_montgomery_reduce (&R[0], m, mp))
    goto expmod_failed;

  r_mpint_set (dst, &R[0]);
  r_mpint_clear (&R[0]);
  r_mpint_clear (&R[1]);
  return TRUE;
expmod_failed:
  r_mpint_clear (&R[0]);
  r_mpint_clear (&R[1]);
  return FALSE;
}

/* Based on Handbook of Applied Cryptography (HAC) 14.4.3 (p.608) */
rboolean
r_mpint_gcd (rmpint * dst, const rmpint * x, const rmpint * y)
{
  rmpint a, b, c, d, g, u, v;
  rboolean ret;

  if (R_UNLIKELY (dst == NULL || x == NULL || y == NULL))
    return FALSE;
  if (r_mpint_iszero (x) && !r_mpint_iszero (y)) {
    r_mpint_set (dst, y);
    dst->sign = 0;
    return TRUE;
  } else if (!r_mpint_iszero (x) && r_mpint_iszero (y)) {
    r_mpint_set (dst, x);
    dst->sign = 0;
    return TRUE;
  } else if (r_mpint_iszero (x)) {
    r_mpint_zero (dst);
    return TRUE;
  }

  /* Step 1 */
  r_mpint_init (&g);
  r_mpint_set_u32 (&g, 1);

  /* Step 2 */
  r_mpint_init_copy (&u, x);
  r_mpint_init_copy (&v, y);
  while (r_mpint_iseven (&u) && r_mpint_iseven (&v)) {
    r_mpint_shr (&u, &u, 1);
    r_mpint_shr (&v, &v, 1);
    r_mpint_shl (&g, &g, 1);
  }

  /* Step 3 */
  r_mpint_init (&a);
  r_mpint_set_u32 (&a, 1);
  r_mpint_init (&b);
  r_mpint_init (&c);
  r_mpint_init_copy (&d, &a);

  /* Step 4, 5, 6 */
  r_mpint_gcd_internal (&u, &v, &a, &b, &c, &d);
  r_mpint_clear (&d);
  r_mpint_clear (&c);
  r_mpint_clear (&b);
  r_mpint_clear (&a);

  r_mpint_clear (&u);

  ret = r_mpint_mul (dst, &g, &v);
  r_mpint_clear (&v);
  r_mpint_clear (&g);

  return ret;
}

rboolean
r_mpint_lcm (rmpint * dst, const rmpint * a, const rmpint * b)
{
  rmpint tmp;
  rboolean ret;

  if (R_UNLIKELY (dst == NULL || a == NULL || b == NULL))
    return FALSE;

  r_mpint_init (&tmp);

  r_mpint_gcd (&tmp, a, b);
#if 1
  ret = r_mpint_mul (dst, a, b) && r_mpint_div (dst, NULL, dst, &tmp);
#else
  /* FIXME: check if this is faster!? */
  if (r_mpint_ucmp (a, b) > 0) {
    ret = r_mpint_div (&tmp, NULL, a, &tmp) && r_mpint_mul (dst, b, &tmp);
  } else {
    ret = r_mpint_div (&tmp, NULL, b, &tmp) && r_mpint_mul (dst, a, &tmp);
  }
#endif
  r_mpint_clear (&tmp);

  return ret;
}

