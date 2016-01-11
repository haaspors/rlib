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
#include <rlib/rmpint.h>
#include "rmpint_private.h"

rboolean
r_mpint_montgomery_setup (rmpint_digit * mp, const rmpint * m)
{
  rmpint_digit x, b;

  if (!r_mpint_isodd (m))
    return FALSE;

  b = r_mpint_get_digit (m, 0);
  x = (((b + 2) & 4) << 1) + b;
  x *= 2 - b * x;
  x *= 2 - b * x;
  x *= 2 - b * x;

  *mp = (rmpint_digit)(((rmpint_word) 1 << (sizeof (rmpint_digit) * 8)) - ((rmpint_word)x));
  return TRUE;
}

rboolean
r_mpint_montgomery_reduce (rmpint * a, const rmpint * m, rmpint_digit mp)
{
  rmpint_digit * cptr, mu;
  rmpint c;
  int x, y;

  r_mpint_init_size (&c, 2*r_mpint_digits_used (m)+1);
  r_mpint_set (&c, a);

  for (x = 0; x < r_mpint_digits_used (m); x++) {
    rmpint_digit carry = 0;

    mu = r_mpint_get_digit (&c, x) * mp;
    cptr = c.data + x;
    for (y = 0; y < r_mpint_digits_used (m); y++) {
      rmpint_word t;
      cptr[0] = t  = ((rmpint_word)cptr[0] + (rmpint_word)carry) +
        (((rmpint_word)mu) * ((rmpint_word)r_mpint_get_digit (m, y)));
      carry = (t >> (sizeof (rmpint_digit) * 8));
      ++cptr;
    }
    while (carry != 0) {
      rmpint_digit t = cptr[0] += carry;
      carry = (t < carry);
      ++cptr;
    }
  }

  c.dig_used = 2*r_mpint_digits_used (m)+1;
  r_mpint_clamp (&c);
  r_mpint_shr_digit (a, &c, r_mpint_digits_used (m));
  r_mpint_clear (&c);

  if (r_mpint_ucmp (a, m) >= 0)
    r_mpint_sub_unsigned (a, a, m);

  return TRUE;
}

rboolean
r_mpint_montgomery_normalize (rmpint * a, const rmpint * m)
{
  int bits;

  r_mpint_set_u32 (a, 1);
  if (r_mpint_digits_used (m) > 1) {
    bits = r_mpint_bits_used (m);
    r_mpint_shl (a, a, bits - 1);

    bits %= (sizeof (rmpint_digit) * 8);
    if (!bits) bits = (sizeof (rmpint_digit) * 8);
    bits--;
  } else {
    bits = 0;
  }

  for (; bits < (int)(sizeof (rmpint_digit) * 8); bits++) {
    r_mpint_shl (a, a, 1);
    if (r_mpint_ucmp (a, m) >= 0)
      r_mpint_sub_unsigned (a, a, m);
  }
  return TRUE;
}

