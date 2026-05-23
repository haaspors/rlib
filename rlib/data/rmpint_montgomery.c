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
#include "rmpint-private.h"

#include <rlib/rmem.h>

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
      rmpint_word t = ((rmpint_word)cptr[0] + (rmpint_word)carry) +
        (((rmpint_word)mu) * ((rmpint_word)r_mpint_get_digit (m, y)));
      cptr[0] = (rmpint_digit)t;
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
r_mpint_montgomery_reduce_ct (rmpint * a, const rmpint * m, rmpint_digit mp)
{
  /* Constant-time Montgomery reduction. The main body is the same
   * Comba-style loop as r_mpint_montgomery_reduce, but the final
   * "if (a >= m) a -= m" is unconditional + masked, and the carry
   * propagation runs through the same fixed digit count regardless
   * of where the carry actually stops. */
  rmpint c;
  rmpint_digit * cptr;
  rmpint_digit mu;
  ruint16 x, y, n;
  rmpint_digit borrow, mask;
  rmpint_digit * scratch;
  rmpint_word t;

  if (R_UNLIKELY (a == NULL || m == NULL))
    return FALSE;

  n = r_mpint_digits_used (m);
  if (R_UNLIKELY (n == 0))
    return FALSE;

  r_mpint_init_size (&c, 2 * n + 1);
  /* c is initialised zero-padded by init_size; copying a in only
   * overwrites the low dig_used digits, so any tail stays zero. */
  r_mpint_set (&c, a);

  for (x = 0; x < n; x++) {
    rmpint_digit carry = 0;

    mu = c.data[x] * mp;
    cptr = c.data + x;
    /* Multiply-add m * mu into c starting at digit x. */
    for (y = 0; y < n; y++) {
      t = ((rmpint_word)cptr[0] + (rmpint_word)carry) +
          (((rmpint_word)mu) * ((rmpint_word)r_mpint_get_digit (m, y)));
      cptr[0] = (rmpint_digit)t;
      carry = (rmpint_digit)(t >> (sizeof (rmpint_digit) * 8));
      ++cptr;
    }
    /* Propagate the remaining carry through the rest of c. cptr is
     * now at c.data[x + n]; the buffer extends through c.data[2n],
     * so n + 1 - x positions remain. Iterate that many regardless of
     * whether carry has already settled - keeps the loop length
     * value-independent. */
    for (y = (ruint16)(n - x + 1); y > 0; y--) {
      t = (rmpint_word)cptr[0] + (rmpint_word)carry;
      cptr[0] = (rmpint_digit)t;
      carry = (rmpint_digit)(t >> (sizeof (rmpint_digit) * 8));
      ++cptr;
    }
  }

  /* After the body c.data[0..n) is zero by construction; c.data[n..2n+1)
   * holds a value v in [0, 2m). Move it down without going through
   * r_mpint_shr_digit (which clamps and so reports a value-dependent
   * dig_used). */
  r_mpint_ensure_digits (a, n + 1);
  for (x = 0; x < n + 1; x++)
    a->data[x] = c.data[n + x];
  for (x = n + 1; x < a->dig_alloc; x++)
    a->data[x] = 0;
  a->dig_used = n + 1;
  a->sign = 0;
  /* Inherit secure-clear sticky-flag from the operand we just absorbed. */
  a->flags |= (m->flags & R_MPINT_FLAG_SECURE_CLEAR);

  /* Constant-time conditional subtract of m. Compute scratch = a - m
   * at (n+1) digits (m extended with one leading 0). The borrow out
   * of the top digit is set iff a < m. */
  scratch = r_alloca ((n + 1) * sizeof (rmpint_digit));
  borrow = 0;
  for (x = 0; x < n; x++) {
    t = (rmpint_word)a->data[x] -
        (rmpint_word)r_mpint_get_digit (m, x) -
        (rmpint_word)borrow;
    scratch[x] = (rmpint_digit)t;
    borrow = (rmpint_digit)((t >> (sizeof (rmpint_digit) * 8)) & 1u);
  }
  t = (rmpint_word)a->data[n] - (rmpint_word)borrow;
  scratch[n] = (rmpint_digit)t;
  borrow = (rmpint_digit)((t >> (sizeof (rmpint_digit) * 8)) & 1u);

  /* borrow == 1 -> a < m -> keep a; borrow == 0 -> use scratch. */
  mask = (rmpint_digit)0 - (rmpint_digit)((borrow & 1u) ^ 1u);  /* 0 if borrow, all-ones else */
  for (x = 0; x < n + 1; x++)
    a->data[x] = (a->data[x] & ~mask) | (scratch[x] & mask);

  /* After the subtract a is in [0, m), so the top digit is zero.
   * Clamp to drop leading-zero digits so downstream ops that
   * compare via r_mpint_cmp (which treats dig_used difference as
   * value difference) see the canonical representation. Variable-
   * time on the result's bit-length - a real residual leak that
   * item 4 of #100 (memory-access audit) should revisit, but
   * required for correctness against the rest of the mpint
   * primitives that assume the no-leading-zeros invariant. */
  a->dig_used = n + 1;
  r_mpint_clamp (a);

  /* scratch held an intermediate derived from a (potentially secret);
   * wipe before the stack frame is popped. */
  r_memclear_secure (scratch, (n + 1) * sizeof (rmpint_digit));
  r_mpint_clear (&c);
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

