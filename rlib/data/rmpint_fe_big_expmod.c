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

/* 4-bit windowed Montgomery exponentiation on RMpintFE_Big.
 *
 * This is the RSA-sized counterpart to r_mpint_expmod_ct_with_mp in
 * rmpint.c. The structural algorithm is the same (precompute a 16-
 * entry power table, then for each 4-bit window of the exponent do 4
 * squarings + 1 multiply against a CT-selected table entry), but the
 * intermediates live in RMpintFE_Big rather than rmpint. That moves
 * us off the variable-width path and removes the dig_used residual:
 * each Mont mul iterates exactly ctx->n_digits, independent of the
 * intermediate value's actual bit length.
 *
 * The cost is ~16 * sizeof(RMpintFE_Big) of stack for the table - at
 * R_MPINT_FE_BIG_MAX_DIGITS = 257 (RSA-8192) that's ~16 KB, well
 * under typical thread stacks. The inner loop runs at FE_Big's CIOS
 * pace, which is faster per step than the rmpint SOS reduce. */

#include "config.h"
#include "rmpint-private.h"

#include <rlib/rmem.h>

#define R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS  4
#define R_MPINT_FE_BIG_EXPMOD_WINDOW_SIZE  (1u << R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS)
#define R_MPINT_FE_BIG_EXPMOD_WINDOW_MASK  (R_MPINT_FE_BIG_EXPMOD_WINDOW_SIZE - 1u)

/* Branchless table lookup: dst := table[idx], touching every entry
 * once so the memory access pattern is independent of idx. n is the
 * runtime modulus digit count (ctx->n_digits); the OR loop only
 * iterates that working window since the high tail of every FE_Big
 * the rest of this file produces is zero by construction. The
 * initial full-width zero of dst maintains that tail invariant on
 * dst for downstream consumers. */
static void
r_mpint_fe_big_table_select (RMpintFE_Big * dst, const RMpintFE_Big * table,
    rsize n_entries, ruint idx, ruint16 n)
{
  rsize i;
  ruint16 d;
  rmpint_digit mask, xor_val, nz;

  for (d = 0; d < R_N_ELEMENTS (dst->d); d++)
    dst->d[d] = 0;

  for (i = 0; i < n_entries; i++) {
    /* mask = all-ones iff i == idx, else all-zeros. Same XOR + "is
     * non-zero" trick the rmpint windowed expmod uses. */
    xor_val = (rmpint_digit)(i ^ idx);
    nz = (xor_val | ((rmpint_digit)0 - xor_val))
        >> (sizeof (rmpint_digit) * 8 - 1);
    mask = nz - (rmpint_digit)1;
    for (d = 0; d < n; d++)
      dst->d[d] |= table[i].d[d] & mask;
  }
}

rboolean
r_mpint_fe_big_expmod_ct (rmpint * dst, const rmpint * base,
    const rmpint * exp, const rmpint * m, const RMpintFE_BigMontCtx * ctx,
    const RMpintFE_Big * mont_r_squared, ruint exp_bits)
{
  RMpintFE_Big table[R_MPINT_FE_BIG_EXPMOD_WINDOW_SIZE];
  RMpintFE_Big result, picked, base_fe, one_fe;
  rmpint reduced_base;
  ruint16 n;
  ruint windowed_bits, i, w;
  ruint window_val, window_idx, j;
  rboolean ok = FALSE;

  if (R_UNLIKELY (dst == NULL || base == NULL || exp == NULL || m == NULL ||
        ctx == NULL || mont_r_squared == NULL))
    return FALSE;

  n = ctx->n_digits;
  if (R_UNLIKELY (n == 0 || n > R_MPINT_FE_BIG_MAX_DIGITS))
    return FALSE;
  if (R_UNLIKELY (r_mpint_iszero (m)))
    return FALSE;

  r_mpint_init_secure (&reduced_base);

  /* Reduce base mod m if it exceeds m. Variable-time on base, which
   * is the public input (RSA ciphertext) - same trade-off the rmpint
   * windowed expmod makes. */
  if (r_mpint_ucmp (base, m) > 0) {
    if (!r_mpint_mod (&reduced_base, base, m))
      goto cleanup;
  } else {
    r_mpint_set (&reduced_base, base);
  }
  r_mpint_fe_big_from_mpint (&base_fe, &reduced_base, n);

  /* table[0] = 1_M (= R mod m). Build via mont_in(1). */
  r_mpint_fe_big_zero (&one_fe);
  one_fe.d[0] = 1;
  r_mpint_fe_big_mont_in (&table[0], &one_fe, mont_r_squared, ctx);

  /* table[1] = base_M. */
  r_mpint_fe_big_mont_in (&table[1], &base_fe, mont_r_squared, ctx);

  /* table[i] = table[i - 1] * table[1] for i in 2..15. */
  for (w = 2; w < R_MPINT_FE_BIG_EXPMOD_WINDOW_SIZE; w++)
    r_mpint_fe_big_mul_mont (&table[w], &table[w - 1], &table[1], ctx);

  /* result = 1_M. */
  r_mpint_fe_big_copy (&result, &table[0]);

  /* Round exp_bits up to a multiple of WINDOW_BITS so the loop body
   * stays uniform across all keys. The topmost window's missing
   * positions read as zero via r_mpint_get_digit_ct, contributing
   * nothing to the exponent value. */
  windowed_bits = (exp_bits + (R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS - 1u)) &
      ~(ruint)(R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS - 1u);

  for (i = windowed_bits; i >= R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS;
      i -= R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS) {
    /* 4 squarings. The first iteration squares 1_M four times (still
     * 1_M), harmless and keeps the loop body uniform. */
    for (j = 0; j < R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS; j++)
      r_mpint_fe_big_sqr_mont (&result, &result, ctx);

    /* Extract bits [i - WINDOW_BITS, i) MSB-first into window_val.
     * The CT variant of get_digit masks on dig_used so the per-bit
     * timing depends only on the bit-position arithmetic (public),
     * not on the secret exponent's active digit count. */
    window_val = 0;
    for (j = R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS; j > 0; j--) {
      ruint bp = i - (R_MPINT_FE_BIG_EXPMOD_WINDOW_BITS - j + 1);
      rmpint_digit bit = (r_mpint_get_digit_ct (exp,
              (ruint32)(bp / (sizeof (rmpint_digit) * 8))) >>
              (bp % (sizeof (rmpint_digit) * 8))) & 1u;
      window_val = (window_val << 1) | bit;
    }

    /* CT table lookup + multiply. */
    window_idx = (ruint)(window_val & R_MPINT_FE_BIG_EXPMOD_WINDOW_MASK);
    r_mpint_fe_big_table_select (&picked, table,
        R_MPINT_FE_BIG_EXPMOD_WINDOW_SIZE, window_idx, n);
    r_mpint_fe_big_mul_mont (&result, &result, &picked, ctx);
  }

  /* Drop result out of Mont form: M(result_M, 1) = result. */
  r_mpint_fe_big_mont_out (&result, &result, ctx);

  if (!r_mpint_fe_big_to_mpint (dst, &result, n))
    goto cleanup;

  ok = TRUE;
cleanup:
  /* Intermediate Mont-form values, the power table, and the reduced
   * base all carry secret information about base / exp; wipe before
   * the stack frame is popped. */
  r_memclear_secure (table, sizeof (table));
  r_memclear_secure (&result, sizeof (result));
  r_memclear_secure (&picked, sizeof (picked));
  r_memclear_secure (&base_fe, sizeof (base_fe));
  r_memclear_secure (&one_fe, sizeof (one_fe));
  r_mpint_clear (&reduced_base);
  return ok;
}
