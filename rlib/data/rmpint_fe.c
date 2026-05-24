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

/* Fixed-width Montgomery field-element arithmetic. See rmpint-private.h
 * for the type and prototype declarations, including the design notes
 * on why these primitives exist alongside the variable-width rmpint
 * primitives - in short, RMpintFE iterates exactly the modulus's digit
 * count regardless of operand value, removing the residual memory-
 * access leak that comes from rmpint clamping dig_used to the value's
 * actual bit length.
 *
 * Originally factored out of rlib/crypto/recurve.c (item 4 of #100) so
 * DSA signing and RSA private-key operations can share the same
 * audited constant-time implementation. */

#include "config.h"
#include "rmpint-private.h"

#include <rlib/rmem.h>

/* ---- Per-modulus setup. ---- */

rboolean
r_mpint_fe_mont_ctx_init (RMpintFEMontCtx * ctx, const rmpint * m)
{
  ruint16 n;

  if (R_UNLIKELY (ctx == NULL || m == NULL))
    return FALSE;

  n = r_mpint_digits_used (m);
  if (R_UNLIKELY (n == 0 || n > R_MPINT_FE_MAX_DIGITS))
    return FALSE;

  if (!r_mpint_montgomery_setup (&ctx->mp, m))
    return FALSE;

  r_mpint_fe_from_mpint (&ctx->p, m, n);
  ctx->n_digits = n;
  return TRUE;
}

rboolean
r_mpint_fe_compute_r_squared (RMpintFE * out, const rmpint * m, ruint16 n)
{
  /* R^2 = 2^(64 * n) mod m. Compute via shift + mod on a scratch
   * mpint; the value is a per-modulus constant so the variable-time
   * cost is paid once outside the CT-sensitive path. */
  rmpint t;
  rboolean ok;

  if (R_UNLIKELY (out == NULL || m == NULL))
    return FALSE;

  r_mpint_init (&t);
  r_mpint_set_u32 (&t, 1);
  ok = r_mpint_shl (&t, &t, (ruint32)(64u * n)) &&
       r_mpint_mod (&t, &t, m);
  if (ok)
    r_mpint_fe_from_mpint (out, &t, n);
  r_mpint_clear (&t);
  return ok;
}

/* ---- Lifecycle / conversion. ---- */

void
r_mpint_fe_zero (RMpintFE * x)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (x->d); i++)
    x->d[i] = 0;
}

void
r_mpint_fe_copy (RMpintFE * dst, const RMpintFE * src)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (dst->d); i++)
    dst->d[i] = src->d[i];
}

/* Copy an mpint's value into an FE, zero-padding to n digits. The
 * "truncate beyond n" branch is unreachable for in-range operands
 * (curve constants, scalars in the documented [0, 2^(32*n)) range),
 * so it doesn't leak anything callers care about. */
void
r_mpint_fe_from_mpint (RMpintFE * fe, const rmpint * mpi, ruint16 n)
{
  ruint16 i;
  ruint16 to_copy = mpi->dig_used;
  if (to_copy > n) to_copy = n;
  for (i = 0; i < to_copy; i++)
    fe->d[i] = mpi->data[i];
  for (i = to_copy; i < R_MPINT_FE_MAX_DIGITS; i++)
    fe->d[i] = 0;
}

/* Extract an FE into an mpint, clamping the mpint at the end so the
 * caller-visible value stays canonical. The clamp is value-dependent,
 * but the value has already left the CT-sensitive code path at this
 * point - it's en route to a public output. */
rboolean
r_mpint_fe_to_mpint (rmpint * mpi, const RMpintFE * fe, ruint16 n)
{
  ruint16 i;
  r_mpint_ensure_digits (mpi, n);
  if (R_UNLIKELY (mpi->dig_alloc < n)) return FALSE;
  for (i = 0; i < n; i++)
    mpi->data[i] = fe->d[i];
  for (i = n; i < mpi->dig_alloc; i++)
    mpi->data[i] = 0;
  mpi->dig_used = n;
  mpi->sign = 0;
  r_mpint_clamp (mpi);
  return TRUE;
}

/* ---- Constant-time helpers. ---- */

rmpint_digit
r_mpint_fe_iszero_ct (const RMpintFE * x, ruint16 n)
{
  ruint16 i;
  rmpint_digit acc = 0;
  rmpint_digit nz;
  for (i = 0; i < n; i++)
    acc |= x->d[i];
  /* (acc | -acc) has its top bit set iff acc != 0. Shift down to a
   * single 0/1 in nz, then nz - 1 gives all-ones if zero, 0 if not. */
  nz = (acc | ((rmpint_digit)0 - acc)) >> (sizeof (rmpint_digit) * 8 - 1);
  return nz - (rmpint_digit)1;
}

void
r_mpint_fe_select_ct (RMpintFE * out, rmpint_digit mask,
    const RMpintFE * a, const RMpintFE * b, ruint16 n)
{
  ruint16 i;
  for (i = 0; i < n; i++)
    out->d[i] = (a->d[i] & mask) | (b->d[i] & ~mask);
}

void
r_mpint_fe_swap_ct (RMpintFE * a, RMpintFE * b, ruint32 bit, ruint16 n)
{
  rmpint_digit mask = (rmpint_digit)0 - (rmpint_digit)(bit & 1u);
  ruint16 i;
  for (i = 0; i < n; i++) {
    rmpint_digit d = (a->d[i] ^ b->d[i]) & mask;
    a->d[i] ^= d;
    b->d[i] ^= d;
  }
}

/* ---- Modular arithmetic mod p. ---- */

void
r_mpint_fe_add (RMpintFE * out, const RMpintFE * a, const RMpintFE * b,
    const RMpintFEMontCtx * ctx)
{
  rmpint_digit t[R_MPINT_FE_MAX_DIGITS + 1];
  rmpint_digit scratch[R_MPINT_FE_MAX_DIGITS + 1];
  ruint16 i, n = ctx->n_digits;
  rmpint_word u;
  rmpint_digit carry = 0, borrow = 0, mask;

  for (i = 0; i < n; i++) {
    u = (rmpint_word)a->d[i] + (rmpint_word)b->d[i] + (rmpint_word)carry;
    t[i] = (rmpint_digit)u;
    carry = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
  }
  t[n] = carry;

  /* scratch = t - p, in n+1 digits. Borrow flags "t < p". */
  for (i = 0; i < n; i++) {
    u = (rmpint_word)t[i] - (rmpint_word)ctx->p.d[i] - (rmpint_word)borrow;
    scratch[i] = (rmpint_digit)u;
    borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);
  }
  u = (rmpint_word)t[n] - (rmpint_word)borrow;
  scratch[n] = (rmpint_digit)u;
  borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);

  /* borrow == 1 means t < p; keep t. borrow == 0 means t >= p; use scratch. */
  mask = (rmpint_digit)0 - (rmpint_digit)((borrow & 1u) ^ 1u);
  for (i = 0; i < n; i++)
    out->d[i] = (t[i] & ~mask) | (scratch[i] & mask);
  for (i = n; i < R_MPINT_FE_MAX_DIGITS; i++)
    out->d[i] = 0;
}

void
r_mpint_fe_sub (RMpintFE * out, const RMpintFE * a, const RMpintFE * b,
    const RMpintFEMontCtx * ctx)
{
  rmpint_digit t[R_MPINT_FE_MAX_DIGITS];
  ruint16 i, n = ctx->n_digits;
  rmpint_word u;
  rmpint_digit borrow = 0, carry = 0, mask;

  for (i = 0; i < n; i++) {
    u = (rmpint_word)a->d[i] - (rmpint_word)b->d[i] - (rmpint_word)borrow;
    t[i] = (rmpint_digit)u;
    borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);
  }

  /* If borrow=1, t is the 2's-complement of -(b-a); adding p (also
   * mod 2^(32n)) lands at p - (b - a) = a - b + p, the canonical
   * non-negative result. The carry out of this add is discarded by
   * design - the value fits in n digits. */
  mask = (rmpint_digit)0 - (rmpint_digit)(borrow & 1u);
  for (i = 0; i < n; i++) {
    u = (rmpint_word)t[i] + (rmpint_word)(ctx->p.d[i] & mask) + (rmpint_word)carry;
    out->d[i] = (rmpint_digit)u;
    carry = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
  }
  for (i = n; i < R_MPINT_FE_MAX_DIGITS; i++)
    out->d[i] = 0;
}

/* Montgomery multiplication via CIOS (Coarsely Integrated Operand
 * Scanning). The mul and the reduce share a single n+2-digit
 * accumulator T, which is what makes this faster than the SOS
 * variant the variable-width r_mpint_montgomery_reduce_ct uses (one
 * pass through T instead of two through separate buffers). */
void
r_mpint_fe_mul_mont (RMpintFE * out, const RMpintFE * a, const RMpintFE * b,
    const RMpintFEMontCtx * ctx)
{
  rmpint_digit T[R_MPINT_FE_MAX_DIGITS + 2];
  rmpint_digit scratch[R_MPINT_FE_MAX_DIGITS + 1];
  ruint16 i, j, n = ctx->n_digits;
  rmpint_word u;
  rmpint_digit c, mu, borrow = 0, mask;

  for (i = 0; i < n + 2; i++) T[i] = 0;

  for (i = 0; i < n; i++) {
    /* T = T + a * b[i] */
    c = 0;
    for (j = 0; j < n; j++) {
      u = (rmpint_word)T[j] +
          (rmpint_word)a->d[j] * (rmpint_word)b->d[i] +
          (rmpint_word)c;
      T[j] = (rmpint_digit)u;
      c = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
    }
    u = (rmpint_word)T[n] + (rmpint_word)c;
    T[n] = (rmpint_digit)u;
    T[n + 1] = (rmpint_digit)(T[n + 1] +
        (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8)));

    /* mu = T[0] * mp. Choosing mu this way makes T[0] zero after the
     * next multiply-add, which is what lets the right-shift be exact. */
    mu = T[0] * ctx->mp;

    /* T = T + mu * p */
    c = 0;
    for (j = 0; j < n; j++) {
      u = (rmpint_word)T[j] +
          (rmpint_word)mu * (rmpint_word)ctx->p.d[j] +
          (rmpint_word)c;
      T[j] = (rmpint_digit)u;
      c = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
    }
    u = (rmpint_word)T[n] + (rmpint_word)c;
    T[n] = (rmpint_digit)u;
    T[n + 1] = (rmpint_digit)(T[n + 1] +
        (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8)));

    /* T >>= digit_bits. T[0] is zero by construction. */
    for (j = 0; j < n + 1; j++) T[j] = T[j + 1];
    T[n + 1] = 0;
  }

  /* T is in [0, 2p). Conditional subtract p (over n+1 digits, since
   * T[n] can carry a 1 from the last iteration). */
  for (j = 0; j < n; j++) {
    u = (rmpint_word)T[j] - (rmpint_word)ctx->p.d[j] - (rmpint_word)borrow;
    scratch[j] = (rmpint_digit)u;
    borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);
  }
  u = (rmpint_word)T[n] - (rmpint_word)borrow;
  scratch[n] = (rmpint_digit)u;
  borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);

  mask = (rmpint_digit)0 - (rmpint_digit)((borrow & 1u) ^ 1u);
  for (j = 0; j < n; j++)
    out->d[j] = (T[j] & ~mask) | (scratch[j] & mask);
  for (j = n; j < R_MPINT_FE_MAX_DIGITS; j++)
    out->d[j] = 0;
}

void
r_mpint_fe_sqr_mont (RMpintFE * out, const RMpintFE * a,
    const RMpintFEMontCtx * ctx)
{
  r_mpint_fe_mul_mont (out, a, a, ctx);
}

void
r_mpint_fe_mont_in (RMpintFE * out, const RMpintFE * a,
    const RMpintFE * mont_r_squared, const RMpintFEMontCtx * ctx)
{
  /* M(a, R^2) = a * R^2 * R^-1 = a * R, the Montgomery lift. */
  r_mpint_fe_mul_mont (out, a, mont_r_squared, ctx);
}

void
r_mpint_fe_mont_out (RMpintFE * out, const RMpintFE * a,
    const RMpintFEMontCtx * ctx)
{
  /* M(a, 1) = a * 1 * R^-1 = a / R, the Montgomery unlift. */
  RMpintFE one;
  r_mpint_fe_zero (&one);
  one.d[0] = 1;
  r_mpint_fe_mul_mont (out, a, &one, ctx);
}

/* ---- Derived operations. ---- */

void
r_mpint_fe_invmod_mont (RMpintFE * out, const RMpintFE * a_M,
    const RMpintFE * p_minus_2, ruint p_minus_2_bits,
    const RMpintFE * mont_r_squared, const RMpintFEMontCtx * ctx)
{
  /* Fermat via left-to-right Montgomery exponentiation with swap-wrap
   * CT dispatch on each exponent bit. The exponent (p - 2) is public
   * (it's a function of the modulus, which itself is public), so its
   * bit pattern doesn't leak anything secret; what the swap-wrap
   * pattern protects is the base, which is the secret operand. */
  RMpintFE R[2], one;
  ruint i;
  rmpint_digit bit;

  r_mpint_fe_zero (&one);
  one.d[0] = 1;
  r_mpint_fe_mont_in (&R[0], &one, mont_r_squared, ctx);  /* R[0] = 1_M */
  r_mpint_fe_copy (&R[1], a_M);                            /* R[1] = a_M */

  for (i = p_minus_2_bits; i > 0; i--) {
    ruint bp = i - 1;
    bit = (p_minus_2->d[bp / (sizeof (rmpint_digit) * 8)] >>
           (bp % (sizeof (rmpint_digit) * 8))) & 1u;

    r_mpint_fe_swap_ct (&R[0], &R[1], (ruint32)bit, ctx->n_digits);
    r_mpint_fe_mul_mont (&R[1], &R[0], &R[1], ctx);
    r_mpint_fe_sqr_mont (&R[0], &R[0], ctx);
    r_mpint_fe_swap_ct (&R[0], &R[1], (ruint32)bit, ctx->n_digits);
  }

  r_mpint_fe_copy (out, &R[0]);
  r_memclear_secure (R, sizeof (R));
}
