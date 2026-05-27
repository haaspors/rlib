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

/* Templated bodies for the fixed-width Montgomery field-element
 * primitives. Included once per (type, ctx, max-digits) tuple from
 * rmpint_fe.c; the caller defines FE_TYPE / FE_CTX / FE_FN / FE_MAX
 * before each #include and #undefs them after. The type names and
 * function prototypes live in the public header (rmpint.h) so callers
 * see plain typedefs and prototypes; only the implementations are
 * generated from this template.
 *
 * Function bodies are written exactly as they would be at a single
 * width - the only template-specific spelling is the FE_FN(name)
 * indirection on function names and the FE_TYPE / FE_CTX / FE_MAX
 * substitutions. */

#if !defined(FE_TYPE) || !defined(FE_CTX) || !defined(FE_FN) || !defined(FE_MAX)
#error "rmpint_fe_template.h: define FE_TYPE, FE_CTX, FE_FN, FE_MAX before #include"
#endif

/* ---- Per-modulus setup. ---- */

rboolean
FE_FN (mont_ctx_init) (FE_CTX * ctx, const rmpint * m)
{
  ruint16 n;

  if (R_UNLIKELY (ctx == NULL || m == NULL))
    return FALSE;

  n = r_mpint_digits_used (m);
  if (R_UNLIKELY (n == 0 || n > FE_MAX))
    return FALSE;

  if (!r_mpint_montgomery_setup (&ctx->mp, m))
    return FALSE;

  FE_FN (from_mpint) (&ctx->p, m, n);
  ctx->n_digits = n;
  return TRUE;
}

rboolean
FE_FN (compute_r_squared) (FE_TYPE * out, const rmpint * m, ruint16 n)
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
    FE_FN (from_mpint) (out, &t, n);
  r_mpint_clear (&t);
  return ok;
}

/* ---- Lifecycle / conversion. ---- */

void
FE_FN (zero) (FE_TYPE * x)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (x->d); i++)
    x->d[i] = 0;
}

void
FE_FN (copy) (FE_TYPE * dst, const FE_TYPE * src)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (dst->d); i++)
    dst->d[i] = src->d[i];
}

/* Copy an mpint's value into an FE, zero-padding to n digits.
 *
 * Iterates uniformly to n (which is the field width, a public
 * quantity) and reads each source digit via r_mpint_get_digit_ct so
 * the split between "real value" and "zero padding" doesn't depend
 * on mpi->dig_used. Trailing positions in [n, FE_MAX) are
 * unconditional zero - n is public so iterating to a fixed FE_MAX
 * doesn't leak anything either way.
 *
 * Callers that pass non-secret mpints (curve constants, public
 * scalars) pay a one-digit-per-iteration masked-read cost; callers
 * that pass secrets (RSA CRT residues, ECC private scalars during
 * blinded operations) get bit-for-bit identical timing across
 * different secret values. */
void
FE_FN (from_mpint) (FE_TYPE * fe, const rmpint * mpi, ruint16 n)
{
  ruint16 i;
  for (i = 0; i < n; i++)
    fe->d[i] = r_mpint_get_digit_ct (mpi, i);
  for (i = n; i < FE_MAX; i++)
    fe->d[i] = 0;
}

/* Extract an FE into an mpint, clamping the mpint at the end so the
 * caller-visible value stays canonical. The clamp is value-dependent,
 * but the value has already left the CT-sensitive code path at this
 * point - it's en route to a public output. */
rboolean
FE_FN (to_mpint) (rmpint * mpi, const FE_TYPE * fe, ruint16 n)
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
FE_FN (iszero_ct) (const FE_TYPE * x, ruint16 n)
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
FE_FN (select_ct) (FE_TYPE * out, rmpint_digit mask,
    const FE_TYPE * a, const FE_TYPE * b, ruint16 n)
{
  ruint16 i;
  for (i = 0; i < n; i++)
    out->d[i] = (a->d[i] & mask) | (b->d[i] & ~mask);
}

void
FE_FN (swap_ct) (FE_TYPE * a, FE_TYPE * b, ruint32 bit, ruint16 n)
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
FE_FN (add) (FE_TYPE * out, const FE_TYPE * a, const FE_TYPE * b,
    const FE_CTX * ctx)
{
  rmpint_digit t[FE_MAX + 1];
  rmpint_digit scratch[FE_MAX + 1];
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
  for (i = n; i < FE_MAX; i++)
    out->d[i] = 0;
}

void
FE_FN (sub) (FE_TYPE * out, const FE_TYPE * a, const FE_TYPE * b,
    const FE_CTX * ctx)
{
  rmpint_digit t[FE_MAX];
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
  for (i = n; i < FE_MAX; i++)
    out->d[i] = 0;
}

/* Montgomery multiplication via CIOS (Coarsely Integrated Operand
 * Scanning). The mul and the reduce share a single n+2-digit
 * accumulator T, which is what makes this faster than the SOS
 * variant the variable-width r_mpint_montgomery_reduce_ct uses (one
 * pass through T instead of two through separate buffers). */
void
FE_FN (mul_mont) (FE_TYPE * out, const FE_TYPE * a, const FE_TYPE * b,
    const FE_CTX * ctx)
{
  rmpint_digit T[FE_MAX + 2];
  rmpint_digit scratch[FE_MAX + 1];
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
  for (j = n; j < FE_MAX; j++)
    out->d[j] = 0;
}

void
FE_FN (sqr_mont) (FE_TYPE * out, const FE_TYPE * a, const FE_CTX * ctx)
{
  FE_FN (mul_mont) (out, a, a, ctx);
}

void
FE_FN (mont_in) (FE_TYPE * out, const FE_TYPE * a,
    const FE_TYPE * mont_r_squared, const FE_CTX * ctx)
{
  /* M(a, R^2) = a * R^2 * R^-1 = a * R, the Montgomery lift. */
  FE_FN (mul_mont) (out, a, mont_r_squared, ctx);
}

void
FE_FN (mont_out) (FE_TYPE * out, const FE_TYPE * a, const FE_CTX * ctx)
{
  /* M(a, 1) = a * 1 * R^-1 = a / R, the Montgomery unlift. */
  FE_TYPE one;
  FE_FN (zero) (&one);
  one.d[0] = 1;
  FE_FN (mul_mont) (out, a, &one, ctx);
}

/* ---- Derived operations. ---- */

void
FE_FN (invmod_mont) (FE_TYPE * out, const FE_TYPE * a_M,
    const FE_TYPE * p_minus_2, ruint p_minus_2_bits,
    const FE_TYPE * mont_r_squared, const FE_CTX * ctx)
{
  /* Fermat via left-to-right Montgomery exponentiation with swap-wrap
   * CT dispatch on each exponent bit. The exponent (p - 2) is public
   * (it's a function of the modulus, which itself is public), so its
   * bit pattern doesn't leak anything secret; what the swap-wrap
   * pattern protects is the base, which is the secret operand. */
  FE_TYPE R[2], one;
  ruint i;
  rmpint_digit bit;

  FE_FN (zero) (&one);
  one.d[0] = 1;
  FE_FN (mont_in) (&R[0], &one, mont_r_squared, ctx);  /* R[0] = 1_M */
  FE_FN (copy) (&R[1], a_M);                            /* R[1] = a_M */

  for (i = p_minus_2_bits; i > 0; i--) {
    ruint bp = i - 1;
    bit = (p_minus_2->d[bp / (sizeof (rmpint_digit) * 8)] >>
           (bp % (sizeof (rmpint_digit) * 8))) & 1u;

    FE_FN (swap_ct) (&R[0], &R[1], (ruint32)bit, ctx->n_digits);
    FE_FN (mul_mont) (&R[1], &R[0], &R[1], ctx);
    FE_FN (sqr_mont) (&R[0], &R[0], ctx);
    FE_FN (swap_ct) (&R[0], &R[1], (ruint32)bit, ctx->n_digits);
  }

  FE_FN (copy) (out, &R[0]);
  r_memclear_secure (R, sizeof (R));
}

/* ---- Wide (non-modular) primitives. Used by the RSA CRT recombination
 * to assemble m = m2 + h * q in constant time outside of any single
 * modular field - the result is the full plaintext, valid mod n but
 * sized as a wide integer for the rmpint hand-off. ---- */

/* Schoolbook multiply: out = a * b, treating a as a_n digits and b
 * as b_n digits. Output is up to (a_n + b_n) digits in normal
 * (non-Montgomery) form; trailing positions in [a_n + b_n, FE_MAX)
 * are zero-padded. Caller is responsible for ensuring
 * a_n + b_n <= FE_MAX (the field-element storage cap).
 *
 * Constant-time in operand contents: no early-out, no data-dependent
 * branches. Loop counts depend on a_n and b_n only (public). */
void
FE_FN (mul_ct) (FE_TYPE * out, const FE_TYPE * a, ruint16 a_n,
    const FE_TYPE * b, ruint16 b_n)
{
  ruint16 i, j, total = (ruint16)(a_n + b_n);
  rmpint_digit c;
  rmpint_word u;

  for (i = 0; i < FE_MAX; i++) out->d[i] = 0;

  for (i = 0; i < a_n; i++) {
    c = 0;
    for (j = 0; j < b_n; j++) {
      u = (rmpint_word)a->d[i] * (rmpint_word)b->d[j] +
          (rmpint_word)out->d[i + j] + (rmpint_word)c;
      out->d[i + j] = (rmpint_digit)u;
      c = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
    }
    if (i + b_n < FE_MAX) out->d[i + b_n] = c;
  }
  /* total <= FE_MAX by precondition; the conditional store inside
   * the loop already covers the carry-out into position total - 1. */
  (void) total;
}

/* Wide add: out = a + b, treating a as a_n digits, b as b_n.
 * Output is max(a_n, b_n) + 1 digits (one for the carry-out);
 * trailing positions zero-padded. Caller ensures the carry-out
 * position fits in FE_MAX. Constant-time in operand contents. */
void
FE_FN (add_ct) (FE_TYPE * out, const FE_TYPE * a, ruint16 a_n,
    const FE_TYPE * b, ruint16 b_n)
{
  ruint16 i, max_n = a_n > b_n ? a_n : b_n;
  rmpint_digit carry = 0;
  rmpint_word u;

  for (i = 0; i < max_n; i++) {
    rmpint_digit av = (i < a_n) ? a->d[i] : (rmpint_digit)0;
    rmpint_digit bv = (i < b_n) ? b->d[i] : (rmpint_digit)0;
    u = (rmpint_word)av + (rmpint_word)bv + (rmpint_word)carry;
    out->d[i] = (rmpint_digit)u;
    carry = (rmpint_digit)(u >> (sizeof (rmpint_digit) * 8));
  }
  if (max_n < FE_MAX) out->d[max_n] = carry;
  for (i = (ruint16)(max_n + 1); i < FE_MAX; i++) out->d[i] = 0;
}

/* Conditional-subtract-once reduction mod p: out = (a < p) ? a : a - p.
 * The CRT recombination uses this to land m2 (which is < q < 2p for
 * any sensibly-chosen RSA key) inside the p-field; outside that
 * precondition the function is well-defined but the result is not
 * "a mod p". Constant-time. */
void
FE_FN (mod_ct) (FE_TYPE * out, const FE_TYPE * a, const FE_CTX * ctx)
{
  FE_TYPE t;
  ruint16 i, n = ctx->n_digits;
  rmpint_word u;
  rmpint_digit borrow = 0, mask;

  /* t = a - p, n digits. Borrow flags "a < p". */
  for (i = 0; i < n; i++) {
    u = (rmpint_word)a->d[i] - (rmpint_word)ctx->p.d[i] - (rmpint_word)borrow;
    t.d[i] = (rmpint_digit)u;
    borrow = (rmpint_digit)((u >> (sizeof (rmpint_digit) * 8)) & 1u);
  }

  /* borrow == 1 → a < p, keep a. borrow == 0 → a >= p, use t. */
  mask = (rmpint_digit)0 - (rmpint_digit)((borrow & 1u) ^ 1u);
  for (i = 0; i < n; i++)
    out->d[i] = (a->d[i] & ~mask) | (t.d[i] & mask);
  for (i = n; i < FE_MAX; i++)
    out->d[i] = 0;
}
