#include <rlib/rlib.h>

/* Single-digit Fermat prime, used by the small-modulus paths so the
 * arithmetic is easy to follow by hand. */
#define SMALL_P  65537u

/* secp256r1's p, used to exercise the multi-digit path against a real
 * curve modulus. */
static const ruint8 SECP256R1_P[] = {
  0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

/* Fill ctx + mont_r_squared + p_minus_2 for an arbitrary odd prime
 * supplied as an mpint. Caller owns p_mp; the FEs copy out of it. */
static void
setup_ctx_from_mpint (RMpintFEMontCtx * ctx, RMpintFE * mont_r_squared,
    RMpintFE * p_minus_2, ruint * p_minus_2_bits, const rmpint * p_mp)
{
  rmpint pm2;

  r_assert (r_mpint_fe_mont_ctx_init (ctx, p_mp));
  r_assert (r_mpint_fe_compute_r_squared (mont_r_squared, p_mp,
        ctx->n_digits));

  r_mpint_init (&pm2);
  r_assert (r_mpint_sub_i32 (&pm2, p_mp, 2));
  r_mpint_fe_from_mpint (p_minus_2, &pm2, ctx->n_digits);
  *p_minus_2_bits = r_mpint_bits_used (&pm2);
  r_mpint_clear (&pm2);
}

/* Compute a + b mod p via FE primitives, return the result as an mpint
 * (clamped). Hides the boilerplate of pushing operands through the FE
 * API for the round-trip check tests below. */
static void
fe_add_via (rmpint * out, const RMpintFEMontCtx * ctx,
    ruint16 n, const rmpint * a, const rmpint * b)
{
  RMpintFE fa, fb, fr;
  r_mpint_fe_from_mpint (&fa, a, n);
  r_mpint_fe_from_mpint (&fb, b, n);
  r_mpint_fe_add (&fr, &fa, &fb, ctx);
  r_assert (r_mpint_fe_to_mpint (out, &fr, n));
}

static void
fe_sub_via (rmpint * out, const RMpintFEMontCtx * ctx,
    ruint16 n, const rmpint * a, const rmpint * b)
{
  RMpintFE fa, fb, fr;
  r_mpint_fe_from_mpint (&fa, a, n);
  r_mpint_fe_from_mpint (&fb, b, n);
  r_mpint_fe_sub (&fr, &fa, &fb, ctx);
  r_assert (r_mpint_fe_to_mpint (out, &fr, n));
}

/* Compute a * b mod p via Mont mul (lift both, multiply, drop). */
static void
fe_mul_via (rmpint * out, const RMpintFEMontCtx * ctx,
    const RMpintFE * mont_r_squared, ruint16 n,
    const rmpint * a, const rmpint * b)
{
  RMpintFE fa, fb, fam, fbm, frm, fr;
  r_mpint_fe_from_mpint (&fa, a, n);
  r_mpint_fe_from_mpint (&fb, b, n);
  r_mpint_fe_mont_in (&fam, &fa, mont_r_squared, ctx);
  r_mpint_fe_mont_in (&fbm, &fb, mont_r_squared, ctx);
  r_mpint_fe_mul_mont (&frm, &fam, &fbm, ctx);
  r_mpint_fe_mont_out (&fr, &frm, ctx);
  r_assert (r_mpint_fe_to_mpint (out, &fr, n));
}


RTEST (rmpint_fe, mont_ctx_init_rejects_bad_modulus, RTEST_FAST)
{
  RMpintFEMontCtx ctx;
  rmpint m;

  /* Even modulus: Montgomery setup needs gcd(m, 2^digit_bits) == 1,
   * so an even m has no Montgomery inverse and ctx_init must refuse. */
  r_mpint_init (&m);
  r_mpint_set_u32 (&m, 0x100u);
  r_assert (!r_mpint_fe_mont_ctx_init (&ctx, &m));

  /* Zero modulus: no digits to work with, refused on the dig_used
   * check before the Montgomery setup even runs. */
  r_mpint_set_u32 (&m, 0);
  r_assert (!r_mpint_fe_mont_ctx_init (&ctx, &m));

  r_mpint_clear (&m);
}
RTEST_END;

RTEST (rmpint_fe, lifecycle, RTEST_FAST)
{
  /* zero, copy, from/to_mpint round-trip. */
  RMpintFE a, b;
  rmpint mp, mp_back;
  ruint16 i;

  r_mpint_fe_zero (&a);
  for (i = 0; i < R_MPINT_FE_MAX_DIGITS; i++)
    r_assert_cmpuint (a.d[i], ==, 0);

  /* Fill a with a known pattern. */
  for (i = 0; i < R_MPINT_FE_MAX_DIGITS; i++)
    a.d[i] = 0xdeadbe00u | i;

  r_mpint_fe_zero (&b);
  r_mpint_fe_copy (&b, &a);
  for (i = 0; i < R_MPINT_FE_MAX_DIGITS; i++)
    r_assert_cmpuint (b.d[i], ==, a.d[i]);

  /* mpint -> FE round-trip. */
  r_mpint_init (&mp);
  r_mpint_init (&mp_back);
  r_mpint_set_u32 (&mp, 0x12345678u);
  r_mpint_fe_from_mpint (&a, &mp, 8);
  r_assert_cmpuint (a.d[0], ==, 0x12345678u);
  for (i = 1; i < R_MPINT_FE_MAX_DIGITS; i++)
    r_assert_cmpuint (a.d[i], ==, 0);
  r_assert (r_mpint_fe_to_mpint (&mp_back, &a, 8));
  r_assert_cmpint (r_mpint_cmp (&mp, &mp_back), ==, 0);

  r_mpint_clear (&mp);
  r_mpint_clear (&mp_back);
}
RTEST_END;

RTEST (rmpint_fe, ct_helpers, RTEST_FAST)
{
  RMpintFE a, b, out;
  rmpint_digit mask;
  ruint16 i;

  /* iszero_ct: all-ones for zero, all-zeros for any non-zero digit. */
  r_mpint_fe_zero (&a);
  r_assert_cmpuint (r_mpint_fe_iszero_ct (&a, 8), ==, (rmpint_digit)-1);
  a.d[0] = 1;
  r_assert_cmpuint (r_mpint_fe_iszero_ct (&a, 8), ==, 0);
  /* Non-zero outside the inspected window must NOT register as non-zero. */
  r_mpint_fe_zero (&a);
  a.d[7] = 0xff;
  r_assert_cmpuint (r_mpint_fe_iszero_ct (&a, 7), ==, (rmpint_digit)-1);

  /* select_ct: mask=all-ones picks a, mask=0 picks b. */
  r_mpint_fe_zero (&a);
  r_mpint_fe_zero (&b);
  for (i = 0; i < 4; i++) { a.d[i] = 0xaaaaaaaau; b.d[i] = 0x55555555u; }
  r_mpint_fe_select_ct (&out, (rmpint_digit)-1, &a, &b, 4);
  for (i = 0; i < 4; i++) r_assert_cmpuint (out.d[i], ==, 0xaaaaaaaau);
  r_mpint_fe_select_ct (&out, 0, &a, &b, 4);
  for (i = 0; i < 4; i++) r_assert_cmpuint (out.d[i], ==, 0x55555555u);
  /* Bit-by-bit mask interleaves between a and b. mask=0x0f0f0f0f
   * picks a's low nibbles (0xa) and b's high nibbles (0x5) per byte. */
  mask = 0x0f0f0f0fu;
  r_mpint_fe_select_ct (&out, mask, &a, &b, 4);
  for (i = 0; i < 4; i++)
    r_assert_cmpuint (out.d[i], ==, 0x5a5a5a5au);

  /* swap_ct: bit=0 is a no-op, bit=1 swaps. */
  r_mpint_fe_zero (&a);
  r_mpint_fe_zero (&b);
  for (i = 0; i < 4; i++) { a.d[i] = 0x11111111u; b.d[i] = 0x22222222u; }
  r_mpint_fe_swap_ct (&a, &b, 0, 4);
  for (i = 0; i < 4; i++) {
    r_assert_cmpuint (a.d[i], ==, 0x11111111u);
    r_assert_cmpuint (b.d[i], ==, 0x22222222u);
  }
  r_mpint_fe_swap_ct (&a, &b, 1, 4);
  for (i = 0; i < 4; i++) {
    r_assert_cmpuint (a.d[i], ==, 0x22222222u);
    r_assert_cmpuint (b.d[i], ==, 0x11111111u);
  }
}
RTEST_END;

RTEST (rmpint_fe, add_sub_small, RTEST_FAST)
{
  /* Add / sub against the variable-width rmpint_mulmod / mod as the
   * reference, on a small single-digit prime. Covers wrap-around in
   * both directions. */
  RMpintFEMontCtx ctx;
  RMpintFE mont_r_squared, p_minus_2;
  ruint p_minus_2_bits;
  rmpint p_mp, a, b, expected, got;
  ruint32 av, bv;

  r_mpint_init (&p_mp);
  r_mpint_set_u32 (&p_mp, SMALL_P);
  setup_ctx_from_mpint (&ctx, &mont_r_squared, &p_minus_2, &p_minus_2_bits, &p_mp);
  (void) mont_r_squared;
  (void) p_minus_2;
  (void) p_minus_2_bits;

  r_mpint_init (&a);
  r_mpint_init (&b);
  r_mpint_init (&expected);
  r_mpint_init (&got);

  /* a + b that fits inside p, and one that overflows. */
  for (av = 1; av < SMALL_P; av += 10000) {
    for (bv = 1; bv < SMALL_P; bv += 12345) {
      r_mpint_set_u32 (&a, av);
      r_mpint_set_u32 (&b, bv);
      r_assert (r_mpint_add (&expected, &a, &b));
      r_assert (r_mpint_mod (&expected, &expected, &p_mp));
      fe_add_via (&got, &ctx, 1, &a, &b);
      r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

      /* sub: cover both a >= b and a < b cases. */
      if (av >= bv) {
        r_assert (r_mpint_sub (&expected, &a, &b));
      } else {
        r_assert (r_mpint_add (&expected, &a, &p_mp));
        r_assert (r_mpint_sub (&expected, &expected, &b));
      }
      r_assert (r_mpint_mod (&expected, &expected, &p_mp));
      fe_sub_via (&got, &ctx, 1, &a, &b);
      r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);
    }
  }

  r_mpint_clear (&p_mp);
  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rmpint_fe, mul_sqr_small, RTEST_FAST)
{
  /* Mont mul + sqr against r_mpint_mulmod as reference. */
  RMpintFEMontCtx ctx;
  RMpintFE mont_r_squared, p_minus_2;
  ruint p_minus_2_bits;
  rmpint p_mp, a, b, expected, got;
  ruint32 av, bv;

  r_mpint_init (&p_mp);
  r_mpint_set_u32 (&p_mp, SMALL_P);
  setup_ctx_from_mpint (&ctx, &mont_r_squared, &p_minus_2, &p_minus_2_bits, &p_mp);
  (void) p_minus_2;
  (void) p_minus_2_bits;

  r_mpint_init (&a);
  r_mpint_init (&b);
  r_mpint_init (&expected);
  r_mpint_init (&got);

  for (av = 1; av < SMALL_P; av += 9999) {
    for (bv = 1; bv < SMALL_P; bv += 11111) {
      r_mpint_set_u32 (&a, av);
      r_mpint_set_u32 (&b, bv);
      r_assert (r_mpint_mulmod (&expected, &a, &b, &p_mp));
      fe_mul_via (&got, &ctx, &mont_r_squared, 1, &a, &b);
      r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

      /* Sqr: a^2 mod p. */
      r_assert (r_mpint_mulmod (&expected, &a, &a, &p_mp));
      fe_mul_via (&got, &ctx, &mont_r_squared, 1, &a, &a);
      r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);
    }
  }

  r_mpint_clear (&p_mp);
  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rmpint_fe, mont_round_trip_small, RTEST_FAST)
{
  /* mont_in then mont_out is the identity. */
  RMpintFEMontCtx ctx;
  RMpintFE mont_r_squared, p_minus_2, fe, fe_M, fe_back;
  ruint p_minus_2_bits;
  rmpint p_mp, a, got;
  ruint32 av;

  r_mpint_init (&p_mp);
  r_mpint_set_u32 (&p_mp, SMALL_P);
  setup_ctx_from_mpint (&ctx, &mont_r_squared, &p_minus_2, &p_minus_2_bits, &p_mp);
  (void) p_minus_2;
  (void) p_minus_2_bits;

  r_mpint_init (&a);
  r_mpint_init (&got);

  for (av = 0; av < SMALL_P; av += 4567) {
    r_mpint_set_u32 (&a, av);
    r_mpint_fe_from_mpint (&fe, &a, 1);
    r_mpint_fe_mont_in (&fe_M, &fe, &mont_r_squared, &ctx);
    r_mpint_fe_mont_out (&fe_back, &fe_M, &ctx);
    r_assert (r_mpint_fe_to_mpint (&got, &fe_back, 1));
    r_assert_cmpint (r_mpint_cmp (&got, &a), ==, 0);
  }

  r_mpint_clear (&p_mp);
  r_mpint_clear (&a);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rmpint_fe, invmod_satisfies_inverse_law, RTEST_FAST)
{
  /* a * invmod(a) === 1 (mod p) for non-zero a. */
  RMpintFEMontCtx ctx;
  RMpintFE mont_r_squared, p_minus_2, a_fe, a_M, ainv_M, prod_M, prod_norm;
  ruint p_minus_2_bits;
  rmpint p_mp, a, got, one;
  ruint32 av;

  r_mpint_init (&p_mp);
  r_mpint_set_u32 (&p_mp, SMALL_P);
  setup_ctx_from_mpint (&ctx, &mont_r_squared, &p_minus_2, &p_minus_2_bits, &p_mp);

  r_mpint_init (&a);
  r_mpint_init (&got);
  r_mpint_init (&one);
  r_mpint_set_u32 (&one, 1);

  for (av = 1; av < SMALL_P; av += 3691) {
    r_mpint_set_u32 (&a, av);
    r_mpint_fe_from_mpint (&a_fe, &a, 1);
    r_mpint_fe_mont_in (&a_M, &a_fe, &mont_r_squared, &ctx);
    r_mpint_fe_invmod_mont (&ainv_M, &a_M, &p_minus_2, p_minus_2_bits,
        &mont_r_squared, &ctx);
    r_mpint_fe_mul_mont (&prod_M, &a_M, &ainv_M, &ctx);
    r_mpint_fe_mont_out (&prod_norm, &prod_M, &ctx);
    r_assert (r_mpint_fe_to_mpint (&got, &prod_norm, 1));
    r_assert_cmpint (r_mpint_cmp (&got, &one), ==, 0);
  }

  r_mpint_clear (&p_mp);
  r_mpint_clear (&a);
  r_mpint_clear (&got);
  r_mpint_clear (&one);
}
RTEST_END;

RTEST (rmpint_fe, multi_digit_against_curve_modulus, RTEST_FAST)
{
  /* Same correctness checks against a real curve modulus (secp256r1's p),
   * so the multi-digit code paths in mul_mont / add / sub aren't only
   * covered by the single-digit small-prime tests. */
  RMpintFEMontCtx ctx;
  RMpintFE mont_r_squared, p_minus_2;
  ruint p_minus_2_bits;
  rmpint p_mp, a, b, expected, got, prod, ainv_norm;
  RMpintFE a_fe, a_M, ainv_M, prod_M, prod_norm;
  ruint16 n;
  ruint16 trial;

  r_mpint_init_binary (&p_mp, SECP256R1_P, sizeof (SECP256R1_P));
  n = r_mpint_digits_used (&p_mp);
  r_assert_cmpuint (n, ==, 8);
  setup_ctx_from_mpint (&ctx, &mont_r_squared, &p_minus_2, &p_minus_2_bits, &p_mp);

  r_mpint_init (&a);
  r_mpint_init (&b);
  r_mpint_init (&expected);
  r_mpint_init (&got);
  r_mpint_init (&prod);
  r_mpint_init (&ainv_norm);

  /* A handful of varied test values - exhaustive coverage isn't
   * meaningful at this size; what matters is hitting the wrap-around
   * paths and the multi-digit carry chains. */
  for (trial = 0; trial < 4; trial++) {
    r_mpint_set_u32 (&a, 0x12345678u + trial * 0x10101010u);
    r_assert (r_mpint_shl (&a, &a, 100));  /* shift into mid-range digits */
    r_mpint_set_u32 (&b, 0xdeadbeefu - trial * 0x01010101u);
    r_assert (r_mpint_shl (&b, &b, 200));

    /* add */
    r_assert (r_mpint_add (&expected, &a, &b));
    r_assert (r_mpint_mod (&expected, &expected, &p_mp));
    fe_add_via (&got, &ctx, n, &a, &b);
    r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

    /* sub */
    if (r_mpint_cmp (&a, &b) >= 0) {
      r_assert (r_mpint_sub (&expected, &a, &b));
    } else {
      r_assert (r_mpint_add (&expected, &a, &p_mp));
      r_assert (r_mpint_sub (&expected, &expected, &b));
    }
    r_assert (r_mpint_mod (&expected, &expected, &p_mp));
    fe_sub_via (&got, &ctx, n, &a, &b);
    r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

    /* mul */
    r_assert (r_mpint_mulmod (&expected, &a, &b, &p_mp));
    fe_mul_via (&got, &ctx, &mont_r_squared, n, &a, &b);
    r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

    /* invmod: a * invmod(a) === 1 (mod p). */
    r_mpint_fe_from_mpint (&a_fe, &a, n);
    r_mpint_fe_mont_in (&a_M, &a_fe, &mont_r_squared, &ctx);
    r_mpint_fe_invmod_mont (&ainv_M, &a_M, &p_minus_2, p_minus_2_bits,
        &mont_r_squared, &ctx);
    r_mpint_fe_mul_mont (&prod_M, &a_M, &ainv_M, &ctx);
    r_mpint_fe_mont_out (&prod_norm, &prod_M, &ctx);
    r_assert (r_mpint_fe_to_mpint (&prod, &prod_norm, n));
    r_assert_cmpuint (r_mpint_bits_used (&prod), ==, 1);  /* == 1 */
  }

  r_mpint_clear (&p_mp);
  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
  r_mpint_clear (&prod);
  r_mpint_clear (&ainv_norm);
}
RTEST_END;
