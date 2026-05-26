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

/* ---- RMpintFE_Big sanity. Same template, wider storage, exercised
 * here against RSA-sized moduli that the ECC-width tests above can't
 * reach. Correctness is cross-checked against the existing rmpint
 * primitives (mulmod / add / sub + mod); the FE primitives only
 * differ from those in their constant-time access pattern, not in
 * their arithmetic. ---- */

static void
fe_big_mul_via (rmpint * out, const RMpintFE_BigMontCtx * ctx,
    const RMpintFE_Big * mont_r_squared, ruint16 n,
    const rmpint * a, const rmpint * b)
{
  RMpintFE_Big fa, fb, fam, fbm, frm, fr;
  r_mpint_fe_big_from_mpint (&fa, a, n);
  r_mpint_fe_big_from_mpint (&fb, b, n);
  r_mpint_fe_big_mont_in (&fam, &fa, mont_r_squared, ctx);
  r_mpint_fe_big_mont_in (&fbm, &fb, mont_r_squared, ctx);
  r_mpint_fe_big_mul_mont (&frm, &fam, &fbm, ctx);
  r_mpint_fe_big_mont_out (&fr, &frm, ctx);
  r_assert (r_mpint_fe_big_to_mpint (out, &fr, n));
}

/* Build an n-bit odd modulus by setting bit (n-1), bit 0, and a few
 * mid-range bits via OR. Not prime - but mul / add / sub correctness
 * doesn't need primality, only odd-ness for the Montgomery setup. */
static void
build_big_odd_modulus (rmpint * m, ruint bits)
{
  rmpint t;
  r_mpint_set_u32 (m, 1);
  r_assert (r_mpint_shl (m, m, bits - 1));
  r_mpint_init (&t);
  r_mpint_set_u32 (&t, 0xdeadbeefu);
  r_assert (r_mpint_shl (&t, &t, bits / 2));  /* mid-range bits */
  r_assert (r_mpint_add (m, m, &t));
  r_assert (r_mpint_add_i32 (m, m, 1));  /* force odd */
  r_mpint_clear (&t);
}

RTEST (rmpint_fe_big, mont_ctx_init_rejects_oversize, RTEST_FAST)
{
  /* A modulus with more digits than R_MPINT_FE_BIG_MAX_DIGITS should
   * be refused so callers can't silently overflow the inline storage. */
  RMpintFE_BigMontCtx ctx;
  rmpint m;

  r_mpint_init (&m);
  r_mpint_set_u32 (&m, 1);
  /* Push to one digit past the maximum (32 * (MAX+1) bits). */
  r_assert (r_mpint_shl (&m, &m, 32u * (R_MPINT_FE_BIG_MAX_DIGITS + 1u)));
  r_assert (r_mpint_add_i32 (&m, &m, 1));
  r_assert (!r_mpint_fe_big_mont_ctx_init (&ctx, &m));

  r_mpint_clear (&m);
}
RTEST_END;

RTEST (rmpint_fe_big, mul_round_trip_2048, RTEST_FAST)
{
  /* Round-trip mul check at an RSA-2048-sized modulus. Exercises the
   * 64+ digit CIOS inner loop that the ECC-width tests don't reach. */
  RMpintFE_BigMontCtx ctx;
  RMpintFE_Big mont_r_squared;
  rmpint m, a, b, expected, got;
  ruint16 n;
  ruint trial;

  r_mpint_init (&m);
  build_big_odd_modulus (&m, 2048);
  r_assert (r_mpint_fe_big_mont_ctx_init (&ctx, &m));
  n = ctx.n_digits;
  r_assert_cmpuint (n, ==, 64);
  r_assert (r_mpint_fe_big_compute_r_squared (&mont_r_squared, &m, n));

  r_mpint_init (&a);
  r_mpint_init (&b);
  r_mpint_init (&expected);
  r_mpint_init (&got);

  for (trial = 0; trial < 4; trial++) {
    r_mpint_set_u32 (&a, 0x12345678u + trial * 0x10101010u);
    r_assert (r_mpint_shl (&a, &a, 700u + trial * 50u));
    r_mpint_set_u32 (&b, 0xdeadbeefu - trial * 0x01010101u);
    r_assert (r_mpint_shl (&b, &b, 1100u + trial * 40u));

    r_assert (r_mpint_mulmod (&expected, &a, &b, &m));
    fe_big_mul_via (&got, &ctx, &mont_r_squared, n, &a, &b);
    r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

    /* sqr matches mul (a, a). */
    r_assert (r_mpint_mulmod (&expected, &a, &a, &m));
    fe_big_mul_via (&got, &ctx, &mont_r_squared, n, &a, &a);
    r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);
  }

  r_mpint_clear (&m);
  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
}
RTEST_END;

/* Wrap the setup boilerplate for r_mpint_fe_big_expmod_ct: take m,
 * fill ctx + mont_r_squared, run the new expmod, return its output. */
static rboolean
big_expmod_via (rmpint * out, const rmpint * base, const rmpint * exp,
    const rmpint * m, ruint exp_bits)
{
  RMpintFE_BigMontCtx ctx;
  RMpintFE_Big r2;
  if (!r_mpint_fe_big_mont_ctx_init (&ctx, m))
    return FALSE;
  if (!r_mpint_fe_big_compute_r_squared (&r2, m, ctx.n_digits))
    return FALSE;
  return r_mpint_fe_big_expmod_ct (out, base, exp, m, &ctx, &r2, exp_bits);
}

RTEST (rmpint_fe_big, expmod_basic, RTEST_FAST)
{
  /* NULL guards + the standard 4^13 mod 497 = 445 vector + a small
   * 65537 modulus loop, mirroring the r_mpint_expmod_ct test in
   * test/rmpint.c so the two CT expmods agree on the same shapes. */
  RMpintFE_BigMontCtx ctx;
  RMpintFE_Big r2;
  rmpint b, e, m, expected, got;
  ruint i;

  r_mpint_init (&b);
  r_mpint_init (&e);
  r_mpint_init (&m);
  r_mpint_init (&expected);
  r_mpint_init (&got);

  /* Pre-populate ctx + r2 against m = 497 so the NULL-pointer guard
   * checks below can pass valid ctx / r2 and isolate the NULL case. */
  r_mpint_set_u32 (&m, 497);
  r_assert (r_mpint_fe_big_mont_ctx_init (&ctx, &m));
  r_assert (r_mpint_fe_big_compute_r_squared (&r2, &m, ctx.n_digits));

  {
    rmpint zb = R_MPINT_INIT, ze = R_MPINT_INIT;
    r_assert (!r_mpint_fe_big_expmod_ct (NULL, &zb, &ze, &m, &ctx, &r2, 32));
    r_assert (!r_mpint_fe_big_expmod_ct (&got, NULL, &ze, &m, &ctx, &r2, 32));
    r_assert (!r_mpint_fe_big_expmod_ct (&got, &zb, NULL, &m, &ctx, &r2, 32));
    r_assert (!r_mpint_fe_big_expmod_ct (&got, &zb, &ze, NULL, &ctx, &r2, 32));
    r_assert (!r_mpint_fe_big_expmod_ct (&got, &zb, &ze, &m, NULL, &r2, 32));
    r_assert (!r_mpint_fe_big_expmod_ct (&got, &zb, &ze, &m, &ctx, NULL, 32));
  }

  r_mpint_set_u32 (&b, 4);
  r_mpint_set_u32 (&e, 13);
  r_mpint_set_u32 (&expected, 445);
  r_assert (big_expmod_via (&got, &b, &e, &m, r_mpint_bits_used (&e)));
  r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

  /* exp_bits cap larger than e's bit count must produce the same
   * result - the leading-zero iterations are no-ops. */
  r_assert (big_expmod_via (&got, &b, &e, &m, 64));
  r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

  /* Cross-check against the variable-time r_mpint_expmod over a
   * scatter of small operands modulo a Fermat prime. */
  r_mpint_set_u32 (&m, 65537);
  for (i = 1; i < 16; i++) {
    r_mpint_set_u32 (&b, 2 + i);
    r_mpint_set_u32 (&e, 1000 + i * 731);
    r_assert (r_mpint_expmod (&expected, &b, &e, &m));
    r_assert (big_expmod_via (&got, &b, &e, &m, 32));
    r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);
  }

  r_mpint_clear (&b);
  r_mpint_clear (&e);
  r_mpint_clear (&m);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rmpint_fe_big, expmod_rsa_2048, RTEST_FAST)
{
  /* Exercise the windowed expmod at an RSA-2048-sized modulus.
   * Cross-check against the variable-time r_mpint_expmod so any
   * algorithmic drift between the two paths surfaces here rather
   * than in a wycheproof RSA test that's three layers up. */
  rmpint m, base, exp, expected, got;

  r_mpint_init (&m);
  r_mpint_init (&base);
  r_mpint_init (&exp);
  r_mpint_init (&expected);
  r_mpint_init (&got);

  build_big_odd_modulus (&m, 2048);

  /* base = 0xcafebabe << 700, exp = 0x12345 << 1500. */
  r_mpint_set_u32 (&base, 0xcafebabeu);
  r_assert (r_mpint_shl (&base, &base, 700));
  r_mpint_set_u32 (&exp, 0x12345u);
  r_assert (r_mpint_shl (&exp, &exp, 1500));

  r_assert (r_mpint_expmod (&expected, &base, &exp, &m));
  r_assert (big_expmod_via (&got, &base, &exp, &m, r_mpint_bits_used (&exp)));
  r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

  /* exp_bits = 2048 (uniform timing case) must give the same result. */
  r_assert (big_expmod_via (&got, &base, &exp, &m, 2048));
  r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

  r_mpint_clear (&m);
  r_mpint_clear (&base);
  r_mpint_clear (&exp);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
}
RTEST_END;

HEAVY_RTEST (rmpint_fe_big, expmod_rsa_8192, RTEST_FASTSLOW)
{
  /* Same cross-check at RSA-8192. Slow enough on a debug build to
   * gate behind --heavy and to want the FASTSLOW timeout budget; the
   * algorithmic property is also verified at 2048 in the FAST test
   * above. */
  rmpint m, base, exp, expected, got;

  r_mpint_init (&m);
  r_mpint_init (&base);
  r_mpint_init (&exp);
  r_mpint_init (&expected);
  r_mpint_init (&got);

  build_big_odd_modulus (&m, 8192);
  r_mpint_set_u32 (&base, 0xcafebabeu);
  r_assert (r_mpint_shl (&base, &base, 3000));
  r_mpint_set_u32 (&exp, 0x65537u);
  r_assert (r_mpint_shl (&exp, &exp, 6000));

  r_assert (r_mpint_expmod (&expected, &base, &exp, &m));
  r_assert (big_expmod_via (&got, &base, &exp, &m, r_mpint_bits_used (&exp)));
  r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

  r_mpint_clear (&m);
  r_mpint_clear (&base);
  r_mpint_clear (&exp);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
}
RTEST_END;

HEAVY_RTEST (rmpint_fe_big, mul_round_trip_8192, RTEST_FAST)
{
  /* RSA-8192 modulus = 256 digits, the widest the type supports.
   * Single trial - the inner loop runs n^2 ~= 65k iterations per
   * mul_mont call, slow enough to gate behind --heavy. */
  RMpintFE_BigMontCtx ctx;
  RMpintFE_Big mont_r_squared;
  rmpint m, a, b, expected, got;
  ruint16 n;

  r_mpint_init (&m);
  build_big_odd_modulus (&m, 8192);
  r_assert (r_mpint_fe_big_mont_ctx_init (&ctx, &m));
  n = ctx.n_digits;
  r_assert_cmpuint (n, ==, 256);
  r_assert (r_mpint_fe_big_compute_r_squared (&mont_r_squared, &m, n));

  r_mpint_init (&a);
  r_mpint_init (&b);
  r_mpint_init (&expected);
  r_mpint_init (&got);

  r_mpint_set_u32 (&a, 0xcafebabeu);
  r_assert (r_mpint_shl (&a, &a, 3000));
  r_mpint_set_u32 (&b, 0xdeadbeefu);
  r_assert (r_mpint_shl (&b, &b, 5000));

  r_assert (r_mpint_mulmod (&expected, &a, &b, &m));
  fe_big_mul_via (&got, &ctx, &mont_r_squared, n, &a, &b);
  r_assert_cmpint (r_mpint_cmp (&got, &expected), ==, 0);

  r_mpint_clear (&m);
  r_mpint_clear (&a);
  r_mpint_clear (&b);
  r_mpint_clear (&expected);
  r_mpint_clear (&got);
}
RTEST_END;
