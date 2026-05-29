#include <rlib/rlib.h>

RTEST (rrand, prng, RTEST_FAST)
{
  RPrng * prng;
  ruint64 s0, s1;

  /* This is a stupid test that just checks that two prng samples are different */
  /* This might be invalid for some prng implementations?!? */
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpuint ((s0 = r_prng_get_u64 (prng)), !=, (s1 = r_prng_get_u64 (prng)));
  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrand, entropy_fill, RTEST_FAST)
{
  ruint8 buffer[64];

  r_assert (!r_rand_entropy_fill (NULL, sizeof (buffer)));
  r_assert (!r_rand_entropy_fill (buffer, 0));
  r_assert (r_rand_entropy_fill (buffer, sizeof (buffer)));
}
RTEST_END;

/* Count the set bits across a buffer and assert the ratio is close to
 * 1/2 -- a crude smoke test that the output is not obviously skewed. */
static void
r_test_assert_monobit (const ruint8 * buf, rsize size)
{
  rsize i, ones = 0, bits = size * 8;

  for (i = 0; i < size; i++)
    ones += RUINT8_POPCOUNT (buf[i]);

  /* Expect ones ~= bits/2; allow a wide 5% band so the test is not
   * flaky while still catching a stuck or constant generator. */
  r_assert_cmpuint (ones, >, bits / 2 - bits / 20);
  r_assert_cmpuint (ones, <, bits / 2 + bits / 20);
}

RTEST (rrand, prng_crypto, RTEST_FAST)
{
  RPrng * prng;
  ruint8 buffer[8192];

  r_assert_cmpptr ((prng = r_prng_new_crypto ()), !=, NULL);
  r_assert_cmpuint (r_prng_get_u64 (prng), !=, r_prng_get_u64 (prng));

  r_assert (r_prng_fill (prng, buffer, sizeof (buffer)));
  r_test_assert_monobit (buffer, sizeof (buffer));

  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrand, prng_crypto_reseed, RTEST_FAST)
{
  RPrng * prng;
  ruint8 buffer[4096];
  rsize i;

  /* Draw past the reseed threshold (1 MiB) to exercise the
   * reseed-from-OS path inside the DRBG. */
  r_assert_cmpptr ((prng = r_prng_new_crypto ()), !=, NULL);
  for (i = 0; i < 320; i++)
    r_assert (r_prng_fill (prng, buffer, sizeof (buffer)));
  r_test_assert_monobit (buffer, sizeof (buffer));

  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrand, prng_system, RTEST_FAST)
{
  RPrng * prng;
  ruint8 buffer[8192];

  r_assert_cmpptr ((prng = r_prng_new_system ()), !=, NULL);
  r_assert_cmpuint (r_prng_get_u64 (prng), !=, r_prng_get_u64 (prng));

  r_assert (r_prng_fill (prng, buffer, sizeof (buffer)));
  r_test_assert_monobit (buffer, sizeof (buffer));

  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrand, fill_nonzero, RTEST_FAST)
{
  RPrng * prng;
  ruint8 buffer[4096];
  rsize i;

  r_assert (!r_prng_fill_nonzero (NULL, NULL, 0));
  r_assert (!r_prng_fill_nonzero (NULL, buffer, 0));

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (!r_prng_fill_nonzero (prng, NULL, 0));
  r_assert (!r_prng_fill_nonzero (prng, buffer, 0));
  r_assert (r_prng_fill_nonzero (prng, buffer, sizeof (buffer)));
  for (i = 0; i < sizeof (buffer); i++)
    r_assert_cmpuint (buffer[i], !=, 0);

  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrand, fill_base64, RTEST_FAST)
{
  RPrng * prng;
  rchar buffer[4096];
  rsize i;

  r_assert (!r_prng_fill_base64 (NULL, NULL, 0));
  r_assert (!r_prng_fill_base64 (NULL, buffer, 0));

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (!r_prng_fill_base64 (prng, NULL, 0));
  r_assert (!r_prng_fill_base64 (prng, buffer, 0));
  r_assert (r_prng_fill_base64 (prng, buffer, sizeof (buffer)));
  for (i = 0; i < sizeof (buffer); i++)
    r_assert (r_base64_is_valid_char (buffer[i]));

  for (i = 1; i < 12; i++)
    r_assert (r_prng_fill_base64 (prng, buffer, i));
  r_prng_unref (prng);
}
RTEST_END;

