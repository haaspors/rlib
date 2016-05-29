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
