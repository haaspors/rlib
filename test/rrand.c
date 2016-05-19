#include <rlib/rlib.h>

RTEST (rrand, prng, RTEST_FAST)
{
  RPrng * prng;
  ruint64 s0, s1;

  /* This is a stupid test that just checks that two prng samples are different */
  /* This might be invalid for some prng implementations?!? */
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpuint ((s0 = r_rand_prng_get (prng)), !=, (s1 = r_rand_prng_get (prng)));
  r_rand_prng_unref (prng);
}
RTEST_END;

