#include <rlib/rlib.h>

RTEST_STRESS (rprng_kiss, get_slow, RTEST_SLOW)
{
  RPrng * prng = r_prng_new_kiss_with_seed (
      RUINT64_CONSTANT (1234567890987654321),   /* x */
      RUINT64_CONSTANT ( 362436362436362436),   /* y */
      RUINT64_CONSTANT (   1066149217761810),   /* z */
      RUINT64_CONSTANT ( 123456123456123456));  /* c */
  ruint64 i, count = 100000000, v;

  for (i = 0; i < count; i++)
    v = r_rand_prng_get (prng);

  r_assert_cmpuint (v, ==, RUINT64_CONSTANT (1666297717051644203));

  r_rand_prng_unref (prng);
}
RTEST_END;

