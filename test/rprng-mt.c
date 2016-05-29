#include <rlib/rlib.h>

RTEST_STRESS (rprng_mt, get_slow, RTEST_SLOW)
{
  static const ruint64 seed[] = {
    RUINT64_CONSTANT (0x12345),
    RUINT64_CONSTANT (0x23456),
    RUINT64_CONSTANT (0x34567),
    RUINT64_CONSTANT (0x45678)
  };
  RPrng * prng = r_prng_new_mt_with_seed_array (seed, R_N_ELEMENTS (seed));
  ruint64 i, count = 1000, v;

  for (i = 0; i < count; i++)
    v = r_prng_get_u64 (prng);

  r_assert_cmpuint (v, ==, RUINT64_CONSTANT (994412663058993407));

  r_prng_unref (prng);
}
RTEST_END;

