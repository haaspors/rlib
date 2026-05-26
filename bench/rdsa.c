#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rdsa.h>
#include "util.h"

#define DSA_BENCH_L         2048
#define DSA_BENCH_N         256
#define DSA_BENCH_ITERS     200

static void
print_dsa_result (const rchar * op, ruint iters, RClockTime elapsed)
{
  rchar * label = r_strprintf ("DSA-%u/%u %s", DSA_BENCH_L, DSA_BENCH_N, op);
  bench_print_ops (label, iters, elapsed);
  r_free (label);
}

RTEST_BENCH (rdsa, sign_2048_256, RTEST_FAST | RTEST_SYSTEM)
{
  /* DSA-2048/256 signing loop. Exercises r_dsa_sign end-to-end -
   * extra-random-bits nonce sampling, the CT k*G expmod and the
   * Fermat-inverter on k. The key is generated once before the
   * timed region so the probable-prime search for p/q doesn't
   * pollute the result. */
  RCryptoKey * priv;
  RPrng * prng;
  ruint8 hash[32];
  ruint8 sig[256];
  rsize sig_size;
  RClockTime start, end;
  ruint i;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new_gen (DSA_BENCH_L, DSA_BENCH_N,
        prng)), !=, NULL);

  for (i = 0; i < sizeof (hash); i++)
    hash[i] = (ruint8)(i * 7u + 1u);

  for (i = 0; i < 5; i++) {
    sig_size = sizeof (sig);
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < DSA_BENCH_ITERS; i++) {
    sig_size = sizeof (sig);
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_dsa_result ("sign", DSA_BENCH_ITERS, end - start);

  r_crypto_key_unref (priv);
  r_prng_unref (prng);
}
RTEST_END;

RTEST_BENCH (rdsa, verify_2048_256, RTEST_FAST | RTEST_SYSTEM)
{
  /* DSA-2048/256 verify loop. Sign once outside the timed region
   * to produce a valid signature, then verify it in a loop. Verify
   * runs through the variable-time mpint primitives - no Mont
   * cache, no Fermat-invert - so this number is comparable across
   * any DSA-perf work landing on the verify side. */
  RCryptoKey * priv;
  RPrng * prng;
  ruint8 hash[32];
  ruint8 sig[256];
  rsize sig_size = sizeof (sig);
  RClockTime start, end;
  ruint i;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new_gen (DSA_BENCH_L, DSA_BENCH_N,
        prng)), !=, NULL);

  for (i = 0; i < sizeof (hash); i++)
    hash[i] = (ruint8)(i * 7u + 1u);

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);

  for (i = 0; i < 5; i++) {
    r_assert_cmpint (r_crypto_key_verify (priv, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, sig_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < DSA_BENCH_ITERS; i++) {
    r_assert_cmpint (r_crypto_key_verify (priv, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, sig_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_dsa_result ("verify", DSA_BENCH_ITERS, end - start);

  r_crypto_key_unref (priv);
  r_prng_unref (prng);
}
RTEST_END;
