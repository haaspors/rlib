#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/red448.h>
#include "util.h"

#define ED448_BENCH_ITERS_SIGN    100
#define ED448_BENCH_ITERS_VERIFY   50

static void
run_ed448_sign_bench (ruint iters)
{
  RCryptoKey * priv;
  ruint8 msg[64];
  ruint8 sig[114];
  rsize sigsize;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((priv = r_ed448_priv_key_new_gen (NULL)), !=, NULL);
  for (i = 0; i < sizeof (msg); i++) msg[i] = (ruint8)i;

  for (i = 0; i < 5; i++) {
    sigsize = sizeof (sig);
    r_assert_cmpint (r_ed448_sign (priv, msg, sizeof (msg),
          sig, &sigsize), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++) {
    sigsize = sizeof (sig);
    r_assert_cmpint (r_ed448_sign (priv, msg, sizeof (msg),
          sig, &sigsize), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  bench_print_ops ("Ed448 sign", iters, end - start);

  r_crypto_key_unref (priv);
}

static void
run_ed448_verify_bench (ruint iters)
{
  RCryptoKey * priv;
  RCryptoKey * pub;
  const ruint8 * pub_bytes;
  rsize pub_size;
  ruint8 msg[64];
  ruint8 sig[114];
  rsize sigsize = sizeof (sig);
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((priv = r_ed448_priv_key_new_gen (NULL)), !=, NULL);
  r_assert (r_ed448_key_get_pub (priv, &pub_bytes, &pub_size));
  r_assert_cmpptr ((pub = r_ed448_pub_key_new (pub_bytes, pub_size)),
      !=, NULL);

  for (i = 0; i < sizeof (msg); i++) msg[i] = (ruint8)i;
  r_assert_cmpint (r_ed448_sign (priv, msg, sizeof (msg),
        sig, &sigsize), ==, R_CRYPTO_OK);

  for (i = 0; i < 5; i++)
    r_assert_cmpint (r_ed448_verify (pub, msg, sizeof (msg),
          sig, sigsize), ==, R_CRYPTO_OK);

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++)
    r_assert_cmpint (r_ed448_verify (pub, msg, sizeof (msg),
          sig, sigsize), ==, R_CRYPTO_OK);
  end = r_time_get_ts_monotonic ();

  bench_print_ops ("Ed448 verify", iters, end - start);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
}

RTEST_BENCH (red448, sign, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_ed448_sign_bench (ED448_BENCH_ITERS_SIGN);
}
RTEST_END;

RTEST_BENCH (red448, verify, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_ed448_verify_bench (ED448_BENCH_ITERS_VERIFY);
}
RTEST_END;
