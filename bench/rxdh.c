#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/rxdh.h>
#include "util.h"

#define XDH_BENCH_ITERS_25519   500
#define XDH_BENCH_ITERS_448     200

static void
run_xdh_bench (REcurveID curve_id, const rchar * curve_name, ruint iters)
{
  RCryptoKey * priv;
  RCryptoKey * peer_priv;
  RCryptoKey * peer_pub;
  const ruint8 * peer_u;
  rsize peer_u_size;
  RPrng * prng;
  ruint8 shared[56];
  rsize shared_size;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_xdh_priv_key_new_gen (curve_id, prng)),
      !=, NULL);
  r_assert_cmpptr ((peer_priv = r_xdh_priv_key_new_gen (curve_id, prng)),
      !=, NULL);
  r_assert (r_xdh_key_get_pub_u (peer_priv, &peer_u, &peer_u_size));
  r_assert_cmpptr ((peer_pub = r_xdh_pub_key_new (curve_id,
        peer_u, peer_u_size)), !=, NULL);

  for (i = 0; i < 5; i++) {
    shared_size = sizeof (shared);
    r_assert_cmpint (r_xdh_compute_shared (priv, peer_pub,
          shared, &shared_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++) {
    shared_size = sizeof (shared);
    r_assert_cmpint (r_xdh_compute_shared (priv, peer_pub,
          shared, &shared_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  {
    rchar * label = r_strprintf ("XDH %s compute_shared", curve_name);
    bench_print_ops (label, iters, end - start);
    r_free (label);
  }

  r_crypto_key_unref (priv);
  r_crypto_key_unref (peer_priv);
  r_crypto_key_unref (peer_pub);
  r_prng_unref (prng);
}

RTEST_BENCH (rxdh, compute_shared_x25519, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_xdh_bench (R_ECURVE_ID_X25519, "X25519", XDH_BENCH_ITERS_25519);
}
RTEST_END;

RTEST_BENCH (rxdh, compute_shared_x448, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_xdh_bench (R_ECURVE_ID_X448, "X448", XDH_BENCH_ITERS_448);
}
RTEST_END;
