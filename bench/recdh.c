#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/recc.h>
#include <rlib/crypto/recurve.h>

#define ECDH_BENCH_ITERS    200

static void
print_ecdh_result (const rchar * curve_name, ruint iters,
    RClockTime elapsed)
{
  rdouble elapsed_s = (rdouble)elapsed / (rdouble)R_SECOND;
  rdouble per_op_ms = elapsed_s * 1000.0 / (rdouble)iters;
  rdouble ops_per_sec = (rdouble)iters / elapsed_s;

  r_print ("%"R_TIME_FORMAT"  ECDH %s compute_shared: %.3f ms/op, "
      "%.1f ops/sec (%u iters in %.3f s)\n",
      R_TIME_ARGS (elapsed), curve_name, per_op_ms, ops_per_sec,
      iters, elapsed_s);
}

/* One bench body that takes the curve as a parameter so the two
 * variants only differ in the @c REcurveID they pass in. Each
 * iteration runs the priv-side compute_shared; the peer keypair is
 * generated once outside the timed region. */
static void
run_ecdh_bench (REcurveID curve_id, const rchar * curve_name)
{
  RCryptoKey * priv;
  RCryptoKey * peer_priv;
  RCryptoKey * peer_pub;
  REcurveAffinePoint peer_Q;
  REcurve curve;
  RPrng * prng;
  ruint8 peer_ecp[1 + 2 * 66];   /* coord_bytes <= 66 for secp521r1 */
  ruint8 shared[128];
  rsize peer_ecp_size;
  rsize shared_size;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_ecdh_priv_key_new_gen (curve_id, prng)),
      !=, NULL);
  r_assert_cmpptr ((peer_priv = r_ecdh_priv_key_new_gen (curve_id, prng)),
      !=, NULL);

  r_ecurve_point_init (&peer_Q);
  r_assert (r_ecc_key_get_q (peer_priv, &peer_Q));
  r_assert (r_ecurve_init (&curve, curve_id));
  peer_ecp_size = sizeof (peer_ecp);
  r_assert (r_ecurve_point_to_uncompressed (&peer_Q, &curve,
        peer_ecp, &peer_ecp_size));
  r_assert_cmpptr ((peer_pub = r_ecdh_pub_key_new (curve_id, peer_ecp,
        peer_ecp_size)), !=, NULL);

  for (i = 0; i < 5; i++) {
    shared_size = sizeof (shared);
    r_assert_cmpint (r_ecdh_compute_shared (priv, peer_pub,
          shared, &shared_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < ECDH_BENCH_ITERS; i++) {
    shared_size = sizeof (shared);
    r_assert_cmpint (r_ecdh_compute_shared (priv, peer_pub,
          shared, &shared_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_ecdh_result (curve_name, ECDH_BENCH_ITERS, end - start);

  r_ecurve_point_clear (&peer_Q);
  r_ecurve_clear (&curve);
  r_crypto_key_unref (priv);
  r_crypto_key_unref (peer_priv);
  r_crypto_key_unref (peer_pub);
  r_prng_unref (prng);
}

RTEST_BENCH (recdh, compute_shared_secp256r1, RTEST_FAST | RTEST_SYSTEM)
{
  /* ECDH on secp256r1 - the most-used curve in the wild. Exercises
   * the CT scalar-mul ladder (r_ecurve_point_scalar_mul) end-to-end
   * with the secret peer-derivation. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_ecdh_bench (R_ECURVE_ID_SECP256R1, "secp256r1");
}
RTEST_END;

RTEST_BENCH (recdh, compute_shared_secp384r1, RTEST_FAST | RTEST_SYSTEM)
{
  /* ECDH on secp384r1. Same path as secp256r1, wider digit count -
   * gives a feel for how the CT scalar-mul scales with curve width
   * without jumping all the way to secp521r1. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_ecdh_bench (R_ECURVE_ID_SECP384R1, "secp384r1");
}
RTEST_END;
