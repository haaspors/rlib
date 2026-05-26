#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/recc.h>
#include <rlib/crypto/recurve.h>

#define ECDSA_BENCH_ITERS    200

/* Fixed SHA-256-shaped hash; ECDSA signs the raw hash so any 32
 * bytes work for benchmarking. */
static const ruint8 ecdsa_bench_hash[32] = {
  0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
  0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
  0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
  0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08,
};

static void
print_ecdsa_result (const rchar * curve_name, const rchar * op, ruint iters,
    RClockTime elapsed)
{
  rdouble elapsed_s = (rdouble)elapsed / (rdouble)R_SECOND;
  rdouble per_op_ms = elapsed_s * 1000.0 / (rdouble)iters;
  rdouble ops_per_sec = (rdouble)iters / elapsed_s;

  r_print ("%"R_TIME_FORMAT"  ECDSA %s %s: %.3f ms/op, %.1f ops/sec "
      "(%u iters in %.3f s)\n",
      R_TIME_ARGS (elapsed), curve_name, op,
      per_op_ms, ops_per_sec, iters, elapsed_s);
}

/* Build an ECDSA keypair on the given curve. Generates a random
 * private scalar via the ECDH key-gen path (the same scalar shape
 * is valid for both algorithms), extracts the scalar bytes and the
 * uncompressed public point, then hands both to the ECDSA
 * constructors. Caller releases both returned keys. */
static rboolean
make_ecdsa_keypair (REcurveID curve_id, RPrng * prng,
    RCryptoKey ** priv_out, RCryptoKey ** pub_out)
{
  RCryptoKey * ecdh_priv;
  REcurve curve;
  REcurveAffinePoint Q;
  ruint8 ecp_buf[1 + 2 * 66];
  rsize ecp_size = sizeof (ecp_buf);
  const ruint8 * scalar_bytes;
  rsize scalar_size;
  rboolean ok = FALSE;

  *priv_out = NULL;
  *pub_out = NULL;

  if ((ecdh_priv = r_ecdh_priv_key_new_gen (curve_id, prng)) == NULL)
    return FALSE;

  if (!r_ecurve_init (&curve, curve_id))
    goto fail_after_priv;

  r_ecurve_point_init (&Q);
  if (!r_ecc_key_get_q (ecdh_priv, &Q))
    goto fail_after_curve;
  if (!r_ecurve_point_to_uncompressed (&Q, &curve, ecp_buf, &ecp_size))
    goto fail_after_curve;
  if (!r_ecc_priv_key_get_scalar (ecdh_priv, &scalar_bytes, &scalar_size))
    goto fail_after_curve;

  *priv_out = r_ecdsa_priv_key_new (curve_id, ecp_buf, ecp_size,
      scalar_bytes, scalar_size);
  *pub_out  = r_ecdsa_pub_key_new (curve_id, ecp_buf, ecp_size);
  ok = (*priv_out != NULL && *pub_out != NULL);

fail_after_curve:
  r_ecurve_point_clear (&Q);
  r_ecurve_clear (&curve);
fail_after_priv:
  r_crypto_key_unref (ecdh_priv);
  if (!ok) {
    if (*priv_out != NULL) { r_crypto_key_unref (*priv_out); *priv_out = NULL; }
    if (*pub_out  != NULL) { r_crypto_key_unref (*pub_out);  *pub_out  = NULL; }
  }
  return ok;
}

RTEST_BENCH (recdsa, sign_secp256r1, RTEST_FAST | RTEST_SYSTEM)
{
  /* ECDSA sign on secp256r1. Exercises r_ecdsa_sign end-to-end -
   * nonce sampling, CT k*G via r_ecurve_point_scalar_mul, the
   * Fermat-inverter on k, and the s = k^-1 * (e + d*r) FE arithmetic. */
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[128];
  rsize sig_size;
  RClockTime start, end;
  ruint i;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (make_ecdsa_keypair (R_ECURVE_ID_SECP256R1, prng, &priv, &pub));

  for (i = 0; i < 5; i++) {
    sig_size = sizeof (sig);
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          ecdsa_bench_hash, sizeof (ecdsa_bench_hash), sig, &sig_size),
        ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < ECDSA_BENCH_ITERS; i++) {
    sig_size = sizeof (sig);
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          ecdsa_bench_hash, sizeof (ecdsa_bench_hash), sig, &sig_size),
        ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_ecdsa_result ("secp256r1", "sign", ECDSA_BENCH_ITERS, end - start);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
}
RTEST_END;

RTEST_BENCH (recdsa, verify_secp256r1, RTEST_FAST | RTEST_SYSTEM)
{
  /* ECDSA verify on secp256r1. Verify is variable-time on the
   * public signature; runs through two scalar-muls (u1*G and u2*Q)
   * plus a point add and a mod reduction. */
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[128];
  rsize sig_size = sizeof (sig);
  RClockTime start, end;
  ruint i;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (make_ecdsa_keypair (R_ECURVE_ID_SECP256R1, prng, &priv, &pub));

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
        ecdsa_bench_hash, sizeof (ecdsa_bench_hash), sig, &sig_size),
      ==, R_CRYPTO_OK);

  for (i = 0; i < 5; i++) {
    r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
          ecdsa_bench_hash, sizeof (ecdsa_bench_hash), sig, sig_size),
        ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < ECDSA_BENCH_ITERS; i++) {
    r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
          ecdsa_bench_hash, sizeof (ecdsa_bench_hash), sig, sig_size),
        ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_ecdsa_result ("secp256r1", "verify", ECDSA_BENCH_ITERS, end - start);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
}
RTEST_END;
