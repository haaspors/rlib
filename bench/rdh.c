#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rdh.h>
#include "util.h"

static void
print_dh_result (const rchar * op, const rchar * group_name, ruint iters,
    RClockTime elapsed)
{
  rchar * label = r_strprintf ("DH %s %s", group_name, op);
  bench_print_ops (label, iters, elapsed);
  r_free (label);
}

/* compute_shared bench: one bench body parameterised by group, so the
 * variants only differ in the @c RDhNamedGroup they pass in. Each
 * iteration runs the priv-side compute_shared; the peer keypair is
 * generated once outside the timed region. */
static void
run_dh_bench (RDhNamedGroup group, const rchar * group_name, ruint iters)
{
  RCryptoKey * priv;
  RCryptoKey * peer_priv;
  RCryptoKey * peer_pub;
  RPrng * prng;
  rmpint p, g, peer_y;
  ruint8 shared[1024];   /* fits the widest group (ffdhe8192 = 1024 bytes) */
  rsize shared_size;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (r_dh_named_group_get_params (group, &p, &g));

  r_assert_cmpptr ((priv = r_dh_priv_key_new_gen_named (group, prng)),
      !=, NULL);
  r_assert_cmpptr ((peer_priv = r_dh_priv_key_new_gen_named (group, prng)),
      !=, NULL);

  /* Build a public-only view of the peer key for r_dh_compute_shared. */
  r_mpint_init (&peer_y);
  r_assert (r_dh_pub_key_get_y (peer_priv, &peer_y));
  r_assert_cmpptr ((peer_pub = r_dh_pub_key_new (&p, &g, &peer_y)),
      !=, NULL);

  for (i = 0; i < 5; i++) {
    shared_size = sizeof (shared);
    r_assert_cmpint (r_dh_compute_shared (priv, peer_pub,
          shared, &shared_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++) {
    shared_size = sizeof (shared);
    r_assert_cmpint (r_dh_compute_shared (priv, peer_pub,
          shared, &shared_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_dh_result ("compute_shared", group_name, iters, end - start);

  r_mpint_clear (&peer_y);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
  r_crypto_key_unref (priv);
  r_crypto_key_unref (peer_priv);
  r_crypto_key_unref (peer_pub);
  r_prng_unref (prng);
}

/* keygen bench: times a full private-key generation (one g^x mod p with
 * the group's private exponent). This is where the short-exponent sizing
 * for the named safe-prime groups shows up most directly. */
static void
run_dh_keygen_bench (RDhNamedGroup group, const rchar * group_name, ruint iters)
{
  RPrng * prng;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  for (i = 0; i < 3; i++)
    r_crypto_key_unref (r_dh_priv_key_new_gen_named (group, prng));

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++) {
    RCryptoKey * priv = r_dh_priv_key_new_gen_named (group, prng);
    r_assert_cmpptr (priv, !=, NULL);
    r_crypto_key_unref (priv);
  }
  end = r_time_get_ts_monotonic ();

  print_dh_result ("keygen", group_name, iters, end - start);

  r_prng_unref (prng);
}

RTEST_BENCH (rdh, compute_shared_modp_2048, RTEST_SLOW)
{
  /* MODP-2048 (RFC 3526 group 14) - the workhorse for IKE / SSH /
   * legacy TLS. Exercises the windowed-CT expmod the RSA private
   * path also uses, here on the public modulus side. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_dh_bench (R_DH_GROUP_MODP_2048, "MODP-2048", 200);
}
RTEST_END;

RTEST_BENCH (rdh, compute_shared_ffdhe_2048, RTEST_SLOW)
{
  /* FFDHE-2048 (RFC 7919) - the TLS-targeted analogue of MODP-2048.
   * Same expmod engine, different group parameters - the perf
   * delta against MODP-2048 surfaces any group-dependent
   * Montgomery setup overhead. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_dh_bench (R_DH_GROUP_FFDHE_2048, "FFDHE-2048", 200);
}
RTEST_END;

RTEST_BENCH (rdh, compute_shared_ffdhe_8192, RTEST_SLOW)
{
  /* FFDHE-8192 (RFC 7919) - the largest finite-field group. Its
   * modexp is ~64x an ffdhe2048 one, so the short private exponent
   * (2*strength bits vs the full modulus width) dominates the cost. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_dh_bench (R_DH_GROUP_FFDHE_8192, "FFDHE-8192", 20);
}
RTEST_END;

RTEST_BENCH (rdh, keygen_ffdhe_2048, RTEST_SLOW)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_dh_keygen_bench (R_DH_GROUP_FFDHE_2048, "FFDHE-2048", 200);
}
RTEST_END;

RTEST_BENCH (rdh, keygen_ffdhe_8192, RTEST_SLOW)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_dh_keygen_bench (R_DH_GROUP_FFDHE_8192, "FFDHE-8192", 20);
}
RTEST_END;
