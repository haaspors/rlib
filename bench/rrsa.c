#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rrsa.h>

/* Per-bench iter counts. Private-side (decrypt / sign) is the
 * cubic-in-bits cost driver, so iters are tuned per key size to
 * keep wall-clock per bench in the ~1s range; verify uses a much
 * larger count because public-key modexp with e=65537 is ~100x
 * faster, and matching the private-side wall-clock budget keeps
 * comparable measurement noise across all five benches. */
#define RSA_BENCH_ITERS_2048    200
#define RSA_BENCH_ITERS_3072    100
#define RSA_BENCH_ITERS_4096     50
#define RSA_BENCH_ITERS_VERIFY 2000

/* Print a single throughput line matching the revudp bench's layout
 * convention - elapsed timestamp + descriptive label + the numbers
 * worth reading at a glance. */
static void
print_rsa_result (const rchar * op, ruint bits, ruint iters,
    RClockTime elapsed)
{
  rdouble elapsed_s = (rdouble)elapsed / (rdouble)R_SECOND;
  rdouble per_op_ms = elapsed_s * 1000.0 / (rdouble)iters;
  rdouble ops_per_sec = (rdouble)iters / elapsed_s;

  r_print ("%"R_TIME_FORMAT"  RSA-%u %s: %.3f ms/op, %.1f ops/sec "
      "(%u iters in %.3f s)\n",
      R_TIME_ARGS (elapsed), bits, op, per_op_ms, ops_per_sec,
      iters, elapsed_s);
}

/* PKCS#1v1.5 decrypt loop for the given key size. Exercises
 * r_rsa_modexp_private end-to-end (CRT halves + post-processing). The
 * key is generated once outside the timed region so its variable-time
 * prime search doesn't pollute the result. */
static void
run_rsa_decrypt_bench (ruint bits, ruint iters)
{
  RCryptoKey * priv;
  RPrng * prng;
  ruint8 plaintext[32];
  ruint8 * ciphertext;
  ruint8 * decrypted;
  rsize ct_size, pt_size;
  rsize buf_size = bits / 8;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((ciphertext = r_malloc (buf_size)), !=, NULL);
  r_assert_cmpptr ((decrypted = r_malloc (buf_size)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_rsa_priv_key_new_gen (bits, 65537, prng)),
      !=, NULL);
  r_assert (r_rsa_priv_key_set_padding (priv, R_RSA_PADDING_PKCS1_V15));

  for (i = 0; i < sizeof (plaintext); i++)
    plaintext[i] = (ruint8)i;
  ct_size = buf_size;
  r_assert_cmpint (r_crypto_key_encrypt (priv, prng, plaintext,
        sizeof (plaintext), ciphertext, &ct_size), ==, R_CRYPTO_OK);

  /* Brief warm-up so cold caches don't bias the first iterations. */
  for (i = 0; i < 5; i++) {
    pt_size = buf_size;
    r_assert_cmpint (r_crypto_key_decrypt (priv, prng, ciphertext, ct_size,
          decrypted, &pt_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++) {
    pt_size = buf_size;
    r_assert_cmpint (r_crypto_key_decrypt (priv, prng, ciphertext, ct_size,
          decrypted, &pt_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_rsa_result ("decrypt", bits, iters, end - start);

  r_crypto_key_unref (priv);
  r_prng_unref (prng);
  r_free (ciphertext);
  r_free (decrypted);
}

/* PKCS#1v1.5 sign loop for the given key size. Same underlying
 * private-key modexp as decrypt; exercised through the signing API
 * surface (DigestInfo wrap + r_crypto_key_sign). */
static void
run_rsa_sign_bench (ruint bits, ruint iters)
{
  RCryptoKey * priv;
  RPrng * prng;
  ruint8 hash[32];
  ruint8 * sig;
  rsize sig_size;
  rsize buf_size = bits / 8;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((sig = r_malloc (buf_size)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_rsa_priv_key_new_gen (bits, 65537, prng)),
      !=, NULL);
  r_assert (r_rsa_priv_key_set_padding (priv, R_RSA_PADDING_PKCS1_V15));

  for (i = 0; i < sizeof (hash); i++)
    hash[i] = (ruint8)(i * 7u + 1u);

  for (i = 0; i < 5; i++) {
    sig_size = buf_size;
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++) {
    sig_size = buf_size;
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_rsa_result ("sign", bits, iters, end - start);

  r_crypto_key_unref (priv);
  r_prng_unref (prng);
  r_free (sig);
}

/* PKCS#1v1.5 verify loop. Signs once outside the timed region to
 * produce a valid signature, then verifies that signature in a
 * loop. Each iteration runs r_crypto_key_verify which exercises
 * the public-key modexp (e=65537, ~17 squarings + 1 multiplication)
 * plus DigestInfo unwrap. The verify call is dispatched on a
 * dedicated pub-only key extracted from priv via (n, e); this
 * mirrors what callers do when they receive a peer's public key
 * over the wire. */
static void
run_rsa_verify_bench (ruint bits, ruint iters)
{
  RCryptoKey * priv;
  RCryptoKey * pub;
  RPrng * prng;
  rmpint n, e;
  ruint8 hash[32];
  ruint8 * sig;
  rsize sig_size;
  rsize buf_size = bits / 8;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((sig = r_malloc (buf_size)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_rsa_priv_key_new_gen (bits, 65537, prng)),
      !=, NULL);
  r_assert (r_rsa_priv_key_set_padding (priv, R_RSA_PADDING_PKCS1_V15));

  r_mpint_init (&n);
  r_mpint_init (&e);
  r_assert (r_rsa_pub_key_get_n (priv, &n));
  r_assert (r_rsa_pub_key_get_e (priv, &e));
  r_assert_cmpptr ((pub = r_rsa_pub_key_new (&n, &e)), !=, NULL);
  r_assert (r_rsa_pub_key_set_padding (pub, R_RSA_PADDING_PKCS1_V15));
  r_mpint_clear (&n);
  r_mpint_clear (&e);

  for (i = 0; i < sizeof (hash); i++)
    hash[i] = (ruint8)(i * 7u + 1u);

  sig_size = buf_size;
  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);

  for (i = 0; i < 5; i++) {
    r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, sig_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++) {
    r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, sig_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_rsa_result ("verify", bits, iters, end - start);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
  r_free (sig);
}

RTEST_BENCH (rrsa, decrypt_2048, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_rsa_decrypt_bench (2048, RSA_BENCH_ITERS_2048);
}
RTEST_END;

RTEST_BENCH (rrsa, decrypt_3072, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_rsa_decrypt_bench (3072, RSA_BENCH_ITERS_3072);
}
RTEST_END;

RTEST_BENCH (rrsa, decrypt_4096, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_rsa_decrypt_bench (4096, RSA_BENCH_ITERS_4096);
}
RTEST_END;

RTEST_BENCH (rrsa, sign_2048, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_rsa_sign_bench (2048, RSA_BENCH_ITERS_2048);
}
RTEST_END;

RTEST_BENCH (rrsa, verify_2048, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_rsa_verify_bench (2048, RSA_BENCH_ITERS_VERIFY);
}
RTEST_END;
