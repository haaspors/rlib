#include <rlib/rlib.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rrsa.h>

#define RSA_BENCH_BITS    2048
#define RSA_BENCH_ITERS   200

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

RTEST_BENCH (rrsa, decrypt_2048, RTEST_FAST | RTEST_SYSTEM)
{
  /* RSA-2048 PKCS#1v1.5 decrypt loop. Exercises r_rsa_modexp_private
   * end-to-end including the CRT halves and the post-processing. The
   * key is generated once before the timed region so its variable-
   * time prime search doesn't pollute the result. */
  RCryptoKey * priv;
  RPrng * prng;
  ruint8 plaintext[32];
  ruint8 ciphertext[RSA_BENCH_BITS / 8];
  ruint8 decrypted[RSA_BENCH_BITS / 8];
  rsize ct_size, pt_size;
  RClockTime start, end;
  ruint i;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_rsa_priv_key_new_gen (RSA_BENCH_BITS, 65537, prng)),
      !=, NULL);
  r_assert (r_rsa_priv_key_set_padding (priv, R_RSA_PADDING_PKCS1_V15));

  for (i = 0; i < sizeof (plaintext); i++)
    plaintext[i] = (ruint8)i;
  ct_size = sizeof (ciphertext);
  r_assert_cmpint (r_crypto_key_encrypt (priv, prng, plaintext,
        sizeof (plaintext), ciphertext, &ct_size), ==, R_CRYPTO_OK);

  /* Brief warm-up so cold caches don't bias the first iterations. */
  for (i = 0; i < 5; i++) {
    pt_size = sizeof (decrypted);
    r_assert_cmpint (r_crypto_key_decrypt (priv, prng, ciphertext, ct_size,
          decrypted, &pt_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < RSA_BENCH_ITERS; i++) {
    pt_size = sizeof (decrypted);
    r_assert_cmpint (r_crypto_key_decrypt (priv, prng, ciphertext, ct_size,
          decrypted, &pt_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_rsa_result ("decrypt", RSA_BENCH_BITS, RSA_BENCH_ITERS, end - start);

  r_crypto_key_unref (priv);
  r_prng_unref (prng);
}
RTEST_END;

RTEST_BENCH (rrsa, sign_2048, RTEST_FAST | RTEST_SYSTEM)
{
  /* RSA-2048 PKCS#1v1.5 signature loop. Same underlying private-key
   * modexp as the decrypt bench, but exercised through the signing
   * API surface (DigestInfo wrap + r_crypto_key_sign). The two share
   * one private-op cost driver; comparing them surfaces any padding-
   * path overhead that differs between encrypt-direction and sign-
   * direction PKCS#1v1.5. */
  RCryptoKey * priv;
  RPrng * prng;
  ruint8 hash[32];  /* SHA-256 digest size */
  ruint8 sig[RSA_BENCH_BITS / 8];
  rsize sig_size;
  RClockTime start, end;
  ruint i;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpptr ((priv = r_rsa_priv_key_new_gen (RSA_BENCH_BITS, 65537, prng)),
      !=, NULL);
  r_assert (r_rsa_priv_key_set_padding (priv, R_RSA_PADDING_PKCS1_V15));

  for (i = 0; i < sizeof (hash); i++)
    hash[i] = (ruint8)(i * 7u + 1u);

  for (i = 0; i < 5; i++) {
    sig_size = sizeof (sig);
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < RSA_BENCH_ITERS; i++) {
    sig_size = sizeof (sig);
    r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
          hash, sizeof (hash), sig, &sig_size), ==, R_CRYPTO_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_rsa_result ("sign", RSA_BENCH_BITS, RSA_BENCH_ITERS, end - start);

  r_crypto_key_unref (priv);
  r_prng_unref (prng);
}
RTEST_END;
