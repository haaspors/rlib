#include <rlib/rlib.h>
#include <rlib/crypto/raes.h>
#include <rlib/crypto/rcipher.h>

/* 16 KiB per encrypt call - large enough to amortise the per-call
 * overhead, small enough to fit comfortably in stack / L1 cache. */
#define AES_BENCH_BLOCKSIZE  (16 * 1024)
#define AES_BENCH_ITERS      2000

static void
print_aes_result (const rchar * label, ruint iters, rsize block_bytes,
    RClockTime elapsed)
{
  rdouble elapsed_s = (rdouble)elapsed / (rdouble)R_SECOND;
  rdouble total_mib = (rdouble)(iters * block_bytes) / (1024.0 * 1024.0);
  rdouble mib_per_s = total_mib / elapsed_s;

  r_print ("%"R_TIME_FORMAT"  AES-%s: %.1f MiB/s "
      "(%u x %"RSIZE_FMT"-byte blocks in %.3f s)\n",
      R_TIME_ARGS (elapsed), label, mib_per_s,
      iters, block_bytes, elapsed_s);
}

/* AES_BENCH_BLOCKSIZE encrypts in a tight loop. The cipher is built
 * once outside the timed region; the IV is per-call (each block is
 * an independent encrypt, as the caller-facing API expects). */
static void
run_aes_bench (RCryptoCipher * cipher, const rchar * label)
{
  ruint8 * input;
  ruint8 * output;
  ruint8 iv[16];
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((input = r_malloc (AES_BENCH_BLOCKSIZE)), !=, NULL);
  r_assert_cmpptr ((output = r_malloc (AES_BENCH_BLOCKSIZE)), !=, NULL);
  for (i = 0; i < AES_BENCH_BLOCKSIZE; i++)
    input[i] = (ruint8)i;

  /* Warm up */
  for (i = 0; i < 5; i++) {
    r_memset (iv, 0, sizeof (iv));
    iv[0] = (ruint8)i;
    r_assert_cmpint (r_crypto_cipher_encrypt (cipher, output,
          AES_BENCH_BLOCKSIZE, input, iv, sizeof (iv)),
        ==, R_CRYPTO_CIPHER_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < AES_BENCH_ITERS; i++) {
    r_memset (iv, 0, sizeof (iv));
    iv[0] = (ruint8)(i & 0xff);
    iv[1] = (ruint8)((i >> 8) & 0xff);
    r_assert_cmpint (r_crypto_cipher_encrypt (cipher, output,
          AES_BENCH_BLOCKSIZE, input, iv, sizeof (iv)),
        ==, R_CRYPTO_CIPHER_OK);
  }
  end = r_time_get_ts_monotonic ();

  print_aes_result (label, AES_BENCH_ITERS, AES_BENCH_BLOCKSIZE, end - start);

  r_free (input);
  r_free (output);
}

/* Fixed-content key buffers; AES doesn't care about key entropy for
 * benchmarking purposes (the schedule is the same shape either way).
 * The 256-bit key uses the upper half of the 32-byte buffer. */
static const ruint8 aes_bench_key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

RTEST_BENCH (raes, cbc_128_encrypt, RTEST_FAST | RTEST_SYSTEM)
{
  RCryptoCipher * c;
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  r_assert_cmpptr ((c = r_cipher_aes_128_cbc_new (aes_bench_key)), !=, NULL);
  run_aes_bench (c, "128 CBC");
  r_crypto_cipher_unref (c);
}
RTEST_END;

RTEST_BENCH (raes, cbc_256_encrypt, RTEST_FAST | RTEST_SYSTEM)
{
  RCryptoCipher * c;
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  r_assert_cmpptr ((c = r_cipher_aes_256_cbc_new (aes_bench_key)), !=, NULL);
  run_aes_bench (c, "256 CBC");
  r_crypto_cipher_unref (c);
}
RTEST_END;

RTEST_BENCH (raes, ctr_128_encrypt, RTEST_FAST | RTEST_SYSTEM)
{
  RCryptoCipher * c;
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  r_assert_cmpptr ((c = r_cipher_aes_128_ctr_new (aes_bench_key)), !=, NULL);
  run_aes_bench (c, "128 CTR");
  r_crypto_cipher_unref (c);
}
RTEST_END;

RTEST_BENCH (raes, ctr_256_encrypt, RTEST_FAST | RTEST_SYSTEM)
{
  RCryptoCipher * c;
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  r_assert_cmpptr ((c = r_cipher_aes_256_ctr_new (aes_bench_key)), !=, NULL);
  run_aes_bench (c, "256 CTR");
  r_crypto_cipher_unref (c);
}
RTEST_END;
