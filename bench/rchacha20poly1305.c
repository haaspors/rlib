#include <rlib/rlib.h>
#include <rlib/crypto/rchacha20poly1305.h>
#include <rlib/crypto/rcipher.h>
#include "util.h"

/* 16 KiB per encrypt call, matching the AES AEAD benchmark so the
 * ChaCha20-Poly1305 headline is directly comparable to AES-GCM. */
#define CC20P1305_BENCH_BLOCKSIZE  (16 * 1024)
#define CC20P1305_BENCH_ITERS      2000

static const ruint8 cc20p1305_bench_key[R_CHACHA20POLY1305_KEY_SIZE] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/* AEAD encrypt + tag throughput with empty AAD, mirroring
 * run_aes_aead_bench so the numbers line up call-for-call. */
static void
run_cc20p1305_bench (RCryptoCipher * cipher)
{
  ruint8 * input;
  ruint8 * output;
  ruint8 iv[R_CHACHA20POLY1305_NONCE_SIZE];
  ruint8 tag[R_CHACHA20POLY1305_TAG_SIZE];
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((input = r_malloc (CC20P1305_BENCH_BLOCKSIZE)), !=, NULL);
  r_assert_cmpptr ((output = r_malloc (CC20P1305_BENCH_BLOCKSIZE)), !=, NULL);
  for (i = 0; i < CC20P1305_BENCH_BLOCKSIZE; i++)
    input[i] = (ruint8)i;

  for (i = 0; i < 5; i++) {
    r_memset (iv, 0, sizeof (iv));
    iv[0] = (ruint8)i;
    r_assert_cmpint (r_crypto_cipher_encrypt_aead (cipher, output,
          CC20P1305_BENCH_BLOCKSIZE, input, NULL, 0, iv, sizeof (iv),
          tag, sizeof (tag)), ==, R_CRYPTO_CIPHER_OK);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < CC20P1305_BENCH_ITERS; i++) {
    r_memset (iv, 0, sizeof (iv));
    iv[0] = (ruint8)(i & 0xff);
    iv[1] = (ruint8)((i >> 8) & 0xff);
    r_assert_cmpint (r_crypto_cipher_encrypt_aead (cipher, output,
          CC20P1305_BENCH_BLOCKSIZE, input, NULL, 0, iv, sizeof (iv),
          tag, sizeof (tag)), ==, R_CRYPTO_CIPHER_OK);
  }
  end = r_time_get_ts_monotonic ();

  bench_print_throughput ("ChaCha20-Poly1305", CC20P1305_BENCH_ITERS,
      CC20P1305_BENCH_BLOCKSIZE, end - start);

  r_free (input);
  r_free (output);
}

RTEST_BENCH (rchacha20poly1305, encrypt, RTEST_FAST)
{
  RCryptoCipher * c;
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  r_assert_cmpptr ((c = r_cipher_chacha20_poly1305_new (cc20p1305_bench_key)), !=, NULL);
  run_cc20p1305_bench (c);
  r_crypto_cipher_unref (c);
}
RTEST_END;
