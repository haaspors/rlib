#include <rlib/rlib.h>

RTEST (rcipher, new_args, RTEST_FAST)
{
  r_assert_cmpptr (r_crypto_cipher_new (NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_crypto_cipher_new (NULL, NULL), ==, NULL);
}
RTEST_END;

RTEST (rcipher, null, RTEST_FAST)
{
  RCryptoCipher * cipher;
  ruint8 in[32];
  ruint8 out[32];

  r_memset (in, 42, sizeof (out));
  r_memclear (out, sizeof (out));
  r_assert_cmpptr ((cipher = r_crypto_cipher_null_new ()), !=, NULL);

  r_assert_cmpmem (in, !=, out, sizeof (in));

  r_assert_cmpint (r_crypto_cipher_encrypt (cipher, NULL, in, sizeof (in), out), ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (in, ==, out, sizeof (in));

  r_memclear (out, sizeof (out));
  r_assert_cmpmem (in, !=, out, sizeof (in));

  r_assert_cmpint (r_crypto_cipher_decrypt (cipher, NULL, in, sizeof (in), out), ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (in, ==, out, sizeof (in));

  r_crypto_cipher_unref (cipher);
}
RTEST_END;

/* Find more AES tests in the AES testsuite */
RTEST (rcipher, aes_ecb_simple, RTEST_FAST)
{
  RCryptoCipher * cipher;
  const ruint8 key[128 / 8] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
  const ruint8 plaintxt[R_AES_BLOCK_BYTES] = {
    0xf3, 0x44, 0x81, 0xec, 0x3c, 0xc6, 0x27, 0xba, 0xcd, 0x5d, 0xc3, 0xfb, 0x08, 0xf2, 0x73, 0xe6
  };
  const ruint8 ciphertxt[R_AES_BLOCK_BYTES] = {
    0x03, 0x36, 0x76, 0x3e, 0x96, 0x6d, 0x92, 0x59, 0x5a, 0x56, 0x7c, 0xc9, 0xce, 0x53, 0x7f, 0x5e
  };

  ruint8 iv[R_AES_BLOCK_BYTES];
  ruint8 out[R_AES_BLOCK_BYTES];

  r_memclear (iv, sizeof (iv));
  r_memclear (out, sizeof (out));
  r_assert_cmpptr ((cipher = r_cipher_aes_128_ecb_new (key)), !=, NULL);

  r_assert_cmpint (r_crypto_cipher_encrypt (cipher, NULL,
        plaintxt, sizeof (plaintxt), out), ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (ciphertxt, ==, out, sizeof (out));

  r_assert_cmpint (r_crypto_cipher_decrypt (cipher, NULL,
        ciphertxt, sizeof (ciphertxt), out), ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (plaintxt, ==, out, sizeof (out));

  r_crypto_cipher_unref (cipher);
}
RTEST_END;

RTEST (rcipher, aes_cbc_simple, RTEST_FAST)
{
  RCryptoCipher * cipher;
  const ruint8 key[128 / 8] = {
    0x1f, 0x8e, 0x49, 0x73, 0x95, 0x3f, 0x3f, 0xb0, 0xbd, 0x6b, 0x16, 0x66, 0x2e, 0x9a, 0x3c, 0x17
  };
  const ruint8 ivstart[R_AES_BLOCK_BYTES] = {
    0x2f, 0xe2, 0xb3, 0x33, 0xce, 0xda, 0x8f, 0x98, 0xf4, 0xa9, 0x9b, 0x40, 0xd2, 0xcd, 0x34, 0xa8
  };
  const ruint8 plaintxt[R_AES_BLOCK_BYTES] = {
    0x45, 0xcf, 0x12, 0x96, 0x4f, 0xc8, 0x24, 0xab, 0x76, 0x61, 0x6a, 0xe2, 0xf4, 0xbf, 0x08, 0x22
  };
  const ruint8 ciphertxt[R_AES_BLOCK_BYTES] = {
    0x0f, 0x61, 0xc4, 0xd4, 0x4c, 0x51, 0x47, 0xc0, 0x3c, 0x19, 0x5a, 0xd7, 0xe2, 0xcc, 0x12, 0xb2
  };

  ruint8 iv[R_AES_BLOCK_BYTES];
  ruint8 out[R_AES_BLOCK_BYTES];

  r_memcpy (iv, ivstart, sizeof (iv));
  r_memclear (out, sizeof (out));
  r_assert_cmpptr ((cipher = r_cipher_aes_128_cbc_new (key)), !=, NULL);

  r_assert_cmpint (r_crypto_cipher_encrypt (cipher, iv,
        plaintxt, sizeof (plaintxt), out), ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (ciphertxt, ==, out, sizeof (out));

  r_memcpy (iv, ivstart, sizeof (iv));
  r_assert_cmpint (r_crypto_cipher_decrypt (cipher, iv,
        ciphertxt, sizeof (ciphertxt), out), ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (plaintxt, ==, out, sizeof (out));

  r_crypto_cipher_unref (cipher);
}
RTEST_END;

