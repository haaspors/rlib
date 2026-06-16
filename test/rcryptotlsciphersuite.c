#include <rlib/rcrypto.h>

RTEST (rtlsciphersuite, is_supported, RTEST_FAST)
{
  /* Update when new cipher suites are added!!! */
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_PSK_WITH_NULL_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_KRB5_WITH_RC4_128_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_DH_RSA_WITH_AES_128_CBC_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_ECDH_ECDSA_WITH_NULL_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_ECDH_ECDSA_WITH_AES_128_CBC_SHA));

  /* We support these TLS cipher suites! Yay*/
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_128_CBC_SHA));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_256_CBC_SHA));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_256_CBC_SHA256));

  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA));

  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384));

  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA));

  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_NULL_MD5));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_NULL_SHA));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_NULL_SHA256));

  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_NULL_WITH_NULL_NULL));

  /* TLS 1.3 AES-GCM suites; ChaCha20-Poly1305 (0x1303) is not yet implemented. */
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_AES_128_GCM_SHA256));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_AES_256_GCM_SHA384));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_CHACHA20_POLY1305_SHA256));
}
RTEST_END;

RTEST (rtlsciphersuite, get_info, RTEST_FAST)
{
  const RTLSCipherSuiteInfo * info;

  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA)), ==, NULL);
  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256)), !=, NULL);

  r_assert_cmpint (info->suite, ==, R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_RSA);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_AES);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_CBC);
  r_assert_cmpuint (info->cipher->keybits, ==, 128);
  r_assert_cmpuint (info->cipher->ivsize, ==, 16);
  r_assert_cmpuint (info->cipher->blocksize, ==, R_AES_BLOCK_BYTES);
  r_assert_cmpint (info->mac, ==, R_MSG_DIGEST_TYPE_SHA256);

  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256)), !=, NULL);
  r_assert_cmpint (info->suite, ==, R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_RSA);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_AES);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_CBC);
  r_assert_cmpint (info->mac, ==, R_MSG_DIGEST_TYPE_SHA256);

  /* AEAD suite: GCM cipher, no record MAC, SHA-384 PRF/transcript hash. */
  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_RSA);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_AES);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);
  r_assert_cmpuint (info->cipher->keybits, ==, 256);
  r_assert_cmpuint (info->cipher->ivsize, ==, 12);
  r_assert_cmpint (info->mac, ==, R_MSG_DIGEST_TYPE_NONE);
  r_assert_cmpint (info->prf, ==, R_MSG_DIGEST_TYPE_SHA384);

  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256)), !=, NULL);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);
  r_assert_cmpint (info->prf, ==, R_MSG_DIGEST_TYPE_SHA256);

  /* ECDHE_ECDSA suite: ECDSA auth (key exchange), GCM cipher, SHA-384 PRF. */
  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);
  r_assert_cmpint (info->mac, ==, R_MSG_DIGEST_TYPE_NONE);
  r_assert_cmpint (info->prf, ==, R_MSG_DIGEST_TYPE_SHA384);

  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_CBC);
  r_assert_cmpint (info->mac, ==, R_MSG_DIGEST_TYPE_SHA256);

  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_NULL_WITH_NULL_NULL)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_NULL);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_NULL);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_STREAM);
  r_assert_cmpuint (info->cipher->keybits, ==, 0);
  r_assert_cmpuint (info->cipher->ivsize, ==, 0);
  r_assert_cmpuint (info->cipher->blocksize, ==, 1);
  r_assert_cmpint (info->mac, ==, R_MSG_DIGEST_TYPE_NONE);

  /* TLS 1.3: AEAD + hash only; key exchange not bound by the suite (NULL). */
  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_AES_128_GCM_SHA256)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_NULL);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);
  r_assert_cmpuint (info->cipher->keybits, ==, 128);
  r_assert_cmpint (info->mac, ==, R_MSG_DIGEST_TYPE_NONE);
  r_assert_cmpint (info->prf, ==, R_MSG_DIGEST_TYPE_SHA256);

  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_AES_256_GCM_SHA384)), !=, NULL);
  r_assert_cmpint (info->cipher->keybits, ==, 256);
  r_assert_cmpint (info->prf, ==, R_MSG_DIGEST_TYPE_SHA384);

  /* ChaCha20-Poly1305 has a code point but no implementation yet. */
  r_assert_cmpptr (r_tls_cipher_suite_get_info (R_TLS_CS_CHACHA20_POLY1305_SHA256), ==, NULL);
}
RTEST_END;

RTEST (rtlsciphersuite, get_info_from_str, RTEST_FAST)
{
  r_assert_cmpptr (r_tls_cipher_suite_get_info_from_str ("foo-bar"), ==, NULL);
  r_assert_cmpptr (r_tls_cipher_suite_get_info (R_TLS_CS_NULL_WITH_NULL_NULL),
      ==,
      r_tls_cipher_suite_get_info_from_str ("TLS-NULL-WITH-NULL-NULL"));
  r_assert_cmpptr (r_tls_cipher_suite_get_info (R_TLS_CS_RSA_WITH_AES_128_CBC_SHA),
      ==,
      r_tls_cipher_suite_get_info_from_str ("TLS-RSA-WITH-AES-128-CBC-SHA"));
}
RTEST_END;

RTEST (rtlsciphersuite, filter, RTEST_FAST)
{
  /* Suites coming from Chrome 52 used for DTLS-SRTP */
  const RTLSCipherSuite incoming[] = {
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    R_TLS_CS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD,
    R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD,
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_DHE_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    R_TLS_CS_DHE_RSA_WITH_AES_256_CBC_SHA,
    R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_RSA_WITH_AES_256_CBC_SHA,
    R_TLS_CS_RSA_WITH_3DES_EDE_CBC_SHA,
  };
  /* None of these are both supported by us and present in @incoming: the
   * ChaCha20 suite is unsupported; the CBC-SHA256 / NULL suites are supported
   * but Chrome did not offer them. */
  const RTLSCipherSuite nonsuites[] = {
    R_TLS_CS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, /* Not supported */
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256,
    R_TLS_CS_RSA_WITH_NULL_MD5,
    R_TLS_CS_NULL_WITH_NULL_NULL,
  };
  const RTLSCipherSuite suites[] = {
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_RSA_WITH_NULL_MD5,
    R_TLS_CS_NULL_WITH_NULL_NULL,
  };

  r_assert_cmpint (R_TLS_CS_NONE, ==,
      r_tls_cipher_suite_filter (incoming, R_N_ELEMENTS (incoming),
        nonsuites, R_N_ELEMENTS (nonsuites)));
  /* ECDHE_ECDSA-GCM is the most-preferred suite both we and Chrome support. */
  r_assert_cmpint (R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ==,
      r_tls_cipher_suite_filter (incoming, R_N_ELEMENTS (incoming),
        suites, R_N_ELEMENTS (suites)));
}
RTEST_END;

