#include <rlib/rlib.h>

RTEST (rtlsciphersuite, is_supported, RTEST_FAST)
{
  /* Update when new cipher suites are added!!! */
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_PSK_WITH_NULL_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_KRB5_WITH_RC4_128_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_DH_RSA_WITH_AES_128_CBC_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_ECDH_ECDSA_WITH_NULL_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_ECDH_ECDSA_WITH_AES_128_CBC_SHA));

  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_256_CBC_SHA));
  r_assert (!r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_256_CBC_SHA256));

  /* We support these TLS cipher suites! Yay*/
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_128_CBC_SHA));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256));

  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_NULL_MD5));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_NULL_SHA));
  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_RSA_WITH_NULL_SHA256));

  r_assert (r_tls_cipher_suite_is_supported (R_TLS_CS_NULL_WITH_NULL_NULL));
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
  r_assert_cmpint (info->mac, ==, R_HASH_TYPE_SHA256);

  r_assert_cmpptr ((info = r_tls_cipher_suite_get_info (R_TLS_CS_NULL_WITH_NULL_NULL)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_NULL);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_NULL);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_STREAM);
  r_assert_cmpuint (info->cipher->keybits, ==, 0);
  r_assert_cmpuint (info->cipher->ivsize, ==, 0);
  r_assert_cmpuint (info->cipher->blocksize, ==, 1);
  r_assert_cmpint (info->mac, ==, R_HASH_TYPE_NONE);
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
  const RTLSCipherSuite nonsuites[] = {
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, /* Not supported */
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, /* Not supported */
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256,
    R_TLS_CS_RSA_WITH_NULL_MD5,
    R_TLS_CS_NULL_WITH_NULL_NULL,
  };
  const RTLSCipherSuite suites[] = {
    R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, /* Not supported */
    R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, /* Not supported */
    R_TLS_CS_RSA_WITH_AES_128_CBC_SHA,
    R_TLS_CS_RSA_WITH_NULL_MD5,
    R_TLS_CS_NULL_WITH_NULL_NULL,
  };

  r_assert_cmpint (R_TLS_CS_NONE, ==,
      r_tls_cipher_suite_filter (incoming, R_N_ELEMENTS (incoming),
        nonsuites, R_N_ELEMENTS (nonsuites)));
  r_assert_cmpint (R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, ==,
      r_tls_cipher_suite_filter (incoming, R_N_ELEMENTS (incoming),
        suites, R_N_ELEMENTS (suites)));
}
RTEST_END;

