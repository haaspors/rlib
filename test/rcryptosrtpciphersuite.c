#include <rlib/rlib.h>

RTEST (rsrtpciphersuite, is_supported, RTEST_FAST)
{
  /* Update when new cipher suites are added!!! */
  r_assert (!r_srtp_cipher_suite_is_supported (R_SRTP_CS_F8_128_HMAC_SHA1_80));

  r_assert (!r_srtp_cipher_suite_is_supported (R_SRTP_CS_AEAD_AES_128_GCM));
  r_assert (!r_srtp_cipher_suite_is_supported (R_SRTP_CS_AEAD_AES_256_GCM));

  /* We support these srtp cipher suites! Yay*/
  r_assert (r_srtp_cipher_suite_is_supported (R_SRTP_CS_AES_128_CM_HMAC_SHA1_80));
  r_assert (r_srtp_cipher_suite_is_supported (R_SRTP_CS_AES_128_CM_HMAC_SHA1_32));

  r_assert (r_srtp_cipher_suite_is_supported (R_SRTP_CS_NULL_HMAC_SHA1_80));
  r_assert (r_srtp_cipher_suite_is_supported (R_SRTP_CS_NULL_HMAC_SHA1_32));

  r_assert (r_srtp_cipher_suite_is_supported (R_SRTP_CS_NULL_NULL));
}
RTEST_END;

RTEST (rsrtpciphersuite, get_info, RTEST_FAST)
{
  const RSRTPCipherSuiteInfo * info;

  r_assert_cmpptr ((info = r_srtp_cipher_suite_get_info (R_SRTP_CS_AEAD_AES_256_GCM)), ==, NULL);

  r_assert_cmpptr ((info = r_srtp_cipher_suite_get_info (R_SRTP_CS_AES_128_CM_HMAC_SHA1_80)), !=, NULL);
  r_assert_cmpint (info->suite, ==, R_SRTP_CS_AES_128_CM_HMAC_SHA1_80);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_AES);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_CTR);
  r_assert_cmpuint (info->cipher->keybits, ==, 128);
  r_assert_cmpuint (info->cipher->ivsize, ==, 16);
  r_assert_cmpuint (info->cipher->blocksize, ==, R_AES_BLOCK_BYTES);
  r_assert_cmpint (info->saltbits, ==, 112);
  r_assert_cmpint (info->auth, ==, R_HASH_TYPE_SHA1);
  r_assert_cmpint (info->srtp_tagbits, ==, 80);
  r_assert_cmpint (info->srtcp_tagbits, ==, 80);

  r_assert_cmpptr ((info = r_srtp_cipher_suite_get_info (R_SRTP_CS_AES_128_CM_HMAC_SHA1_32)), !=, NULL);
  r_assert_cmpint (info->suite, ==, R_SRTP_CS_AES_128_CM_HMAC_SHA1_32);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_AES);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_CTR);
  r_assert_cmpuint (info->cipher->keybits, ==, 128);
  r_assert_cmpuint (info->cipher->ivsize, ==, 16);
  r_assert_cmpuint (info->cipher->blocksize, ==, R_AES_BLOCK_BYTES);
  r_assert_cmpint (info->saltbits, ==, 112);
  r_assert_cmpint (info->auth, ==, R_HASH_TYPE_SHA1);
  r_assert_cmpint (info->srtp_tagbits, ==, 32);
  r_assert_cmpint (info->srtcp_tagbits, ==, 80);

  r_assert_cmpptr ((info = r_srtp_cipher_suite_get_info (R_SRTP_CS_NULL_NULL)), !=, NULL);
  r_assert_cmpint (info->cipher->type, ==, R_CRYPTO_CIPHER_ALGO_NULL);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_STREAM);
  r_assert_cmpuint (info->cipher->keybits, ==, 0);
  r_assert_cmpuint (info->cipher->ivsize, ==, 0);
  r_assert_cmpuint (info->cipher->blocksize, ==, 1);
  r_assert_cmpint (info->saltbits, ==, 0);
  r_assert_cmpint (info->auth, ==, R_HASH_TYPE_NONE);
  r_assert_cmpint (info->srtp_tagbits, ==, 0);
  r_assert_cmpint (info->srtcp_tagbits, ==, 0);
}
RTEST_END;

RTEST (rsrtpciphersuite, get_info_from_str, RTEST_FAST)
{
  r_assert_cmpptr (r_srtp_cipher_suite_get_info_from_str ("foo-bar"), ==, NULL);
  r_assert_cmpptr (r_srtp_cipher_suite_get_info (R_SRTP_CS_NULL_NULL),
      ==,
      r_srtp_cipher_suite_get_info_from_str ("SRTP-NULL-NULL"));
  r_assert_cmpptr (r_srtp_cipher_suite_get_info (R_SRTP_CS_AES_128_CM_HMAC_SHA1_80),
      ==,
      r_srtp_cipher_suite_get_info_from_str ("SRTP-AES-128-CM-HMAC-SHA1-80"));
}
RTEST_END;

RTEST (rsrtpciphersuite, filter, RTEST_FAST)
{
  const RSRTPCipherSuite incoming[] = {
    R_SRTP_CS_AES_128_CM_HMAC_SHA1_80,
  };
  const RSRTPCipherSuite nonsuites[] = {
    R_SRTP_CS_AEAD_AES_256_GCM, /* Not supported */
    R_SRTP_CS_F8_128_HMAC_SHA1_80, /* Not supported */
    R_SRTP_CS_AES_128_CM_HMAC_SHA1_32,
    R_SRTP_CS_NULL_NULL,
  };
  const RSRTPCipherSuite suites[] = {
    R_SRTP_CS_AEAD_AES_256_GCM, /* Not supported */
    R_SRTP_CS_F8_128_HMAC_SHA1_80, /* Not supported */
    R_SRTP_CS_AES_128_CM_HMAC_SHA1_80,
    R_SRTP_CS_NULL_NULL,
  };

  r_assert_cmpint (R_SRTP_CS_NONE, ==,
      r_srtp_cipher_suite_filter (incoming, R_N_ELEMENTS (incoming),
        nonsuites, R_N_ELEMENTS (nonsuites)));
  r_assert_cmpint (R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, ==,
      r_srtp_cipher_suite_filter (incoming, R_N_ELEMENTS (incoming),
        suites, R_N_ELEMENTS (suites)));
}
RTEST_END;

