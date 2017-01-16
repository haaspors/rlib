#include <rlib/rlib.h>

RTEST (rcryptomac, hmac_md5, R_TEST_TYPE_FAST)
{
  RHmac * hmac;
  static const ruint8 key[] = {
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
    0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b };
  static const ruint8 expected[] = {
    0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
    0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d };
  ruint8 actual[64];
  rsize size;
  rchar * tmp;

  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_MD5, "Jefe", 4)), !=, NULL);
  r_assert (r_hmac_update (hmac, "what do ya want for nothing?", 28));
  r_assert_cmpstr ((tmp = r_hmac_get_hex (hmac)), ==,
      "750c783e6ab0b503eaa86e310a5db738");
  r_hmac_free (hmac);
  r_free (tmp);

  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_MD5, key, sizeof (key))), !=, NULL);
  r_assert (r_hmac_update (hmac, "Hi There", 8));
  r_assert (r_hmac_get_data (hmac, actual, sizeof (actual), &size));
  r_assert_cmpmem (actual, ==, expected, size);
  r_hmac_free (hmac);

  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_MD5, "", 0)), !=, NULL);
  r_assert (r_hmac_update (hmac, "", 0));
  r_assert_cmpstr ((tmp = r_hmac_get_hex (hmac)), ==,
      "74e6f7298a9c2d168935f58c001bad88");
  r_free (tmp);
  r_hmac_free (hmac);
}
RTEST_END;

RTEST (rcryptomac, hmac_sha1, R_TEST_TYPE_FAST)
{
  RHmac * hmac;
  rchar * tmp;

  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, "", 0)), !=, NULL);
  r_assert (r_hmac_update (hmac, "", 0));
  r_assert_cmpstr ((tmp = r_hmac_get_hex (hmac)), ==,
      "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
  r_free (tmp);
  r_hmac_free (hmac);

  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, "key", 3)), !=, NULL);
  r_assert (r_hmac_update (hmac, "The quick brown fox jumps over the lazy dog", 43));
  r_assert_cmpstr ((tmp = r_hmac_get_hex (hmac)), ==,
      "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9");
  r_free (tmp);
  r_hmac_free (hmac);
}
RTEST_END;

