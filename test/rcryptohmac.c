#include <rlib/rcrypto.h>

#include "wipewitness.h"

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

RTEST (rcryptomac, hmac_unsupported_type, R_TEST_TYPE_FAST)
{
  /* r_msg_digest_new returns NULL for these types; r_hmac_new must not crash. */
  RHmac * hmac;

  r_assert_cmpptr (r_hmac_new (R_MSG_DIGEST_TYPE_MD2, "k", 1), ==, NULL);
  r_assert_cmpptr (r_hmac_new (R_MSG_DIGEST_TYPE_MD4, "k", 1), ==, NULL);
  r_assert_cmpptr (r_hmac_new (R_MSG_DIGEST_TYPE_NONE, "k", 1), ==, NULL);

  /* SHA-224 and SHA-384 are implemented; r_hmac_new should succeed. */
  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA224, "k", 1)),
      !=, NULL);
  r_hmac_free (hmac);
  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA384, "k", 1)),
      !=, NULL);
  r_hmac_free (hmac);
}
RTEST_END;

RTEST (rcryptomac, free_wipes_keyblock, R_TEST_TYPE_FAST)
{
  /* Sentinel-tagged HMAC key: shorter than the SHA-256 block size
   * so r_hmac_new takes the zero-padding branch into keyblock, then
   * r_hmac_reset folds it into the inner/outer pads. Both code
   * paths must wipe before release; otherwise the sentinel survives
   * in the freed-buffer pile. */
  static const ruint8 sentinel_key[24] = {
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xFE, 0xED, 0xFA, 0xCE, 0xBA, 0xAD, 0xF0, 0x0D,
    0x13, 0x37, 0xC0, 0xDE, 0xB1, 0x05, 0xF0, 0x0D
  };
  RHmac * hmac;

  r_wipe_witness_install ();
  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA256, sentinel_key,
          sizeof (sentinel_key))), !=, NULL);
  r_hmac_free (hmac);
  r_wipe_witness_uninstall ();

  r_assert (!r_wipe_witness_freed_contains (sentinel_key, sizeof (sentinel_key)));
}
RTEST_END;

RTEST (rcryptomac, hmac_verify, R_TEST_TYPE_FAST)
{
  /* RFC 4231 Test Case 2: HMAC-MD5("Jefe", "what do ya want for
   * nothing?") = 750c783e6ab0b503eaa86e310a5db738. r_hmac_verify
   * must accept the matching tag, reject single-byte tweaks at
   * both ends, accept truncated-tag prefixes, and refuse over-long
   * tags. */
  static const ruint8 tag_full[] = {
    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38
  };
  static const ruint8 tag_bad_first[] = {
    0x76, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38
  };
  static const ruint8 tag_bad_last[] = {
    0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
    0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x39
  };
  RHmac * hmac;

#define _MAC_NEW_AND_UPDATE() do {                                              \
    r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_MD5, "Jefe", 4)),    \
        !=, NULL);                                                              \
    r_assert (r_hmac_update (hmac, "what do ya want for nothing?", 28));        \
  } while (0)

  _MAC_NEW_AND_UPDATE ();
  r_assert (r_hmac_verify (hmac, tag_full, sizeof (tag_full)));
  r_hmac_free (hmac);

  _MAC_NEW_AND_UPDATE ();
  r_assert (!r_hmac_verify (hmac, tag_bad_first, sizeof (tag_bad_first)));
  r_hmac_free (hmac);

  _MAC_NEW_AND_UPDATE ();
  r_assert (!r_hmac_verify (hmac, tag_bad_last, sizeof (tag_bad_last)));
  r_hmac_free (hmac);

  /* Truncated tag: matching the first 10 bytes (SRTP-80-style) is
   * accepted; flipping byte 4 within that prefix is rejected. */
  _MAC_NEW_AND_UPDATE ();
  r_assert (r_hmac_verify (hmac, tag_full, 10));
  r_hmac_free (hmac);

  _MAC_NEW_AND_UPDATE ();
  r_assert (!r_hmac_verify (hmac, tag_bad_first, 10));
  r_hmac_free (hmac);

  /* tag_size > r_hmac_size is rejected without going through the
   * compare. */
  _MAC_NEW_AND_UPDATE ();
  r_assert (!r_hmac_verify (hmac, tag_full, sizeof (tag_full) + 1));
  r_hmac_free (hmac);

  /* NULL arguments are rejected. */
  _MAC_NEW_AND_UPDATE ();
  r_assert (!r_hmac_verify (hmac, NULL, sizeof (tag_full)));
  r_hmac_free (hmac);
  r_assert (!r_hmac_verify (NULL, tag_full, sizeof (tag_full)));

#undef _MAC_NEW_AND_UPDATE
}
RTEST_END;

