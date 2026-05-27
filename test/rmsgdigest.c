#include <rlib/rlib.h>

#include "wipewitness.h"

RTEST (rmsgdigest, type_string, R_TEST_TYPE_FAST)
{
  r_assert_cmpstr (r_msg_digest_type_string (R_MSG_DIGEST_TYPE_MD5), ==, "md5");
  r_assert_cmpstr (r_msg_digest_type_string (R_MSG_DIGEST_TYPE_SHA1), ==, "sha-1");
  r_assert_cmpstr (r_msg_digest_type_string (R_MSG_DIGEST_TYPE_SHA224), ==, "sha-224");
  r_assert_cmpstr (r_msg_digest_type_string (R_MSG_DIGEST_TYPE_SHA256), ==, "sha-256");
  r_assert_cmpstr (r_msg_digest_type_string (R_MSG_DIGEST_TYPE_SHA384), ==, "sha-384");
  r_assert_cmpstr (r_msg_digest_type_string (R_MSG_DIGEST_TYPE_SHA512), ==, "sha-512");
}
RTEST_END;

RTEST (rmsgdigest, type_from_str, R_TEST_TYPE_FAST)
{
  r_assert_cmpint (r_msg_digest_type_from_str (R_STR_WITH_SIZE_ARGS ("md5")),     ==, R_MSG_DIGEST_TYPE_MD5);
  r_assert_cmpint (r_msg_digest_type_from_str (R_STR_WITH_SIZE_ARGS ("sha-1")),   ==, R_MSG_DIGEST_TYPE_SHA1);
  r_assert_cmpint (r_msg_digest_type_from_str (R_STR_WITH_SIZE_ARGS ("sha-224")), ==, R_MSG_DIGEST_TYPE_SHA224);
  r_assert_cmpint (r_msg_digest_type_from_str (R_STR_WITH_SIZE_ARGS ("sha-256")), ==, R_MSG_DIGEST_TYPE_SHA256);
  r_assert_cmpint (r_msg_digest_type_from_str (R_STR_WITH_SIZE_ARGS ("sha-384")), ==, R_MSG_DIGEST_TYPE_SHA384);
  r_assert_cmpint (r_msg_digest_type_from_str (R_STR_WITH_SIZE_ARGS ("sha-512")), ==, R_MSG_DIGEST_TYPE_SHA512);
}
RTEST_END;

RTEST (rmsgdigest, md5, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_md5 ();
  ruint8 data[32];
  rsize size;
  rchar * hex;

  r_assert_cmpuint (r_msg_digest_size (md),       ==, 128 / 8);
  r_assert_cmpuint (r_msg_digest_blocksize (md),  ==, 512 / 8);
  r_assert (r_msg_digest_update (md, "foobar", 6));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpmem (data, ==,
      "\x38\x58\xf6\x22\x30\xac\x3c\x91\x5f\x30\x0c\x66\x43\x12\xc6\x3f", size);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "3858f62230ac3c915f300c664312c63f");
  r_assert (r_msg_digest_update (md, "foobar", 6));

  r_assert (r_msg_digest_finish (md));
  r_assert (!r_msg_digest_update (md, "foobar", 6));

  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha1, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha1 ();
  ruint8 data[32];
  rsize size;
  rchar * hex;

  r_assert_cmpuint (r_msg_digest_size (md),       ==, 160 / 8);
  r_assert_cmpuint (r_msg_digest_blocksize (md),  ==, 512 / 8);
  r_assert (r_msg_digest_update (md, "foobar", 6));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpmem (data, ==,
      "\x88\x43\xd7\xf9\x24\x16\x21\x1d\xe9\xeb\xb9\x63\xff\x4c\xe2\x81\x25\x93\x28\x78", size);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "8843d7f92416211de9ebb963ff4ce28125932878");
  r_free (hex);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex_full (md, ":", 1)), ==,
      "88:43:d7:f9:24:16:21:1d:e9:eb:b9:63:ff:4c:e2:81:25:93:28:78");
  r_assert (r_msg_digest_update (md, "foobar", 6));

  r_assert (r_msg_digest_finish (md));
  r_assert (!r_msg_digest_update (md, "foobar", 6));

  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, new_dispatch, R_TEST_TYPE_FAST)
{
  /* r_msg_digest_new must dispatch to every implemented digest, not
   * just MD5/SHA1/SHA256/SHA512. */
  RMsgDigest * md;

  r_assert_cmpptr ((md = r_msg_digest_new (R_MSG_DIGEST_TYPE_SHA224)), !=, NULL);
  r_assert_cmpuint (r_msg_digest_size (md), ==, 224 / 8);
  r_msg_digest_free (md);

  r_assert_cmpptr ((md = r_msg_digest_new (R_MSG_DIGEST_TYPE_SHA384)), !=, NULL);
  r_assert_cmpuint (r_msg_digest_size (md), ==, 384 / 8);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha224, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha224 ();
  ruint8 data[32];
  rsize size;
  rchar * hex;

  r_assert_cmpuint (r_msg_digest_size (md),       ==, 224 / 8);
  r_assert_cmpuint (r_msg_digest_blocksize (md),  ==, 512 / 8);
  r_assert (r_msg_digest_update (md, "foobar", 6));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpmem (data, ==,
      "\xde\x76\xc3\xe5\x67\xfc\xa9\xd2\x46\xf5\xf8\xd3\xb2\xe7\x04\xa3\x8c\x3c\x5e\x25\x89\x88\xab\x52\x5f\x94\x1d\xb8", size);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "de76c3e567fca9d246f5f8d3b2e704a38c3c5e258988ab525f941db8");
  r_free (hex);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex_full (md, ":", 1)), ==,
      "de:76:c3:e5:67:fc:a9:d2:46:f5:f8:d3:b2:e7:04:a3:8c:3c:5e:25:89:88:ab:52:5f:94:1d:b8");
  r_assert (r_msg_digest_update (md, "foobar", 6));

  r_assert (r_msg_digest_finish (md));
  r_assert (!r_msg_digest_update (md, "foobar", 6));

  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha256, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha256 ();
  ruint8 data[32];
  rsize size;
  rchar * hex;

  r_assert_cmpuint (r_msg_digest_size (md),       ==, 256 / 8);
  r_assert_cmpuint (r_msg_digest_blocksize (md),  ==, 512 / 8);
  r_assert (r_msg_digest_update (md, "foobar", 6));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpmem (data, ==,
      "\xc3\xab\x8f\xf1\x37\x20\xe8\xad\x90\x47\xdd\x39\x46\x6b\x3c\x89"
      "\x74\xe5\x92\xc2\xfa\x38\x3d\x4a\x39\x60\x71\x4c\xae\xf0\xc4\xf2", size);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2");
  r_assert (r_msg_digest_update (md, "foobar", 6));

  r_assert (r_msg_digest_finish (md));
  r_assert (!r_msg_digest_update (md, "foobar", 6));

  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha384, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha384 ();
  ruint8 data[64];
  rsize size;
  rchar * hex;

  r_assert_cmpuint (r_msg_digest_size (md),       ==, 384 / 8);
  r_assert_cmpuint (r_msg_digest_blocksize (md),  ==, 1024 / 8);
  r_assert (r_msg_digest_update (md, "foobar", 6));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpmem (data, ==,
      "\x3c\x9c\x30\xd9\xf6\x65\xe7\x4d\x51\x5c\x84\x29"
      "\x60\xd4\xa4\x51\xc8\x3a\x01\x25\xfd\x3d\xe7\x39"
      "\x2d\x7b\x37\x23\x1a\xf1\x0c\x72\xea\x58\xae\xdf"
      "\xcd\xf8\x9a\x57\x65\xbf\x90\x2a\xf9\x3e\xcf\x06", size);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "3c9c30d9f665e74d515c842960d4a451c83a0125fd3de739"
      "2d7b37231af10c72ea58aedfcdf89a5765bf902af93ecf06");

  r_assert (r_msg_digest_update (md, "foobar", 6));

  r_assert (r_msg_digest_finish (md));
  r_assert (!r_msg_digest_update (md, "foobar", 6));

  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha512, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha512 ();
  ruint8 data[64];
  rsize size;
  rchar * hex;

  r_assert_cmpuint (r_msg_digest_size (md),       ==, 512 / 8);
  r_assert_cmpuint (r_msg_digest_blocksize (md),  ==, 1024 / 8);
  r_assert (r_msg_digest_update (md, "foobar", 6));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpmem (data, ==,
      "\x0a\x50\x26\x1e\xbd\x1a\x39\x0f\xed\x2b\xf3\x26\xf2\x67\x3c\x14"
      "\x55\x82\xa6\x34\x2d\x52\x32\x04\x97\x3d\x02\x19\x33\x7f\x81\x61"
      "\x6a\x80\x69\xb0\x12\x58\x7c\xf5\x63\x5f\x69\x25\xf1\xb5\x6c\x36"
      "\x02\x30\xc1\x9b\x27\x35\x00\xee\x01\x3e\x03\x06\x01\xbf\x24\x25", size);
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f8161"
      "6a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425");
  r_assert (r_msg_digest_update (md, "foobar", 6));

  r_assert (r_msg_digest_finish (md));
  r_assert (!r_msg_digest_update (md, "foobar", 6));

  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, md5_fill_block, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_md5 ();
  ruint8 data[32];
  rsize i, size;
  rchar * hex;

  for (i = 0; i < r_msg_digest_blocksize (md); i += 8)
    r_assert (r_msg_digest_update (md, "foobar64", 8));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "57c58653b9d1fe7485d4754c24ae50ef");
  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha1_fill_block, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha1 ();
  ruint8 data[32];
  rsize i, size;
  rchar * hex;

  for (i = 0; i < r_msg_digest_blocksize (md); i += 8)
    r_assert (r_msg_digest_update (md, "foobar64", 8));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "44ad860c45a831da1edf9ceb0d3c259d52efe68e");
  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha256_fill_block, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha256 ();
  ruint8 data[32];
  rsize i, size;
  rchar * hex;

  for (i = 0; i < r_msg_digest_blocksize (md); i += 8)
    r_assert (r_msg_digest_update (md, "foobar64", 8));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "c937e19346c302d51371e5df65cea11ed71c6f58678adc27fe1a55ace8167aa6");
  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, sha512_fill_block, R_TEST_TYPE_FAST)
{
  RMsgDigest * md = r_msg_digest_new_sha512 ();
  ruint8 data[64];
  rsize i, size;
  rchar * hex;

  for (i = 0; i < r_msg_digest_blocksize (md); i += 8)
    r_assert (r_msg_digest_update (md, "foobar64", 8));
  r_assert (r_msg_digest_get_data (md, data, sizeof (data), &size));
  r_assert_cmpuint (size, ==, r_msg_digest_size (md));
  r_assert_cmpstr ((hex = r_msg_digest_get_hex (md)), ==,
      "265927b8379557541f940d2dd259ee89a55381804514b758be3dab33f981e8389"
      "27e08ffc73ae538d581b65a2eb706459817ff51172742a9e1cf832b0727cc66");
  r_free (hex);
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, free_wipes_state, R_TEST_TYPE_FAST)
{
  /* Sentinel-tagged input shorter than the MD5 block: with no
   * finalise call the trailing per-algorithm partial-block buffer
   * still holds the raw input bytes verbatim. r_msg_digest_free
   * must wipe the whole md (mdsize covers the trailing state)
   * before r_free, or the sentinel survives in the freed pile. */
  static const ruint8 sentinel[24] = {
    0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF,
    0xFE, 0xED, 0xFA, 0xCE, 0xBA, 0xAD, 0xF0, 0x0D,
    0x13, 0x37, 0xC0, 0xDE, 0xB1, 0x05, 0xF0, 0x0D
  };
  RMsgDigest * md;

  r_wipe_witness_install ();
  r_assert_cmpptr ((md = r_msg_digest_new (R_MSG_DIGEST_TYPE_MD5)), !=, NULL);
  r_assert (r_msg_digest_update (md, sentinel, sizeof (sentinel)));
  r_msg_digest_free (md);
  r_wipe_witness_uninstall ();

  r_assert (!r_wipe_witness_freed_contains (sentinel, sizeof (sentinel)));
}
RTEST_END;


/* ---- SHAKE256 (FIPS 202 §6.2). ---- */

/* NIST CAVP / FIPS 202 published vectors. The 32-byte output of the
 * empty message and the absorbing-rate boundary test are the two
 * standard short cases the IETF and FIPS-202 examples publish. */

RTEST (rmsgdigest, shake256_empty_32, R_TEST_TYPE_FAST)
{
  /* SHAKE256("", 32) = 46b9dd2b0ba88d13233b3feb743eeb243fcd52ea
   * 62b81b82b50c27646ed5762f */
  RMsgDigest * md;
  ruint8 out[32];
  static const ruint8 expected[32] = {
    0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
    0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
    0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
    0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
  };

  r_assert_cmpptr ((md = r_msg_digest_new_shake256 ()), !=, NULL);
  r_assert (r_msg_digest_squeeze (md, out, sizeof (out)));
  r_assert_cmpmem (out, ==, expected, sizeof (out));
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, shake256_empty_64, R_TEST_TYPE_FAST)
{
  /* Extending the empty-message squeeze to 64 bytes - tests
   * permute-between-blocks on the squeeze side. */
  RMsgDigest * md;
  ruint8 out[64];
  static const ruint8 expected[64] = {
    0x46, 0xb9, 0xdd, 0x2b, 0x0b, 0xa8, 0x8d, 0x13,
    0x23, 0x3b, 0x3f, 0xeb, 0x74, 0x3e, 0xeb, 0x24,
    0x3f, 0xcd, 0x52, 0xea, 0x62, 0xb8, 0x1b, 0x82,
    0xb5, 0x0c, 0x27, 0x64, 0x6e, 0xd5, 0x76, 0x2f,
    0xd7, 0x5d, 0xc4, 0xdd, 0xd8, 0xc0, 0xf2, 0x00,
    0xcb, 0x05, 0x01, 0x9d, 0x67, 0xb5, 0x92, 0xf6,
    0xfc, 0x82, 0x1c, 0x49, 0x47, 0x9a, 0xb4, 0x86,
    0x40, 0x29, 0x2e, 0xac, 0xb3, 0xb7, 0xc4, 0xbe,
  };

  r_assert_cmpptr ((md = r_msg_digest_new_shake256 ()), !=, NULL);
  r_assert (r_msg_digest_squeeze (md, out, sizeof (out)));
  r_assert_cmpmem (out, ==, expected, sizeof (out));
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, shake256_abc_64, R_TEST_TYPE_FAST)
{
  /* SHAKE256("abc", 64) - one of the standard "abc" KATs from the
   * Keccak team's reference implementation. */
  RMsgDigest * md;
  ruint8 out[64];
  static const ruint8 expected[64] = {
    0x48, 0x33, 0x66, 0x60, 0x13, 0x60, 0xa8, 0x77,
    0x1c, 0x68, 0x63, 0x08, 0x0c, 0xc4, 0x11, 0x4d,
    0x8d, 0xb4, 0x45, 0x30, 0xf8, 0xf1, 0xe1, 0xee,
    0x4f, 0x94, 0xea, 0x37, 0xe7, 0x8b, 0x57, 0x39,
    0xd5, 0xa1, 0x5b, 0xef, 0x18, 0x6a, 0x53, 0x86,
    0xc7, 0x57, 0x44, 0xc0, 0x52, 0x7e, 0x1f, 0xaa,
    0x9f, 0x87, 0x26, 0xe4, 0x62, 0xa1, 0x2a, 0x4f,
    0xeb, 0x06, 0xbd, 0x88, 0x01, 0xe7, 0x51, 0xe4,
  };

  r_assert_cmpptr ((md = r_msg_digest_new_shake256 ()), !=, NULL);
  r_assert (r_msg_digest_update (md, "abc", 3));
  r_assert (r_msg_digest_squeeze (md, out, sizeof (out)));
  r_assert_cmpmem (out, ==, expected, sizeof (out));
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, shake256_long_msg_across_rate, R_TEST_TYPE_FAST)
{
  /* Message length 200 bytes of 0xA3 - longer than the 136-byte
   * rate, so this exercises the absorb-side permute-between-blocks
   * path. Expected output truncated to 32 bytes per the FIPS 202
   * Intermediate Values document for SHAKE256. */
  RMsgDigest * md;
  ruint8 msg[200];
  ruint8 out[32];
  static const ruint8 expected[32] = {
    0xcd, 0x8a, 0x92, 0x0e, 0xd1, 0x41, 0xaa, 0x04,
    0x07, 0xa2, 0x2d, 0x59, 0x28, 0x86, 0x52, 0xe9,
    0xd9, 0xf1, 0xa7, 0xee, 0x0c, 0x1e, 0x7c, 0x1c,
    0xa6, 0x99, 0x42, 0x4d, 0xa8, 0x4a, 0x90, 0x4d,
  };
  rsize i;

  for (i = 0; i < sizeof (msg); i++) msg[i] = 0xA3;
  r_assert_cmpptr ((md = r_msg_digest_new_shake256 ()), !=, NULL);
  r_assert (r_msg_digest_update (md, msg, sizeof (msg)));
  r_assert (r_msg_digest_squeeze (md, out, sizeof (out)));
  r_assert_cmpmem (out, ==, expected, sizeof (out));
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, shake256_multi_squeeze_concat, R_TEST_TYPE_FAST)
{
  /* Squeezing n + m bytes in two calls must produce the same byte
   * sequence as a single n+m squeeze. Exercises the cross-rate
   * cursor on the squeeze side. */
  RMsgDigest * a, * b;
  ruint8 single[200], split[200];

  r_assert_cmpptr ((a = r_msg_digest_new_shake256 ()), !=, NULL);
  r_assert (r_msg_digest_update (a, "abc", 3));
  r_assert (r_msg_digest_squeeze (a, single, sizeof (single)));
  r_msg_digest_free (a);

  r_assert_cmpptr ((b = r_msg_digest_new_shake256 ()), !=, NULL);
  r_assert (r_msg_digest_update (b, "abc", 3));
  r_assert (r_msg_digest_squeeze (b, split, 17));
  r_assert (r_msg_digest_squeeze (b, split + 17, 120));
  r_assert (r_msg_digest_squeeze (b, split + 137, sizeof (split) - 137));
  r_assert_cmpmem (split, ==, single, sizeof (single));
  r_msg_digest_free (b);
}
RTEST_END;

RTEST (rmsgdigest, shake256_get_data_rejected, R_TEST_TYPE_FAST)
{
  /* The fixed-output get_data entry point doesn't apply to XOFs;
   * caller must use _squeeze. */
  RMsgDigest * md;
  ruint8 buf[32];
  rsize out_size;

  r_assert_cmpptr ((md = r_msg_digest_new_shake256 ()), !=, NULL);
  r_assert (!r_msg_digest_get_data (md, buf, sizeof (buf), &out_size));
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, shake256_squeeze_rejected_for_sha256, R_TEST_TYPE_FAST)
{
  /* Inverse: squeeze() must reject fixed-output digests. */
  RMsgDigest * md;
  ruint8 buf[32];

  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);
  r_assert (!r_msg_digest_squeeze (md, buf, sizeof (buf)));
  r_msg_digest_free (md);
}
RTEST_END;

RTEST (rmsgdigest, shake256_type_metadata, R_TEST_TYPE_FAST)
{
  RMsgDigest * md;

  r_assert_cmpuint (r_msg_digest_type_size (R_MSG_DIGEST_TYPE_SHAKE256), ==, 0);
  r_assert_cmpuint (r_msg_digest_type_blocksize (R_MSG_DIGEST_TYPE_SHAKE256),
      ==, 136);
  r_assert_cmpstr (r_msg_digest_type_string (R_MSG_DIGEST_TYPE_SHAKE256),
      ==, "shake256");
  r_assert_cmpint (r_msg_digest_type_from_str ("shake256", -1),
      ==, R_MSG_DIGEST_TYPE_SHAKE256);

  /* type-dispatched constructor too. */
  r_assert_cmpptr ((md = r_msg_digest_new (R_MSG_DIGEST_TYPE_SHAKE256)),
      !=, NULL);
  r_assert_cmpuint (r_msg_digest_size (md), ==, 0);
  r_assert_cmpuint (r_msg_digest_blocksize (md), ==, 136);
  r_msg_digest_free (md);
}
RTEST_END;
