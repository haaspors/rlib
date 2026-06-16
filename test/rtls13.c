#include <rlib/rnet.h>
#include <rlib/rcrypto.h>

RTEST (rtls13, key_schedule_sha256, R_TEST_TYPE_FAST)
{
  ruint8 zero[32];
  ruint8 early[32], derived[32], emptyhash[32], out[32];
  RMsgDigest * md;

  r_memset (zero, 0, sizeof (zero));

  /* Early Secret = HKDF-Extract(0, 0^HashLen): the fixed PSK-less value. */
  r_assert (r_hkdf_extract (R_MSG_DIGEST_TYPE_SHA256, NULL, 0,
        zero, sizeof (zero), early));
  r_assert_cmpmem (early, ==,
      "\x33\xad\x0a\x1c\x60\x7e\xc0\x3b\x09\xe6\xcd\x98\x93\x68\x0c\xe2"
      "\x10\xad\xf3\x00\xaa\x1f\x26\x60\xe1\xb2\x2e\x10\xf1\x70\xf9\x2a", 32);

  /* Transcript-Hash("") = SHA-256(""). */
  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);
  r_assert (r_msg_digest_get_data (md, emptyhash, sizeof (emptyhash), NULL));
  r_msg_digest_free (md);
  r_assert_cmpmem (emptyhash, ==,
      "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
      "\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55", 32);

  /* Derive-Secret(Early, "derived", "") -- the canonical TLS 1.3 SHA-256 value
   * (RFC 8448), exercising Derive-Secret + HKDF-Expand-Label end to end. */
  r_assert (r_tls13_derive_secret (R_MSG_DIGEST_TYPE_SHA256, early,
        (const rchar *) "derived", 7, emptyhash, derived));
  r_assert_cmpmem (derived, ==,
      "\x6f\x26\x15\xa1\x08\xc7\x02\xc5\x67\x8f\x54\xfc\x9d\xba\xb6\x97"
      "\x16\xc0\x76\x18\x9c\x48\x25\x0c\xeb\xea\xc3\x57\x6c\x36\x11\xba", 32);

  /* Invalid args. */
  r_assert (!r_tls13_expand_label (R_MSG_DIGEST_TYPE_SHA256, early,
        (const rchar *) "x", 1, NULL, 1, out, 32));    /* ctx NULL but ctxlen>0 */
  r_assert (!r_tls13_expand_label (R_MSG_DIGEST_TYPE_SHA256, early,
        NULL, 0, NULL, 0, out, 32));                   /* NULL/empty label */
  r_assert (!r_tls13_expand_label (R_MSG_DIGEST_TYPE_SHA256, early,
        (const rchar *) "x", 1, NULL, 0, out, 0));     /* 0 outlen */
  r_assert (!r_tls13_derive_secret (R_MSG_DIGEST_TYPE_SHA256, early,
        (const rchar *) "derived", 7, NULL, derived)); /* NULL transcript */
}
RTEST_END;
