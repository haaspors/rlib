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

RTEST (rtls13, aead_nonce, R_TEST_TYPE_FAST)
{
  static const ruint8 iv[12] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
  ruint8 nonce[12];

  /* seq 0 leaves the IV unchanged. */
  r_assert (r_tls13_aead_nonce (iv, sizeof (iv), 0, nonce));
  r_assert_cmpmem (nonce, ==, iv, sizeof (iv));

  /* The big-endian seq XORs into the low 8 octets (RFC 8446 5.3). */
  r_assert (r_tls13_aead_nonce (iv, sizeof (iv), 0x0102030405060708ULL, nonce));
  r_assert_cmpmem (nonce, ==,
      "\x00\x01\x02\x03\x05\x07\x05\x03\x0d\x0f\x0d\x03", sizeof (iv));

  /* Invalid args. */
  r_assert (!r_tls13_aead_nonce (NULL, sizeof (iv), 0, nonce));
  r_assert (!r_tls13_aead_nonce (iv, 0, 0, nonce));
  r_assert (!r_tls13_aead_nonce (iv, R_TLS13_AEAD_NONCE_MAX + 1, 0, nonce));
  r_assert (!r_tls13_aead_nonce (iv, sizeof (iv), 0, NULL));
}
RTEST_END;

RTEST (rtls13, record_protect_roundtrip, R_TEST_TYPE_FAST)
{
  static const ruint8 key[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
  static const ruint8 iv[12] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab };
  static const ruint8 content[] = {
    0x14, 0x00, 0x00, 0x20, 0xde, 0xad, 0xbe, 0xef }; /* a mock Finished */
  RCryptoCipher * cipher;
  ruint8 rec[64], plain[64];
  rsize reclen = 0, plainlen = 0;
  RTLSContentType type = R_TLS_CONTENT_TYPE_FIRST;

  cipher = r_cipher_aes_128_gcm_new (key);
  r_assert_cmpptr (cipher, !=, NULL);

  r_assert (r_tls13_record_protect (cipher, iv, sizeof (iv), 3,
        R_TLS_CONTENT_TYPE_HANDSHAKE, content, sizeof (content),
        rec, sizeof (rec), &reclen));
  /* encrypted_record = ciphertext(content + type) + 16-byte tag. */
  r_assert_cmpuint (reclen, ==, sizeof (content) + 1 + R_TLS13_AEAD_TAG_SIZE);
  /* The protected bytes are not the plaintext content. */
  r_assert (r_memcmp (rec, content, sizeof (content)) != 0);

  r_assert (r_tls13_record_unprotect (cipher, iv, sizeof (iv), 3,
        rec, reclen, plain, sizeof (plain), &plainlen, &type));
  r_assert_cmphex (type, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (plainlen, ==, sizeof (content));
  r_assert_cmpmem (plain, ==, content, sizeof (content));

  /* A wrong sequence number derives a different nonce -> auth failure. */
  r_assert (!r_tls13_record_unprotect (cipher, iv, sizeof (iv), 4,
        rec, reclen, plain, sizeof (plain), &plainlen, &type));
  /* A flipped ciphertext byte fails the tag check. */
  rec[0] ^= 0x01;
  r_assert (!r_tls13_record_unprotect (cipher, iv, sizeof (iv), 3,
        rec, reclen, plain, sizeof (plain), &plainlen, &type));
  rec[0] ^= 0x01;

  /* Guards: too-small output, undersized record, NULL args. */
  r_assert (!r_tls13_record_protect (cipher, iv, sizeof (iv), 0,
        R_TLS_CONTENT_TYPE_HANDSHAKE, content, sizeof (content),
        rec, sizeof (content), &reclen));
  r_assert (!r_tls13_record_unprotect (cipher, iv, sizeof (iv), 0,
        rec, R_TLS13_AEAD_TAG_SIZE, plain, sizeof (plain), &plainlen, &type));
  r_assert (!r_tls13_record_protect (NULL, iv, sizeof (iv), 0,
        R_TLS_CONTENT_TYPE_HANDSHAKE, content, sizeof (content),
        rec, sizeof (rec), &reclen));

  r_crypto_cipher_unref (cipher);
}
RTEST_END;
