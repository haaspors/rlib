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

RTEST (rtls13, key_schedule_rfc8448, R_TEST_TYPE_FAST)
{
  /* The Simple 1-RTT Handshake of RFC 8448, section 3
   * (TLS_AES_128_GCM_SHA256): drive the full key schedule from the ECDHE shared
   * secret and the ClientHello..ServerHello transcript hash, and check every
   * derived secret / traffic key against the published values. */
  static const ruint8 ecdhe[32] = {
    0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9,
    0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef,
    0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d };
  static const ruint8 th_ch_sh[32] = {
    0x86, 0x0c, 0x06, 0xed, 0xc0, 0x78, 0x58, 0xee, 0x8e, 0x78, 0xf0, 0xe7,
    0x42, 0x8c, 0x58, 0xed, 0xd6, 0xb4, 0x3f, 0x2c, 0xa3, 0xe6, 0xe9, 0x5f,
    0x02, 0xed, 0x06, 0x3c, 0xf0, 0xe1, 0xca, 0xd8 };
  RTLS13Schedule sched;
  RTLS13RecordKeys rk = R_TLS13_RECORD_KEYS_INIT;
  const RCryptoCipherInfo * info;
  ruint8 finkey[32], vd[32];

  r_assert (r_tls13_schedule_init (&sched, R_MSG_DIGEST_TYPE_SHA256));
  r_assert_cmpmem (sched.early, ==,
      "\x33\xad\x0a\x1c\x60\x7e\xc0\x3b\x09\xe6\xcd\x98\x93\x68\x0c\xe2"
      "\x10\xad\xf3\x00\xaa\x1f\x26\x60\xe1\xb2\x2e\x10\xf1\x70\xf9\x2a", 32);

  r_assert (r_tls13_schedule_handshake (&sched, ecdhe, sizeof (ecdhe), th_ch_sh));
  r_assert_cmpmem (sched.handshake, ==,
      "\x1d\xc8\x26\xe9\x36\x06\xaa\x6f\xdc\x0a\xad\xc1\x2f\x74\x1b\x01"
      "\x04\x6a\xa6\xb9\x9f\x69\x1e\xd2\x21\xa9\xf0\xca\x04\x3f\xbe\xac", 32);
  r_assert_cmpmem (sched.chs, ==,
      "\xb3\xed\xdb\x12\x6e\x06\x7f\x35\xa7\x80\xb3\xab\xf4\x5e\x2d\x8f"
      "\x3b\x1a\x95\x07\x38\xf5\x2e\x96\x00\x74\x6a\x0e\x27\xa5\x5a\x21", 32);
  r_assert_cmpmem (sched.shs, ==,
      "\xb6\x7b\x7d\x69\x0c\xc1\x6c\x4e\x75\xe5\x42\x13\xcb\x2d\x37\xb4"
      "\xe9\xc9\x12\xbc\xde\xd9\x10\x5d\x42\xbe\xfd\x59\xd3\x91\xad\x38", 32);

  /* Server handshake-traffic key / IV. */
  r_assert_cmpptr ((info = r_crypto_cipher_find_by_type (
          R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_GCM, 128)), !=, NULL);
  r_assert (r_tls13_traffic_keys (R_MSG_DIGEST_TYPE_SHA256, sched.shs, info, &rk));
  r_assert_cmpptr (rk.cipher, !=, NULL);
  r_assert_cmpuint (rk.ivlen, ==, 12);
  r_assert_cmpuint (rk.seq, ==, 0);
  r_assert_cmpmem (rk.iv, ==, "\x5d\x31\x3e\xb2\x67\x12\x76\xee\x13\x00\x0b\x30", 12);
  r_crypto_cipher_unref (rk.cipher);

  /* Server Finished key + a verify_data over the CH..SH transcript hash
   * (independently HMAC-computed). */
  r_assert (r_tls13_finished_key (R_MSG_DIGEST_TYPE_SHA256, sched.shs, finkey));
  r_assert_cmpmem (finkey, ==,
      "\x00\x8d\x3b\x66\xf8\x16\xea\x55\x9f\x96\xb5\x37\xe8\x85\xc3\x1f"
      "\xc0\x68\xbf\x49\x2c\x65\x2f\x01\xf2\x88\xa1\xd8\xcd\xc1\x9f\xc8", 32);
  r_assert (r_tls13_verify_data (R_MSG_DIGEST_TYPE_SHA256, finkey, th_ch_sh, vd));
  r_assert_cmpmem (vd, ==,
      "\x2b\x47\x34\x88\xb0\xe9\xd7\x08\x5d\x0b\xff\x61\xac\xdd\x4e\xfe"
      "\x3b\x04\x05\x4b\x30\x6c\x39\x96\x35\x21\x55\xba\x24\xb5\x03\x87", 32);
}
RTEST_END;

RTEST (rtls13, cert_verify_tbs, R_TEST_TYPE_FAST)
{
  ruint8 th[32], out[R_TLS13_CERT_VERIFY_TBS_MAX];
  rsize outlen = 0, i;

  for (i = 0; i < sizeof (th); i++)
    th[i] = (ruint8) i;

  r_assert (r_tls13_cert_verify_tbs (TRUE, th, sizeof (th),
        out, sizeof (out), &outlen));
  r_assert_cmpuint (outlen, ==, 64 + 33 + 1 + sizeof (th));
  for (i = 0; i < 64; i++)
    r_assert_cmphex (out[i], ==, 0x20);
  r_assert_cmpmem (out + 64, ==, "TLS 1.3, server CertificateVerify", 33);
  r_assert_cmphex (out[97], ==, 0x00);
  r_assert_cmpmem (out + 98, ==, th, sizeof (th));

  /* Client context string differs only in that one word. */
  r_assert (r_tls13_cert_verify_tbs (FALSE, th, sizeof (th),
        out, sizeof (out), &outlen));
  r_assert_cmpmem (out + 64, ==, "TLS 1.3, client CertificateVerify", 33);

  /* Too-small output is rejected. */
  r_assert (!r_tls13_cert_verify_tbs (TRUE, th, sizeof (th), out, 10, &outlen));
}
RTEST_END;
