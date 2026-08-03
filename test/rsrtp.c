#include <rlib/rnet.h>

/* SRTP-AES-128-CM-HMAC-SHA1-80 */
/* a=ssrc:3027665466 cname:ceiNLmy6VHSE5Ja7 */
static const ruint8 masterkey[] = {
  0x3c, 0x39, 0xa8, 0x5c, 0x2d, 0xf0, 0x5e, 0x52, 0x7e, 0x79, 0x12, 0xba, 0x60, 0xc5, 0x25, 0xfe,
  0x29, 0xf7, 0x97, 0xd9, 0xda, 0xa3, 0x17, 0x60, 0xdf, 0x34, 0xb9, 0x5f, 0x87, 0xd3
};
static const ruint8 masterkey2[] = {
  0x91, 0x0e, 0x4f, 0x2b, 0xc7, 0x83, 0x1a, 0x6d, 0x40, 0x22, 0xf9, 0x0c, 0x55, 0xe8, 0x37, 0xb4,
  0x1c, 0x6a, 0x08, 0xd3, 0xe5, 0x59, 0x72, 0x84, 0xbe, 0x11, 0xa7, 0x3f, 0x02, 0x9c
};
static const ruint32 ssrc = 0xb476823a;
static const rchar cname[] = "ceiNLmy6VHSE5Ja7";

static const ruint8 pkt_srtp_aes_128_cm_opus[] = {
  0x90, 0xef, 0x41, 0xcd, 0x55, 0x50, 0xbe, 0x52, 0xb4, 0x76, 0x82, 0x3a, 0xbe, 0xde, 0x00, 0x02,
  0x32, 0x54, 0xe1, 0xe1, 0x10, 0xaa, 0x00, 0x00, 0xd7, 0x3e, 0xf0, 0x0e, 0x5a, 0xef, 0x66, 0x95,
  0x24, 0x99, 0x30, 0xb0, 0x99, 0xd6, 0xd1, 0x35, 0x10, 0x22, 0xd8, 0x30, 0xb1, 0x45, 0x30, 0xc9,
  0x49, 0x6f, 0xdc, 0xd6, 0x80, 0x31, 0xfe, 0x29, 0x8d, 0x6d, 0x56, 0xa9, 0xa3, 0x93, 0xa5, 0x10,
  0x89, 0x89, 0x57, 0xb8, 0xbf, 0x8c, 0xb3, 0x5f, 0x0c, 0xe7, 0xc0, 0x89, 0x8d, 0x99, 0x3a, 0xaa,
  0xbd, 0xc1, 0xbd, 0x7f, 0x5a, 0xd1, 0xec, 0x9a, 0x26, 0xd8, 0x31, 0x0a, 0x20, 0xa1, 0xcf, 0x6a,
  0x08, 0xd2, 0x3e, 0x15, 0xcf, 0x0e, 0xfb, 0xdb, 0xe1, 0x64, 0x49, 0x7e, 0x9a
};

static const ruint8 pkt_rtp_opus[] = {
  0x90, 0xef, 0x41, 0xcd, 0x55, 0x50, 0xbe, 0x52, 0xb4, 0x76, 0x82, 0x3a, 0xbe, 0xde, 0x00, 0x02,
  0x32, 0x54, 0xe1, 0xe1, 0x10, 0xaa, 0x00, 0x00, 0x78, 0x03, 0x9c, 0xdb, 0x17, 0x91, 0x6b, 0xe3,
  0xb1, 0x02, 0x0a, 0xf1, 0xa5, 0x56, 0xe1, 0xc4, 0xf0, 0x2d, 0xf0, 0x1c, 0x90, 0x16, 0x0f, 0x34,
  0x2e, 0xc2, 0x34, 0xab, 0x93, 0xfc, 0xf9, 0xde, 0x7f, 0x94, 0xb3, 0x10, 0xaf, 0x10, 0xf3, 0x23,
  0x3b, 0xce, 0xd7, 0x9f, 0x55, 0xa0, 0x70, 0x33, 0x62, 0x9a, 0x72, 0xe9, 0x28, 0xcd, 0x40, 0xa5,
  0xae, 0x61, 0xca, 0xa1, 0xf6, 0x72, 0x7c, 0x10, 0xce, 0x6e, 0xd6, 0xd9, 0x87, 0x16, 0xb1, 0xe8,
  0x22, 0x66, 0x28
};

static const ruint8 pkt_srtcp_aes_128_cm[] = {
  0x80, 0xc8, 0x00, 0x06, 0xb4, 0x76, 0x82, 0x3a, 0x47, 0x9b, 0xb7, 0x9d, 0x9e, 0x09, 0x15, 0xca,
  0x10, 0x80, 0x43, 0x20, 0x32, 0x7d, 0x42, 0xd9, 0xc9, 0x49, 0xe8, 0x6b, 0x1f, 0xd1, 0x78, 0xe2,
  0xd7, 0xc3, 0x7e, 0x3b, 0x23, 0x6d, 0x4b, 0x99, 0x96, 0x81, 0x5a, 0x7d, 0xbb, 0x18, 0x17, 0xf8,
  0x57, 0x3e, 0xe4, 0x3a, 0x02, 0xce, 0xb6, 0x24, 0x80, 0x00, 0x00, 0x01, 0x65, 0x89, 0xe9, 0xde,
  0x21, 0x01, 0x61, 0xb5, 0xde, 0xbe
};

static const ruint8 pkt_rtcp_sr_sdes[] = {
  0x80, 0xc8, 0x00, 0x06, 0xb4, 0x76, 0x82, 0x3a, 0xdc, 0x23, 0x27, 0xb2, 0xac, 0x34, 0x8f, 0x54,
  0x55, 0x50, 0xcd, 0x92, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x01, 0x75, 0x81, 0xca, 0x00, 0x06,
  0xb4, 0x76, 0x82, 0x3a, 0x01, 0x10, 0x63, 0x65, 0x69, 0x4e, 0x4c, 0x6d, 0x79, 0x36, 0x56, 0x48,
  0x53, 0x45, 0x35, 0x4a, 0x61, 0x37, 0x00, 0x00
};

RTEST (rsrtp, no_crypto_ctx, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf;
  RSRTPError err;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sizeof (pkt_rtp_opus))), !=, NULL);
  r_assert_cmpptr (r_srtp_encrypt_rtp (ctx, buf, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_NO_CRYPTO_CTX);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes))), !=, NULL);
  r_assert_cmpptr (r_srtp_encrypt_rtcp (ctx, buf, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_NO_CRYPTO_CTX);
  r_buffer_unref (buf);

  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, add_crypto_ctx, RTEST_FAST)
{
  RSRTPCtx * ctx;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey), ==, R_SRTP_ERROR_OK);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, decrypt_aes_128_cm, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf, * res;
  RSRTPError err;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);

  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_srtp_aes_128_cm_opus, sizeof (pkt_srtp_aes_128_cm_opus))), !=, NULL);

  r_assert_cmpptr ((res = r_srtp_decrypt_rtp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (res, 0, -1, ==, pkt_rtp_opus, sizeof (pkt_rtp_opus));
  r_buffer_unref (res);

  /* Replaying the packet should yield R_SRTP_ERROR_REPLAYED */
  r_assert_cmpptr ((res = r_srtp_decrypt_rtp (ctx, buf, &err)), ==, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_REPLAYED);

  r_buffer_unref (buf);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, encrypt_aes_128_cm, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf, * res;
  RSRTPError err;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);

  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sizeof (pkt_rtp_opus))), !=, NULL);

  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (res, 0, -1, ==, pkt_srtp_aes_128_cm_opus, sizeof (pkt_srtp_aes_128_cm_opus));
  r_buffer_unref (res);

  /* Replaying the packet should yield R_SRTP_ERROR_REPLAYED */
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (ctx, buf, &err)), ==, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_REPLAYED);

  r_buffer_unref (buf);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, bidirectional_keys, RTEST_FAST)
{
  RSRTPCtx * a, * b;
  RBuffer * buf, * enc, * dec;
  RSRTPError err;

  /* RFC 5764 4.2: send and receive use different keys. Peer A sends with
   * masterkey and receives with masterkey2; peer B is the mirror. A must
   * encrypt with its send key, so the ciphertext matches the masterkey
   * vector -- not the receive key it would reuse under the bug. */
  r_assert_cmpptr ((a = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpptr ((b = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_with_filter_dual (a, R_SRTP_FILTER_ANY,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey2, masterkey), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_crypto_context_with_filter_dual (b, R_SRTP_FILTER_ANY,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey, masterkey2), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sizeof (pkt_rtp_opus))), !=, NULL);

  /* A encrypts outbound with its send key (masterkey). */
  r_assert_cmpptr ((enc = r_srtp_encrypt_rtp (a, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (enc, 0, -1, ==, pkt_srtp_aes_128_cm_opus, sizeof (pkt_srtp_aes_128_cm_opus));

  /* B decrypts inbound with its receive key (also masterkey). */
  r_assert_cmpptr ((dec = r_srtp_decrypt_rtp (b, enc, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (dec, 0, -1, ==, pkt_rtp_opus, sizeof (pkt_rtp_opus));
  r_buffer_unref (dec);

  r_buffer_unref (enc);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (a);
  r_srtp_ctx_unref (b);
}
RTEST_END;

/* RFC 6904 Appendix A: AES-CM header-extension encryption. The key is the
 * RFC 3711 Appendix B.3 master key (16 bytes) followed by the master salt
 * (14 bytes), matching how a crypto context is keyed. */
static const ruint8 rfc6904_key[] = {
  0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
  0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
};

/* SSRC 0xcafebabe, seq 0x1234, ROC 0, one-byte (0xBEDE) extension of six
 * words holding elements with IDs 1..4, then an 8-byte payload. */
static const ruint8 rfc6904_rtp[] = {
  0x90, 0x00, 0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
  0xbe, 0xde, 0x00, 0x06,
  0x17, 0x41, 0x42, 0x73, 0xa4, 0x75, 0x26, 0x27, 0x48, 0x22, 0x00, 0x00, 0xc8, 0x30, 0x8e, 0x46,
  0x55, 0x99, 0x63, 0x86, 0xb3, 0x95, 0xfb, 0x00,
  0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x01
};

/* The extension bodies of IDs 1, 3 and 4 encrypted; ID 2's body (0000c8),
 * every element header and the trailing padding byte stay in the clear. */
static const ruint8 rfc6904_ext_cipher[] = {
  0x17, 0x58, 0x8a, 0x92, 0x70, 0xf4, 0xe1, 0x5e, 0x1c, 0x22, 0x00, 0x00, 0xc8, 0x30, 0x95, 0x46,
  0xa9, 0x94, 0xf0, 0xbc, 0x54, 0x78, 0x97, 0x00
};

static void
rfc6904_add_ids (RSRTPCtx * ctx)
{
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (ctx, 1, TRUE), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (ctx, 3, TRUE), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (ctx, 4, TRUE), ==, R_SRTP_ERROR_OK);
}

RTEST (rsrtp, hdr_ext_bad_id, RTEST_FAST)
{
  RSRTPCtx * ctx;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (NULL, 1, TRUE), ==, R_SRTP_ERROR_INVAL);
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (ctx, 0, TRUE), ==, R_SRTP_ERROR_INVAL);
  /* Clearing an ID on a context that never enabled encryption is a no-op. */
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (ctx, 5, FALSE), ==, R_SRTP_ERROR_OK);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, encrypt_hdr_ext_rfc6904, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf, * res;
  RSRTPError err;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);
  rfc6904_add_ids (ctx);

  r_assert_cmpptr ((buf = r_buffer_new_dup (rfc6904_rtp, sizeof (rfc6904_rtp))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);

  /* The 4-byte extension header (BEDE 0006) is not encrypted. */
  r_assert_cmpbufmem (res, 12, 4, ==, rfc6904_rtp + 12, 4);
  /* The 24-byte extension data matches the RFC 6904 A.2 ciphertext exactly. */
  r_assert_cmpbufmem (res, 16, sizeof (rfc6904_ext_cipher), ==,
      rfc6904_ext_cipher, sizeof (rfc6904_ext_cipher));

  r_buffer_unref (res);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, hdr_ext_roundtrip, RTEST_FAST)
{
  RSRTPCtx * enc, * dec;
  RBuffer * buf, * res, * out;
  RSRTPError err;

  /* Distinct contexts: encrypt marks the stream outbound, decrypt inbound. */
  r_assert_cmpptr ((enc = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpptr ((dec = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (enc, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (dec, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);
  rfc6904_add_ids (enc);
  rfc6904_add_ids (dec);

  r_assert_cmpptr ((buf = r_buffer_new_dup (rfc6904_rtp, sizeof (rfc6904_rtp))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (enc, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (res, 16, sizeof (rfc6904_ext_cipher), ==,
      rfc6904_ext_cipher, sizeof (rfc6904_ext_cipher));

  /* Decrypting restores the original packet, extension and all. */
  r_assert_cmpptr ((out = r_srtp_decrypt_rtp (dec, res, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (out, 0, -1, ==, rfc6904_rtp, sizeof (rfc6904_rtp));

  r_buffer_unref (out);
  r_buffer_unref (res);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (enc);
  r_srtp_ctx_unref (dec);
}
RTEST_END;

RTEST (rsrtp, hdr_ext_auth_covers_ciphertext, RTEST_FAST)
{
  RSRTPCtx * enc, * dec;
  RBuffer * buf, * res, * tampered;
  RSRTPError err;
  ruint8 raw[128];
  rsize size;

  r_assert_cmpptr ((enc = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpptr ((dec = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (enc, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (dec, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);
  rfc6904_add_ids (enc);
  rfc6904_add_ids (dec);

  r_assert_cmpptr ((buf = r_buffer_new_dup (rfc6904_rtp, sizeof (rfc6904_rtp))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (enc, buf, &err)), !=, NULL);

  /* Flip a byte of the encrypted extension: the auth tag covers the encrypted
   * form (RFC 6904), so verification must fail before any decryption. */
  size = r_buffer_get_size (res);
  r_assert_cmpuint (r_buffer_extract (res, 0, raw, size), ==, size);
  raw[16] ^= 0xff;
  r_assert_cmpptr ((tampered = r_buffer_new_dup (raw, size)), !=, NULL);
  r_assert_cmpptr (r_srtp_decrypt_rtp (dec, tampered, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_AUTH);

  r_buffer_unref (tampered);
  r_buffer_unref (res);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (enc);
  r_srtp_ctx_unref (dec);
}
RTEST_END;

RTEST (rsrtp, hdr_ext_late_registration_ignored, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf, * res;
  RSRTPError err;
  ruint8 raw[sizeof (rfc6904_rtp)];

  /* The per-stream keys are derived when the stream is first used, so an ID
   * registered after that has no effect on the existing stream: its extension
   * stays in the clear. This documents the "configure before traffic" contract. */
  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);

  /* First packet creates the stream while no IDs are registered. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rfc6904_rtp, sizeof (rfc6904_rtp))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (res, 16, 24, ==, rfc6904_rtp + 16, 24);
  r_buffer_unref (res);
  r_buffer_unref (buf);

  /* Registering now must not retroactively key the already-created stream. */
  rfc6904_add_ids (ctx);
  r_memcpy (raw, rfc6904_rtp, sizeof (rfc6904_rtp));
  raw[3] = 0x35;                 /* bump the sequence so it is not a replay */
  r_assert_cmpptr ((buf = r_buffer_new_dup (raw, sizeof (raw))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (res, 16, 24, ==, rfc6904_rtp + 16, 24);
  r_buffer_unref (res);
  r_buffer_unref (buf);

  r_srtp_ctx_unref (ctx);
}
RTEST_END;

/* Two-byte header form (profile 0x100x): ID 1 len 4 (deadbeef) then padding. */
static const ruint8 twobyte_rtp[] = {
  0x90, 0x00, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe,
  0x10, 0x00, 0x00, 0x02,
  0x01, 0x04, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00,
  0xaa, 0xbb, 0xcc, 0xdd
};

RTEST (rsrtp, hdr_ext_twobyte_roundtrip, RTEST_FAST)
{
  RSRTPCtx * enc, * dec;
  RBuffer * buf, * res, * out;
  RSRTPError err;
  ruint8 raw[128];

  r_assert_cmpptr ((enc = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpptr ((dec = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (enc, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (dec, 0xcafebabe,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, rfc6904_key), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (enc, 1, TRUE), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_set_encrypted_header_extension (dec, 1, TRUE), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (twobyte_rtp, sizeof (twobyte_rtp))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (enc, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);

  /* The 2-byte element header (01 04) and the trailing padding stay clear,
   * while the 4-byte body is transformed. */
  r_assert_cmpbufmem (res, 16, 2, ==, twobyte_rtp + 16, 2);
  r_assert_cmpuint (r_buffer_extract (res, 0, raw, r_buffer_get_size (res)), >, 0);
  r_assert_cmpmem (raw + 18, !=, twobyte_rtp + 18, 4);

  r_assert_cmpptr ((out = r_srtp_decrypt_rtp (dec, res, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (out, 0, -1, ==, twobyte_rtp, sizeof (twobyte_rtp));

  r_buffer_unref (out);
  r_buffer_unref (res);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (enc);
  r_srtp_ctx_unref (dec);
}
RTEST_END;

/* MKI (RFC 3711 3.1) tags each master key so a context can roll keys. */
static const ruint8 mki4_one[] = { 0x00, 0x00, 0x00, 0x01 };
static const ruint8 mkiA[] = { 0xaa, 0xaa };
static const ruint8 mkiB[] = { 0xbb, 0xbb };

/* Two staged keys sharing an ssrc: MKI A -> masterkey, MKI B -> masterkey2,
 * each keyed identically in both directions so enc/dec contexts mirror. */
static void
mki_add_two (RSRTPCtx * ctx)
{
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, sizeof (mkiA),
        masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_master_key (ctx, ssrc,
        masterkey2, masterkey2, mkiB), ==, R_SRTP_ERROR_OK);
}

RTEST (rsrtp, mki_invalid_args, RTEST_FAST)
{
  RSRTPCtx * ctx;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);

  /* Bad ctx / size / NULL MKI on the constructor. */
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (NULL, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, 2, masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_INVAL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, 0, masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_INVAL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, R_SRTP_MAX_MKI_SIZE + 1,
        masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_INVAL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, 2, masterkey, masterkey, NULL), ==, R_SRTP_ERROR_INVAL);

  /* Staging a key on a missing context, or on one that has no MKI. */
  r_assert_cmpint (r_srtp_add_master_key (ctx, 0xdeadbeef,
        masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_NO_CRYPTO_CTX);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, 0x1234,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_master_key (ctx, 0x1234,
        masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_NO_CRYPTO_CTX);

  /* A real MKI context: duplicate MKI and unknown send selection are refused. */
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, 2, masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_master_key (ctx, ssrc,
        masterkey2, masterkey2, mkiA), ==, R_SRTP_ERROR_CRYPTO_CTX_EXISTS);
  r_assert_cmpint (r_srtp_set_send_master_key (ctx, ssrc, mkiB), ==, R_SRTP_ERROR_NO_CRYPTO_CTX);
  r_assert_cmpint (r_srtp_add_master_key (ctx, ssrc,
        masterkey2, masterkey2, mkiB), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_set_send_master_key (ctx, ssrc, mkiB), ==, R_SRTP_ERROR_OK);

  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, mki_rtp_wire, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf, * res;
  RSRTPError err;
  rsize plain = sizeof (pkt_srtp_aes_128_cm_opus);
  rsize tag = 10;                  /* HMAC-SHA1-80 */

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, sizeof (mki4_one),
        masterkey, masterkey, mki4_one), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sizeof (pkt_rtp_opus))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);

  /* The MKI is inserted between the ciphertext and the auth tag, and the tag
   * does not cover it (RFC 3711 3.1). So header, ext, ciphertext and tag are
   * byte-for-byte the non-MKI vector, only pushed apart by the MKI. */
  r_assert_cmpuint (r_buffer_get_size (res), ==, plain + sizeof (mki4_one));
  r_assert_cmpbufmem (res, 0, plain - tag, ==, pkt_srtp_aes_128_cm_opus, plain - tag);
  r_assert_cmpbufmem (res, plain - tag, sizeof (mki4_one), ==, mki4_one, sizeof (mki4_one));
  r_assert_cmpbufmem (res, plain - tag + sizeof (mki4_one), tag, ==,
      pkt_srtp_aes_128_cm_opus + plain - tag, tag);

  r_buffer_unref (res);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtp, mki_rollover, RTEST_FAST)
{
  RSRTPCtx * enc, * dec;
  RBuffer * buf, * res, * out;
  RSRTPError err;
  ruint8 raw[sizeof (pkt_rtp_opus)];
  rsize sz = sizeof (pkt_rtp_opus);
  rsize tag = 10, mkipos;

  r_assert_cmpptr ((enc = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpptr ((dec = r_srtp_ctx_new ()), !=, NULL);
  mki_add_two (enc);
  mki_add_two (dec);

  /* First generation: the sender defaults to the first key (MKI A). */
  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sz)), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (enc, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  mkipos = r_buffer_get_size (res) - tag - sizeof (mkiA);
  r_assert_cmpbufmem (res, mkipos, sizeof (mkiA), ==, mkiA, sizeof (mkiA));
  r_assert_cmpptr ((out = r_srtp_decrypt_rtp (dec, res, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (out, 0, -1, ==, pkt_rtp_opus, sz);
  r_buffer_unref (out);
  r_buffer_unref (res);
  r_buffer_unref (buf);

  /* Roll the sender to MKI B; the receiver follows by reading the MKI, and the
   * same context (replay window, ROC) carries over the key change. */
  r_assert_cmpint (r_srtp_set_send_master_key (enc, ssrc, mkiB), ==, R_SRTP_ERROR_OK);
  r_memcpy (raw, pkt_rtp_opus, sz);
  raw[3] = 0xce;                   /* bump the sequence so it is not a replay */
  r_assert_cmpptr ((buf = r_buffer_new_dup (raw, sz)), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (enc, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  mkipos = r_buffer_get_size (res) - tag - sizeof (mkiB);
  r_assert_cmpbufmem (res, mkipos, sizeof (mkiB), ==, mkiB, sizeof (mkiB));
  r_assert_cmpptr ((out = r_srtp_decrypt_rtp (dec, res, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (out, 0, -1, ==, raw, sz);
  r_buffer_unref (out);
  r_buffer_unref (res);
  r_buffer_unref (buf);

  r_srtp_ctx_unref (enc);
  r_srtp_ctx_unref (dec);
}
RTEST_END;

RTEST (rsrtp, mki_rollover_key_index_independent, RTEST_FAST)
{
  RSRTPCtx * a, * c;
  RBuffer * buf, * ra, * rc;
  RSRTPError err;
  ruint8 raw[sizeof (pkt_rtp_opus)];
  rsize sz = sizeof (pkt_rtp_opus);
  ruint8 pa[256], pc[256];
  rsize na, nc;

  /* A rolls to MKI B before sending anything, so B is derived at stream
   * index 0. */
  r_assert_cmpptr ((a = r_srtp_ctx_new ()), !=, NULL);
  mki_add_two (a);
  r_assert_cmpint (r_srtp_set_send_master_key (a, ssrc, mkiB), ==, R_SRTP_ERROR_OK);
  r_memcpy (raw, pkt_rtp_opus, sz);
  raw[2] = 0x41; raw[3] = 0xff;    /* seq 0x41ff */
  r_assert_cmpptr ((buf = r_buffer_new_dup (raw, sz)), !=, NULL);
  r_assert_cmpptr ((ra = r_srtp_encrypt_rtp (a, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_buffer_unref (buf);

  /* C sends once with MKI A (advancing its index), then rolls to B and sends
   * the same seq. The B key is thus re-derived at a nonzero index. Session-key
   * derivation must not depend on the packet index (RFC 3711 4.3.1, KDR 0), so
   * the same plaintext / SSRC / index / master key must encrypt identically. */
  r_assert_cmpptr ((c = r_srtp_ctx_new ()), !=, NULL);
  mki_add_two (c);
  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sz)), !=, NULL);   /* seq 0x41cd, MKI A */
  r_assert_cmpptr ((rc = r_srtp_encrypt_rtp (c, buf, &err)), !=, NULL);
  r_buffer_unref (rc);
  r_buffer_unref (buf);
  r_assert_cmpint (r_srtp_set_send_master_key (c, ssrc, mkiB), ==, R_SRTP_ERROR_OK);
  r_assert_cmpptr ((buf = r_buffer_new_dup (raw, sz)), !=, NULL);            /* seq 0x41ff, MKI B */
  r_assert_cmpptr ((rc = r_srtp_encrypt_rtp (c, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_buffer_unref (buf);

  na = r_buffer_extract (ra, 0, pa, sizeof (pa));
  nc = r_buffer_extract (rc, 0, pc, sizeof (pc));
  r_assert_cmpuint (na, ==, nc);
  r_assert_cmpmem (pa, ==, pc, na);

  r_buffer_unref (ra);
  r_buffer_unref (rc);
  r_srtp_ctx_unref (a);
  r_srtp_ctx_unref (c);
}
RTEST_END;

RTEST (rsrtp, mki_unknown_rejected, RTEST_FAST)
{
  RSRTPCtx * enc, * dec;
  RBuffer * buf, * res;
  RSRTPError err;

  /* enc knows A and B and sends with B; dec only knows A. */
  r_assert_cmpptr ((enc = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpptr ((dec = r_srtp_ctx_new ()), !=, NULL);
  mki_add_two (enc);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (dec, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, sizeof (mkiA),
        masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_set_send_master_key (enc, ssrc, mkiB), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sizeof (pkt_rtp_opus))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtp (enc, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);

  /* dec has no master key for MKI B: rejected before any auth/decrypt. */
  r_assert_cmpptr (r_srtp_decrypt_rtp (dec, res, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_NO_CRYPTO_CTX);

  r_buffer_unref (res);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (enc);
  r_srtp_ctx_unref (dec);
}
RTEST_END;

RTEST (rsrtcp, decrypt_aes_128_cm, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf, * res;
  RSRTPError err;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * packet;
  RRTCPSenderInfo srinfo;
  RRTCPSDESChunk * chunk;
  RRTCPSDESItem item = R_RTCP_SDES_ITEM_INIT;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);

  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_srtcp_aes_128_cm, sizeof (pkt_srtcp_aes_128_cm))), !=, NULL);

  r_assert_cmpptr ((res = r_srtp_decrypt_rtcp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (res, 0, -1, ==, pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes));


  r_assert (r_rtcp_buffer_map (&rtcp, res, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 2);
  r_assert_cmpptr ((packet = r_rtcp_buffer_get_first_packet (&rtcp)), !=, NULL);
  r_assert_cmpint (r_rtcp_packet_get_type (packet), ==, R_RTCP_PT_SR);
  r_assert_cmpuint (r_rtcp_packet_get_count (packet), ==, 0);
  r_assert (r_rtcp_packet_sr_get_sender_info (packet, &srinfo));
  r_assert_cmphex (srinfo.ssrc, ==, ssrc);
  r_assert_cmpuint (srinfo.ntptime, ==, RUINT64_CONSTANT (0xdc2327b2ac348f54));
  r_assert_cmpuint (srinfo.rtptime, ==, 0x5550cd92);
  r_assert_cmpuint (srinfo.packets, ==, 5);
  r_assert_cmpuint (srinfo.bytes, ==, 0x0175);

  r_assert_cmpptr ((packet = r_rtcp_buffer_get_next_packet (&rtcp, packet)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_count (packet), ==, 1);
  r_assert_cmpint (r_rtcp_packet_get_type (packet), ==, R_RTCP_PT_SDES);
  r_assert_cmpptr ((chunk = r_rtcp_packet_sdes_get_first_chunk (packet)), !=, NULL);
  r_assert_cmphex (r_rtcp_packet_sdes_chunk_get_ssrc (packet, chunk), ==, 0xb476823a);
  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (packet, chunk, &item), ==, R_RTCP_PARSE_OK);
  r_assert_cmphex (item.type, ==, R_RTCP_SDES_CNAME);
  r_assert_cmpuint (item.len, ==, 16);
  r_assert_cmpmem (item.data, ==, cname, item.len);

  r_assert (r_rtcp_buffer_unmap (&rtcp, res));
  r_buffer_unref (res);

  /* Replaying the packet should yield R_SRTP_ERROR_REPLAYED */
  r_assert_cmpptr ((res = r_srtp_decrypt_rtcp (ctx, buf, &err)), ==, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_REPLAYED);

  r_buffer_unref (buf);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtcp, encrypt_aes_128_cm, RTEST_FAST)
{
  RSRTPCtx * ctx;
  RBuffer * buf, * res;
  RSRTPError err;

  r_assert_cmpptr ((ctx = r_srtp_ctx_new ()), !=, NULL);

  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc (ctx, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, masterkey), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes))), !=, NULL);

  r_assert_cmpptr ((res = r_srtp_encrypt_rtcp (ctx, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (res, 0, -1, ==, pkt_srtcp_aes_128_cm, sizeof (pkt_srtcp_aes_128_cm));
  r_buffer_unref (res);

  r_buffer_unref (buf);
  r_srtp_ctx_unref (ctx);
}
RTEST_END;

RTEST (rsrtcp, mki_roundtrip, RTEST_FAST)
{
  RSRTPCtx * enc, * dec;
  RBuffer * buf, * res, * out;
  RSRTPError err;

  r_assert_cmpptr ((enc = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpptr ((dec = r_srtp_ctx_new ()), !=, NULL);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (enc, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, sizeof (mkiA),
        masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_OK);
  r_assert_cmpint (r_srtp_add_crypto_context_for_ssrc_with_mki (dec, ssrc,
        R_SRTP_CS_AES_128_CM_HMAC_SHA1_80, sizeof (mkiA),
        masterkey, masterkey, mkiA), ==, R_SRTP_ERROR_OK);

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes))), !=, NULL);
  r_assert_cmpptr ((res = r_srtp_encrypt_rtcp (enc, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  /* The MKI sits just before the 10-byte auth tag (RFC 3711 3.4). */
  r_assert_cmpbufmem (res, r_buffer_get_size (res) - 10 - sizeof (mkiA),
      sizeof (mkiA), ==, mkiA, sizeof (mkiA));

  r_assert_cmpptr ((out = r_srtp_decrypt_rtcp (dec, res, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_SRTP_ERROR_OK);
  r_assert_cmpbufmem (out, 0, -1, ==, pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes));

  r_buffer_unref (out);
  r_buffer_unref (res);
  r_buffer_unref (buf);
  r_srtp_ctx_unref (enc);
  r_srtp_ctx_unref (dec);
}
RTEST_END;

