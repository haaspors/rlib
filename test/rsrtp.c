#include <rlib/rlib.h>

/* SRTP-AES-128-CM-HMAC-SHA1-80 */
/* a=ssrc:3027665466 cname:ceiNLmy6VHSE5Ja7 */
static const ruint8 masterkey[] = {
  0x3c, 0x39, 0xa8, 0x5c, 0x2d, 0xf0, 0x5e, 0x52, 0x7e, 0x79, 0x12, 0xba, 0x60, 0xc5, 0x25, 0xfe,
  0x29, 0xf7, 0x97, 0xd9, 0xda, 0xa3, 0x17, 0x60, 0xdf, 0x34, 0xb9, 0x5f, 0x87, 0xd3
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

