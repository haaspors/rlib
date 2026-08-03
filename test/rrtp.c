#include <rlib/rnet.h>

static const ruint8 pkt_stun[] = {
  0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x46, 0x76, 0x41, 0x31, 0x65, 0x6d, 0x75, 0x49,
  0x73, 0x6b, 0x4e, 0x59
};

static const ruint8 pkt_rtp_pcmu[] = {
  0x80, 0x80, 0x92, 0xdb, 0x00, 0x00, 0x00, 0xa0, 0x34, 0x3d, 0xa9, 0x9b, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0x7f,
  0xff, 0x7f, 0x7f, 0xff, 0xff, 0x7f, 0x7f, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfe, 0x7e, 0xfd, 0x7d,
  0xfd, 0x7e, 0x75, 0xfc, 0x73, 0x75, 0xfe, 0x71, 0x7b, 0x7e, 0x7a, 0xfc, 0xfd, 0xf9, 0xfb, 0xfb,
  0xf6, 0xff, 0xf9, 0xf8, 0x7c, 0xfa, 0xfd, 0x7d, 0xfc, 0xff, 0x7e, 0xfe, 0xfe, 0xfe, 0x7e, 0xfd,
  0x7e, 0x7d, 0xfe, 0x7c, 0x7c, 0x7d, 0x7a, 0x7b, 0x7b, 0x7c, 0x7d, 0x7f, 0xfd, 0xfb, 0xf8, 0xf5,
  0xf4, 0xf1, 0xf0, 0xf1, 0xf0, 0xf2, 0xf5, 0xf7, 0xfb, 0xff, 0x7a, 0x76, 0x71, 0x6e, 0x6d, 0x6b,
  0x6b, 0x6b, 0x6b, 0x6c, 0x6e, 0x70, 0x75, 0x7c, 0xf9, 0xf2, 0xeb, 0xe8, 0xe3, 0xdf, 0xde, 0xdb,
  0xe3, 0xdf, 0xe4, 0x7e, 0xf4, 0x6f, 0x62, 0x66, 0x5e, 0x5e, 0x5f, 0x60
};

static const ruint8 pkt_rtcp_sr_sdes[] = {
  0x80, 0xc8, 0x00, 0x06, 0xf3, 0xcb, 0x20, 0x01, 0x83, 0xab, 0x03, 0xa1, 0xeb, 0x02, 0x0b, 0x3a,
  0x00, 0x00, 0x94, 0x20, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x9b, 0x88,
  0x81, 0xca, 0x00, 0x05, 0xf3, 0xcb, 0x20, 0x01, 0x01, 0x0a, 0x6f, 0x75, 0x74, 0x43, 0x68, 0x61,
  0x6e, 0x6e, 0x65, 0x6c, 0x00, 0x00, 0x00, 0x00
};

static const ruint8 pkt_rtcp_rr_bye[] = {
  0x81, 0xc9, 0x00, 0x07, 0x16, 0x6a, 0xe2, 0x87, 0x87, 0x54, 0x14, 0xdb, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x16, 0x4c, 0x00, 0x00, 0x02, 0x02, 0xb9, 0x41, 0x7d, 0x6a, 0x00, 0x05, 0xbc, 0x26,
  0x81, 0xcb, 0x00, 0x01, 0x16, 0x6a, 0xe2, 0x87
};

static const ruint8 pkt_rtp_opus[] = {
  0x90, 0x6f, 0x3d, 0x82, 0x76, 0x95, 0x0f, 0x20, 0xcf, 0xe9, 0x0c, 0xfe, 0xbe, 0xde, 0x00, 0x02,
  0x32, 0x64, 0x9f, 0xf9, 0x10, 0x97, 0x00, 0x00, 0xaa, 0x59, 0x08, 0xeb, 0x1b, 0xcd, 0xc4, 0xeb,
  0xec, 0x72, 0x2d, 0xd9, 0x37, 0xd5, 0x92, 0x86, 0x4e, 0xd7, 0x8d, 0x6f, 0xed, 0xbf, 0x42, 0x67,
  0xfc, 0x12, 0xfb, 0x0f, 0x2a, 0xb5, 0xad, 0xb2, 0xcb, 0x32, 0x4a, 0x49, 0x63, 0x3c, 0x19, 0x4c,
  0xe3, 0x18, 0xe1, 0x53, 0xc0, 0x70, 0x4d, 0x84, 0x3c, 0x36, 0xfa, 0xfe, 0xf8, 0x93, 0x5c, 0x78,
  0x0e, 0x73, 0xcf, 0x9d, 0x4b, 0x9e, 0x42, 0x17, 0x89, 0xba, 0x18, 0xaa, 0xbb, 0xbb, 0x15, 0x33,
  0x6a, 0x2d, 0xd6, 0x86, 0x0b, 0x21, 0xf5, 0x63, 0x17, 0x17, 0xef, 0x8e, 0x83, 0x13, 0x04, 0xe6,
  0x8d, 0xd2, 0xcd, 0x56, 0x46, 0x95, 0xa1, 0x50, 0xf2, 0xda, 0x90, 0x36, 0x89, 0xc8
};


RTEST (rrtp, is_valid_hdr, RTEST_FAST)
{
  r_assert (!r_rtp_is_valid_hdr (pkt_stun, sizeof (pkt_stun)));
  r_assert (r_rtp_is_valid_hdr (pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu)));
  r_assert (!r_rtp_is_valid_hdr (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes)));
}
RTEST_END;

RTEST (rrtcp, feedback_pli_nack_wire, RTEST_FAST)
{
  /* PSFB/PLI (no FCI) followed by RTPFB/Generic-NACK (one FCI entry). */
  static const ruint8 golden[] = {
    0x81, 0xce, 0x00, 0x02,                          /* PSFB FMT=PLI, len=2 */
    0xaa, 0xaa, 0x00, 0x01,                          /* sender */
    0xbb, 0xbb, 0x00, 0x02,                          /* media */
    0x81, 0xcd, 0x00, 0x03,                          /* RTPFB FMT=NACK, len=3 */
    0xaa, 0xaa, 0x00, 0x01,                          /* sender */
    0xbb, 0xbb, 0x00, 0x02,                          /* media */
    0x12, 0x34, 0x00, 0xff                           /* FCI: PID, BLP */
  };
  ruint8 nackfci[4];
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  const ruint8 * fci;
  ruint16 fcisize = 0;

  r_store_be16 (&nackfci[0], 0x1234);
  r_store_be16 (&nackfci[2], 0x00ff);

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_fb (buf, R_RTCP_PT_PSFB, R_RTCP_PSFB_FMT_PLI, 0xaaaa0001, 0xbbbb0002, NULL, 0));
  r_assert (r_rtcp_buffer_add_fb (buf, R_RTCP_PT_RTPFB, R_RTCP_RTPFB_FMT_NACK, 0xaaaa0001, 0xbbbb0002, nackfci, 4));
  r_assert_cmpbufmem (buf, 0, -1, ==, golden, sizeof (golden));
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (golden, sizeof (golden))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 2);
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_PSFB);
  r_assert_cmpuint (r_rtcp_packet_fb_get_fmt (pkt), ==, R_RTCP_PSFB_FMT_PLI);
  r_assert_cmphex (r_rtcp_packet_fb_get_sender_ssrc (pkt), ==, 0xaaaa0001);
  r_assert_cmphex (r_rtcp_packet_fb_get_media_ssrc (pkt), ==, 0xbbbb0002);
  r_rtcp_packet_fb_get_fci (pkt, &fcisize);
  r_assert_cmpuint (fcisize, ==, 0);
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, pkt)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_RTPFB);
  r_assert_cmpuint (r_rtcp_packet_fb_get_fmt (pkt), ==, R_RTCP_RTPFB_FMT_NACK);
  r_assert_cmpptr ((fci = r_rtcp_packet_fb_get_fci (pkt, &fcisize)), !=, NULL);
  r_assert_cmpuint (fcisize, ==, 4);
  r_assert_cmpmem (fci, ==, nackfci, 4);
  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, bye_no_reason_wire, RTEST_FAST)
{
  /* BYE with a single SSRC and no reason string. */
  static const ruint8 golden[] = {
    0x81, 0xcb, 0x00, 0x01,                          /* V2 SC1, PT=BYE, len=1 */
    0x11, 0x11, 0x11, 0x11                           /* ssrc */
  };
  ruint32 ssrcs[1] = { 0x11111111 };
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  ruint8 rlen = 0xaa;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_bye (buf, ssrcs, 1, NULL));
  r_assert_cmpbufmem (buf, 0, -1, ==, golden, sizeof (golden));
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (golden, sizeof (golden))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_BYE);
  r_assert_cmpuint (r_rtcp_packet_bye_get_ssrc_count (pkt), ==, 1);
  r_assert_cmphex (r_rtcp_packet_bye_get_ssrc (pkt, 0), ==, 0x11111111);
  /* no reason present */
  r_assert_cmpint (r_rtcp_packet_bye_get_reason (pkt, NULL, 0, &rlen), ==, R_RTCP_PARSE_ZERO);
  r_assert_cmpuint (rlen, ==, 0);
  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, app_wire, RTEST_FAST)
{
  static const ruint8 golden[] = {
    0x83, 0xcc, 0x00, 0x04,                          /* V2 subtype=3, PT=APP, len=4 */
    0x33, 0x33, 0x33, 0x33,                          /* ssrc */
    0x50, 0x49, 0x4e, 0x47,                          /* "PING" */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08   /* data */
  };
  static const ruint8 appdata[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  const ruint8 * adata;
  ruint16 asize = 0;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_app (buf, 3, 0x33333333, "PING", appdata, sizeof (appdata)));
  r_assert_cmpbufmem (buf, 0, -1, ==, golden, sizeof (golden));
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (golden, sizeof (golden))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_APP);
  r_assert_cmpuint (r_rtcp_packet_get_count (pkt), ==, 3);
  r_assert_cmphex (r_rtcp_packet_app_get_ssrc (pkt), ==, 0x33333333);
  r_assert_cmpmem (r_rtcp_packet_app_get_name (pkt), ==, "PING", 4);
  r_assert_cmpptr ((adata = r_rtcp_packet_app_get_data (pkt, &asize)), !=, NULL);
  r_assert_cmpuint (asize, ==, sizeof (appdata));
  r_assert_cmpmem (adata, ==, appdata, sizeof (appdata));
  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, xr_dlrr_wire, RTEST_FAST)
{
  /* Extended Report (RFC 3611) with a DLRR block (two sub-blocks, so two
   * source SSRCs) followed by a Receiver Reference Time block (no source). */
  static const ruint8 pkt[] = {
    0x80, 0xcf, 0x00, 0x0b,                          /* V2, PT=XR (207), len=11 */
    0xaa, 0xaa, 0x00, 0x01,                          /* reporter SSRC */
    0x05, 0x00, 0x00, 0x06,                          /* DLRR, block length 6 words */
    0xbb, 0xbb, 0x00, 0x02,                          /* sub-block 1 SSRC */
    0x00, 0x00, 0x00, 0x00,                          /*   last RR */
    0x00, 0x00, 0x00, 0x00,                          /*   delay since last RR */
    0xbb, 0xbb, 0x00, 0x03,                          /* sub-block 2 SSRC */
    0x00, 0x00, 0x00, 0x00,                          /*   last RR */
    0x00, 0x00, 0x00, 0x00,                          /*   delay since last RR */
    0x04, 0x00, 0x00, 0x02,                          /* RRT, block length 2 words */
    0x00, 0x00, 0x00, 0x00,                          /*   NTP timestamp (high) */
    0x00, 0x00, 0x00, 0x00                           /*   NTP timestamp (low) */
  };
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt_p;
  RRTCPXRBlock * block;

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt, sizeof (pkt))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 1);
  r_assert_cmpptr ((pkt_p = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt_p), ==, R_RTCP_PT_XR);
  r_assert_cmphex (r_rtcp_packet_get_ssrc (pkt_p), ==, 0xaaaa0001);

  r_assert_cmpptr ((block = r_rtcp_packet_xr_get_first_block (pkt_p)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_xr_block_get_type (block), ==, R_RTCP_XR_BT_DLRR);
  r_assert_cmpuint (r_rtcp_packet_xr_block_get_length (block), ==, 24);
  r_assert_cmpuint (r_rtcp_packet_xr_block_get_ssrc_count (pkt_p, block), ==, 2);
  r_assert_cmphex (r_rtcp_packet_xr_block_get_ssrc (pkt_p, block, 0), ==, 0xbbbb0002);
  r_assert_cmphex (r_rtcp_packet_xr_block_get_ssrc (pkt_p, block, 1), ==, 0xbbbb0003);
  r_assert_cmphex (r_rtcp_packet_xr_block_get_ssrc (pkt_p, block, 2), ==, 0);

  r_assert_cmpptr ((block = r_rtcp_packet_xr_get_next_block (pkt_p, block)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_xr_block_get_type (block), ==, R_RTCP_XR_BT_RRT);
  r_assert_cmpuint (r_rtcp_packet_xr_block_get_ssrc_count (pkt_p, block), ==, 0);
  r_assert_cmphex (r_rtcp_packet_xr_block_get_ssrc (pkt_p, block, 0), ==, 0);

  r_assert_cmpptr (r_rtcp_packet_xr_get_next_block (pkt_p, block), ==, NULL);

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, sdes_two_items_wire, RTEST_FAST)
{
  /* SDES chunk with two items (CNAME + TOOL). */
  static const ruint8 golden[] = {
    0x81, 0xca, 0x00, 0x04,                          /* V2 SC1, PT=SDES, len=4 */
    0xca, 0xfe, 0xf0, 0x0d,                          /* chunk ssrc */
    0x01, 0x03, 0x61, 0x62, 0x63,                    /* CNAME "abc" */
    0x06, 0x04, 0x72, 0x6c, 0x69, 0x62,              /* TOOL "rlib" */
    0x00                                             /* terminator (already word-aligned) */
  };
  static const ruint8 cname[] = "abc";
  static const ruint8 tool[] = "rlib";
  RRTCPSDESItem items[2];
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  RRTCPSDESChunk * chunk;
  RRTCPSDESItem item = R_RTCP_SDES_ITEM_INIT;

  items[0].type = R_RTCP_SDES_CNAME; items[0].len = 3; items[0].data = (ruint8 *) cname;
  items[1].type = R_RTCP_SDES_TOOL;  items[1].len = 4; items[1].data = (ruint8 *) tool;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_sdes (buf, 0xcafef00d, items, 2));
  r_assert_cmpbufmem (buf, 0, -1, ==, golden, sizeof (golden));
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (golden, sizeof (golden))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_SDES);
  r_assert_cmpptr ((chunk = r_rtcp_packet_sdes_get_next_chunk (pkt, NULL)), !=, NULL);
  r_assert_cmphex (r_rtcp_packet_sdes_chunk_get_ssrc (pkt, chunk), ==, 0xcafef00d);
  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (pkt, chunk, &item), ==, R_RTCP_PARSE_OK);
  r_assert_cmpuint (item.type, ==, R_RTCP_SDES_CNAME);
  r_assert_cmpmem (item.data, ==, cname, 3);
  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (pkt, chunk, &item), ==, R_RTCP_PARSE_OK);
  r_assert_cmpuint (item.type, ==, R_RTCP_SDES_TOOL);
  r_assert_cmpmem (item.data, ==, tool, 4);
  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (pkt, chunk, &item), ==, R_RTCP_PARSE_ZERO);
  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, sr_sender_only_wire, RTEST_FAST)
{
  /* SR with no report blocks (RC=0): serialize to exact wire bytes, and parse
   * the same bytes back -- each side checked against the spec independently. */
  static const ruint8 golden[] = {
    0x80, 0xc8, 0x00, 0x06,                          /* V2 RC0, PT=SR, len=6 */
    0x11, 0x22, 0x33, 0x44,                          /* ssrc */
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  /* ntp */
    0xde, 0xad, 0xbe, 0xef,                          /* rtptime */
    0x00, 0x00, 0x00, 0x64,                          /* packets = 100 */
    0x00, 0x00, 0x4e, 0x20                           /* bytes = 20000 */
  };
  /* field order: ssrc, rtptime, ntptime, packets, bytes */
  RRTCPSenderInfo si = { 0x11223344, 0xdeadbeef, 0x0102030405060708, 100, 20000 };
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  RRTCPSenderInfo gsi;
  RRTCPReportBlock grb;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_sr (buf, &si, NULL, 0));
  r_assert_cmpbufmem (buf, 0, -1, ==, golden, sizeof (golden));
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (golden, sizeof (golden))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_SR);
  r_assert_cmpuint (r_rtcp_packet_get_count (pkt), ==, 0);
  r_assert (r_rtcp_packet_sr_get_sender_info (pkt, &gsi));
  r_assert_cmphex (gsi.ssrc, ==, 0x11223344);
  r_assert_cmphex (gsi.ntptime, ==, 0x0102030405060708);
  r_assert_cmphex (gsi.rtptime, ==, 0xdeadbeef);
  r_assert_cmpuint (gsi.packets, ==, 100);
  r_assert_cmpuint (gsi.bytes, ==, 20000);
  r_assert (!r_rtcp_packet_sr_get_report_block (pkt, 0, &grb));
  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, rr_two_blocks_wire, RTEST_FAST)
{
  /* RR with two report blocks (RC=2): exercises the idx>0 block offsets. */
  static const ruint8 golden[] = {
    0x82, 0xc9, 0x00, 0x0d,                          /* V2 RC2, PT=RR, len=13 */
    0x99, 0xaa, 0xbb, 0xcc,                          /* reporter ssrc */
    0x55, 0x66, 0x77, 0x88,                          /* rb0 ssrc */
    0x05, 0xff, 0xff, 0xfd,                          /* frac=5, lost=-3 */
    0x00, 0x00, 0x10, 0x00,                          /* exthighestseq */
    0x00, 0x00, 0x00, 0x40,                          /* jitter */
    0xaa, 0xbb, 0xcc, 0xdd,                          /* lsr */
    0x00, 0x00, 0x00, 0x11,                          /* dlsr */
    0x12, 0x34, 0x56, 0x78,                          /* rb1 ssrc */
    0x00, 0x00, 0x00, 0x00,                          /* frac=0, lost=0 */
    0x00, 0x00, 0x20, 0x00,                          /* exthighestseq */
    0x00, 0x00, 0x00, 0x80,                          /* jitter */
    0x12, 0x34, 0x56, 0x78,                          /* lsr */
    0x00, 0x00, 0x00, 0x22                           /* dlsr */
  };
  RRTCPReportBlock rb[2] = {
    { 0x55667788, 5, -3, 0x1000, 0x40, 0xaabbccdd, 0x11 },
    { 0x12345678, 0,  0, 0x2000, 0x80, 0x12345678, 0x22 }
  };
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  RRTCPReportBlock grb;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_rr (buf, 0x99aabbcc, rb, 2));
  r_assert_cmpbufmem (buf, 0, -1, ==, golden, sizeof (golden));
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (golden, sizeof (golden))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_RR);
  r_assert_cmpuint (r_rtcp_packet_get_count (pkt), ==, 2);
  r_assert_cmphex (r_rtcp_packet_rr_get_ssrc (pkt), ==, 0x99aabbcc);
  r_assert (r_rtcp_packet_sr_get_report_block (pkt, 0, &grb));
  r_assert_cmphex (grb.ssrc, ==, 0x55667788);
  r_assert_cmpint (grb.packetslost, ==, -3);
  r_assert (r_rtcp_packet_sr_get_report_block (pkt, 1, &grb));
  r_assert_cmphex (grb.ssrc, ==, 0x12345678);
  r_assert_cmpint (grb.packetslost, ==, 0);
  r_assert_cmphex (grb.exthighestseq, ==, 0x2000);
  r_assert_cmphex (grb.dlsr, ==, 0x22);
  r_assert (!r_rtcp_packet_sr_get_report_block (pkt, 2, &grb));
  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, ext_with_csrc_wire, RTEST_FAST)
{
  /* RTP packet with both a CSRC entry and a header extension: serialize to
   * exact wire bytes (constructor + setters) and parse the same bytes back. */
  static const ruint8 golden[] = {
    0x91, 0x60, 0x00, 0x01,                          /* V2 X=1 CC=1, PT=96, seq=1 */
    0x00, 0x00, 0x00, 0x10,                          /* timestamp = 0x10 */
    0xde, 0xad, 0xbe, 0xef,                          /* ssrc */
    0x11, 0x22, 0x33, 0x44,                          /* csrc[0] */
    0xbe, 0xde, 0x00, 0x01,                          /* ext: profile=0xbede, len=1 */
    0xaa, 0xbb, 0xcc, 0xdd,                          /* ext data */
    0x01, 0x02                                       /* payload */
  };
  static const ruint8 extdata[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
  static const ruint8 pay[2] = { 0x01, 0x02 };
  RBuffer * buf, * payload;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;
  ruint16 profile = 0, esize = 0;
  const ruint8 * edata = NULL;

  /* serialize */
  r_assert_cmpptr ((payload = r_buffer_new_dup (pay, sizeof (pay))), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer_ext (payload, 0, 1,
          0xbede, extdata, sizeof (extdata))), !=, NULL);
  r_buffer_unref (payload);
  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_WRITE));
  r_rtp_buffer_set_pt (&rtp, 96);
  r_rtp_buffer_set_seq (&rtp, 1);
  r_rtp_buffer_set_timestamp (&rtp, 0x10);
  r_rtp_buffer_set_ssrc (&rtp, 0xdeadbeef);
  r_assert (r_rtp_buffer_set_csrc (&rtp, 0, 0x11223344));
  r_assert (r_rtp_buffer_unmap (&rtp, buf));
  r_assert_cmpbufmem (buf, 0, -1, ==, golden, sizeof (golden));
  r_buffer_unref (buf);

  /* deserialize the same bytes */
  r_assert_cmpptr ((buf = r_buffer_new_dup (golden, sizeof (golden))), !=, NULL);
  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtp_buffer_get_csrc_count (&rtp), ==, 1);
  r_assert_cmphex (r_rtp_buffer_get_csrc (&rtp, 0), ==, 0x11223344);
  r_assert (r_rtp_buffer_has_extension (&rtp));
  r_assert (r_rtp_buffer_get_extension (&rtp, &profile, &edata, &esize));
  r_assert_cmphex (profile, ==, 0xbede);
  r_assert_cmpuint (esize, ==, sizeof (extdata));
  r_assert_cmpmem (edata, ==, extdata, sizeof (extdata));
  r_assert_cmpuint (r_rtp_buffer_get_pt (&rtp), ==, 96);
  r_assert_cmpuint (r_rtp_buffer_get_seq (&rtp), ==, 1);
  r_assert_cmphex (r_rtp_buffer_get_ssrc (&rtp), ==, 0xdeadbeef);
  r_assert_cmpuint (rtp.pay.size, ==, sizeof (pay));
  r_assert_cmpmem (rtp.pay.data, ==, pay, sizeof (pay));
  r_assert (r_rtp_buffer_unmap (&rtp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, new_rtp_buffer, RTEST_FAST)
{
  RBuffer * buf, * payload;

  r_assert_cmpptr (r_buffer_new_rtp_buffer (NULL, 0, 0), ==, NULL);

  r_assert_cmpptr ((payload = r_buffer_new_alloc (NULL, 42, NULL)), !=, NULL);

  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer (payload, 0, 0)), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, R_RTP_HDR_SIZE + 42);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer (payload, 2, 0)), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, R_RTP_HDR_SIZE + 42 + 2);
  r_buffer_unref (buf);

  r_buffer_unref (payload);
}
RTEST_END;

RTEST (rrtp, new_rtp_buffer_alloc, RTEST_FAST)
{
  RBuffer * buf;

  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer_alloc (0, 0, 0)), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, R_RTP_HDR_SIZE);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer_alloc (0, 0, 2)), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, R_RTP_HDR_SIZE + 2 * sizeof (ruint32));
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer_alloc (0, 8, 0)), !=, NULL);
  r_assert_cmpuint (r_buffer_get_size (buf), ==, R_RTP_HDR_SIZE + 8);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, read_plain_hdr_pcmu_payload, RTEST_FAST)
{
  RBuffer * buf;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu))), !=, NULL);

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (rtp.hdr.size, ==, R_RTP_HDR_SIZE);
  r_assert_cmpuint (rtp.ext.data, ==, NULL);
  r_assert_cmpuint (rtp.pay.size, ==, 160);
  r_assert_cmpmem (rtp.pay.data, ==, &pkt_rtp_pcmu[R_RTP_HDR_SIZE], rtp.pay.size);
  r_assert_cmpuint (rtp.hdr.size + rtp.ext.size + rtp.pay.size, ==, sizeof (pkt_rtp_pcmu));

  r_assert (!r_rtp_buffer_has_padding (&rtp));
  r_assert_cmpuint (r_rtp_buffer_get_padding (&rtp), ==, 0);
  r_assert (!r_rtp_buffer_has_extension (&rtp));
  r_assert (r_rtp_buffer_has_marker (&rtp));

  r_assert_cmpuint (r_rtp_buffer_get_csrc_count (&rtp), ==, 0);
  r_assert_cmpuint (r_rtp_buffer_get_pt (&rtp), ==, R_RTP_PT_PCMU);
  r_assert_cmpuint (r_rtp_buffer_get_seq (&rtp), ==, 37595);
  r_assert_cmphex (r_rtp_buffer_get_ssrc (&rtp), ==, 0x343da99b);
  r_assert_cmpuint (r_rtp_buffer_get_timestamp (&rtp), ==, 160);

  r_assert (r_rtp_buffer_unmap (&rtp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, padding_underflow, RTEST_FAST)
{
  /* P bit set but the trailing pad-count byte (0xff) exceeds the 2-byte
   * payload -- pay.size (unsigned) must not underflow into a huge value. */
  static const ruint8 pkt[] = {
    0xa0, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x42, 0xff
  };
  RBuffer * buf;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt, sizeof (pkt))), !=, NULL);
  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert (r_rtp_buffer_has_padding (&rtp));
  r_assert_cmpuint (r_rtp_buffer_get_padding (&rtp), ==, 0xff);  /* verbatim */
  r_assert_cmpuint (rtp.pay.size, <=, 2);
  r_assert (r_rtp_buffer_unmap (&rtp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, padding_count, RTEST_FAST)
{
  /* A constructed packet with N padding octets reports N, and the payload
   * mapping excludes them. */
  RBuffer * buf, * payload;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;
  ruint8 data[4] = { 1, 2, 3, 4 };

  r_assert_cmpptr ((payload = r_buffer_new_dup (data, sizeof (data))), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer (payload, 5, 0)), !=, NULL);
  r_buffer_unref (payload);

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert (r_rtp_buffer_has_padding (&rtp));
  r_assert_cmpuint (r_rtp_buffer_get_padding (&rtp), ==, 5);
  r_assert_cmpuint (rtp.pay.size, ==, sizeof (data));
  r_assert (r_rtp_buffer_unmap (&rtp, buf));

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, write_plain_hdr_pcmu_payload, RTEST_FAST)
{
  RBuffer * buf, * payload;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;

  r_assert_cmpptr ((payload = r_buffer_new_dup (
          pkt_rtp_pcmu + R_RTP_HDR_SIZE, sizeof (pkt_rtp_pcmu) - R_RTP_HDR_SIZE)), !=, NULL);

  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer (payload, 0, 0)), !=, NULL);
  r_buffer_unref (payload);

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_WRITE));
  r_rtp_buffer_set_marker (&rtp, TRUE);
  r_rtp_buffer_set_pt (&rtp, R_RTP_PT_PCMU);
  r_rtp_buffer_set_seq (&rtp, 37595);
  r_rtp_buffer_set_ssrc (&rtp, 0x343da99b);
  r_rtp_buffer_set_timestamp (&rtp, 160);
  r_assert (r_rtp_buffer_unmap (&rtp, buf));

  r_assert_cmpuint (r_buffer_get_size (buf), ==, sizeof (pkt_rtp_pcmu));
  r_assert_cmpbufmem (buf, 0, -1, ==, pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, write_csrc_list, RTEST_FAST)
{
  /* r_rtp_buffer_set_csrc writes into the CSRC list allocated by
   * r_buffer_new_rtp_buffer (..., cc).  After setting two entries
   * we should read them back via r_rtp_buffer_get_csrc and find a
   * matching CSRC count. */
  RBuffer * buf, * payload;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;
  ruint8 zero = 0;

  r_assert_cmpptr ((payload = r_buffer_new_dup (&zero, 1)), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer (payload, 0, 2)), !=, NULL);
  r_buffer_unref (payload);

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_WRITE));
  r_assert_cmpuint (r_rtp_buffer_get_csrc_count (&rtp), ==, 2);
  r_assert (r_rtp_buffer_set_csrc (&rtp, 0, 0xdeadbeef));
  r_assert (r_rtp_buffer_set_csrc (&rtp, 1, 0xcafebabe));
  /* Out-of-range index is rejected. */
  r_assert (!r_rtp_buffer_set_csrc (&rtp, 2, 0x12345678));
  r_assert (r_rtp_buffer_unmap (&rtp, buf));

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtp_buffer_get_csrc_count (&rtp), ==, 2);
  r_assert_cmphex (r_rtp_buffer_get_csrc (&rtp, 0), ==, 0xdeadbeef);
  r_assert_cmphex (r_rtp_buffer_get_csrc (&rtp, 1), ==, 0xcafebabe);
  r_assert (r_rtp_buffer_unmap (&rtp, buf));

  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, read_ext_hdr_opus_payload, RTEST_FAST)
{
  RBuffer * buf;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtp_opus, sizeof (pkt_rtp_opus))), !=, NULL);

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (rtp.hdr.size, ==, R_RTP_HDR_SIZE);
  r_assert_cmpuint (rtp.ext.size, ==, 12);
  r_assert_cmpmem (rtp.ext.data, ==, &pkt_rtp_opus[R_RTP_HDR_SIZE], rtp.ext.size);
  r_assert_cmpuint (rtp.pay.size, ==, 102);
  r_assert_cmpmem (rtp.pay.data, ==, &pkt_rtp_opus[R_RTP_HDR_SIZE + rtp.ext.size], rtp.ext.size);
  r_assert_cmpuint (rtp.hdr.size + rtp.ext.size + rtp.pay.size, ==, sizeof (pkt_rtp_opus));

  r_assert (!r_rtp_buffer_has_padding (&rtp));
  r_assert (r_rtp_buffer_has_extension (&rtp));
  {
    ruint16 profile = 0, esize = 0;
    const ruint8 * edata = NULL;
    r_assert (r_rtp_buffer_get_extension (&rtp, &profile, &edata, &esize));
    r_assert_cmphex (profile, ==, RUINT16_FROM_BE (*(const ruint16 *)rtp.ext.data));
    r_assert_cmpuint (esize, ==, rtp.ext.size - 4);
    r_assert_cmpptr (edata, ==, rtp.ext.data + 4);
  }
  r_assert (!r_rtp_buffer_has_marker (&rtp));

  r_assert_cmpuint (r_rtp_buffer_get_csrc_count (&rtp), ==, 0);
  r_assert_cmpuint (r_rtp_buffer_get_pt (&rtp), ==, 111);
  r_assert_cmpuint (r_rtp_buffer_get_seq (&rtp), ==, 0x3d82);
  r_assert_cmphex (r_rtp_buffer_get_ssrc (&rtp), ==, 0xcfe90cfe);
  r_assert_cmpuint (r_rtp_buffer_get_timestamp (&rtp), ==, 0x76950f20);

  r_assert (r_rtp_buffer_unmap (&rtp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtp, write_ext_hdr, RTEST_FAST)
{
  /* Construct a packet with a header extension and read it back. */
  RBuffer * buf, * payload;
  RRTPBuffer rtp = R_RTP_BUFFER_INIT;
  static const ruint8 extdata[8] = { 0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17 };
  static const ruint8 pay[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
  ruint16 profile = 0, esize = 0;
  const ruint8 * edata = NULL;

  r_assert_cmpptr ((payload = r_buffer_new_dup (pay, sizeof (pay))), !=, NULL);
  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer_ext (payload, 0, 0,
          0xbede, extdata, sizeof (extdata))), !=, NULL);
  r_buffer_unref (payload);

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert (r_rtp_buffer_has_extension (&rtp));
  r_assert (r_rtp_buffer_get_extension (&rtp, &profile, &edata, &esize));
  r_assert_cmphex (profile, ==, 0xbede);
  r_assert_cmpuint (esize, ==, sizeof (extdata));
  r_assert_cmpmem (edata, ==, extdata, sizeof (extdata));
  r_assert_cmpuint (rtp.pay.size, ==, sizeof (pay));
  r_assert_cmpmem (rtp.pay.data, ==, pay, sizeof (pay));
  r_assert (r_rtp_buffer_unmap (&rtp, buf));
  r_buffer_unref (buf);

  /* A non-word-aligned extension size is rejected. */
  r_assert_cmpptr ((payload = r_buffer_new_dup (pay, sizeof (pay))), !=, NULL);
  r_assert_cmpptr (r_buffer_new_rtp_buffer_ext (payload, 0, 0, 0xbede, extdata, 3),
      ==, NULL);
  r_buffer_unref (payload);
}
RTEST_END;

RTEST (rrtp, estimate_seq_idx, RTEST_FAST)
{
  r_assert_cmpuint (r_rtp_estimate_seq_idx (0, 0), ==, 0);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (R_RTP_SEQ_MEDIAN, 0), ==, R_RTP_SEQ_MEDIAN);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (RUINT16_MAX, 0), ==, RUINT16_MAX);

  r_assert_cmpuint (r_rtp_estimate_seq_idx (0, R_RTP_SEQ_MEDIAN), ==, 0);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (0, R_RTP_SEQ_MEDIAN + 1), ==, 0x10000);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (0, RUINT16_MAX), ==, 0x10000);

  r_assert_cmpuint (r_rtp_estimate_seq_idx (RUINT16_MAX, RUINT16_MAX), ==, RUINT16_MAX);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (RUINT16_MAX, RUINT16_MAX + 1), ==, RUINT16_MAX);

  r_assert_cmpuint (r_rtp_estimate_seq_idx (100, (10 << 16) |  99), ==, (10 << 16) | 100);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (100, (10 << 16) | 100), ==, (10 << 16) | 100);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (100, (10 << 16) | 101), ==, (10 << 16) | 100);

  r_assert_cmpuint (r_rtp_estimate_seq_idx (R_RTP_SEQ_MEDIAN,
        (10 << 16) | 100), ==, (10 << 16) | R_RTP_SEQ_MEDIAN);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (R_RTP_SEQ_MEDIAN + 1,
        (10 << 16) | 100), ==, (10 << 16) | (R_RTP_SEQ_MEDIAN + 1));
  r_assert_cmpuint (r_rtp_estimate_seq_idx (R_RTP_SEQ_MEDIAN + 200,
        (10 << 16) | 100), ==, ( 9 << 16) | (R_RTP_SEQ_MEDIAN + 200));

  r_assert_cmpuint (r_rtp_estimate_seq_idx (R_RTP_SEQ_MEDIAN + 100,
        (10 << 16) | (R_RTP_SEQ_MEDIAN + 100)), ==, (10 << 16) | (R_RTP_SEQ_MEDIAN + 100));
  r_assert_cmpuint (r_rtp_estimate_seq_idx (RUINT16_MAX,
        (10 << 16) | (R_RTP_SEQ_MEDIAN + 100)), ==, (10 << 16) | RUINT16_MAX);
  r_assert_cmpuint (r_rtp_estimate_seq_idx (99,
        (10 << 16) | (R_RTP_SEQ_MEDIAN + 100)), ==, (11 << 16) | 99);
}
RTEST_END;

RTEST (rrtcp, is_valid_hdr, RTEST_FAST)
{
  r_assert (!r_rtcp_is_valid_hdr (pkt_stun, sizeof (pkt_stun)));
  r_assert (!r_rtcp_is_valid_hdr (pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu)));
  r_assert (r_rtcp_is_valid_hdr (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes)));
}
RTEST_END;

RTEST (rrtcp, sr_report_block_count_vs_length_mismatch, RTEST_FAST)
{
  /* RTCP SR with len=6 (28 bytes total -- just SR fixed header + sender info)
   * but advertised count=1.  Accessing the missing report block must not
   * read past the buffer. */
  static const ruint8 pkt_sr_lying_count[28] = {
    0x81, 0xc8, 0x00, 0x06,
    0xf3, 0xcb, 0x20, 0x01,
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
    0, 0, 0, 0,  0, 0, 0, 0
  };
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * packet;
  RRTCPReportBlock rb;

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_sr_lying_count,
          sizeof (pkt_sr_lying_count))), !=, NULL);
  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));

  r_assert_cmpptr ((packet = r_rtcp_buffer_get_first_packet (&rtcp)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_count (packet), ==, 1);
  r_assert_cmpuint (r_rtcp_packet_get_length (packet), ==, 28);
  r_assert (!r_rtcp_packet_sr_get_report_block (packet, 0, &rb));

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, sr_sdes_compound_packet, RTEST_FAST)
{
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * packet;
  RRTCPSenderInfo srinfo;
  RRTCPReportBlock rb;
  RRTCPSDESChunk * chunk;
  RRTCPSDESItem item = R_RTCP_SDES_ITEM_INIT;

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes))), !=, NULL);

  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));

  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 2);

  r_assert_cmpptr ((packet = r_rtcp_buffer_get_first_packet (&rtcp)), !=, NULL);
  r_assert (!r_rtcp_packet_has_padding (packet));
  r_assert_cmpuint (r_rtcp_packet_get_count (packet), ==, 0);
  r_assert_cmpint (r_rtcp_packet_get_type (packet), ==, R_RTCP_PT_SR);
  r_assert_cmpuint (r_rtcp_packet_get_length (packet), ==, 28);

  /* Sender report */
  r_assert (r_rtcp_packet_sr_get_sender_info (packet, &srinfo));
  r_assert_cmphex (srinfo.ssrc, ==, 0xf3cb2001);
  r_assert_cmpuint (srinfo.ntptime, ==, RUINT64_CONSTANT (0x83ab03a1eb020b3a));
  r_assert_cmpuint (srinfo.rtptime, ==, 0x9420);
  r_assert_cmpuint (srinfo.packets, ==, 0x9e);
  r_assert_cmpuint (srinfo.bytes, ==, 0x9b88);

  r_assert (!r_rtcp_packet_sr_get_report_block (packet, 0, &rb));

  /* SDES */
  r_assert_cmpptr ((packet = r_rtcp_buffer_get_next_packet (&rtcp, packet)), !=, NULL);
  r_assert (!r_rtcp_packet_has_padding (packet));
  r_assert_cmpuint (r_rtcp_packet_get_count (packet), ==, 1);
  r_assert_cmpint (r_rtcp_packet_get_type (packet), ==, R_RTCP_PT_SDES);
  r_assert_cmpuint (r_rtcp_packet_get_length (packet), ==, 24);

  r_assert_cmpptr ((chunk = r_rtcp_packet_sdes_get_first_chunk (packet)), !=, NULL);
  r_assert_cmphex (r_rtcp_packet_sdes_chunk_get_ssrc (packet, chunk), ==, 0xf3cb2001);
  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (packet, chunk, &item), ==, R_RTCP_PARSE_OK);
  r_assert_cmphex (item.type, ==, R_RTCP_SDES_CNAME);
  r_assert_cmpuint (item.len, ==, 10);
  r_assert_cmpmem (item.data, ==, "outChannel", item.len);

  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (packet, chunk, &item), ==, R_RTCP_PARSE_ZERO);
  r_assert_cmpptr (r_rtcp_packet_sdes_get_next_chunk (packet, chunk), ==, NULL);

  r_assert_cmpptr ((packet = r_rtcp_buffer_get_next_packet (&rtcp, packet)), ==, NULL);

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, rr_bye_compound_packet, RTEST_FAST)
{
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * packet;
  RRTCPReportBlock rb;
  rchar reason[255];
  ruint8 rlen;

  r_assert_cmpptr ((buf = r_buffer_new_dup (pkt_rtcp_rr_bye, sizeof (pkt_rtcp_rr_bye))), !=, NULL);

  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));

  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 2);

  /* Receiver report */
  r_assert_cmpptr ((packet = r_rtcp_buffer_get_first_packet (&rtcp)), !=, NULL);
  r_assert (!r_rtcp_packet_has_padding (packet));
  r_assert_cmpuint (r_rtcp_packet_get_count (packet), ==, 1);
  r_assert_cmpint (r_rtcp_packet_get_type (packet), ==, R_RTCP_PT_RR);
  r_assert_cmpuint (r_rtcp_packet_get_length (packet), ==, 32);

  r_assert_cmphex (r_rtcp_packet_rr_get_ssrc (packet), ==, 0x166ae287);
  r_assert (r_rtcp_packet_rr_get_report_block (packet, 0, &rb));
  r_assert_cmphex (rb.ssrc, ==, 0x875414db);
  r_assert_cmpuint (rb.fractionlost, ==, 0);
  r_assert_cmpint (rb.packetslost, ==, 0);
  r_assert_cmpuint (rb.exthighestseq, ==, 5708);
  r_assert_cmpuint (rb.jitter, ==, 514);
  r_assert_cmpuint (rb.lsr, ==, 3108076906);
  r_assert_cmpuint (rb.dlsr, ==, 375846);

  r_assert (!r_rtcp_packet_rr_get_report_block (packet, 1, &rb));

  /* Bye */
  r_assert_cmpptr ((packet = r_rtcp_buffer_get_next_packet (&rtcp, packet)), !=, NULL);
  r_assert (!r_rtcp_packet_has_padding (packet));
  r_assert_cmpuint (r_rtcp_packet_get_count (packet), ==, 1);
  r_assert_cmpint (r_rtcp_packet_get_type (packet), ==, R_RTCP_PT_BYE);
  r_assert_cmpuint (r_rtcp_packet_get_length (packet), ==, 8);

  r_assert_cmphex (r_rtcp_packet_bye_get_ssrc (packet, 0), ==, 0x166ae287);
  r_assert_cmphex (r_rtcp_packet_bye_get_ssrc (packet, 1), ==, 0x0);
  r_assert_cmpint (r_rtcp_packet_bye_get_reason (packet,
        reason, sizeof (reason), &rlen), ==, R_RTCP_PARSE_ZERO);
  r_assert_cmpuint (rlen, ==, 0);

  r_assert_cmpptr ((packet = r_rtcp_buffer_get_next_packet (&rtcp, packet)), ==, NULL);

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;


RTEST (rrtcp, write_sr_rr_compound, RTEST_FAST)
{
  /* Build an SR + RR compound, then read it back via the parser. */
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  /* RRTCPSenderInfo field order: ssrc, rtptime, ntptime, packets, bytes */
  RRTCPSenderInfo si = { 0x11223344, 0xdeadbeef, 0x0102030405060708, 100, 20000 };
  /* RRTCPReportBlock: ssrc, fractionlost, packetslost, exthighestseq, jitter, lsr, dlsr */
  RRTCPReportBlock rb = { 0x55667788, 5, -3, 0x1000, 0x40, 0xaabbccdd, 0x11 };
  RRTCPSenderInfo gsi;
  RRTCPReportBlock grb;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_sr (buf, &si, &rb, 1));
  r_assert (r_rtcp_buffer_add_rr (buf, 0x99aabbcc, &rb, 1));

  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 2);

  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_SR);
  r_assert_cmpuint (r_rtcp_packet_get_count (pkt), ==, 1);
  r_assert (r_rtcp_packet_sr_get_sender_info (pkt, &gsi));
  r_assert_cmphex (gsi.ssrc, ==, si.ssrc);
  r_assert_cmphex (gsi.ntptime, ==, si.ntptime);
  r_assert_cmphex (gsi.rtptime, ==, si.rtptime);
  r_assert_cmpuint (gsi.packets, ==, si.packets);
  r_assert_cmpuint (gsi.bytes, ==, si.bytes);
  r_assert (r_rtcp_packet_sr_get_report_block (pkt, 0, &grb));
  r_assert_cmphex (grb.ssrc, ==, rb.ssrc);
  r_assert_cmpuint (grb.fractionlost, ==, rb.fractionlost);
  r_assert_cmpint (grb.packetslost, ==, rb.packetslost);
  r_assert_cmpuint (grb.exthighestseq, ==, rb.exthighestseq);
  r_assert_cmpuint (grb.jitter, ==, rb.jitter);
  r_assert_cmphex (grb.lsr, ==, rb.lsr);
  r_assert_cmpuint (grb.dlsr, ==, rb.dlsr);

  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, pkt)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_RR);
  r_assert_cmpuint (r_rtcp_packet_get_count (pkt), ==, 1);
  r_assert_cmphex (r_rtcp_packet_rr_get_ssrc (pkt), ==, 0x99aabbcc);
  r_assert (r_rtcp_packet_sr_get_report_block (pkt, 0, &grb));
  r_assert_cmphex (grb.ssrc, ==, rb.ssrc);
  r_assert_cmpint (grb.packetslost, ==, rb.packetslost);

  r_assert_cmpptr (r_rtcp_buffer_get_next_packet (&rtcp, pkt), ==, NULL);

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, write_sdes, RTEST_FAST)
{
  /* Build a single-chunk SDES with a CNAME item and read it back. */
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  RRTCPSDESChunk * chunk;
  RRTCPSDESItem item = R_RTCP_SDES_ITEM_INIT;
  static const ruint8 cname[] = "alice@example";
  RRTCPSDESItem items[1];

  items[0].type = R_RTCP_SDES_CNAME;
  items[0].len = sizeof (cname) - 1;
  items[0].data = (ruint8 *) cname;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_sdes (buf, 0xcafef00d, items, 1));

  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_SDES);
  r_assert_cmpuint (r_rtcp_packet_get_count (pkt), ==, 1);

  r_assert_cmpptr ((chunk = r_rtcp_packet_sdes_get_next_chunk (pkt, NULL)), !=, NULL);
  r_assert_cmphex (r_rtcp_packet_sdes_chunk_get_ssrc (pkt, chunk), ==, 0xcafef00d);
  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (pkt, chunk, &item),
      ==, R_RTCP_PARSE_OK);
  r_assert_cmpuint (item.type, ==, R_RTCP_SDES_CNAME);
  r_assert_cmpuint (item.len, ==, sizeof (cname) - 1);
  r_assert_cmpmem (item.data, ==, cname, sizeof (cname) - 1);
  /* the list terminates */
  r_assert_cmpint (r_rtcp_packet_sdes_chunk_get_next_item (pkt, chunk, &item),
      ==, R_RTCP_PARSE_ZERO);

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, write_bye_app, RTEST_FAST)
{
  /* Build a BYE (with reason) + APP compound and read it back. */
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  ruint32 ssrcs[2] = { 0x11111111, 0x22222222 };
  static const rchar reason[] = "bye now";
  static const ruint8 appdata[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
  rchar rbuf[32];
  ruint8 rlen = 0;
  const ruint8 * adata;
  ruint16 asize = 0;

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_bye (buf, ssrcs, 2, reason));
  r_assert (r_rtcp_buffer_add_app (buf, 3, 0x33333333, "PING", appdata, sizeof (appdata)));

  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 2);

  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_BYE);
  r_assert_cmpuint (r_rtcp_packet_bye_get_ssrc_count (pkt), ==, 2);
  r_assert_cmphex (r_rtcp_packet_bye_get_ssrc (pkt, 0), ==, 0x11111111);
  r_assert_cmphex (r_rtcp_packet_bye_get_ssrc (pkt, 1), ==, 0x22222222);
  r_assert_cmpint (r_rtcp_packet_bye_get_reason (pkt, rbuf, sizeof (rbuf), &rlen),
      ==, R_RTCP_PARSE_OK);
  r_assert_cmpuint (rlen, ==, sizeof (reason) - 1);
  r_assert_cmpstr (rbuf, ==, reason);

  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, pkt)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_APP);
  r_assert_cmpuint (r_rtcp_packet_get_count (pkt), ==, 3);   /* subtype */
  r_assert_cmphex (r_rtcp_packet_app_get_ssrc (pkt), ==, 0x33333333);
  r_assert_cmpmem (r_rtcp_packet_app_get_name (pkt), ==, "PING", 4);
  r_assert_cmpptr ((adata = r_rtcp_packet_app_get_data (pkt, &asize)), !=, NULL);
  r_assert_cmpuint (asize, ==, sizeof (appdata));
  r_assert_cmpmem (adata, ==, appdata, sizeof (appdata));

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcp, write_feedback, RTEST_FAST)
{
  /* A PSFB/PLI (no FCI) and an RTPFB/Generic-NACK (one FCI entry). */
  RBuffer * buf;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  ruint8 nackfci[4];
  const ruint8 * fci;
  ruint16 fcisize = 0;

  r_store_be16 (&nackfci[0], 0x1234);   /* PID */
  r_store_be16 (&nackfci[2], 0x00ff);   /* BLP */

  r_assert_cmpptr ((buf = r_buffer_new ()), !=, NULL);
  r_assert (r_rtcp_buffer_add_fb (buf, R_RTCP_PT_PSFB, R_RTCP_PSFB_FMT_PLI,
          0xaaaa0001, 0xbbbb0002, NULL, 0));
  r_assert (r_rtcp_buffer_add_fb (buf, R_RTCP_PT_RTPFB, R_RTCP_RTPFB_FMT_NACK,
          0xaaaa0001, 0xbbbb0002, nackfci, sizeof (nackfci)));
  /* invalid: wrong PT and non-word-aligned FCI are rejected */
  r_assert (!r_rtcp_buffer_add_fb (buf, R_RTCP_PT_SR, 1, 0, 0, NULL, 0));
  r_assert (!r_rtcp_buffer_add_fb (buf, R_RTCP_PT_RTPFB, 1, 0, 0, nackfci, 3));

  r_assert (r_rtcp_buffer_map (&rtcp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (r_rtcp_buffer_get_packet_count (&rtcp), ==, 2);

  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_PSFB);
  r_assert_cmpuint (r_rtcp_packet_fb_get_fmt (pkt), ==, R_RTCP_PSFB_FMT_PLI);
  r_assert_cmphex (r_rtcp_packet_fb_get_sender_ssrc (pkt), ==, 0xaaaa0001);
  r_assert_cmphex (r_rtcp_packet_fb_get_media_ssrc (pkt), ==, 0xbbbb0002);
  r_rtcp_packet_fb_get_fci (pkt, &fcisize);
  r_assert_cmpuint (fcisize, ==, 0);

  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, pkt)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_RTPFB);
  r_assert_cmpuint (r_rtcp_packet_fb_get_fmt (pkt), ==, R_RTCP_RTPFB_FMT_NACK);
  r_assert_cmphex (r_rtcp_packet_fb_get_media_ssrc (pkt), ==, 0xbbbb0002);
  r_assert_cmpptr ((fci = r_rtcp_packet_fb_get_fci (pkt, &fcisize)), !=, NULL);
  r_assert_cmpuint (fcisize, ==, sizeof (nackfci));
  r_assert_cmpmem (fci, ==, nackfci, sizeof (nackfci));

  r_assert (r_rtcp_buffer_unmap (&rtcp, buf));
  r_buffer_unref (buf);
}
RTEST_END;
