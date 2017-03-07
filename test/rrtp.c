#include <rlib/rlib.h>

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

