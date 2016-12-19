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


RTEST (rrtp, is_valid_hdr, RTEST_FAST)
{
  r_assert (!r_rtp_is_valid_hdr (pkt_stun, sizeof (pkt_stun)));
  r_assert (r_rtp_is_valid_hdr (pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu)));
  r_assert (!r_rtp_is_valid_hdr (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes)));
}
RTEST_END;

RTEST (rrtcp, is_valid_hdr, RTEST_FAST)
{
  r_assert (!r_rtcp_is_valid_hdr (pkt_stun, sizeof (pkt_stun)));
  r_assert (!r_rtcp_is_valid_hdr (pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu)));
  r_assert (r_rtcp_is_valid_hdr (pkt_rtcp_sr_sdes, sizeof (pkt_rtcp_sr_sdes)));
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

  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu), sizeof (pkt_rtp_pcmu),
          0, NULL, NULL)), !=, NULL);

  r_assert (r_rtp_buffer_map (&rtp, buf, R_MEM_MAP_READ));
  r_assert_cmpuint (rtp.hdr.size, ==, R_RTP_HDR_SIZE);
  r_assert_cmpuint (rtp.ext.data, ==, NULL);
  r_assert_cmpuint (rtp.pay.size, ==, 160);
  r_assert_cmpmem (rtp.pay.data, ==, &pkt_rtp_pcmu[R_RTP_HDR_SIZE], rtp.pay.size);

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

  r_assert_cmpptr ((payload = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu),
          sizeof (pkt_rtp_pcmu) - R_RTP_HDR_SIZE, R_RTP_HDR_SIZE,
          NULL, NULL)), !=, NULL);

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
  r_assert_cmpint (r_buffer_memcmp (buf, 0, pkt_rtp_pcmu, sizeof (pkt_rtp_pcmu)), ==, 0);
  r_buffer_unref (buf);
}
RTEST_END;

