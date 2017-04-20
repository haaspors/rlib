#include <rlib/rlib.h>

static const rchar sdp_rfc_4566[] =
  "v=0\r\n"
  "o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n"
  "s=SDP Seminar\r\n"
  "i=A Seminar on the session description protocol\r\n"
  "u=http://www.example.com/seminars/sdp.pdf\r\n"
  "e=j.doe@example.com (Jane Doe)\r\n"
  "c=IN IP4 224.2.17.12/127\r\n"
  "t=2873397496 2873404696\r\n"
  "a=recvonly\r\n"
  "m=audio 49170 RTP/AVP 0\r\n"
  "m=video 51372 RTP/AVP 99\r\n"
  "a=rtpmap:99 h263-1998/90000\r\n";

static const rchar sdp_rfc_3264[] =
  "v=0\r\n"
  "o=alice 2890844526 2890844527 IN IP4 host.anywhere.com\r\n"
  "s=\r\n"
  "c=IN IP4 host.anywhere.com\r\n"
  "t=0 0\r\n"
  "m=audio 49170 RTP/AVP 0\r\n"
  "a=rtpmap:0 PCMU/8000\r\n"
  "m=video 0 RTP/AVP 31\r\n"
  "a=rtpmap:31 H261/90000\r\n"
  "m=video 53000 RTP/AVP 32\r\n"
  "a=rtpmap:32 MPV/90000\r\n"
  "m=audio 53122 RTP/AVP 110\r\n"
  "a=rtpmap:110 telephone-events/8000\r\n"
  "a=sendonly\r\n";



RTEST (rsdp, from_rfc_4566, RTEST_FAST)
{
  RBuffer * buf;
  RSdpBuf sdp;
  rchar * tmp;
  RStrChunk a = R_STR_CHUNK_INIT;

  r_assert_cmpint (r_sdp_buffer_map (NULL, NULL), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, NULL), ==, R_SDP_INVAL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_rfc_4566))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (NULL, buf), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_OK);

  r_assert_cmpstr ((tmp = r_sdp_buf_version (&sdp)), ==, "0"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_username (&sdp)), ==, "jdoe"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_id (&sdp)), ==, "2890844526"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_version (&sdp)), ==, "2890842807"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_orig_session_id_u64 (&sdp), ==, RUINT64_CONSTANT (2890844526));
  r_assert_cmpuint (r_sdp_buf_orig_session_version_u64 (&sdp), ==, RUINT64_CONSTANT (2890842807));
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_nettype (&sdp)), ==, "IN"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addrtype (&sdp)), ==, "IP4"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addr (&sdp)), ==, "10.47.16.5"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_session_name (&sdp)), ==, "SDP Seminar"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_session_info (&sdp)), ==, "A Seminar on the session description protocol"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_uri_str (&sdp)), ==, "http://www.example.com/seminars/sdp.pdf"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_email_count (&sdp), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_email (&sdp, 0)), ==, "j.doe@example.com (Jane Doe)"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_phone_count (&sdp), ==, 0);
  r_assert_cmpstr ((tmp = r_sdp_buf_conn_nettype (&sdp)), ==, "IN"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_conn_addrtype (&sdp)), ==, "IP4"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_conn_addr (&sdp)), ==, "224.2.17.12"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_conn_ttl (&sdp), ==, 127);
  r_assert_cmpuint (r_sdp_buf_conn_addrcount (&sdp), ==, 1);
  r_assert_cmpuint (r_sdp_buf_bandwidth_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_time_count (&sdp), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_time_start (&sdp, 0)), ==, "2873397496"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_time_stop (&sdp, 0)), ==, "2873404696"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_time_repeat_count (&sdp, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_time_zone_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_attrib_count (&sdp), ==, 1);
  r_assert (!r_sdp_buf_has_attrib (&sdp, "foobar", -1));
  r_assert ( r_sdp_buf_has_attrib (&sdp, "recvonly", -1));
  r_assert_cmpptr (r_sdp_buf_attrib_dup_value (&sdp, "foobar", -1, NULL), ==, NULL);
  r_assert_cmpptr (r_sdp_buf_attrib_dup_value (&sdp, "recvonly", -1, NULL), ==, NULL);
  r_assert_cmpuint (r_sdp_buf_media_count (&sdp), ==, 2);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_type (&sdp, 0)), ==, "audio"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_port (&sdp, 0), ==, 49170);
  r_assert_cmpuint (r_sdp_buf_media_portcount (&sdp, 0), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_proto (&sdp, 0)), ==, "RTP/AVP"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_fmt_count (&sdp, 0), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_fmt (&sdp, 0, 0)), ==, "0"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_conn_count (&sdp, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_bandwidth_count (&sdp, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_attrib_count (&sdp, 0), ==, 0);
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 0, "foobar", -1));
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 0, "rtpmap", -1));
  r_assert_cmpstr ((tmp = r_sdp_buf_media_type (&sdp, 1)), ==, "video"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_port (&sdp, 1), ==, 51372);
  r_assert_cmpuint (r_sdp_buf_media_portcount (&sdp, 1), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_proto (&sdp, 1)), ==, "RTP/AVP"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_fmt_count (&sdp, 1), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_fmt (&sdp, 1, 0)), ==, "99"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 1, 0), ==, 99);
  r_assert_cmpuint (r_sdp_buf_media_conn_count (&sdp, 1), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_bandwidth_count (&sdp, 1), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_attrib_count (&sdp, 1), ==, 1);
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 1, "foobar", -1));
  r_assert ( r_sdp_buf_media_has_attrib (&sdp, 1, "rtpmap", -1));
  r_assert_cmpstr ((tmp = r_sdp_buf_media_attrib_dup_value (&sdp, 1, "rtpmap", -1, NULL)), ==, "99 h263-1998/90000"); r_free (tmp);

  r_assert_cmpint (r_sdp_buf_media_rtpmap_for_fmt_idx (&sdp, 1, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "h263-1998/90000"); r_free (tmp);

  r_assert_cmpint (r_sdp_buffer_unmap (NULL, NULL), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, NULL), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buffer_unmap (NULL, buf), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, buf), ==, R_SDP_OK);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rsdp, from_rfc_3264, RTEST_FAST)
{
  RBuffer * buf;
  RSdpBuf sdp;
  rchar * tmp;
  RStrChunk a = R_STR_CHUNK_INIT;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_rfc_3264))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_OK);

  r_assert_cmpstr ((tmp = r_sdp_buf_version (&sdp)), ==, "0"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_username (&sdp)), ==, "alice"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_id (&sdp)), ==, "2890844526"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_version (&sdp)), ==, "2890844527"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_orig_session_id_u64 (&sdp), ==, RUINT64_CONSTANT (2890844526));
  r_assert_cmpuint (r_sdp_buf_orig_session_version_u64 (&sdp), ==, RUINT64_CONSTANT (2890844527));
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_nettype (&sdp)), ==, "IN"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addrtype (&sdp)), ==, "IP4"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addr (&sdp)), ==, "host.anywhere.com"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_session_name (&sdp)), ==, ""); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_session_info (&sdp)), ==, NULL);
  r_assert_cmpuint (r_sdp_buf_email_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_phone_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_bandwidth_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_time_count (&sdp), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_time_start (&sdp, 0)), ==, "0"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_time_stop (&sdp, 0)), ==, "0"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_time_repeat_count (&sdp, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_time_zone_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_attrib_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_count (&sdp), ==, 4);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_type (&sdp, 0)), ==, "audio"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_type (&sdp, 1)), ==, "video"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_type (&sdp, 2)), ==, "video"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_type (&sdp, 3)), ==, "audio"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_port (&sdp, 0), ==, 49170);
  r_assert_cmpuint (r_sdp_buf_media_port (&sdp, 1), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_port (&sdp, 2), ==, 53000);
  r_assert_cmpuint (r_sdp_buf_media_port (&sdp, 3), ==, 53122);
  r_assert_cmpuint (r_sdp_buf_media_portcount (&sdp, 0), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_portcount (&sdp, 1), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_portcount (&sdp, 2), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_portcount (&sdp, 3), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_proto (&sdp, 0)), ==, "RTP/AVP"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_proto (&sdp, 1)), ==, "RTP/AVP"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_proto (&sdp, 2)), ==, "RTP/AVP"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_proto (&sdp, 3)), ==, "RTP/AVP"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_fmt_count (&sdp, 0), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_fmt_count (&sdp, 1), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_fmt_count (&sdp, 2), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_fmt_count (&sdp, 3), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 1, 0), ==, 31);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 2, 0), ==, 32);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 3, 0), ==, 110);
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 0, "recvonly", -1));
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 1, "recvonly", -1));
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 2, "recvonly", -1));
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 3, "recvonly", -1));
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 0, "sendonly", -1));
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 1, "sendonly", -1));
  r_assert (!r_sdp_buf_media_has_attrib (&sdp, 2, "sendonly", -1));
  r_assert ( r_sdp_buf_media_has_attrib (&sdp, 3, "sendonly", -1));
  r_assert_cmpint (r_sdp_buf_media_rtpmap_for_fmt_idx (&sdp, 0, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "PCMU/8000"); r_free (tmp);
  r_assert_cmpint (r_sdp_buf_media_rtpmap_for_fmt_idx (&sdp, 1, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "H261/90000"); r_free (tmp);
  r_assert_cmpint (r_sdp_buf_media_rtpmap_for_fmt_idx (&sdp, 2, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "MPV/90000"); r_free (tmp);
  r_assert_cmpint (r_sdp_buf_media_rtpmap_for_fmt_idx (&sdp, 3, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "telephone-events/8000"); r_free (tmp);

  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, buf), ==, R_SDP_OK);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rsdp, only_lf, RTEST_FAST)
{
  RBuffer * buf;
  RSdpBuf sdp;
  static const rchar sdp_only_LF[] =
    "v=0\n"
    "o=- 9223372039002259456 2 IN IP4 127.0.0.1\n"
    "s=-\n"
    "t=0 0\n"
    "a=recvonly\n";
  rchar * tmp;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_only_LF))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_sdp_buf_version (&sdp)), ==, "0"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_username (&sdp)), ==, "-"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_id (&sdp)), ==, "9223372039002259456"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_version (&sdp)), ==, "2"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_orig_session_id_u64 (&sdp), ==, RUINT64_CONSTANT (9223372039002259456));
  r_assert_cmpuint (r_sdp_buf_orig_session_version_u64 (&sdp), ==, 2);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_nettype (&sdp)), ==, "IN"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addrtype (&sdp)), ==, "IP4"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addr (&sdp)), ==, "127.0.0.1"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_session_name (&sdp)), ==, "-"); r_free (tmp);
  r_assert (r_sdp_buf_has_attrib (&sdp, "recvonly", -1));
  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, buf), ==, R_SDP_OK);

  r_buffer_unref (buf);
}
RTEST_END;

static const rchar sdp_missing_required[] =
  "v=0\r\n"
  /* Missing o= */
  "s=SDP Seminar\r\n"
  "m=audio 49170 RTP/AVP 0\r\n";

static const rchar sdp_wrong_order[] =
  "v=0\r\n"
  "o=jdoe 2890844526 2890842807 IN IP4 10.47.16.5\r\n"
  "s=SDP Seminar\r\n"
  "i=A Seminar on the session description protocol\r\n"
  "u=http://www.example.com/seminars/sdp.pdf\r\n"
  "a=recvonly\r\n"
  "c=IN IP4 224.2.17.12/127\r\n"
  "e=j.doe@example.com (Jane Doe)\r\n"
  "t=2873397496 2873404696\r\n"
  "m=audio 49170 RTP/AVP 0\r\n"
  "m=video 51372 RTP/AVP 99\r\n"
  "a=rtpmap:99 h263-1998/90000\r\n";


RTEST (rsdp, invalid, RTEST_FAST)
{
  RBuffer * buf;
  RSdpBuf sdp;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_missing_required))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_MISSING_REQUIRED_LINE);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_wrong_order))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_MORE_DATA);
  r_buffer_unref (buf);
}
RTEST_END;

static const rchar sdp_chrome_webrtc_offer[] =
  "v=0\r\n"
  "o=- 8610450130369641692 2 IN IP4 127.0.0.1\r\n"
  "s=-\r\n"
  "t=0 0\r\n"
  "a=group:BUNDLE audio\r\n"
  "a=msid-semantic:WMS tb3X62H7DwsD9WSJ9Shkiq0PjmXg7YdDXf3C\r\n"
  "m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 126\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "a=rtcp:9 IN IP4 0.0.0.0\r\n"
  "a=ice-ufrag:ALgn\r\n"
  "a=ice-pwd:FckU0ZVjV+e5dfAwXpFREIXq\r\n"
  "a=fingerprint:sha-256 DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49\r\n"
  "a=setup:actpass\r\n"
  "a=mid:audio\r\n"
  "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
  "a=sendrecv\r\n"
  "a=rtcp-mux\r\n"
  "a=rtpmap:111 opus/48000/2\r\n"
  "a=rtcp-fb:111 transport-cc\r\n"
  "a=fmtp:111 minptime=10;useinbandfec=1\r\n"
  "a=rtpmap:103 ISAC/16000\r\n"
  "a=rtpmap:104 ISAC/32000\r\n"
  "a=rtpmap:9 G722/8000\r\n"
  "a=rtpmap:0 PCMU/8000\r\n"
  "a=rtpmap:8 PCMA/8000\r\n"
  "a=rtpmap:106 CN/32000\r\n"
  "a=rtpmap:105 CN/16000\r\n"
  "a=rtpmap:13 CN/8000\r\n"
  "a=rtpmap:126 telephone-event/8000\r\n"
  "a=ssrc:600258811 cname:1uk9tTrmGFQYxweh\r\n"
  "a=ssrc:600258811 msid:tb3X62H7DwsD9WSJ9Shkiq0PjmXg7YdDXf3C 5f825656-d361-4767-98cc-959e0fb1fd04\r\n"
  "a=ssrc:600258811 mslabel:tb3X62H7DwsD9WSJ9Shkiq0PjmXg7YdDXf3C\r\n"
  "a=ssrc:600258811 label:5f825656-d361-4767-98cc-959e0fb1fd04\r\n";

RTEST (rsdp, chrome_webrtc_offer, RTEST_FAST)
{
  RBuffer * buf;
  RSdpBuf sdp;
  rchar * tmp;

  RStrChunk a = R_STR_CHUNK_INIT;

  r_assert_cmpint (r_sdp_buffer_map (NULL, NULL), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, NULL), ==, R_SDP_INVAL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_chrome_webrtc_offer))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (NULL, buf), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_OK);

  r_assert_cmpstr ((tmp = r_sdp_buf_version (&sdp)), ==, "0"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_username (&sdp)), ==, "-"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_id (&sdp)), ==, "8610450130369641692"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_session_version (&sdp)), ==, "2"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_orig_session_id_u64 (&sdp), ==, RUINT64_CONSTANT (8610450130369641692));
  r_assert_cmpuint (r_sdp_buf_orig_session_version_u64 (&sdp), ==, 2);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_nettype (&sdp)), ==, "IN"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addrtype (&sdp)), ==, "IP4"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_orig_addr (&sdp)), ==, "127.0.0.1"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_session_name (&sdp)), ==, "-"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_email_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_phone_count (&sdp), ==, 0);
  r_assert_cmpstr (r_sdp_buf_conn_nettype (&sdp), ==, NULL);
  r_assert_cmpstr (r_sdp_buf_conn_addrtype (&sdp), ==, NULL);
  r_assert_cmpstr (r_sdp_buf_conn_addr (&sdp), ==, NULL);
  r_assert_cmpuint (r_sdp_buf_bandwidth_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_time_count (&sdp), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_time_start (&sdp, 0)), ==, "0"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_sdp_buf_time_stop (&sdp, 0)), ==, "0"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_time_repeat_count (&sdp, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_time_zone_count (&sdp), ==, 0);
  r_assert_cmpuint (r_sdp_buf_attrib_count (&sdp), ==, 2);
  r_assert (r_sdp_buf_has_attrib (&sdp, "group", -1));
  r_assert (r_sdp_buf_has_attrib (&sdp, "msid-semantic", -1));

  r_assert_cmpuint (r_sdp_buf_media_count (&sdp), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_type (&sdp, 0)), ==, "audio"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_port (&sdp, 0), ==, 9);
  r_assert_cmpuint (r_sdp_buf_media_portcount (&sdp, 0), ==, 1);
  r_assert_cmpstr ((tmp = r_sdp_buf_media_proto (&sdp, 0)), ==, "UDP/TLS/RTP/SAVPF"); r_free (tmp);
  r_assert_cmpuint (r_sdp_buf_media_fmt_count (&sdp, 0), ==, 10);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 0), ==, 111);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 1), ==, 103);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 2), ==, 104);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 3), ==, 9);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 4), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 5), ==, 8);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 6), ==, 106);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 7), ==, 105);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 8), ==, 13);
  r_assert_cmpuint (r_sdp_buf_media_fmt_uint (&sdp, 0, 9), ==, 126);

  r_assert_cmpuint (r_sdp_buf_media_conn_count (&sdp, 0), ==, 1);
  r_assert_cmpuint (r_sdp_buf_media_bandwidth_count (&sdp, 0), ==, 0);
  r_assert_cmpuint (r_sdp_buf_media_attrib_count (&sdp, 0), ==, 25);
  r_assert (r_sdp_buf_media_has_attrib (&sdp, 0, "rtcp-mux", -1));

  r_assert_cmpint (r_sdp_buf_media_rtpmap_for_fmt_idx (&sdp, 0, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "opus/48000/2"); r_free (tmp);
  r_assert_cmpint (r_sdp_buf_media_fmtp_for_fmt_idx (&sdp, 0, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "minptime=10;useinbandfec=1"); r_free (tmp);
  r_assert_cmpint (r_sdp_buf_media_rtcpfb_for_fmt_idx (&sdp, 0, 0, &a), ==, R_SDP_OK);
  r_assert_cmpstr ((tmp = r_str_chunk_dup (&a)), ==, "transport-cc"); r_free (tmp);

  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, buf), ==, R_SDP_OK);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rsdp, msg_replicate_rfc_4566, RTEST_FAST)
{
  RSdpMsg * msg;
  RBuffer * buf;
  RUri * uri;
  RSdpMedia * m;

  r_assert_cmpptr ((msg = r_sdp_msg_new ()), !=, NULL);

  r_assert_cmpint (r_sdp_msg_set_originator (msg,
        "jdoe", -1, "2890844526", -1, "2890842807", -1,
        "IN", 2, "IP4", 3, "10.47.16.5", -1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_msg_set_session_name (msg, "SDP Seminar", -1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_msg_set_session_info (msg, "A Seminar on the session description protocol", -1), ==, R_SDP_OK);
  r_assert_cmpptr ((uri = r_uri_new_escaped ("http://www.example.com/seminars/sdp.pdf", -1)), !=, NULL);
  r_assert_cmpint (r_sdp_msg_set_uri (msg, uri), ==, R_SDP_OK);
  r_uri_unref (uri);
  r_assert_cmpint (r_sdp_msg_add_email (msg, "j.doe@example.com (Jane Doe)", -1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_msg_set_connection_full (msg, "IN", 2, "IP4", 3, "224.2.17.12", -1, 127, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_msg_add_time (msg, RUINT64_CONSTANT (2873397496), RUINT64_CONSTANT (2873404696)), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_msg_add_attribute (msg, "recvonly", -1, NULL, 0), ==, R_SDP_OK);
  r_assert_cmpptr ((m = r_sdp_media_new_full ("audio", -1, 49170, 1, "RTP/AVP", -1)), !=, NULL);
  r_assert_cmpint (r_sdp_msg_add_media (msg, m), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt_static (m, R_RTP_PT_PCMU), ==, R_SDP_OK);
  r_sdp_media_unref (m);
  r_assert_cmpptr ((m = r_sdp_media_new_full ("video", -1, 51372, 1, "RTP/AVP", -1)), !=, NULL);
  r_assert_cmpint (r_sdp_msg_add_media (msg, m), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, R_RTP_PT_DYNAMIC_FIRST + 3,
        R_STR_WITH_SIZE_ARGS ("h263-1998"), 90000, 0), ==, R_SDP_OK);
  r_sdp_media_unref (m);

  r_assert_cmpptr ((buf = r_sdp_msg_to_buffer (msg)), !=, NULL);
  r_sdp_msg_unref (msg);

  r_assert_cmpbufsstr (buf, 0, -1, ==, sdp_rfc_4566);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rsdp, msg_from_sdp_buffer, RTEST_FAST)
{
  RBuffer * buf;
  RSdpBuf sdp;
  RSdpMsg * msg;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_chrome_webrtc_offer))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_OK);
  r_assert_cmpptr ((msg = r_sdp_msg_new_from_sdp_buffer (&sdp)), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, buf), ==, R_SDP_OK);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_sdp_msg_to_buffer (msg)), !=, NULL);
  r_sdp_msg_unref (msg);

  r_assert_cmpbufsstr (buf, 0, -1, ==, sdp_chrome_webrtc_offer);
  r_buffer_unref (buf);
}
RTEST_END;

static const ruint64 jsep_sessid = RUINT64_CONSTANT (0x8000000080000000);
static const ruint jsep_sessver = 2;
static const rchar sdp_jsep_default[] =
  "v=0\r\n"
  "o=- 9223372039002259456 2 IN IP4 127.0.0.1\r\n"
  "s=-\r\n"
  "t=0 0\r\n";

static const rchar ice_ufrag[] = "NYta";
static const rchar ice_pwd[] = "SpxH0MIwI+r5qsNjKcSERVKd";
static const ruint32 audio_ssrc = 12345678;
static const ruint32 video_ssrc = 87654321;
static const rchar jsep_cname[] = "1hx9gGezTSDLkjru";
static const rchar jsep_msid_value[] = "go3K62U7QjfQ9JFW9Fuxvd0CwzKt7LqQKs3P";
static const rchar jsep_msid_audio[] = "ece80006-ec0d-46fc-9775-faa39ace53c5";
static const rchar jsep_msid_video[] = "90db69b6-00c0-4160-99c2-fe96251afedd";
static const rchar jsep_fingerprint[] = "DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49";
static const rchar sdp_jsep_with_av[] =
  "v=0\r\n"
  "o=- 9223372039002259456 2 IN IP4 127.0.0.1\r\n"
  "s=-\r\n"
  "t=0 0\r\n"
  "a=group:BUNDLE audio video\r\n"
  "m=audio 9 UDP/TLS/RTP/SAVPF 0 8\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "a=rtcp:9 IN IP4 0.0.0.0\r\n"
  "a=mid:audio\r\n"
  "a=rtcp-mux\r\n"
  "a=sendrecv\r\n"
  "a=ice-ufrag:NYta\r\n"
  "a=ice-pwd:SpxH0MIwI+r5qsNjKcSERVKd\r\n"
  "a=fingerprint:sha-256 DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49\r\n"
  "a=setup:actpass\r\n"
  "a=rtpmap:0 PCMU/8000\r\n"
  "a=rtpmap:8 PCMA/8000\r\n"
  "a=ssrc:12345678 cname:1hx9gGezTSDLkjru\r\n"
  "a=ssrc:12345678 msid:go3K62U7QjfQ9JFW9Fuxvd0CwzKt7LqQKs3P ece80006-ec0d-46fc-9775-faa39ace53c5\r\n"
  "a=ssrc:12345678 mslabel:go3K62U7QjfQ9JFW9Fuxvd0CwzKt7LqQKs3P\r\n"
  "a=ssrc:12345678 label:ece80006-ec0d-46fc-9775-faa39ace53c5\r\n"
  "m=video 9 UDP/TLS/RTP/SAVPF 100\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "a=rtcp:9 IN IP4 0.0.0.0\r\n"
  "a=mid:video\r\n"
  "a=rtcp-mux\r\n"
  "a=sendrecv\r\n"
  "a=ice-ufrag:NYta\r\n"
  "a=ice-pwd:SpxH0MIwI+r5qsNjKcSERVKd\r\n"
  "a=fingerprint:sha-256 DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49\r\n"
  "a=setup:actpass\r\n"
  "a=rtpmap:100 VP8/90000\r\n"
  "a=ssrc:87654321 cname:1hx9gGezTSDLkjru\r\n"
  "a=ssrc:87654321 msid:go3K62U7QjfQ9JFW9Fuxvd0CwzKt7LqQKs3P 90db69b6-00c0-4160-99c2-fe96251afedd\r\n"
  "a=ssrc:87654321 mslabel:go3K62U7QjfQ9JFW9Fuxvd0CwzKt7LqQKs3P\r\n"
  "a=ssrc:87654321 label:90db69b6-00c0-4160-99c2-fe96251afedd\r\n";

RTEST (rsdp, msg_new_jsep, RTEST_FAST)
{
  RSdpMsg * msg;
  RSdpMedia * m;
  RBuffer * buf;

  r_assert_cmpptr ((msg = r_sdp_msg_new_jsep (jsep_sessid, jsep_sessver)), !=, NULL);
  r_assert_cmpptr ((buf = r_sdp_msg_to_buffer (msg)), !=, NULL);
  r_sdp_msg_unref (msg);
  r_assert_cmpbufsstr (buf, 0, -1, ==, sdp_jsep_default);
  r_buffer_unref (buf);

  r_assert_cmpptr ((msg = r_sdp_msg_new_jsep (jsep_sessid, jsep_sessver)), !=, NULL);
  r_assert_cmpptr ((m = r_sdp_media_new_jsep_dtls ("audio", -1, "audio", -1, R_SDP_MD_SENDRECV)), !=, NULL);
  r_assert_cmpint (r_sdp_msg_add_media (msg, m), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_ice_credentials (m,
        R_STR_WITH_SIZE_ARGS (ice_ufrag), R_STR_WITH_SIZE_ARGS (ice_pwd)), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_dtls_setup (m, R_SDP_CONN_ROLE_ACTPASS,
        R_MSG_DIGEST_TYPE_SHA256, R_STR_WITH_SIZE_ARGS (jsep_fingerprint)), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, R_RTP_PT_PCMU,
        R_STR_WITH_SIZE_ARGS ("PCMU"), 8000, 0), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, R_RTP_PT_PCMA,
        R_STR_WITH_SIZE_ARGS ("PCMA"), 8000, 0), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_ssrc_cname (m, audio_ssrc, jsep_cname, -1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_jsep_msid (m, audio_ssrc,
        R_STR_WITH_SIZE_ARGS (jsep_msid_value), R_STR_WITH_SIZE_ARGS (jsep_msid_audio)), ==, R_SDP_OK);
  r_sdp_media_unref (m);
  r_assert_cmpptr ((m = r_sdp_media_new_jsep_dtls ("video", -1, "video", -1, R_SDP_MD_SENDRECV)), !=, NULL);
  r_assert_cmpint (r_sdp_msg_add_media (msg, m), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_ice_credentials (m,
        R_STR_WITH_SIZE_ARGS (ice_ufrag), R_STR_WITH_SIZE_ARGS (ice_pwd)), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_dtls_setup (m, R_SDP_CONN_ROLE_ACTPASS,
        R_MSG_DIGEST_TYPE_SHA256, R_STR_WITH_SIZE_ARGS (jsep_fingerprint)), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, (RRTPPayloadType)100,
        R_STR_WITH_SIZE_ARGS ("VP8"), 90000, 0), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_ssrc_cname (m, video_ssrc, jsep_cname, -1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_jsep_msid (m, video_ssrc,
        R_STR_WITH_SIZE_ARGS (jsep_msid_value), R_STR_WITH_SIZE_ARGS (jsep_msid_video)), ==, R_SDP_OK);
  r_sdp_media_unref (m);
  r_assert_cmpptr ((buf = r_sdp_msg_to_buffer (msg)), !=, NULL);
  r_sdp_msg_unref (msg);
  r_assert_cmpbufsstr (buf, 0, -1, ==, sdp_jsep_with_av);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rsdp, create_webrtc_sdp, RTEST_FAST)
{
  RSdpMsg * msg;
  RSdpMedia * m;
  RSocketAddress * addr;
  RBuffer * buf;
  static const rchar expected[] =
    "v=0\r\n"
    "o=- 2489868560574230385 2 IN IP4 127.0.0.1\r\n"
    "s=-\r\n"
    "t=0 0\r\n"
    "a=group:BUNDLE audio\r\n"
    "m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 106 105 13 126\r\n"
    "c=IN IP4 0.0.0.0\r\n"
    "a=rtcp:9 IN IP4 0.0.0.0\r\n"
    "a=mid:audio\r\n"
    "a=rtcp-mux\r\n"
    "a=recvonly\r\n"
    "a=ice-ufrag:4f5Pqit80I/GWqjp\r\n"
    "a=ice-pwd:p+q6kISttan/TbFv8tauTFfA\r\n"
    "a=ice-lite\r\n"
    "a=candidate:1467250027 1 udp 2122260223 127.0.0.1 56144 typ host generation 0\r\n"
    "a=fingerprint:sha-256 74:AC:BD:23:74:28:88:33:67:89:4A:3E:05:12:24:55:C1:1C:71:C4:DE:00:C7:47:D3:5D:98:51:36:A8:0A:B8\r\n"
    "a=setup:passive\r\n"
    "a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level\r\n"
    "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
    "a=rtpmap:111 opus/48000/2\r\n"
    "a=rtcp-fb:111 transport-cc\r\n"
    "a=fmtp:111 minptime=10;useinbandfec=1\r\n"
    "a=rtpmap:103 ISAC/16000\r\n"
    "a=rtpmap:104 ISAC/32000\r\n"
    "a=rtpmap:9 G722/8000\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:106 CN/32000\r\n"
    "a=rtpmap:105 CN/16000\r\n"
    "a=rtpmap:13 CN/8000\r\n"
    "a=rtpmap:126 telephone-event/8000\r\n";

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 56144)), !=, NULL);

  r_assert_cmpptr ((msg = r_sdp_msg_new_jsep (RUINT64_CONSTANT (2489868560574230385), 2)), !=, NULL);
  r_assert_cmpptr ((m = r_sdp_media_new_jsep_dtls ("audio", -1, "audio", -1, R_SDP_MD_RECVONLY)), !=, NULL);
  r_assert_cmpint (r_sdp_msg_add_media (msg, m), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_ice_credentials (m, R_STR_WITH_SIZE_ARGS ("4f5Pqit80I/GWqjp"),
        R_STR_WITH_SIZE_ARGS ("p+q6kISttan/TbFv8tauTFfA")), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_attribute (m, R_STR_WITH_SIZE_ARGS ("ice-lite"), NULL, 0), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_ice_candidate (m, R_STR_WITH_SIZE_ARGS ("1467250027"), 1,
        R_STR_WITH_SIZE_ARGS ("udp"), RUINT64_CONSTANT (2122260223), addr, R_SDP_ICE_TYPE_HOST,
        NULL, R_STR_WITH_SIZE_ARGS ("generation 0")), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_dtls_setup (m, R_SDP_CONN_ROLE_PASSIVE,
        R_MSG_DIGEST_TYPE_SHA256,
        R_STR_WITH_SIZE_ARGS ("74:AC:BD:23:74:28:88:33:67:89:4A:3E:05:12:24:55:C1:1C:71:C4:DE:00:C7:47:D3:5D:98:51:36:A8:0A:B8")),
      ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_attribute (m, R_STR_WITH_SIZE_ARGS ("extmap"), R_STR_WITH_SIZE_ARGS ("1 urn:ietf:params:rtp-hdrext:ssrc-audio-level")), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_attribute (m, R_STR_WITH_SIZE_ARGS ("extmap"), R_STR_WITH_SIZE_ARGS ("3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time")), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, (RRTPPayloadType)111,
        R_STR_WITH_SIZE_ARGS ("opus"), 48000, 2), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_attribute (m, R_STR_WITH_SIZE_ARGS ("rtcp-fb"), R_STR_WITH_SIZE_ARGS ("111 transport-cc")), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_attribute (m, R_STR_WITH_SIZE_ARGS ("fmtp"), R_STR_WITH_SIZE_ARGS ("111 minptime=10;useinbandfec=1")), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, (RRTPPayloadType)103,
        R_STR_WITH_SIZE_ARGS ("ISAC"), 16000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, (RRTPPayloadType)104,
        R_STR_WITH_SIZE_ARGS ("ISAC"), 32000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, R_RTP_PT_G722,
        R_STR_WITH_SIZE_ARGS ("G722"), 8000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, R_RTP_PT_PCMU,
        R_STR_WITH_SIZE_ARGS ("PCMU"), 8000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, R_RTP_PT_PCMA,
        R_STR_WITH_SIZE_ARGS ("PCMA"), 8000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, (RRTPPayloadType)106,
        R_STR_WITH_SIZE_ARGS ("CN"), 32000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, (RRTPPayloadType)105,
        R_STR_WITH_SIZE_ARGS ("CN"), 16000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, R_RTP_PT_CN,
        R_STR_WITH_SIZE_ARGS ("CN"), 8000, 1), ==, R_SDP_OK);
  r_assert_cmpint (r_sdp_media_add_rtp_fmt (m, (RRTPPayloadType)126,
        R_STR_WITH_SIZE_ARGS ("telephone-event"), 8000, 1), ==, R_SDP_OK);

  r_socket_address_unref (addr);
  r_sdp_media_unref (m);
  r_assert_cmpptr ((buf = r_sdp_msg_to_buffer (msg)), !=, NULL);
  r_sdp_msg_unref (msg);
  r_assert_cmpbufsstr (buf, 0, -1, ==, expected);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rsdp, find_grouping_BUNDLE, RTEST_FAST)
{
  RBuffer * buf;
  RSdpBuf sdp;
  RStrChunk group;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_chrome_webrtc_offer))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_OK);

  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, NULL,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "foobar", -1), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), NULL, -1), ==, R_SDP_INVAL);
  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "foobar", 0), ==, R_SDP_INVAL);

  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "foobar", -1), ==, R_SDP_NOT_FOUND);
  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "audio", -1), ==, R_SDP_OK);
  r_assert_cmpstrn ("audio", ==, group.str, group.size);
  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "audio", 3), ==, R_SDP_NOT_FOUND);
  r_assert_cmpstr (group.str, ==, NULL);

  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, buf), ==, R_SDP_OK);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_jsep_with_av))), !=, NULL);
  r_assert_cmpint (r_sdp_buffer_map (&sdp, buf), ==, R_SDP_OK);

  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "foobar", -1), ==, R_SDP_NOT_FOUND);
  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "audio", -1), ==, R_SDP_OK);
  r_assert_cmpstrn ("audio video", ==, group.str, group.size);
  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "audio", 3), ==, R_SDP_NOT_FOUND);
  r_assert_cmpstr (group.str, ==, NULL);
  r_assert_cmpint (r_sdp_buf_find_grouping (&sdp, &group,
        R_STR_WITH_SIZE_ARGS ("BUNDLE"), "video", -1), ==, R_SDP_OK);
  r_assert_cmpstrn ("audio video", ==, group.str, group.size);

  r_assert_cmpint (r_sdp_buffer_unmap (&sdp, buf), ==, R_SDP_OK);
  r_buffer_unref (buf);
}
RTEST_END;

