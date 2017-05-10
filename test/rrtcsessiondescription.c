#include <rlib/rlib.h>

static const rchar sdp_chrome_webrtc_offer_audio_only[] =
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

RTEST (rrtcsessiondescription, new_from_sdp_webrtc_chrome_audio_only, RTEST_FAST)
{
  RRtcSessionDescription * sd;
  RBuffer * buf;
  RRtcError err;
  RRtcMediaLineInfo * mline;
  RRtcTransportInfo * trans;
  RRtcRtpCodecParameters * codec;
  RRtcRtpEncodingParameters * encoding;
  RRtcRtpHdrExtParameters * hdrext;

  r_assert_cmpptr (r_rtc_session_description_new_from_sdp (R_RTC_SIGNAL_OFFER, NULL, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_RTC_INVAL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_chrome_webrtc_offer_audio_only))), !=, NULL);
  r_assert_cmpptr ((sd = r_rtc_session_description_new_from_sdp (R_RTC_SIGNAL_OFFER, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_RTC_OK);
  r_assert_cmpint (sd->dir, ==, R_RTC_DIR_NONE);
  r_assert_cmpstr (sd->username, ==, "-");
  r_assert_cmpstr (sd->session_name, ==, "-");
  r_assert_cmpstr (sd->session_id, ==, "8610450130369641692");
  r_assert_cmpuint (sd->session_ver, ==, 2);
  r_assert_cmpstr (sd->orig_nettype, ==, "IN");
  r_assert_cmpstr (sd->orig_addrtype, ==, "IP4");
  r_assert_cmpstr (sd->orig_addr, ==, "127.0.0.1");
  r_assert_cmpstr (sd->conn_nettype, ==, NULL);
  r_assert_cmpstr (sd->conn_addrtype, ==, NULL);
  r_assert_cmpstr (sd->conn_addr, ==, NULL);
  r_assert_cmpuint (sd->conn_ttl, ==, 0);
  r_assert_cmpuint (sd->conn_addrcount, ==, 0);

  r_assert_cmpuint (r_rtc_session_description_transport_count (sd), ==, 1);
  r_assert_cmpptr ((trans = r_rtc_session_description_get_transport (sd, "audio")), !=, NULL);
  r_assert_cmpstr (trans->id, ==, "audio");
  r_assert_cmpptr (trans->addr, !=, NULL);
  r_assert (trans->rtcpmux);
  r_assert_cmpstr (trans->rtp.ice.ufrag, ==, "ALgn");
  r_assert_cmpstr (trans->rtp.ice.pwd, ==, "FckU0ZVjV+e5dfAwXpFREIXq");
  r_assert (!trans->rtp.ice.lite);
  r_assert_cmpint (trans->rtp.dtls.role, ==, R_RTC_ROLE_AUTO);
  r_assert_cmpint (trans->rtp.dtls.md, ==, R_MSG_DIGEST_TYPE_SHA256);
  r_assert_cmpstr (trans->rtp.dtls.fingerprint, ==, "DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49");

  r_assert_cmpuint (r_rtc_session_description_media_line_count (sd), ==, 1);
  r_assert_cmpptr ((mline = r_rtc_session_description_get_media_line (sd,
          R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (mline->type, ==, R_RTC_MEDIA_AUDIO);
  r_assert_cmpint (mline->dir, ==, R_RTC_DIR_SEND_RECV);
  r_assert_cmpstr (mline->mid, ==, "audio");
  r_assert_cmpint (mline->proto, ==, R_RTC_PROTO_RTP);
  r_assert_cmpint (mline->protoflags, ==, R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE | R_RTC_PROTO_FLAG_FEEDBACK);
  r_assert_cmpstr (mline->trans, ==, "audio");
  r_assert (mline->bundled);
  r_assert_cmpuint (r_ptr_array_size (&mline->candidates), ==, 0);
  r_assert (!mline->endofcandidates);
  r_assert_cmpptr (mline->params, !=, NULL);
  r_assert_cmpstr (r_rtc_rtp_parameters_mid (mline->params), ==, mline->mid);
  r_assert_cmpstr (r_rtc_rtp_parameters_rtcp_cname (mline->params), ==, "1uk9tTrmGFQYxweh");
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_ssrc (mline->params), ==, 600258811);
  r_assert_cmpint (r_rtc_rtp_parameters_rtcp_flags (mline->params), ==, R_RTC_RTCP_MUX);

  /* codecs */
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (mline->params), ==, 10);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 0)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "opus");
  r_assert_cmpuint (codec->pt, ==, 111);
  r_assert_cmpuint (codec->rate, ==, 48000);
  r_assert_cmpuint (codec->channels, ==, 2);
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 1);
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 0), ==, "transport-cc");
  r_assert_cmpstr (codec->fmtp, ==, "minptime=10;useinbandfec=1");
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 1)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "ISAC");
  r_assert_cmpuint (codec->pt, ==, 103);
  r_assert_cmpuint (codec->rate, ==, 16000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 2)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "ISAC");
  r_assert_cmpuint (codec->pt, ==, 104);
  r_assert_cmpuint (codec->rate, ==, 32000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 3)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "G722");
  r_assert_cmpuint (codec->pt, ==, R_RTP_PT_G722);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 4)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "PCMU");
  r_assert_cmpuint (codec->pt, ==, R_RTP_PT_PCMU);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 5)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "PCMA");
  r_assert_cmpuint (codec->pt, ==, R_RTP_PT_PCMA);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 6)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "CN");
  r_assert_cmpuint (codec->pt, ==, 106);
  r_assert_cmpuint (codec->rate, ==, 32000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 7)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "CN");
  r_assert_cmpuint (codec->pt, ==, 105);
  r_assert_cmpuint (codec->rate, ==, 16000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 8)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "CN");
  r_assert_cmpuint (codec->pt, ==, R_RTP_PT_CN);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 9)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "telephone-event");
  r_assert_cmpuint (codec->pt, ==, 126);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);

  /* encodings */
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (mline->params), ==, 6);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 0)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 600258811);
  r_assert_cmpuint (encoding->pt, ==, 111);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 1)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 600258811);
  r_assert_cmpuint (encoding->pt, ==, 103);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 2)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 600258811);
  r_assert_cmpuint (encoding->pt, ==, 104);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 3)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 600258811);
  r_assert_cmpuint (encoding->pt, ==, R_RTP_PT_G722);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 4)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 600258811);
  r_assert_cmpuint (encoding->pt, ==, R_RTP_PT_PCMU);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 5)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 600258811);
  r_assert_cmpuint (encoding->pt, ==, R_RTP_PT_PCMA);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);

  /* header extensions */
  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (mline->params), ==, 1);
  r_assert_cmpptr ((hdrext = r_rtc_rtp_parameters_get_hdrext (mline->params, 0)), !=, NULL);
  r_assert_cmpuint (hdrext->id, ==, 1);
  r_assert_cmpstr (hdrext->uri, ==, "urn:ietf:params:rtp-hdrext:ssrc-audio-level");

  r_rtc_session_description_unref (sd);
  r_buffer_unref (buf);
}
RTEST_END;


static const rchar sdp_chrome_webrtc_offer_av[] =
  "v=0\r\n"
  "o=- 7090199216460686594 2 IN IP4 127.0.0.1\r\n"
  "s=-\r\n"
  "t=0 0\r\n"
  "a=group:BUNDLE audio video\r\n"
  "a=msid-semantic: WMS eypMqXxBuVvIM7OozGCOCHzotp9hzt9NoP7d\r\n"
  "m=audio 9 UDP/TLS/RTP/SAVPF 111 103 104 9 0 8 110 112 113 126\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "a=rtcp:9 IN IP4 0.0.0.0\r\n"
  "a=ice-ufrag:AKbc\r\n"
  "a=ice-pwd:QTIVSkIWXNWrOZtkwXVcmbbY\r\n"
  "a=fingerprint:sha-256 C4:37:9E:59:AD:C2:89:DD:3E:7A:E1:BD:C6:B5:C0:C0:77:D5:B6:66:6A:63:85:DC:90:A4:C3:AC:73:7E:13:F4\r\n"
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
  "a=rtpmap:110 telephone-event/48000\r\n"
  "a=rtpmap:112 telephone-event/32000\r\n"
  "a=rtpmap:113 telephone-event/16000\r\n"
  "a=rtpmap:126 telephone-event/8000\r\n"
  "a=ssrc:3189111920 cname:AyGJ3PEhxKQXrY0g\r\n"
  "a=ssrc:3189111920 msid:eypMqXxBuVvIM7OozGCOCHzotp9hzt9NoP7d ce68caff-83bf-4a56-ad89-136bfbf688b7\r\n"
  "a=ssrc:3189111920 mslabel:eypMqXxBuVvIM7OozGCOCHzotp9hzt9NoP7d\r\n"
  "a=ssrc:3189111920 label:ce68caff-83bf-4a56-ad89-136bfbf688b7\r\n"
  "m=video 9 UDP/TLS/RTP/SAVPF 98 96 100 102 127 97 99 101 125\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "a=rtcp:9 IN IP4 0.0.0.0\r\n"
  "a=ice-ufrag:AKbc\r\n"
  "a=ice-pwd:QTIVSkIWXNWrOZtkwXVcmbbY\r\n"
  "a=fingerprint:sha-256 C4:37:9E:59:AD:C2:89:DD:3E:7A:E1:BD:C6:B5:C0:C0:77:D5:B6:66:6A:63:85:DC:90:A4:C3:AC:73:7E:13:F4\r\n"
  "a=setup:actpass\r\n"
  "a=mid:video\r\n"
  "a=extmap:2 urn:ietf:params:rtp-hdrext:toffset\r\n"
  "a=extmap:3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time\r\n"
  "a=extmap:4 urn:3gpp:video-orientation\r\n"
  "a=extmap:5 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01\r\n"
  "a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay\r\n"
  "a=sendrecv\r\n"
  "a=rtcp-mux\r\n"
  "a=rtcp-rsize\r\n"
  "a=rtpmap:96 VP8/90000\r\n"
  "a=rtcp-fb:96 ccm fir\r\n"
  "a=rtcp-fb:96 nack\r\n"
  "a=rtcp-fb:96 nack pli\r\n"
  "a=rtcp-fb:96 goog-remb\r\n"
  "a=rtcp-fb:96 transport-cc\r\n"
  "a=rtpmap:98 VP9/90000\r\n"
  "a=rtcp-fb:98 ccm fir\r\n"
  "a=rtcp-fb:98 nack\r\n"
  "a=rtcp-fb:98 nack pli\r\n"
  "a=rtcp-fb:98 goog-remb\r\n"
  "a=rtcp-fb:98 transport-cc\r\n"
  "a=rtpmap:100 H264/90000\r\n"
  "a=rtcp-fb:100 ccm fir\r\n"
  "a=rtcp-fb:100 nack\r\n"
  "a=rtcp-fb:100 nack pli\r\n"
  "a=rtcp-fb:100 goog-remb\r\n"
  "a=rtcp-fb:100 transport-cc\r\n"
  "a=fmtp:100 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
  "a=rtpmap:102 red/90000\r\n"
  "a=rtpmap:127 ulpfec/90000\r\n"
  "a=rtpmap:97 rtx/90000\r\n"
  "a=fmtp:97 apt=96\r\n"
  "a=rtpmap:99 rtx/90000\r\n"
  "a=fmtp:99 apt=98\r\n"
  "a=rtpmap:101 rtx/90000\r\n"
  "a=fmtp:101 apt=100\r\n"
  "a=rtpmap:125 rtx/90000\r\n"
  "a=fmtp:125 apt=102\r\n"
  "a=ssrc-group:FID 1721550844 2037870788\r\n"
  "a=ssrc:1721550844 cname:AyGJ3PEhxKQXrY0g\r\n"
  "a=ssrc:1721550844 msid:eypMqXxBuVvIM7OozGCOCHzotp9hzt9NoP7d b5fc80d1-eb1e-4110-9aec-6050d4655d71\r\n"
  "a=ssrc:1721550844 mslabel:eypMqXxBuVvIM7OozGCOCHzotp9hzt9NoP7d\r\n"
  "a=ssrc:1721550844 label:b5fc80d1-eb1e-4110-9aec-6050d4655d71\r\n"
  "a=ssrc:2037870788 cname:AyGJ3PEhxKQXrY0g\r\n"
  "a=ssrc:2037870788 msid:eypMqXxBuVvIM7OozGCOCHzotp9hzt9NoP7d b5fc80d1-eb1e-4110-9aec-6050d4655d71\r\n"
  "a=ssrc:2037870788 mslabel:eypMqXxBuVvIM7OozGCOCHzotp9hzt9NoP7d\r\n"
  "a=ssrc:2037870788 label:b5fc80d1-eb1e-4110-9aec-6050d4655d71\r\n";

RTEST (rrtcsessiondescription, new_from_sdp_webrtc_chrome_av, RTEST_FAST)
{
  RRtcSessionDescription * sd;
  RBuffer * buf;
  RRtcError err;
  RRtcTransportInfo * trans;
  RRtcMediaLineInfo * mline;
  RRtcRtpCodecParameters * codec;
  RRtcRtpEncodingParameters * encoding;
  RRtcRtpHdrExtParameters * hdrext;

  r_assert_cmpptr (r_rtc_session_description_new_from_sdp (R_RTC_SIGNAL_OFFER, NULL, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_RTC_INVAL);

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_chrome_webrtc_offer_av))), !=, NULL);
  r_assert_cmpptr ((sd = r_rtc_session_description_new_from_sdp (R_RTC_SIGNAL_OFFER, buf, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_RTC_OK);
  r_assert_cmpint (sd->dir, ==, R_RTC_DIR_NONE);
  r_assert_cmpstr (sd->username, ==, "-");
  r_assert_cmpstr (sd->session_name, ==, "-");
  r_assert_cmpstr (sd->session_id, ==, "7090199216460686594");
  r_assert_cmpuint (sd->session_ver, ==, 2);
  r_assert_cmpstr (sd->orig_nettype, ==, "IN");
  r_assert_cmpstr (sd->orig_addrtype, ==, "IP4");
  r_assert_cmpstr (sd->orig_addr, ==, "127.0.0.1");
  r_assert_cmpstr (sd->conn_nettype, ==, NULL);
  r_assert_cmpstr (sd->conn_addrtype, ==, NULL);
  r_assert_cmpstr (sd->conn_addr, ==, NULL);
  r_assert_cmpuint (sd->conn_ttl, ==, 0);
  r_assert_cmpuint (sd->conn_addrcount, ==, 0);

  r_assert_cmpuint (r_rtc_session_description_transport_count (sd), ==, 2);
  r_assert_cmpuint (r_rtc_session_description_media_line_count (sd), ==, 2);

  r_assert_cmpptr ((trans = r_rtc_session_description_get_transport (sd, "audio")), !=, NULL);
  r_assert_cmpstr (trans->id, ==, "audio");
  r_assert_cmpptr (trans->addr, !=, NULL);
  r_assert (trans->rtcpmux);
  r_assert_cmpstr (trans->rtp.ice.ufrag, ==, "AKbc");
  r_assert_cmpstr (trans->rtp.ice.pwd, ==, "QTIVSkIWXNWrOZtkwXVcmbbY");
  r_assert (!trans->rtp.ice.lite);
  r_assert_cmpint (trans->rtp.dtls.role, ==, R_RTC_ROLE_AUTO);
  r_assert_cmpint (trans->rtp.dtls.md, ==, R_MSG_DIGEST_TYPE_SHA256);
  r_assert_cmpstr (trans->rtp.dtls.fingerprint, ==, "C4:37:9E:59:AD:C2:89:DD:3E:7A:E1:BD:C6:B5:C0:C0:77:D5:B6:66:6A:63:85:DC:90:A4:C3:AC:73:7E:13:F4");

  r_assert_cmpptr ((mline = r_rtc_session_description_get_media_line (sd,
          R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (mline->type, ==, R_RTC_MEDIA_AUDIO);
  r_assert_cmpint (mline->dir, ==, R_RTC_DIR_SEND_RECV);
  r_assert_cmpstr (mline->mid, ==, "audio");
  r_assert_cmpint (mline->proto, ==, R_RTC_PROTO_RTP);
  r_assert_cmpint (mline->protoflags, ==, R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE | R_RTC_PROTO_FLAG_FEEDBACK);
  r_assert_cmpstr (mline->trans, ==, "audio");
  r_assert (mline->bundled);
  r_assert_cmpuint (r_ptr_array_size (&mline->candidates), ==, 0);
  r_assert (!mline->endofcandidates);
  r_assert_cmpptr (mline->params, !=, NULL);
  r_assert_cmpstr (r_rtc_rtp_parameters_mid (mline->params), ==, mline->mid);
  r_assert_cmpstr (r_rtc_rtp_parameters_rtcp_cname (mline->params), ==, "AyGJ3PEhxKQXrY0g");
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_ssrc (mline->params), ==, 3189111920);
  r_assert_cmpint (r_rtc_rtp_parameters_rtcp_flags (mline->params), ==, R_RTC_RTCP_MUX);

  /* codecs */
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (mline->params), ==, 10);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 0)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "opus");
  r_assert_cmpuint (codec->pt, ==, 111);
  r_assert_cmpuint (codec->rate, ==, 48000);
  r_assert_cmpuint (codec->channels, ==, 2);
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 1);
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 0), ==, "transport-cc");
  r_assert_cmpstr (codec->fmtp, ==, "minptime=10;useinbandfec=1");
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 1)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "ISAC");
  r_assert_cmpuint (codec->pt, ==, 103);
  r_assert_cmpuint (codec->rate, ==, 16000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 2)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "ISAC");
  r_assert_cmpuint (codec->pt, ==, 104);
  r_assert_cmpuint (codec->rate, ==, 32000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 3)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "G722");
  r_assert_cmpuint (codec->pt, ==, R_RTP_PT_G722);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 4)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "PCMU");
  r_assert_cmpuint (codec->pt, ==, R_RTP_PT_PCMU);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 5)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "PCMA");
  r_assert_cmpuint (codec->pt, ==, R_RTP_PT_PCMA);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 6)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "telephone-event");
  r_assert_cmpuint (codec->pt, ==, 110);
  r_assert_cmpuint (codec->rate, ==, 48000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 7)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "telephone-event");
  r_assert_cmpuint (codec->pt, ==, 112);
  r_assert_cmpuint (codec->rate, ==, 32000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 8)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "telephone-event");
  r_assert_cmpuint (codec->pt, ==, 113);
  r_assert_cmpuint (codec->rate, ==, 16000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 9)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "telephone-event");
  r_assert_cmpuint (codec->pt, ==, 126);
  r_assert_cmpuint (codec->rate, ==, 8000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);

  /* encodings */
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (mline->params), ==, 6);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 0)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 3189111920);
  r_assert_cmpuint (encoding->pt, ==, 111);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 1)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 3189111920);
  r_assert_cmpuint (encoding->pt, ==, 103);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 2)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 3189111920);
  r_assert_cmpuint (encoding->pt, ==, 104);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 3)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 3189111920);
  r_assert_cmpuint (encoding->pt, ==, R_RTP_PT_G722);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 4)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 3189111920);
  r_assert_cmpuint (encoding->pt, ==, R_RTP_PT_PCMU);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 5)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 3189111920);
  r_assert_cmpuint (encoding->pt, ==, R_RTP_PT_PCMA);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 0);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 0);

  /* header extensions */
  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (mline->params), ==, 1);
  r_assert_cmpptr ((hdrext = r_rtc_rtp_parameters_get_hdrext (mline->params, 0)), !=, NULL);
  r_assert_cmpuint (hdrext->id, ==, 1);
  r_assert_cmpstr (hdrext->uri, ==, "urn:ietf:params:rtp-hdrext:ssrc-audio-level");

  r_assert_cmpptr ((trans = r_rtc_session_description_get_transport (sd, "video")), !=, NULL);
  r_assert_cmpstr (trans->id, ==, "video");
  r_assert_cmpptr (trans->addr, !=, NULL);
  r_assert (trans->rtcpmux);
  r_assert_cmpstr (trans->rtp.ice.ufrag, ==, "AKbc");
  r_assert_cmpstr (trans->rtp.ice.pwd, ==, "QTIVSkIWXNWrOZtkwXVcmbbY");
  r_assert (!trans->rtp.ice.lite);
  r_assert_cmpint (trans->rtp.dtls.role, ==, R_RTC_ROLE_AUTO);
  r_assert_cmpint (trans->rtp.dtls.md, ==, R_MSG_DIGEST_TYPE_SHA256);
  r_assert_cmpstr (trans->rtp.dtls.fingerprint, ==, "C4:37:9E:59:AD:C2:89:DD:3E:7A:E1:BD:C6:B5:C0:C0:77:D5:B6:66:6A:63:85:DC:90:A4:C3:AC:73:7E:13:F4");

  r_assert_cmpptr ((mline = r_rtc_session_description_get_media_line (sd,
          R_STR_WITH_SIZE_ARGS ("video"))), !=, NULL);
  r_assert_cmpint (mline->type, ==, R_RTC_MEDIA_VIDEO);
  r_assert_cmpint (mline->dir, ==, R_RTC_DIR_SEND_RECV);
  r_assert_cmpstr (mline->mid, ==, "video");
  r_assert_cmpint (mline->proto, ==, R_RTC_PROTO_RTP);
  r_assert_cmpint (mline->protoflags, ==, R_RTC_PROTO_FLAG_AV_PROFILE | R_RTC_PROTO_FLAG_SECURE | R_RTC_PROTO_FLAG_FEEDBACK);
  r_assert_cmpstr (mline->trans, ==, "audio");
  r_assert (mline->bundled);
  r_assert_cmpuint (r_ptr_array_size (&mline->candidates), ==, 0);
  r_assert (!mline->endofcandidates);
  r_assert_cmpptr (mline->params, !=, NULL);
  r_assert_cmpstr (r_rtc_rtp_parameters_mid (mline->params), ==, mline->mid);
  r_assert_cmpstr (r_rtc_rtp_parameters_rtcp_cname (mline->params), ==, "AyGJ3PEhxKQXrY0g");
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_ssrc (mline->params), ==, 1721550844);
  r_assert_cmpint (r_rtc_rtp_parameters_rtcp_flags (mline->params), ==, R_RTC_RTCP_MUX | R_RTC_RTCP_RSIZE);

  /* codecs */
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (mline->params), ==, 9);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 0)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "VP9");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_VIDEO);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_MEDIA);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_VP9);
  r_assert_cmpuint (codec->pt, ==, 98);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 5);
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 0), ==, "ccm fir");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 1), ==, "nack");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 2), ==, "nack pli");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 3), ==, "goog-remb");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 4), ==, "transport-cc");
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 1)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "VP8");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_VIDEO);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_MEDIA);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_VP8);
  r_assert_cmpuint (codec->pt, ==, 96);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 5);
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 0), ==, "ccm fir");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 1), ==, "nack");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 2), ==, "nack pli");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 3), ==, "goog-remb");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 4), ==, "transport-cc");
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 2)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "H264");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_VIDEO);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_MEDIA);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_H264);
  r_assert_cmpuint (codec->pt, ==, 100);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f");
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 5);
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 0), ==, "ccm fir");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 1), ==, "nack");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 2), ==, "nack pli");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 3), ==, "goog-remb");
  r_assert_cmpstr (r_ptr_array_get (&codec->rtcpfb, 4), ==, "transport-cc");
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 3)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "red");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_UNKNOWN);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_FEC);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_RED);
  r_assert_cmpuint (codec->pt, ==, 102);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 0);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 4)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "ulpfec");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_UNKNOWN);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_FEC);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_ULP_FEC);
  r_assert_cmpuint (codec->pt, ==, 127);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, NULL);
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 0);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 5)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "rtx");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_UNKNOWN);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_RTX);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_RTX);
  r_assert_cmpuint (codec->pt, ==, 97);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, "apt=96");
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 0);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 6)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "rtx");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_UNKNOWN);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_RTX);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_RTX);
  r_assert_cmpuint (codec->pt, ==, 99);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, "apt=98");
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 0);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 7)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "rtx");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_UNKNOWN);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_RTX);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_RTX);
  r_assert_cmpuint (codec->pt, ==, 101);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, "apt=100");
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 0);
  r_assert_cmpptr ((codec = r_rtc_rtp_parameters_get_codec (mline->params, 8)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "rtx");
  r_assert_cmpuint (codec->media, ==, R_RTC_MEDIA_UNKNOWN);
  r_assert_cmpuint (codec->kind, ==, R_RTC_CODEC_KIND_RTX);
  r_assert_cmpuint (codec->type, ==, R_RTC_CODEC_RTX);
  r_assert_cmpuint (codec->pt, ==, 125);
  r_assert_cmpuint (codec->rate, ==, 90000);
  r_assert_cmpuint (codec->channels, ==, 1);
  r_assert_cmpstr (codec->fmtp, ==, "apt=102");
  r_assert_cmpuint (r_ptr_array_size (&codec->rtcpfb), ==, 0);

  /* encodings */
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (mline->params), ==, 3);
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 0)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 1721550844);
  r_assert_cmpuint (encoding->pt, ==, 98);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 2037870788);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 2037870788);
  r_assert_cmpstr (encoding->fec.mechanism, ==, "red+ulpfec");
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 1)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 1721550844);
  r_assert_cmpuint (encoding->pt, ==, 96);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 2037870788);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 2037870788);
  r_assert_cmpstr (encoding->fec.mechanism, ==, "red+ulpfec");
  r_assert_cmpptr ((encoding = r_rtc_rtp_parameters_get_encoding (mline->params, 2)), !=, NULL);
  r_assert_cmpuint (encoding->ssrc, ==, 1721550844);
  r_assert_cmpuint (encoding->pt, ==, 100);
  r_assert_cmpuint (encoding->rtx.ssrc, ==, 2037870788);
  r_assert_cmpuint (encoding->fec.ssrc, ==, 2037870788);
  r_assert_cmpstr (encoding->fec.mechanism, ==, "red+ulpfec");

  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (mline->params), ==, 5);
  r_assert_cmpptr ((hdrext = r_rtc_rtp_parameters_get_hdrext (mline->params, 0)), !=, NULL);
  r_assert_cmpuint (hdrext->id, ==, 2);
  r_assert_cmpstr (hdrext->uri, ==, "urn:ietf:params:rtp-hdrext:toffset");
  r_assert_cmpptr ((hdrext = r_rtc_rtp_parameters_get_hdrext (mline->params, 1)), !=, NULL);
  r_assert_cmpuint (hdrext->id, ==, 3);
  r_assert_cmpstr (hdrext->uri, ==, "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time");
  r_assert_cmpptr ((hdrext = r_rtc_rtp_parameters_get_hdrext (mline->params, 2)), !=, NULL);
  r_assert_cmpuint (hdrext->id, ==, 4);
  r_assert_cmpstr (hdrext->uri, ==, "urn:3gpp:video-orientation");
  r_assert_cmpptr ((hdrext = r_rtc_rtp_parameters_get_hdrext (mline->params, 3)), !=, NULL);
  r_assert_cmpuint (hdrext->id, ==, 5);
  r_assert_cmpstr (hdrext->uri, ==, "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
  r_assert_cmpptr ((hdrext = r_rtc_rtp_parameters_get_hdrext (mline->params, 4)), !=, NULL);
  r_assert_cmpuint (hdrext->id, ==, 6);
  r_assert_cmpstr (hdrext->uri, ==, "http://www.webrtc.org/experiments/rtp-hdrext/playout-delay");

  r_rtc_session_description_unref (sd);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST (rrtcsessiondescription, simple_to_sdp, RTEST_FAST)
{
  RRtcSessionDescription * sd;
  RRtcMediaLineInfo * mline;
  RRtcTransportInfo * trans;
  RSocketAddress * addr;
  RRtcError err;
  RBuffer * buf;

  r_assert_cmpptr ((sd = r_rtc_session_description_new (R_RTC_SIGNAL_OFFER)), !=, NULL);

  r_assert_cmpptr (r_rtc_session_description_to_sdp (sd, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_RTC_INCOMPLETE);

  r_assert_cmpint (r_rtc_session_description_set_originator_full (sd,
        R_STR_WITH_SIZE_ARGS ("jdoe"), R_STR_WITH_SIZE_ARGS ("123456789"), 2,
        R_STR_WITH_SIZE_ARGS ("IN"), R_STR_WITH_SIZE_ARGS ("IP4"),
        R_STR_WITH_SIZE_ARGS ("127.0.0.1")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_session_description_set_session_name (sd,
        R_STR_WITH_SIZE_ARGS ("-")), ==, R_RTC_OK);
  r_assert_cmpptr (r_rtc_session_description_to_sdp (sd, &err), ==, NULL);
  r_assert_cmpint (err, ==, R_RTC_INCOMPLETE);

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (94, 9, 81, 234, 45342)), !=, NULL);
  r_assert_cmpptr ((trans = r_rtc_transport_info_new_full (R_STR_WITH_SIZE_ARGS ("audio"), addr, FALSE)), !=, NULL);
  r_socket_address_unref (addr);
  r_assert_cmpint (r_rtc_session_description_take_transport (sd, trans), ==, R_RTC_OK);
  r_assert_cmpptr ((mline = r_rtc_media_line_info_new (NULL, 0,
          R_RTC_DIR_NONE, R_RTC_MEDIA_AUDIO, R_RTC_PROTO_RTP,
          R_RTC_PROTO_FLAGS_AVPF)), !=, NULL);
  r_assert_cmpptr ((mline->trans = r_strdup (trans->id)), !=, NULL);
  r_assert_cmpptr ((mline->params = r_rtc_rtp_parameters_new (mline->mid, -1)), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (mline->params, "PCMU", 0, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (mline->params, "PCMA", 8, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_session_description_take_media_line (sd, mline), ==, R_RTC_OK);

  r_assert_cmpptr ((buf = r_rtc_session_description_to_sdp (sd, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_RTC_OK);
  r_assert_cmpbufsstr (buf, 0, -1, ==,
      "v=0\r\n"
      "o=jdoe 123456789 2 IN IP4 127.0.0.1\r\n"
      "s=-\r\n"
      "t=0 0\r\n"
      "m=audio 45342 RTP/AVPF 0 8\r\n"
      "c=IN IP4 94.9.81.234\r\n"
      "a=rtpmap:0 PCMU/8000\r\n"
      "a=rtpmap:8 PCMA/8000\r\n");
  r_buffer_unref (buf);

  r_rtc_session_description_unref (sd);
}
RTEST_END;

static const rchar sdp_rlib_webrtc[] =
  "v=0\r\n"
  "o=jdoe 123456789 2 IN IP4 127.0.0.1\r\n"
  "s=-\r\n"
  "t=0 0\r\n"
  "a=group:BUNDLE audio video\r\n"
  "m=audio 9 UDP/TLS/RTP/SAVPF 0 8\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "a=candidate:1467250027 1 udp 2122260223 127.0.0.1 46244 typ host\r\n"
  "a=candidate:1467250027 2 udp 2122260222 127.0.0.1 46245 typ host\r\n"
  "a=end-of-candidates\r\n"
  "a=ice-ufrag:ALgn\r\n"
  "a=ice-pwd:FckU0ZVjV+e5dfAwXpFREIXq\r\n"
  "a=fingerprint:sha-256 DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49\r\n"
  "a=setup:actpass\r\n"
  "a=mid:audio\r\n"
  "a=sendrecv\r\n"
  "a=rtcp-mux\r\n"
  "a=rtpmap:0 PCMU/8000\r\n"
  "a=rtpmap:8 PCMA/8000\r\n"
  "a=ssrc:3735928559 cname:1uk9tTrmGFQYxweh\r\n"
  "m=video 9 UDP/TLS/RTP/SAVPF 100\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "a=candidate:1467250027 1 udp 2122260223 127.0.0.1 46246 typ host\r\n"
  "a=candidate:1467250027 2 udp 2122260222 127.0.0.1 46247 typ host\r\n"
  "a=end-of-candidates\r\n"
  "a=ice-ufrag:ALgn\r\n"
  "a=ice-pwd:FckU0ZVjV+e5dfAwXpFREIXq\r\n"
  "a=fingerprint:sha-256 DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49\r\n"
  "a=setup:actpass\r\n"
  "a=mid:video\r\n"
  "a=sendrecv\r\n"
  "a=rtcp-mux\r\n"
  "a=rtcp-rsize\r\n"
  "a=rtpmap:100 VP8/90000\r\n"
  "a=ssrc:3405691582 cname:AyGJ3PEhxKQXrY0g\r\n";

RTEST (rrtcsessiondescription, webrtc_with_BUNDLE_to_sdp, RTEST_FAST)
{
  RRtcSessionDescription * sd;
  RRtcMediaLineInfo * mline;
  RRtcTransportInfo * trans;
  RSocketAddress * addr;
  RRtcError err;
  RBuffer * buf;

  r_assert_cmpptr ((sd = r_rtc_session_description_new (R_RTC_SIGNAL_OFFER)), !=, NULL);

  r_assert_cmpint (r_rtc_session_description_set_originator_full (sd,
        R_STR_WITH_SIZE_ARGS ("jdoe"), R_STR_WITH_SIZE_ARGS ("123456789"), 2,
        R_STR_WITH_SIZE_ARGS ("IN"), R_STR_WITH_SIZE_ARGS ("IP4"),
        R_STR_WITH_SIZE_ARGS ("127.0.0.1")), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_session_description_set_session_name (sd,
        R_STR_WITH_SIZE_ARGS ("-")), ==, R_RTC_OK);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (0, 0, 0, 0, 9)), !=, NULL);
  r_assert_cmpptr ((trans = r_rtc_transport_info_new_full (R_STR_WITH_SIZE_ARGS ("audio"), addr, FALSE)), !=, NULL);
  r_socket_address_unref (addr);
  r_assert_cmpint (r_rtc_transport_set_ice_parameters (trans, "ALgn", -1, "FckU0ZVjV+e5dfAwXpFREIXq", -1, FALSE), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_transport_set_dtls_parameters (trans, R_RTC_ROLE_AUTO,
        R_MSG_DIGEST_TYPE_SHA256, "DC:1A:C4:76:1E:FF:22:64:75:B8:66:87:F2:BC:D3:17:F5:04:6F:F8:D4:C6:01:36:F5:49:E6:4F:D5:BC:E9:49", -1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_session_description_take_transport (sd, trans), ==, R_RTC_OK);
  r_assert_cmpptr ((mline = r_rtc_media_line_info_new (R_STR_WITH_SIZE_ARGS ("audio"),
          R_RTC_DIR_SEND_RECV, R_RTC_MEDIA_AUDIO, R_RTC_PROTO_RTP,
          R_RTC_PROTO_FLAGS_SAVPF)), !=, NULL);
  mline->bundled = TRUE;
  r_assert_cmpptr ((mline->trans = r_strdup (trans->id)), !=, NULL);
  r_assert_cmpint (r_rtc_media_line_info_take_ice_candidate (mline,
        r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("1467250027"),
          RUINT64_CONSTANT (2122260223), R_RTC_ICE_COMPONENT_RTP,
          R_RTC_ICE_PROTO_UDP, "127.0.0.1", 46244,
          R_RTC_ICE_CANDIDATE_HOST)), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_media_line_info_take_ice_candidate (mline,
        r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("1467250027"),
          RUINT64_CONSTANT (2122260222), R_RTC_ICE_COMPONENT_RTCP,
          R_RTC_ICE_PROTO_UDP, "127.0.0.1", 46245,
          R_RTC_ICE_CANDIDATE_HOST)), ==, R_RTC_OK);
  mline->endofcandidates = TRUE;
  r_assert_cmpptr ((mline->params = r_rtc_rtp_parameters_new (mline->mid, -1)), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_set_rtcp (mline->params,
        R_STR_WITH_SIZE_ARGS ("1uk9tTrmGFQYxweh"), 0xdeadbeef,
        R_RTC_RTCP_MUX), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (mline->params, "PCMU", 0, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (mline->params, "PCMA", 8, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_session_description_take_media_line (sd, mline), ==, R_RTC_OK);
  r_assert_cmpptr ((mline = r_rtc_media_line_info_new (R_STR_WITH_SIZE_ARGS ("video"),
          R_RTC_DIR_SEND_RECV, R_RTC_MEDIA_VIDEO, R_RTC_PROTO_RTP,
          R_RTC_PROTO_FLAGS_SAVPF)), !=, NULL);
  mline->bundled = TRUE;
  r_assert_cmpptr ((mline->trans = r_strdup (trans->id)), !=, NULL);
  r_assert_cmpint (r_rtc_media_line_info_take_ice_candidate (mline,
        r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("1467250027"),
          RUINT64_CONSTANT (2122260223), R_RTC_ICE_COMPONENT_RTP,
          R_RTC_ICE_PROTO_UDP, "127.0.0.1", 46246,
          R_RTC_ICE_CANDIDATE_HOST)), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_media_line_info_take_ice_candidate (mline,
        r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("1467250027"),
          RUINT64_CONSTANT (2122260222), R_RTC_ICE_COMPONENT_RTCP,
          R_RTC_ICE_PROTO_UDP, "127.0.0.1", 46247,
          R_RTC_ICE_CANDIDATE_HOST)), ==, R_RTC_OK);
  mline->endofcandidates = TRUE;
  r_assert_cmpptr ((mline->params = r_rtc_rtp_parameters_new (mline->mid, -1)), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_set_rtcp (mline->params,
        R_STR_WITH_SIZE_ARGS ("AyGJ3PEhxKQXrY0g"), 0xcafebabe,
        R_RTC_RTCP_MUX | R_RTC_RTCP_RSIZE), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (mline->params, "VP8", 100, 90000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_session_description_take_media_line (sd, mline), ==, R_RTC_OK);

  r_assert_cmpptr ((buf = r_rtc_session_description_to_sdp (sd, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_RTC_OK);
  r_assert_cmpbufsstr (buf, 0, -1, ==, sdp_rlib_webrtc);
  r_buffer_unref (buf);

  r_rtc_session_description_unref (sd);
}
RTEST_END;

RTEST (rrtcsessiondescription, new_from_sdp_to_sdp_symetric, RTEST_FAST)
{
  RRtcSessionDescription * sd;
  RRtcError err;
  RBuffer * buf, * out;

  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_rlib_webrtc))), !=, NULL);
  r_assert_cmpptr ((sd = r_rtc_session_description_new_from_sdp (R_RTC_SIGNAL_OFFER, buf, &err)), !=, NULL);
  r_assert_cmpptr ((out = r_rtc_session_description_to_sdp (sd, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_RTC_OK);
  r_rtc_session_description_unref (sd);
  r_assert_cmpbufsstr (out, 0, -1, ==, sdp_rlib_webrtc);
  //r_assert_cmpbuf (buf, 0, ==, out, 0, -1);
  r_buffer_unref (buf);
  r_buffer_unref (out);

#if 0
  r_assert_cmpptr ((buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (sdp_chrome_webrtc_offer_av))), !=, NULL);
  r_assert_cmpptr ((sd = r_rtc_session_description_new_from_sdp (R_RTC_SIGNAL_OFFER, buf, &err)), !=, NULL);
  r_assert_cmpptr ((out = r_rtc_session_description_to_sdp (sd, &err)), !=, NULL);
  r_assert_cmpint (err, ==, R_RTC_OK);
  r_rtc_session_description_unref (sd);
  r_assert_cmpbuf (buf, 0, ==, out, 0, -1);
  r_buffer_unref (buf);
  r_buffer_unref (out);
#endif
}
RTEST_END;

