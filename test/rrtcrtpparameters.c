#include <rlib/rlib.h>

RTEST (rrtcrtpparameters, new, RTEST_FAST)
{
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (NULL, 0)), !=, NULL);
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (p), ==, 0);
  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (p), ==, 0);
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (p), ==, 0);
  r_rtc_rtp_parameters_unref (p);

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_rtc_rtp_parameters_unref (p);
}
RTEST_END;

RTEST (rrtcrtpparameters, rtcp, RTEST_FAST)
{
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);

  r_assert_cmpstr (r_rtc_rtp_parameters_rtcp_cname (p), ==, NULL);
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_ssrc (p), ==, 0);
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_flags (p), ==, R_RTC_RTCP_NONE);

  r_assert_cmpint (r_rtc_rtp_parameters_set_rtcp (p, R_STR_WITH_SIZE_ARGS ("foobar"),
        0, R_RTC_RTCP_NONE), ==, R_RTC_INVAL);
  r_assert_cmpint (r_rtc_rtp_parameters_set_rtcp (p, NULL, 0,
        0xcafebabe, R_RTC_RTCP_NONE), ==, R_RTC_INVAL);

  r_assert_cmpint (r_rtc_rtp_parameters_set_rtcp (p, R_STR_WITH_SIZE_ARGS ("foobar"),
        0xcafebabe, R_RTC_RTCP_MUX), ==, R_RTC_OK);
  r_assert_cmpstr (r_rtc_rtp_parameters_rtcp_cname (p), ==, "foobar");
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_ssrc (p), ==, 0xcafebabe);
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_flags (p), ==, R_RTC_RTCP_MUX);

  r_assert_cmpint (r_rtc_rtp_parameters_set_rtcp (p, R_STR_WITH_SIZE_ARGS ("test42"),
        0xdeadbeef, R_RTC_RTCP_RSIZE), ==, R_RTC_OK);
  r_assert_cmpstr (r_rtc_rtp_parameters_rtcp_cname (p), ==, "test42");
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_ssrc (p), ==, 0xdeadbeef);
  r_assert_cmpuint (r_rtc_rtp_parameters_rtcp_flags (p), ==, R_RTC_RTCP_RSIZE);

  r_rtc_rtp_parameters_unref (p);
}
RTEST_END;

RTEST (rrtcrtpparameters, codec, RTEST_FAST)
{
  RRtcRtpParameters * p;
  RRtcRtpCodecParameters c;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);

  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (p,
        "PCMU", R_RTP_PT_PCMU, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (p), ==, 1);

  r_rtc_rtp_codec_parameters_init (&c);
  c.name = r_strdup ("opus");
  c.pt = (RRTPPayloadType) 111;
  c.rate = 48000;
  c.channels = 2;
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec (p, &c), ==, R_RTC_OK);
  r_rtc_rtp_codec_parameters_clear (&c);
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (p), ==, 2);

  r_rtc_rtp_parameters_unref (p);
}
RTEST_END;

RTEST (rrtcrtpparameters, encoding, RTEST_FAST)
{
  RRtcRtpParameters * p;
  RRtcRtpEncodingParameters e;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);

  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (p,
        0xcafebabe, R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (p), ==, 1);

  r_rtc_rtp_encoding_parameters_init (&e);
  e.ssrc = 0xdeadbeaf;
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding (p, &e), ==, R_RTC_OK);
  r_rtc_rtp_encoding_parameters_clear (&e);
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (p), ==, 2);

  r_rtc_rtp_parameters_unref (p);
}
RTEST_END;

RTEST (rrtcrtpparameters, hdrext, RTEST_FAST)
{
  RRtcRtpParameters * p;
  RRtcRtpHdrExtParameters hdrext;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);

  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (p,
        "urn:ietf:params:rtp-hdrext:sdes:mid", 1), ==, R_RTC_OK);
  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (p), ==, 1);

  r_rtc_rtp_hdrext_parameters_init (&hdrext);
  hdrext.uri = r_strdup ("urn:ietf:params:rtp-hdrext:stream-correlator");
  hdrext.id = 52595;
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext (p, &hdrext), ==, R_RTC_OK);
  r_rtc_rtp_hdrext_parameters_clear (&hdrext);
  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (p), ==, 2);

  r_rtc_rtp_parameters_unref (p);
}
RTEST_END;

