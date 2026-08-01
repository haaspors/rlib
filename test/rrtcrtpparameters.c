#include <rlib/rrtc.h>

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

RTEST (rrtcrtpparameters, hdrext_dup, RTEST_FAST)
{
  /* r_rtc_rtp_hdrext_parameters_dup used to copy uri / id / prefencrypt
   * but silently drop the params array.  Verify all scalar fields and
   * each existing params entry survives the dup (shallow pointer copy
   * since the entry type is opaque). */
  RRtcRtpHdrExtParameters orig;
  RRtcRtpHdrExtParameters * copy;
  rchar slotA = 'A', slotB = 'B';

  r_rtc_rtp_hdrext_parameters_init (&orig);
  orig.uri = r_strdup ("urn:ietf:params:rtp-hdrext:foobar");
  orig.id  = 42;
  orig.prefencrypt = TRUE;
  r_ptr_array_add (&orig.params, &slotA, NULL);
  r_ptr_array_add (&orig.params, &slotB, NULL);

  r_assert_cmpptr ((copy = r_rtc_rtp_hdrext_parameters_dup (&orig)), !=, NULL);
  r_assert_cmpstr (copy->uri, ==, "urn:ietf:params:rtp-hdrext:foobar");
  r_assert_cmpptr (copy->uri, !=, orig.uri);  /* uri is duped, not aliased */
  r_assert_cmpuint (copy->id, ==, 42);
  r_assert (copy->prefencrypt);
  r_assert_cmpuint (r_ptr_array_size (&copy->params), ==, 2);
  r_assert_cmpptr (r_ptr_array_get (&copy->params, 0), ==, &slotA);
  r_assert_cmpptr (r_ptr_array_get (&copy->params, 1), ==, &slotB);

  r_rtc_rtp_hdrext_parameters_clear (copy); r_free (copy);
  r_rtc_rtp_hdrext_parameters_clear (&orig);
}
RTEST_END;

RTEST (rrtcrtpparameters, codec_dup, RTEST_FAST)
{
  /* codec dup must deep-copy the name, fmtp and every rtcpfb entry
   * (own allocations, not aliases) and carry the scalar fields over. */
  RRtcRtpCodecParameters * orig;
  RRtcRtpCodecParameters * copy;

  r_assert_cmpptr ((orig = r_rtc_rtp_codec_parameters_new (
          R_STR_WITH_SIZE_ARGS ("opus"), (RRTPPayloadType) 111, 48000, 2)), !=, NULL);
  orig->maxptime = 120;
  orig->ptime = 20;
  orig->fmtp = r_strdup ("minptime=10;useinbandfec=1");
  r_ptr_array_add (&orig->rtcpfb, r_strdup ("nack"), r_free);
  r_ptr_array_add (&orig->rtcpfb, r_strdup ("transport-cc"), r_free);

  r_assert_cmpptr ((copy = r_rtc_rtp_codec_parameters_dup (orig)), !=, NULL);
  r_assert_cmpstr (copy->name, ==, "opus");
  r_assert_cmpptr (copy->name, !=, orig->name);        /* duped, not aliased */
  r_assert_cmpint (copy->pt, ==, 111);
  r_assert_cmpuint (copy->rate, ==, 48000);
  r_assert_cmpuint (copy->channels, ==, 2);
  r_assert_cmpuint (copy->maxptime, ==, 120);
  r_assert_cmpuint (copy->ptime, ==, 20);
  r_assert_cmpstr (copy->fmtp, ==, "minptime=10;useinbandfec=1");
  r_assert_cmpptr (copy->fmtp, !=, orig->fmtp);        /* duped, not aliased */
  r_assert_cmpuint (r_ptr_array_size (&copy->rtcpfb), ==, 2);
  r_assert_cmpstr (r_ptr_array_get (&copy->rtcpfb, 0), ==, "nack");
  r_assert_cmpptr (r_ptr_array_get (&copy->rtcpfb, 0), !=,
      r_ptr_array_get (&orig->rtcpfb, 0));             /* entries duped too */
  r_assert_cmpstr (r_ptr_array_get (&copy->rtcpfb, 1), ==, "transport-cc");

  r_rtc_rtp_codec_parameters_clear (copy); r_free (copy);
  r_rtc_rtp_codec_parameters_clear (orig); r_free (orig);
}
RTEST_END;

RTEST (rrtcrtpparameters, encoding_dup, RTEST_FAST)
{
  /* encoding dup copies every scalar field and deep-copies the FEC
   * mechanism string (own allocation, not an alias). */
  RRtcRtpEncodingParameters * orig;
  RRtcRtpEncodingParameters * copy;

  r_assert_cmpptr ((orig = r_rtc_rtp_encoding_parameters_new (
          0xdeadbeef, (RRTPPayloadType) 96)), !=, NULL);
  orig->pri = R_RTC_PRIORITY_HIGH;
  orig->rtx.ssrc = 0xcafebabe;
  orig->fec.ssrc = 0x12345678;
  orig->fec.mechanism = r_strdup ("red+ulpfec");
  orig->maxbr = 512000;

  r_assert_cmpptr ((copy = r_rtc_rtp_encoding_parameters_dup (orig)), !=, NULL);
  r_assert_cmpuint (copy->ssrc, ==, 0xdeadbeef);
  r_assert_cmpint (copy->pt, ==, 96);
  r_assert_cmpint (copy->pri, ==, R_RTC_PRIORITY_HIGH);
  r_assert_cmpuint (copy->rtx.ssrc, ==, 0xcafebabe);
  r_assert_cmpuint (copy->fec.ssrc, ==, 0x12345678);
  r_assert_cmpstr (copy->fec.mechanism, ==, "red+ulpfec");
  r_assert_cmpptr (copy->fec.mechanism, !=, orig->fec.mechanism); /* duped */
  r_assert_cmpuint (copy->maxbr, ==, 512000);

  r_rtc_rtp_encoding_parameters_clear (copy); r_free (copy);
  r_rtc_rtp_encoding_parameters_clear (orig); r_free (orig);
}
RTEST_END;

RTEST (rrtcrtpparameters, take, RTEST_FAST)
{
  /* The take_* entry points adopt a heap descriptor and expose it via
   * the count / get accessors; NULL descriptors are rejected. */
  RRtcRtpParameters * p;
  RRtcRtpCodecParameters * codec;
  RRtcRtpEncodingParameters * enc;
  RRtcRtpHdrExtParameters * hdrext;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);

  r_assert_cmpint (r_rtc_rtp_parameters_take_codec (p, NULL), ==, R_RTC_INVAL);
  r_assert_cmpint (r_rtc_rtp_parameters_take_encoding (p, NULL), ==, R_RTC_INVAL);
  r_assert_cmpint (r_rtc_rtp_parameters_take_hdrext (p, NULL), ==, R_RTC_INVAL);
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (p), ==, 0);
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (p), ==, 0);
  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (p), ==, 0);

  r_assert_cmpptr ((codec = r_rtc_rtp_codec_parameters_new (
          R_STR_WITH_SIZE_ARGS ("PCMA"), R_RTP_PT_PCMA, 8000, 1)), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_take_codec (p, codec), ==, R_RTC_OK);
  r_assert_cmpuint (r_rtc_rtp_parameters_codec_count (p), ==, 1);
  r_assert_cmpptr (r_rtc_rtp_parameters_get_codec (p, 0), ==, codec);
  r_assert_cmpstr (r_rtc_rtp_parameters_get_codec (p, 0)->name, ==, "PCMA");

  r_assert_cmpptr ((enc = r_rtc_rtp_encoding_parameters_new (
          0xabadcafe, R_RTP_PT_PCMA)), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_take_encoding (p, enc), ==, R_RTC_OK);
  r_assert_cmpuint (r_rtc_rtp_parameters_encoding_count (p), ==, 1);
  r_assert_cmpptr (r_rtc_rtp_parameters_get_encoding (p, 0), ==, enc);
  r_assert_cmpuint (r_rtc_rtp_parameters_get_encoding (p, 0)->ssrc, ==, 0xabadcafe);

  r_assert_cmpptr ((hdrext = r_rtc_rtp_hdrext_parameters_new (
          R_STR_WITH_SIZE_ARGS ("urn:ietf:params:rtp-hdrext:sdes:mid"), 3)), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_take_hdrext (p, hdrext), ==, R_RTC_OK);
  r_assert_cmpuint (r_rtc_rtp_parameters_hdrext_count (p), ==, 1);
  r_assert_cmpptr (r_rtc_rtp_parameters_get_hdrext (p, 0), ==, hdrext);
  r_assert_cmpuint (r_rtc_rtp_parameters_get_hdrext (p, 0)->id, ==, 3);

  r_rtc_rtp_parameters_unref (p);
}
RTEST_END;

RTEST (rrtcrtpcodecparameters, codecs_by_name, RTEST_FAST)
{
  RRtcRtpCodecParameters * codec;

  r_assert_cmpptr ((codec = r_rtc_rtp_codec_parameters_new (R_STR_WITH_SIZE_ARGS ("PCMU"),
          R_RTP_PT_PCMU, 8000, 1)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "PCMU");
  r_assert_cmpint (codec->media, ==, R_RTC_MEDIA_AUDIO);
  r_assert_cmpint (codec->kind, ==, R_RTC_CODEC_KIND_MEDIA);
  r_assert_cmpint (codec->type, ==, R_RTC_CODEC_PCMU);
  r_rtc_rtp_codec_parameters_clear (codec); r_free (codec);

  r_assert_cmpptr ((codec = r_rtc_rtp_codec_parameters_new (R_STR_WITH_SIZE_ARGS ("foobar"),
          R_RTP_PT_DYNAMIC_FIRST, 8000, 1)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "foobar");
  r_assert_cmpint (codec->media, ==, R_RTC_MEDIA_UNKNOWN);
  r_assert_cmpint (codec->kind, ==, R_RTC_CODEC_KIND_UNKNOWN);
  r_assert_cmpint (codec->type, ==, R_RTC_CODEC_UNKNOWN);
  r_rtc_rtp_codec_parameters_clear (codec); r_free (codec);

  r_assert_cmpptr ((codec = r_rtc_rtp_codec_parameters_new (R_STR_WITH_SIZE_ARGS ("vp9"),
          R_RTP_PT_DYNAMIC_FIRST, 90000, 1)), !=, NULL);
  r_assert_cmpstr (codec->name, ==, "vp9");
  r_assert_cmpint (codec->media, ==, R_RTC_MEDIA_VIDEO);
  r_assert_cmpint (codec->kind, ==, R_RTC_CODEC_KIND_MEDIA);
  r_assert_cmpint (codec->type, ==, R_RTC_CODEC_VP9);
  r_rtc_rtp_codec_parameters_clear (codec); r_free (codec);
}
RTEST_END;

