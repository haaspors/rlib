#include <rlib/rlib.h>

RTEST (rrtcicecandidate, new, RTEST_FAST)
{
  RRtcIceCandidate * cand;

  r_assert_cmpptr (r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, "10.0.0.1", 47523, 42), ==, NULL);
  r_assert_cmpptr (r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, NULL, 47523, R_RTC_ICE_CANDIDATE_HOST), ==, NULL);
  r_assert_cmpptr (r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, "foobar", 47523, R_RTC_ICE_CANDIDATE_HOST), ==, NULL);
  r_assert_cmpptr (r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
        R_RTC_ICE_COMPONENT_RTP, 42, "10.0.0.1", 47523, R_RTC_ICE_CANDIDATE_HOST), ==, NULL);
  r_assert_cmpptr (r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
        42, R_RTC_ICE_PROTO_UDP, "10.0.0.1", 47523, R_RTC_ICE_CANDIDATE_HOST), ==, NULL);

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, "10.0.0.1", 47523,
        R_RTC_ICE_CANDIDATE_HOST)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_candidate_get_type (cand), ==, R_RTC_ICE_CANDIDATE_HOST);
  r_assert_cmpint (r_rtc_ice_candidate_get_component (cand), ==, R_RTC_ICE_COMPONENT_RTP);
  r_assert_cmpint (r_rtc_ice_candidate_get_protocol (cand), ==, R_RTC_ICE_PROTO_UDP);
  r_assert_cmpuint (r_rtc_ice_candidate_get_pri (cand), ==, 0);
  r_assert_cmpuint (r_rtc_ice_candidate_ext_count (cand), ==, 0);
  r_rtc_ice_candidate_unref (cand);
}
RTEST_END;

RTEST (rrtcicecandidate, new_from_sdp, RTEST_FAST)
{
  RRtcIceCandidate * cand;
  RSocketAddress * addr;
  const RStrKV * kv;
  rchar * tmp;

  r_assert_cmpptr (r_rtc_ice_candidate_new_from_sdp_attrib_value (NULL, 0), ==, NULL);
  r_assert_cmpptr (r_rtc_ice_candidate_new_from_sdp_attrib_value ("foobar", -1), ==, NULL);

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new_from_sdp_attrib_value (
          R_STR_WITH_SIZE_ARGS ("1467250027 1 udp 2122260223 127.0.0.1 56148 typ host generation 0"))), !=, NULL);
  r_assert_cmpstr (r_rtc_ice_candidate_get_foundation (cand), ==, "1467250027");
  r_assert_cmpint (r_rtc_ice_candidate_get_component (cand), ==, R_RTC_ICE_COMPONENT_RTP);
  r_assert_cmpint (r_rtc_ice_candidate_get_protocol (cand), ==, R_RTC_ICE_PROTO_UDP);
  r_assert_cmpuint (r_rtc_ice_candidate_get_pri (cand), ==, RUINT64_CONSTANT (2122260223));
  r_assert_cmpptr ((addr = r_rtc_ice_candidate_get_addr (cand)), !=, NULL);
  r_assert_cmpstr ((tmp = r_socket_address_to_str (addr)), ==, "127.0.0.1:56148"); r_free (tmp);
  r_socket_address_unref (addr);
  r_assert_cmpint (r_rtc_ice_candidate_get_type (cand), ==, R_RTC_ICE_CANDIDATE_HOST);
  r_assert_cmpptr (r_rtc_ice_candidate_get_raddr (cand), ==, NULL);
  r_assert_cmpuint (r_rtc_ice_candidate_ext_count (cand), ==, 1);
  r_assert_cmpptr ((kv = r_rtc_ice_candidate_get_ext (cand, 0)), !=, NULL);
  r_assert_cmpstr ((tmp = r_str_kv_dup_key (kv)), ==, "generation"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_str_kv_dup_value (kv)), ==, "0"); r_free (tmp);
  r_rtc_ice_candidate_unref (cand);

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new_from_sdp_attrib_value (
          R_STR_WITH_SIZE_ARGS ("550891826 2 udp 15108212 137.10.230.30 39641 typ relay raddr 8.16.8.16 rport 65427 generation 0"))), !=, NULL);
  r_assert_cmpstr (r_rtc_ice_candidate_get_foundation (cand), ==, "550891826");
  r_assert_cmpint (r_rtc_ice_candidate_get_component (cand), ==, R_RTC_ICE_COMPONENT_RTCP);
  r_assert_cmpint (r_rtc_ice_candidate_get_protocol (cand), ==, R_RTC_ICE_PROTO_UDP);
  r_assert_cmpuint (r_rtc_ice_candidate_get_pri (cand), ==, RUINT64_CONSTANT (15108212));
  r_assert_cmpptr ((addr = r_rtc_ice_candidate_get_addr (cand)), !=, NULL);
  r_assert_cmpstr ((tmp = r_socket_address_to_str (addr)), ==, "137.10.230.30:39641"); r_free (tmp);
  r_socket_address_unref (addr);
  r_assert_cmpint (r_rtc_ice_candidate_get_type (cand), ==, R_RTC_ICE_CANDIDATE_RELAY);
  r_assert_cmpptr ((addr = r_rtc_ice_candidate_get_raddr (cand)), !=, NULL);
  r_assert_cmpstr ((tmp = r_socket_address_to_str (addr)), ==, "8.16.8.16:65427"); r_free (tmp);
  r_socket_address_unref (addr);
  r_assert_cmpuint (r_rtc_ice_candidate_ext_count (cand), ==, 1);
  r_assert_cmpptr ((kv = r_rtc_ice_candidate_get_ext (cand, 0)), !=, NULL);
  r_assert_cmpstr ((tmp = r_str_kv_dup_key (kv)), ==, "generation"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_str_kv_dup_value (kv)), ==, "0"); r_free (tmp);
  r_rtc_ice_candidate_unref (cand);

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new_from_sdp_attrib_value (
          R_STR_WITH_SIZE_ARGS ("foobar 1 udp 25148212 127.0.0.1 1337 typ host"))), !=, NULL);
  r_assert_cmpstr (r_rtc_ice_candidate_get_foundation (cand), ==, "foobar");
  r_assert_cmpint (r_rtc_ice_candidate_get_component (cand), ==, R_RTC_ICE_COMPONENT_RTP);
  r_assert_cmpint (r_rtc_ice_candidate_get_protocol (cand), ==, R_RTC_ICE_PROTO_UDP);
  r_assert_cmpuint (r_rtc_ice_candidate_get_pri (cand), ==, RUINT64_CONSTANT (25148212));
  r_assert_cmpptr ((addr = r_rtc_ice_candidate_get_addr (cand)), !=, NULL);
  r_assert_cmpstr ((tmp = r_socket_address_to_str (addr)), ==, "127.0.0.1:1337"); r_free (tmp);
  r_socket_address_unref (addr);
  r_assert_cmpint (r_rtc_ice_candidate_get_type (cand), ==, R_RTC_ICE_CANDIDATE_HOST);
  r_assert_cmpptr ((addr = r_rtc_ice_candidate_get_raddr (cand)), ==, NULL);
  r_assert_cmpuint (r_rtc_ice_candidate_ext_count (cand), ==, 0);
  r_rtc_ice_candidate_unref (cand);
}
RTEST_END;

RTEST (rrtcicecandidate, add_ext, RTEST_FAST)
{
  RRtcIceCandidate * cand;
  const RStrKV * kv;
  rchar * tmp;

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, "10.0.0.1", 47523,
        R_RTC_ICE_CANDIDATE_HOST)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_candidate_get_type (cand), ==, R_RTC_ICE_CANDIDATE_HOST);
  r_assert_cmpint (r_rtc_ice_candidate_get_component (cand), ==, R_RTC_ICE_COMPONENT_RTP);
  r_assert_cmpint (r_rtc_ice_candidate_get_protocol (cand), ==, R_RTC_ICE_PROTO_UDP);
  r_assert_cmpuint (r_rtc_ice_candidate_get_pri (cand), ==, 0);
  r_assert_cmpuint (r_rtc_ice_candidate_ext_count (cand), ==, 0);

  r_assert_cmpint (r_rtc_ice_candidate_add_ext (cand, "generation", -1, "0", -1), ==, R_RTC_OK);
  r_assert_cmpuint (r_rtc_ice_candidate_ext_count (cand), ==, 1);
  r_assert_cmpptr ((kv = r_rtc_ice_candidate_get_ext (cand, 0)), !=, NULL);
  r_assert_cmpstr ((tmp = r_str_kv_dup_key (kv)), ==, "generation"); r_free (tmp);
  r_assert_cmpstr ((tmp = r_str_kv_dup_value (kv)), ==, "0"); r_free (tmp);

  r_rtc_ice_candidate_unref (cand);
}
RTEST_END;

RTEST (rrtcicecandidate, to_string, RTEST_FAST)
{
  RRtcIceCandidate * cand;
  rchar * tmp;

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new (R_STR_WITH_SIZE_ARGS ("tmp"), 0,
          R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, "10.0.0.1", 47523,
          R_RTC_ICE_CANDIDATE_HOST)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_candidate_add_ext (cand, "generation", -1, "0", -1), ==, R_RTC_OK);
  r_assert_cmpstr ((tmp = r_rtc_ice_candidate_to_string (cand)), ==,
      "tmp 1 udp 0 10.0.0.1 47523 typ host generation 0"); r_free (tmp);
  r_rtc_ice_candidate_unref (cand);

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new (
          R_STR_WITH_SIZE_ARGS ("1467250027"), RUINT64_CONSTANT (2122260223),
        R_RTC_ICE_COMPONENT_RTP, R_RTC_ICE_PROTO_UDP, "127.0.0.1", 56148,
        R_RTC_ICE_CANDIDATE_HOST)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_candidate_add_ext (cand, "generation", -1, "0", -1), ==, R_RTC_OK);
  r_assert_cmpstr ((tmp = r_rtc_ice_candidate_to_string (cand)), ==,
      "1467250027 1 udp 2122260223 127.0.0.1 56148 typ host generation 0"); r_free (tmp);
  r_rtc_ice_candidate_unref (cand);

  r_assert_cmpptr ((cand = r_rtc_ice_candidate_new (
          R_STR_WITH_SIZE_ARGS ("1467250027"), RUINT64_CONSTANT (2122260222),
        R_RTC_ICE_COMPONENT_RTCP, R_RTC_ICE_PROTO_UDP, "94.9.0.11", 56149,
        R_RTC_ICE_CANDIDATE_SRFLX)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_candidate_add_ext (cand, "dummy", -1, "foobar", -1), ==, R_RTC_OK);
  r_assert_cmpstr ((tmp = r_rtc_ice_candidate_to_string (cand)), ==,
      "1467250027 2 udp 2122260222 94.9.0.11 56149 typ srflx dummy foobar"); r_free (tmp);
  r_rtc_ice_candidate_unref (cand);
}
RTEST_END;

