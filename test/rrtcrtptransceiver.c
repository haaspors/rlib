#include <rlib/rrtc.h>

static void
test_noop_event (rpointer data, rpointer ctx)
{
  (void) data; (void) ctx;
}

static void
test_noop_buffer (rpointer data, RBuffer * buf, rpointer ctx)
{
  (void) data; (void) buf; (void) ctx;
}

static const RRtcRtpReceiverCallbacks test_recv_cbs = {
  test_noop_event, test_noop_event, test_noop_buffer, test_noop_buffer,
};
static const RRtcRtpSenderCallbacks test_send_cbs = {
  test_noop_event, test_noop_event, test_noop_buffer,
};

RTEST (rrtcrtptransceiver, via_session, RTEST_FAST)
{
  RPrng * prng;
  RRtcSession * session;
  RRtcIceTransport * a, * b;
  RRtcCryptoTransport * crypto;
  RRtcRtpTransceiver * t, * t2;
  RRtcRtpReceiver * recv;
  RRtcRtpSender * send;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_create_fake_pair (&a, &b), ==, R_RTC_OK);
  r_assert_cmpptr ((crypto = r_rtc_session_create_raw_transport (session, a)), !=, NULL);

  /* An empty session has no transceivers to look up. */
  r_assert_cmpptr (r_rtc_session_lookup_rtp_transceiver (session,
        R_STR_WITH_SIZE_ARGS ("audio")), ==, NULL);

  r_assert_cmpptr ((t = r_rtc_session_create_rtp_transceiver (session,
          R_STR_WITH_SIZE_ARGS ("audio"), &test_recv_cbs, &test_send_cbs,
          NULL, NULL, crypto, crypto)), !=, NULL);

  /* Its id is the generated 24-char base64 string; mid comes from the
   * paired sender / receiver. */
  r_assert_cmpptr (r_rtc_rtp_transceiver_get_id (t), !=, NULL);
  r_assert_cmpuint (r_strlen (r_rtc_rtp_transceiver_get_id (t)), ==, 24);
  r_assert_cmpstr (r_rtc_rtp_transceiver_get_mid (t), ==, "audio");

  r_assert_cmpptr ((recv = r_rtc_rtp_transceiver_get_receiver (t)), !=, NULL);
  r_assert_cmpstr (r_rtc_rtp_receiver_get_mid (recv), ==, "audio");
  r_rtc_rtp_receiver_unref (recv);
  r_assert_cmpptr ((send = r_rtc_rtp_transceiver_get_sender (t)), !=, NULL);
  r_assert_cmpstr (r_rtc_rtp_sender_get_mid (send), ==, "audio");
  r_rtc_rtp_sender_unref (send);

  /* Lookup returns the same object (with a fresh reference). */
  r_assert_cmpptr ((t2 = r_rtc_session_lookup_rtp_transceiver (session,
          R_STR_WITH_SIZE_ARGS ("audio"))), ==, t);
  r_rtc_rtp_transceiver_unref (t2);

  /* A second transceiver for the same mid is rejected. */
  r_assert_cmpptr (r_rtc_session_create_rtp_transceiver (session,
          R_STR_WITH_SIZE_ARGS ("audio"), &test_recv_cbs, &test_send_cbs,
          NULL, NULL, crypto, crypto), ==, NULL);

  r_rtc_rtp_transceiver_unref (t);
  r_rtc_crypto_transport_unref (crypto);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (session);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrtcrtptransceiver, set_sender_receiver, RTEST_FAST)
{
  RPrng * prng;
  RRtcSession * session;
  RRtcIceTransport * a, * b;
  RRtcCryptoTransport * crypto;
  RRtcRtpSender * sender, * got;
  RRtcRtpTransceiver * t;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_create_fake_pair (&a, &b), ==, R_RTC_OK);
  r_assert_cmpptr ((crypto = r_rtc_session_create_raw_transport (session, a)), !=, NULL);

  /* Creating a sender implicitly creates a transceiver with only the
   * send side populated. */
  r_assert_cmpptr ((sender = r_rtc_session_create_rtp_sender (session,
          R_STR_WITH_SIZE_ARGS ("video"), &test_send_cbs, NULL, NULL,
          crypto, crypto)), !=, NULL);
  r_assert_cmpptr ((t = r_rtc_session_lookup_rtp_transceiver (session,
          R_STR_WITH_SIZE_ARGS ("video"))), !=, NULL);

  r_assert_cmpptr ((got = r_rtc_rtp_transceiver_get_sender (t)), ==, sender);
  r_rtc_rtp_sender_unref (got);
  r_assert_cmpptr (r_rtc_rtp_transceiver_get_receiver (t), ==, NULL);

  /* Re-setting the already-populated sender is a state error; NULL
   * arguments are rejected up front. */
  r_assert_cmpint (r_rtc_rtp_transceiver_set_sender (t, sender), ==, R_RTC_WRONG_STATE);
  r_assert_cmpint (r_rtc_rtp_transceiver_set_sender (t, NULL), ==, R_RTC_INVAL);
  r_assert_cmpint (r_rtc_rtp_transceiver_set_receiver (t, NULL), ==, R_RTC_INVAL);

  r_rtc_rtp_transceiver_unref (t);
  r_rtc_rtp_sender_unref (sender);
  r_rtc_crypto_transport_unref (crypto);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (session);
  r_prng_unref (prng);
}
RTEST_END;
