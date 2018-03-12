#include <rlib/rrtc.h>

static const rchar pemcert[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIC8TCCAdmgAwIBAgIJALoi/+XOQDHjMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV\r\n"
  "BAMMBHJsaWIwHhcNMTYxMTE1MTMzNjI0WhcNMTcxMTE1MTMzNjI0WjAPMQ0wCwYD\r\n"
  "VQQDDARybGliMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwjolUmQU\r\n"
  "r9Q2FZ7O3qau+Z6+VvuJROvxzjt1aIQLLO/hF0Ya56BZCZD5aKyqQM//fTm97VTb\r\n"
  "CQYBaNg03D20XPDIWmr7EdHxYK+YI+jz7DrWqhM4jwSvvteXXXWD7bVdCq+RyveD\r\n"
  "NrgoGZqL5UCiWS1BWkB9nS/KQtgxrT3hWSOlG1xRh6hfeIy4H2CB3Qk/Q3PHjMcH\r\n"
  "7CKhCj+ctbqR3r2K3BLL3fgZKnfQdCPsZplN8Ey4hSOc/67NQK/yn/S0JgeHmjb8\r\n"
  "D5xbaDiOloOHJJg6dm1QU0UuEpiK2Uda0VR6TGu9Ci05h5U3HoV9CbyAGQhmFSem\r\n"
  "NreAELYv89sMgwIDAQABo1AwTjAdBgNVHQ4EFgQUXFVr3x4Bcglp/MP0ZFEk/Ntz\r\n"
  "wJYwHwYDVR0jBBgwFoAUXFVr3x4Bcglp/MP0ZFEk/NtzwJYwDAYDVR0TBAUwAwEB\r\n"
  "/zANBgkqhkiG9w0BAQsFAAOCAQEAL4ZKyDRXP3+Jr/GN+p6WbFW3tHuhxWxy8rMy\r\n"
  "W7OHX/sHASzJiaEmjtIlPx/7uFFowktEmXyybEmBvYp64UZ2mo2v+CCm+236wPTS\r\n"
  "gGfpcp9nP2RI0VFdJLHuqWapa5CQJZISRAO/tj7UqflOWBohm04EvmJe53JGEq+4\r\n"
  "Dk41kC+z3jVPGHG+jR3uYOw7JCmFT+bt4P5EDxGAKe9eoweLHBJ8vlJ7cUdHhBv1\r\n"
  "BUCMVR86kPZFzHKVQtWNXt26H/khgz7RA/qUSJA17Nk2h0h60b1AbkljkduWWIMZ\r\n"
  "5B2DUz4MEDUHjppHF9+A2q5ZN+25eOYbrkS5Dq50VPNrvd8dSQ==\r\n"
  "-----END CERTIFICATE-----\r\n";

static const rchar pempk[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDCOiVSZBSv1DYV\r\n"
  "ns7epq75nr5W+4lE6/HOO3VohAss7+EXRhrnoFkJkPlorKpAz/99Ob3tVNsJBgFo\r\n"
  "2DTcPbRc8MhaavsR0fFgr5gj6PPsOtaqEziPBK++15dddYPttV0Kr5HK94M2uCgZ\r\n"
  "movlQKJZLUFaQH2dL8pC2DGtPeFZI6UbXFGHqF94jLgfYIHdCT9Dc8eMxwfsIqEK\r\n"
  "P5y1upHevYrcEsvd+Bkqd9B0I+xmmU3wTLiFI5z/rs1Ar/Kf9LQmB4eaNvwPnFto\r\n"
  "OI6Wg4ckmDp2bVBTRS4SmIrZR1rRVHpMa70KLTmHlTcehX0JvIAZCGYVJ6Y2t4AQ\r\n"
  "ti/z2wyDAgMBAAECggEABJZzAzsx8eVFUcVqhX/SajsBq/RNDb+0+nYVE97qlKkl\r\n"
  "2/Lf99ClycAO5BYP/2/qTP7sKYrzkYb+yYcx2HHsrLVTRi94trcKyIndQhvihxXs\r\n"
  "tB+4Gki2Df/xp1d7QkYiaHo1K2IlS0mWSOSJoWShcRHMlWEolmnmkSWiJsFrbTuL\r\n"
  "sxB/6lVmD6Bbez/ob5JzK4QBAEREd0QbUCQiDssFvf0nlDmtKrxosLFuu86z0nIR\r\n"
  "3OKyr9n6IW64r7x7Ccv/5pY3Cmkg0/knF4bi60ssm2byY2TW3wnOT0inVrp0UUQP\r\n"
  "ex9Dse3izVyMLaeqLh6GCQhLFROE85qslLmOYb56YQKBgQD7HHWdsrNDtkHkXvyz\r\n"
  "TWi8dPVMVk4/X/G3vPr2nBRHj9MzXX/ZgoFpklMsR/EtKh9LBBh9vY9YnXhIGUrc\r\n"
  "vwt1PSUIsjUuHBfhxnHxcZEu2ROw18LJmSRp6duZADFcH8ApPFg1dVZ2APyHyS4J\r\n"
  "tTL/DIeQ6ASq0EENjuO5VgM5PwKBgQDGAiz9c3/1OPZNiENyCYbrqOzduzkoisX7\r\n"
  "yGYFiJpLdsmrRsztqJktwiDEYYrJoV+AHmKa79Iexp6vvq9gQFN3XvFw6U1XXF5D\r\n"
  "RtLHHqWgoj9yFIpmVXfcdFICfNdPcVn7NAE0CQBRNgBJGSvRoSeTpOyjVmF9Mu18\r\n"
  "h2wUK0L3vQKBgBms7kXCmNvKjfA42iPHPXdPiilVBckrGT8NPqfqi5RJm3G8FK97\r\n"
  "zZmq0YBMltdkYDC+aXap5DdOWpccpu/tRNGm/9tkxVVCoBqAvPPQBeVBYucJGKye\r\n"
  "UP/XXpHFWEawJGjS9733knCcZzXHF0L82QsFD/N8FcYVZyFow9YWelvnAoGAIj8o\r\n"
  "FuIOJJSojPpfZ+7b5hB+f08tcKSn34dmldhtj1XJRZVmRkidzbtAvZZ9UahWgys+\r\n"
  "NLv75JTHx2+8l3IovYGvUq8XUF/Kcepi9EuJrAHD5XBGC7MGmxuHP6Tl/HiHbpot\r\n"
  "Bxnzcxha7kmrOYOc+71PrGR5UhUn3Bz0BX0CBSUCgYAKxDbgtJ1NZgf33yMQb1BG\r\n"
  "vgLQWiysO9t1dXFN9YiPsZ1Rkyj9iOdROG47T1ifcrCw45mqBF71COM23zplWz64\r\n"
  "wUg8Baom8FExrgLtVDeyQO7qkiOoP96r9Fm34Y4Sgv1/oiO9f5KYckMcSig9zCQA\r\n"
  "VFwqM04nD9RsYGRKy6NhrA==\r\n"
  "-----END PRIVATE KEY-----\r\n";

typedef struct {
  RRtcSession * session;
  RRtcRtpReceiver * recv;
  RRtcRtpSender * send;

  RQueue rtp;
  RQueue rtcp;
} TestRtcCtx;

RTEST_FIXTURE_STRUCT (rrtc)
{
  RPrng * prng;
  REvLoop * loop;

  TestRtcCtx alice;
  TestRtcCtx bob;
};

static void
test_rtc_recv_ready (rpointer data, rpointer ctx)
{
  TestRtcCtx * rtc;
  if (R_UNLIKELY ((rtc = data) == NULL)) return;

  r_assert_cmpptr (rtc->recv, ==, ctx);
}

static void
test_rtc_recv_close (rpointer data, rpointer ctx)
{
  TestRtcCtx * rtc;
  if (R_UNLIKELY ((rtc = data) == NULL)) return;

  r_assert_cmpptr (rtc->recv, ==, ctx);
}

static void
test_rtc_recv_rtp (rpointer data, RBuffer * buf, rpointer ctx)
{
  TestRtcCtx * rtc;
  if (R_UNLIKELY ((rtc = data) == NULL)) return;

  r_assert_cmpptr (rtc->recv, ==, ctx);
  r_queue_push (&rtc->rtp, r_buffer_ref (buf));
}

static void
test_rtc_recv_rtcp (rpointer data, RBuffer * buf, rpointer ctx)
{
  TestRtcCtx * rtc;
  if (R_UNLIKELY ((rtc = data) == NULL)) return;

  r_assert_cmpptr (rtc->recv, ==, ctx);
  r_queue_push (&rtc->rtcp, r_buffer_ref (buf));
}

static void
test_rtc_send_ready (rpointer data, rpointer ctx)
{
  TestRtcCtx * rtc;
  if (R_UNLIKELY ((rtc = data) == NULL)) return;

  r_assert_cmpptr (rtc->send, ==, ctx);
}

static void
test_rtc_send_close (rpointer data, rpointer ctx)
{
  TestRtcCtx * rtc;
  if (R_UNLIKELY ((rtc = data) == NULL)) return;

  r_assert_cmpptr (rtc->send, ==, ctx);
}

static void
test_rtc_ctx_init (TestRtcCtx * ctx, RPrng * prng, RRtcIceTransport * ice)
{
  RRtcCryptoTransport * crypto;
  const RRtcRtpReceiverCallbacks recv_cbs = {
    test_rtc_recv_ready,
    test_rtc_recv_close,
    test_rtc_recv_rtp,
    test_rtc_recv_rtcp,
  };
  const RRtcRtpSenderCallbacks send_cbs = {
    test_rtc_send_ready,
    test_rtc_send_close,
  };

  r_assert_cmpptr ((ctx->session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((crypto = r_rtc_session_create_raw_transport (ctx->session, ice)), !=, NULL);
  r_assert_cmpptr ((ctx->send = r_rtc_session_create_rtp_sender (ctx->session,
          R_STR_WITH_SIZE_ARGS ("audio"), &send_cbs, ctx, NULL,
          crypto, crypto)), !=, NULL);
  r_assert_cmpptr ((ctx->recv = r_rtc_session_create_rtp_receiver (ctx->session,
          R_STR_WITH_SIZE_ARGS ("audio"), &recv_cbs, ctx, NULL,
          crypto, crypto)), !=, NULL);
  r_rtc_crypto_transport_unref (crypto);

  r_queue_init (&ctx->rtp);
  r_queue_init (&ctx->rtcp);
}

static void
test_rtc_ctx_clear (TestRtcCtx * ctx)
{
  r_rtc_rtp_sender_unref (ctx->send);
  r_rtc_rtp_receiver_unref (ctx->recv);
  r_rtc_session_unref (ctx->session);

  r_queue_clear (&ctx->rtp, r_buffer_unref);
  r_queue_clear (&ctx->rtcp, r_buffer_unref);
}

RTEST_FIXTURE_SETUP (rrtc)
{
  RRtcIceTransport * a, * b;

  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_create_fake_pair (&a, &b), ==, R_RTC_OK);
  test_rtc_ctx_init (&fixture->alice, fixture->prng, a);
  test_rtc_ctx_init (&fixture->bob, fixture->prng, b);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
}

RTEST_FIXTURE_TEARDOWN (rrtc)
{
  test_rtc_ctx_clear (&fixture->alice);
  test_rtc_ctx_clear (&fixture->bob);
  r_prng_unref (fixture->prng);
  r_ev_loop_unref (fixture->loop);
}


RTEST (rrtc_session, new, RTEST_FAST)
{
  RRtcSession * session;
  RPrng * prng;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);

  r_assert_cmpptr (r_rtc_session_new (NULL), ==, NULL);
  r_assert_cmpptr ((session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr (r_rtc_session_get_id (session), !=, NULL);
  r_rtc_session_unref (session);

  r_assert_cmpptr ((session = r_rtc_session_new_full ("test", -1, prng)), !=, NULL);
  r_assert_cmpstr (r_rtc_session_get_id (session), ==, "test");
  r_rtc_session_unref (session);

  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrtc, create_ice_transport, RTEST_FAST)
{
  RPrng * prng;
  RRtcSession * session;
  RRtcIceTransport * ice;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((session = r_rtc_session_new (prng)), !=, NULL);

  r_assert_cmpptr (r_rtc_session_create_ice_transport (session,
        NULL, 0, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (session,
        R_STR_WITH_SIZE_ARGS ("joe"), NULL, 0), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (session,
        NULL, 0, R_STR_WITH_SIZE_ARGS ("pwd")), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (session,
        R_STR_WITH_SIZE_ARGS ("joe"), "pwd", 0), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (session,
        "joe", 0, R_STR_WITH_SIZE_ARGS ("pwd")), ==, NULL);

  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (session,
        R_STR_WITH_SIZE_ARGS ("joe"), R_STR_WITH_SIZE_ARGS ("pwd"))), !=, NULL);
  r_rtc_ice_transport_unref (ice);

  r_rtc_session_unref (session);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrtc, create_dtls_transport_server, RTEST_FAST)
{
  RPrng * prng;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RRtcSession * session;
  RRtcIceTransport * ice;

  RRtcCryptoTransport * crypto;

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (R_STR_WITH_SIZE_ARGS (pemcert))), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (R_STR_WITH_SIZE_ARGS (pempk), NULL, 0)), !=, NULL);
  r_assert_cmpptr ((session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (session,
        R_STR_WITH_SIZE_ARGS ("joe"), R_STR_WITH_SIZE_ARGS ("pwd"))), !=, NULL);

  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        NULL, R_RTC_CRYPTO_ROLE_SERVER, NULL, NULL), ==, NULL);
#if 0
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, NULL, NULL), ==, NULL);
#endif
  r_assert_cmpptr ((crypto = r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, cert, pk)), !=, NULL);

  r_rtc_crypto_transport_unref (crypto);
  r_rtc_ice_transport_unref (ice);

  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_prng_unref (prng);
  r_rtc_session_unref (session);
}
RTEST_END;

RTEST (rrtc, create_rtp_sender, RTEST_FAST)
{
  RPrng * prng;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RRtcSession * session;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * crypto;

  RRtcRtpSender * sender;

  const RRtcRtpSenderCallbacks cbs_null = { NULL, NULL };
  const RRtcRtpSenderCallbacks cbs = {
    test_rtc_send_ready,
    test_rtc_send_close,
  };

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (R_STR_WITH_SIZE_ARGS (pemcert))), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (R_STR_WITH_SIZE_ARGS (pempk), NULL, 0)), !=, NULL);
  r_assert_cmpptr ((session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (session,
        R_STR_WITH_SIZE_ARGS ("joe"), R_STR_WITH_SIZE_ARGS ("pwd"))), !=, NULL);
  r_assert_cmpptr ((crypto = r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, cert, pk)), !=, NULL);

  r_assert_cmpptr (r_rtc_session_create_rtp_sender (session, NULL, 0,
        NULL, NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (session, NULL, 0,
        NULL, NULL, NULL, crypto, crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (session, NULL, 0,
        &cbs_null, NULL, NULL, crypto, crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (session, NULL, 0,
        &cbs, NULL, NULL, crypto, crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (session,
        R_STR_WITH_SIZE_ARGS ("audio"), &cbs_null, NULL, NULL,
        crypto, crypto), ==, NULL);

  r_assert_cmpptr ((sender = r_rtc_session_create_rtp_sender (session,
          R_STR_WITH_SIZE_ARGS ("audio"), &cbs, NULL, NULL,
          crypto, crypto)), !=, NULL);
  r_rtc_rtp_sender_unref (sender);

  r_rtc_crypto_transport_unref (crypto);
  r_rtc_ice_transport_unref (ice);
  r_rtc_session_unref (session);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (rrtc, create_rtp_receiver, RTEST_FAST)
{
  RPrng * prng;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RRtcSession * session;
  RRtcIceTransport * ice;
  RRtcCryptoTransport * crypto;

  RRtcRtpReceiver * receiver;

  const RRtcRtpReceiverCallbacks cbs_null = { NULL, NULL, NULL, NULL };
  const RRtcRtpReceiverCallbacks cbs = {
    test_rtc_recv_ready,
    test_rtc_recv_close,
    test_rtc_recv_rtp,
    test_rtc_recv_rtcp,
  };

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (R_STR_WITH_SIZE_ARGS (pemcert))), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (R_STR_WITH_SIZE_ARGS (pempk), NULL, 0)), !=, NULL);
  r_assert_cmpptr ((session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((ice = r_rtc_session_create_ice_transport (session,
        R_STR_WITH_SIZE_ARGS ("joe"), R_STR_WITH_SIZE_ARGS ("pwd"))), !=, NULL);
  r_assert_cmpptr ((crypto = r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, cert, pk)), !=, NULL);

  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (session,
        NULL, 0, NULL, NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (session,
        NULL, 0, NULL, NULL, NULL, crypto, crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (session,
        R_STR_WITH_SIZE_ARGS ("audio"), NULL, NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (session,
        R_STR_WITH_SIZE_ARGS ("audio"), NULL, NULL, NULL, crypto, crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (session,
        R_STR_WITH_SIZE_ARGS ("audio"), &cbs_null, NULL, NULL,
        crypto, crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (session,
        NULL, 0, &cbs_null, NULL, NULL,
        crypto, crypto), ==, NULL);

  r_assert_cmpptr ((receiver = r_rtc_session_create_rtp_receiver (session,
          R_STR_WITH_SIZE_ARGS ("audio"), &cbs, NULL, NULL,
          crypto, crypto)), !=, NULL);
  r_rtc_rtp_receiver_unref (receiver);

  r_rtc_crypto_transport_unref (crypto);
  r_rtc_ice_transport_unref (ice);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_prng_unref (prng);
  r_rtc_session_unref (session);
}
RTEST_END;

RTEST (rrtc, fake_ice_transport, RTEST_FAST)
{
  RRtcIceTransport * a = NULL, * b = NULL;

  r_assert_cmpint (r_rtc_ice_transport_create_fake_pair (&a, NULL), ==, R_RTC_INVAL);
  r_assert_cmpint (r_rtc_ice_transport_create_fake_pair (NULL, &b), ==, R_RTC_INVAL);
  r_assert_cmpint (r_rtc_ice_transport_create_fake_pair (&a, &b), ==, R_RTC_OK);

  r_assert_cmpptr (a, !=, NULL);
  r_assert_cmpptr (b, !=, NULL);

  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
}
RTEST_END;

RTEST_F (rrtc, send_recv, RTEST_FAST)
{
  RBuffer * buf, * pop;
  RRtcRtpParameters * p;

  r_assert_cmpuint (r_queue_size (&fixture->alice.rtp), ==, 0);
  r_assert_cmpuint (r_queue_size (&fixture->alice.rtcp), ==, 0);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 0);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtcp), ==, 0);

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  r_assert_cmpptr ((buf = r_buffer_new_rtp_buffer_alloc (0, 0, 0)), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);

  r_assert_cmpuint (r_queue_size (&fixture->alice.rtp), ==, 0);
  r_assert_cmpuint (r_queue_size (&fixture->alice.rtcp), ==, 0);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtcp), ==, 0);

  r_assert_cmpptr ((pop = r_queue_pop (&fixture->bob.rtp)), ==, buf);
  r_buffer_unref (pop);

  r_buffer_unref (buf);
}
RTEST_END;

