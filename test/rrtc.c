#include <rlib/rlib.h>

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

RTEST_FIXTURE_STRUCT (rrtc)
{
  RPrng * prng;
  RRtcSession * session;

  RRtcIceTransport * ice;
  RRtcCryptoTransport * crypto;
  RCryptoCert * cert;
  RCryptoKey * pk;
};

static void
test_rtc_recv_ready (rpointer data, rpointer ctx)
{
  RTEST_FIXTURE_STRUCT (rrtc) * fixture;
  if (R_UNLIKELY ((fixture = data) == NULL)) return;

  r_assert_cmpptr (fixture->session, ==, ctx);
}

static void
test_rtc_recv_close (rpointer data, rpointer ctx)
{
  RTEST_FIXTURE_STRUCT (rrtc) * fixture;
  if (R_UNLIKELY ((fixture = data) == NULL)) return;

  r_assert_cmpptr (fixture->session, ==, ctx);
}

static void
test_rtc_recv_rtp (rpointer data, RBuffer * buf, rpointer ctx)
{
  RTEST_FIXTURE_STRUCT (rrtc) * fixture;
  if (R_UNLIKELY ((fixture = data) == NULL)) return;

  r_assert_cmpptr (fixture->session, ==, ctx);
  (void) buf;
}

static void
test_rtc_recv_rtcp (rpointer data, RBuffer * buf, rpointer ctx)
{
  RTEST_FIXTURE_STRUCT (rrtc) * fixture;
  if (R_UNLIKELY ((fixture = data) == NULL)) return;

  r_assert_cmpptr (fixture->session, ==, ctx);
  (void) buf;
}

static void
test_rtc_send_ready (rpointer data, rpointer ctx)
{
  RTEST_FIXTURE_STRUCT (rrtc) * fixture;
  if (R_UNLIKELY ((fixture = data) == NULL)) return;

  (void) ctx;
}

static void
test_rtc_send_close (rpointer data, rpointer ctx)
{
  RTEST_FIXTURE_STRUCT (rrtc) * fixture;
  if (R_UNLIKELY ((fixture = data) == NULL)) return;

  (void) ctx;
}

RTEST_FIXTURE_SETUP (rrtc)
{
  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->session = r_rtc_session_new (fixture->prng)), !=, NULL);
  r_assert_cmpptr ((fixture->ice = r_rtc_session_create_ice_transport (fixture->session,
        R_STR_WITH_SIZE_ARGS ("joe"), R_STR_WITH_SIZE_ARGS ("pwd"))), !=, NULL);
  r_assert_cmpptr ((fixture->cert = r_pem_parse_cert_from_data (R_STR_WITH_SIZE_ARGS (pemcert))), !=, NULL);
  r_assert_cmpptr ((fixture->pk = r_pem_parse_key_from_data (R_STR_WITH_SIZE_ARGS (pempk), NULL, 0)), !=, NULL);
  r_assert_cmpptr ((fixture->crypto = r_rtc_session_create_dtls_transport (fixture->session,
        fixture->ice, R_RTC_CRYPTO_ROLE_SERVER, fixture->cert, fixture->pk)), !=, NULL);
}

RTEST_FIXTURE_TEARDOWN (rrtc)
{
  r_rtc_crypto_transport_unref (fixture->crypto);
  r_crypto_key_unref (fixture->pk);
  r_crypto_cert_unref (fixture->cert);
  r_rtc_ice_transport_unref (fixture->ice);
  r_rtc_session_unref (fixture->session);
  r_prng_unref (fixture->prng);
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

RTEST_F (rrtc, create_ice_transport, RTEST_FAST)
{
  r_assert_cmpptr (r_rtc_session_create_ice_transport (fixture->session,
        NULL, 0, NULL, 0), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (fixture->session,
        R_STR_WITH_SIZE_ARGS ("joe"), NULL, 0), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (fixture->session,
        NULL, 0, R_STR_WITH_SIZE_ARGS ("pwd")), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (fixture->session,
        R_STR_WITH_SIZE_ARGS ("joe"), "pwd", 0), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_ice_transport (fixture->session,
        "joe", 0, R_STR_WITH_SIZE_ARGS ("pwd")), ==, NULL);

  r_assert_cmpptr (fixture->ice, !=, NULL);
}
RTEST_END;

RTEST_F (rrtc, create_dtls_transport_server, RTEST_FAST)
{
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (fixture->session,
        NULL, R_RTC_CRYPTO_ROLE_SERVER, NULL, NULL), ==, NULL);
#if 0
  r_assert_cmpptr ((crypto = r_rtc_session_create_dtls_transport (fixture->session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, NULL, NULL)), ==, NULL);
  r_rtc_crypto_transport_unref (crypto);
#endif

  r_assert_cmpptr (fixture->crypto, !=, NULL);
}
RTEST_END;

RTEST_F (rrtc, create_rtp_sender, RTEST_FAST)
{
  RRtcRtpSender * sender;

  const RRtcRtpSenderCallbacks cbs_null = { NULL, NULL };
  const RRtcRtpSenderCallbacks cbs = {
    test_rtc_send_ready,
    test_rtc_send_close,
  };

  r_assert_cmpptr (r_rtc_session_create_rtp_sender (fixture->session, NULL, 0,
        NULL, NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (fixture->session, NULL, 0,
        NULL, NULL, NULL, fixture->crypto, fixture->crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (fixture->session, NULL, 0,
        &cbs_null, fixture, NULL, fixture->crypto, fixture->crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (fixture->session, NULL, 0,
        &cbs, fixture, NULL, fixture->crypto, fixture->crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_sender (fixture->session,
        R_STR_WITH_SIZE_ARGS ("audio"), &cbs_null, fixture, NULL,
        fixture->crypto, fixture->crypto), ==, NULL);

  r_assert_cmpptr ((sender = r_rtc_session_create_rtp_sender (fixture->session,
          R_STR_WITH_SIZE_ARGS ("audio"), &cbs, fixture, NULL,
          fixture->crypto, fixture->crypto)), !=, NULL);
  r_rtc_rtp_sender_unref (sender);
}
RTEST_END;

RTEST_F (rrtc, create_rtp_receiver, RTEST_FAST)
{
  RRtcRtpReceiver * receiver;

  const RRtcRtpReceiverCallbacks cbs_null = { NULL, NULL, NULL, NULL };
  const RRtcRtpReceiverCallbacks cbs = {
    test_rtc_recv_ready,
    test_rtc_recv_close,
    test_rtc_recv_rtp,
    test_rtc_recv_rtcp,
  };

  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (fixture->session,
        NULL, 0, NULL, NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (fixture->session,
        NULL, 0, NULL, fixture, NULL, fixture->crypto, fixture->crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (fixture->session,
        R_STR_WITH_SIZE_ARGS ("audio"), NULL, NULL, NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (fixture->session,
        R_STR_WITH_SIZE_ARGS ("audio"), NULL, NULL, NULL, fixture->crypto, fixture->crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (fixture->session,
        R_STR_WITH_SIZE_ARGS ("audio"), &cbs_null, fixture, NULL,
        fixture->crypto, fixture->crypto), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_rtp_receiver (fixture->session,
        NULL, 0, &cbs_null, fixture, NULL,
        fixture->crypto, fixture->crypto), ==, NULL);

  r_assert_cmpptr ((receiver = r_rtc_session_create_rtp_receiver (fixture->session,
          R_STR_WITH_SIZE_ARGS ("audio"), &cbs, fixture, NULL,
          fixture->crypto, fixture->crypto)), !=, NULL);
  r_rtc_rtp_receiver_unref (receiver);
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

