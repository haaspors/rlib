#include <rlib/rrtc.h>
#include <rlib/rcrypto.h>

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
  RRtcCryptoTransport * crypto;
  RRtcRtpReceiver * recv;
  RRtcRtpSender * send;

  RQueue rtp;
  RQueue rtcp;
  RQueue send_rtcp; /* RTCP delivered to our sender side */

  ruint recv_closed;
  ruint send_closed;
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
  rtc->recv_closed++;
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
  rtc->send_closed++;
}

static void
test_rtc_send_rtcp (rpointer data, RBuffer * buf, rpointer ctx)
{
  TestRtcCtx * rtc;
  if (R_UNLIKELY ((rtc = data) == NULL)) return;

  r_assert_cmpptr (rtc->send, ==, ctx);
  r_queue_push (&rtc->send_rtcp, r_buffer_ref (buf));
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
    test_rtc_send_rtcp,
  };

  r_assert_cmpptr ((ctx->session = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((crypto = r_rtc_session_create_raw_transport (ctx->session, ice)), !=, NULL);
  r_assert_cmpptr ((ctx->send = r_rtc_session_create_rtp_sender (ctx->session,
          R_STR_WITH_SIZE_ARGS ("audio"), &send_cbs, ctx, NULL,
          crypto, crypto)), !=, NULL);
  r_assert_cmpptr ((ctx->recv = r_rtc_session_create_rtp_receiver (ctx->session,
          R_STR_WITH_SIZE_ARGS ("audio"), &recv_cbs, ctx, NULL,
          crypto, crypto)), !=, NULL);
  ctx->crypto = crypto; /* keep the ref for close()-driven teardown tests */

  r_queue_init (&ctx->rtp);
  r_queue_init (&ctx->rtcp);
  r_queue_init (&ctx->send_rtcp);
}

static void
test_rtc_ctx_clear (TestRtcCtx * ctx)
{
  r_rtc_rtp_sender_unref (ctx->send);
  r_rtc_rtp_receiver_unref (ctx->recv);
  r_rtc_crypto_transport_unref (ctx->crypto);
  r_rtc_session_unref (ctx->session);

  r_queue_clear (&ctx->rtp, r_buffer_unref);
  r_queue_clear (&ctx->rtcp, r_buffer_unref);
  r_queue_clear (&ctx->send_rtcp, r_buffer_unref);
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
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, cert, NULL), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_SERVER, NULL, pk), ==, NULL);
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

RTEST (rrtc, create_dtls_transport_client, RTEST_FAST)
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

  /* An unresolved role must be rejected; the concrete side is picked from
   * the SDP a=setup attribute before the transport is created. */
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_AUTO, cert, pk), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, (RRtcCryptoRole) 0xff, cert, pk), ==, NULL);

  /* Same argument validation as the server role. */
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_CLIENT, NULL, pk), ==, NULL);
  r_assert_cmpptr (r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_CLIENT, cert, NULL), ==, NULL);

  r_assert_cmpptr ((crypto = r_rtc_session_create_dtls_transport (session,
        ice, R_RTC_CRYPTO_ROLE_CLIENT, cert, pk)), !=, NULL);

  r_rtc_crypto_transport_unref (crypto);
  r_rtc_ice_transport_unref (ice);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_prng_unref (prng);
  r_rtc_session_unref (session);
}
RTEST_END;

typedef struct {
  ruint ready;
} TestDtlsPeer;

static void
test_dtls_peer_ready (rpointer data, rpointer ctx)
{
  TestDtlsPeer * peer = data;
  (void) ctx;
  peer->ready++;
}

static void
test_dtls_peer_noop (rpointer data, rpointer ctx)
{
  (void) data; (void) ctx;
}

static void
test_dtls_peer_noop_buf (rpointer data, RBuffer * buf, rpointer ctx)
{
  (void) data; (void) buf; (void) ctx;
}

RTEST (rrtc, dtls_client_server_handshake, RTEST_FAST)
{
  /* Drive a full DTLS-SRTP handshake between a server-role transport and a
   * client-role transport over a fake ICE pair.  Both sides derive keying
   * material and install an SRTP context, which fires the receiver ready
   * callback -- proving the client role completes the handshake and keys. */
  RPrng * prng;
  REvLoop * loop;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RRtcIceTransport * a, * b;
  RRtcSession * srvses, * clises;
  RRtcCryptoTransport * srv, * cli;
  RRtcRtpReceiver * srvrecv, * clirecv;
  RRtcRtpParameters * p;
  TestDtlsPeer srvpeer = { 0 }, clipeer = { 0 };
  const RRtcRtpReceiverCallbacks srv_cbs = {
    test_dtls_peer_ready, test_dtls_peer_noop,
    test_dtls_peer_noop_buf, test_dtls_peer_noop_buf,
  };
  const RRtcRtpReceiverCallbacks cli_cbs = {
    test_dtls_peer_ready, test_dtls_peer_noop,
    test_dtls_peer_noop_buf, test_dtls_peer_noop_buf,
  };

  r_assert_cmpptr ((prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (R_STR_WITH_SIZE_ARGS (pemcert))), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (R_STR_WITH_SIZE_ARGS (pempk), NULL, 0)), !=, NULL);
  r_assert_cmpint (r_rtc_ice_transport_create_fake_pair (&a, &b), ==, R_RTC_OK);

  r_assert_cmpptr ((srvses = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((clises = r_rtc_session_new (prng)), !=, NULL);
  r_assert_cmpptr ((srv = r_rtc_session_create_dtls_transport (srvses, a,
          R_RTC_CRYPTO_ROLE_SERVER, cert, pk)), !=, NULL);
  r_assert_cmpptr ((cli = r_rtc_session_create_dtls_transport (clises, b,
          R_RTC_CRYPTO_ROLE_CLIENT, cert, pk)), !=, NULL);

  r_assert_cmpptr ((srvrecv = r_rtc_session_create_rtp_receiver (srvses,
          R_STR_WITH_SIZE_ARGS ("audio"), &srv_cbs, &srvpeer, NULL,
          srv, srv)), !=, NULL);
  r_assert_cmpptr ((clirecv = r_rtc_session_create_rtp_receiver (clises,
          R_STR_WITH_SIZE_ARGS ("audio"), &cli_cbs, &clipeer, NULL,
          cli, cli)), !=, NULL);

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);

  /* Start the passive (server) side first so it is ready to answer the
   * ClientHello the active side emits on start. */
  r_assert_cmpint (r_rtc_rtp_receiver_start (srvrecv, p, loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (clirecv, p, loop), ==, R_RTC_OK);

  r_assert_cmpuint (srvpeer.ready, ==, 1);
  r_assert_cmpuint (clipeer.ready, ==, 1);

  r_assert_cmpint (r_rtc_rtp_receiver_stop (srvrecv), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (clirecv), ==, R_RTC_OK);

  r_rtc_rtp_parameters_unref (p);
  r_rtc_rtp_receiver_unref (srvrecv);
  r_rtc_rtp_receiver_unref (clirecv);
  r_rtc_crypto_transport_unref (srv);
  r_rtc_crypto_transport_unref (cli);
  r_rtc_ice_transport_unref (a);
  r_rtc_ice_transport_unref (b);
  r_rtc_session_unref (srvses);
  r_rtc_session_unref (clises);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_ev_loop_unref (loop);
  r_prng_unref (prng);
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

  const RRtcRtpSenderCallbacks cbs_null = { NULL, NULL, NULL };
  const RRtcRtpSenderCallbacks cbs = {
    test_rtc_send_ready,
    test_rtc_send_close,
    NULL,
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

RTEST_F (rrtc, listener_dispatches_codec_pt_with_no_encoding, RTEST_FAST)
{
  /* update_receiver populated recv_ptmap by walking params->codecs but
   * indexed into params->encodings instead.  With only codecs present
   * the misindexed read returned NULL and crashed, and with mismatched
   * sizes it inserted garbage PTs.  Drive the codec-only path: start
   * a receiver with one codec (PT=PCMA) and no encodings, send an RTP
   * packet stamped with that PT, expect it in the receiver's queue. */
  static const ruint8 rtp_pt_pcma[] = {
    0x80, 0x08,              /* v=2 p=0 x=0 cc=0, m=0 pt=8 (PCMA) */
    0x00, 0x01,              /* seq */
    0x00, 0x00, 0x00, 0x00,  /* timestamp */
    0x11, 0x22, 0x33, 0x44,  /* SSRC (any -- there's no SSRC entry) */
    0x00                     /* one byte payload */
  };
  RBuffer * buf;
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (p,
        "PCMA", R_RTP_PT_PCMA, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_pt_pcma, sizeof (rtp_pt_pcma))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);

  while ((buf = r_queue_pop (&fixture->bob.rtp)) != NULL)
    r_buffer_unref (buf);
}
RTEST_END;

RTEST_F (rrtc, receiver_stop_clears_ssrc_demux, RTEST_FAST)
{
  /* Starting a receiver with an explicit SSRC populates the listener's
   * recv_ssrcmap with that SSRC -> receiver mapping.  Stopping the
   * receiver used to leave the map populated (FIXME: Remove from recv_*
   * hash tables as well!), so a subsequent RTP packet with the same
   * SSRC would still dispatch to the dead receiver.  After stopping,
   * a packet matching that SSRC must NOT land in the receiver's queue. */
  static const ruint8 rtp_ssrc_deadbeef[] = {
    0x80, 0x00,              /* v=2 p=0 x=0 cc=0, m=0 pt=0 */
    0x00, 0x01,              /* seq = 1 */
    0x00, 0x00, 0x00, 0x00,  /* timestamp */
    0xde, 0xad, 0xbe, 0xef,  /* SSRC */
    0x00                     /* one byte payload */
  };
  RBuffer * buf;
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (p, 0xdeadbeef,
        R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  /* Sanity: an RTP packet stamped with the registered SSRC reaches bob.rtp. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_ssrc_deadbeef,
          sizeof (rtp_ssrc_deadbeef))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_buffer_unref (buf);

  /* Stop bob's receiver.  This must purge the listener's ssrc map. */
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);

  /* Send another RTP packet with the same SSRC.  Without the fix the
   * stale ssrc->receiver mapping still dispatches to the (stopped but
   * test-held) receiver and bumps bob.rtp to 2. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_ssrc_deadbeef,
          sizeof (rtp_ssrc_deadbeef))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);

  while ((buf = r_queue_pop (&fixture->bob.rtp)) != NULL)
    r_buffer_unref (buf);
}
RTEST_END;

RTEST_F (rrtc, listener_mid_demux_learns_ssrc, RTEST_FAST)
{
  /* A bundled stream announces its MID in an RFC 8285 one-byte header
   * extension before its SSRC is known.  The listener must route the
   * first packet on the MID, then cache the SSRC so the next packet
   * (which may carry no extension) takes the SSRC fast path. */
  static const ruint8 rtp_mid_audio[] = {
    0x90, 0x00,              /* v=2 p=0 x=1 cc=0, m=0 pt=0 */
    0x00, 0x01,              /* seq */
    0x00, 0x00, 0x00, 0x00,  /* timestamp */
    0xca, 0xfe, 0xba, 0xbe,  /* SSRC (not registered up front) */
    0xbe, 0xde, 0x00, 0x02,  /* ext: profile 0xBEDE, len 2 words */
    0x14, 'a', 'u', 'd', 'i', /* one-byte elem id=1 len=5, "audi" */
    'o',  0x00, 0x00,        /* "o" + 2 padding to a 4-byte boundary */
    0x00                     /* one byte payload */
  };
  static const ruint8 rtp_mid_video[] = {
    0x90, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x11, 0x11, 0x11,  /* different SSRC */
    0xbe, 0xde, 0x00, 0x02,
    0x14, 'v', 'i', 'd', 'e',
    'o',  0x00, 0x00,        /* MID "video" -- no receiver has this mid */
    0x00
  };
  static const ruint8 rtp_no_ext[] = {
    0x80, 0x00,              /* no extension bit */
    0x00, 0x03,
    0x00, 0x00, 0x00, 0x00,
    0xca, 0xfe, 0xba, 0xbe,  /* same SSRC as the MID packet above */
    0x00
  };
  RBuffer * buf;
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (p,
        "urn:ietf:params:rtp-hdrext:sdes:mid", 1), ==, R_RTC_OK);
  /* A codec whose PT (8) never matches the PT-0 packets below, so the
   * empty-map broadcast fallback is off and routing must go through the
   * MID / learned-SSRC paths. */
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (p,
        "PCMA", R_RTP_PT_PCMA, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  /* First packet: routed by its MID extension. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_mid_audio, sizeof (rtp_mid_audio))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_buffer_unref (buf);

  /* A MID with no matching receiver is dropped, not broadcast (the fake
   * transport discards the handler's return, so the queue size is what
   * proves non-delivery). */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_mid_video, sizeof (rtp_mid_video))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_buffer_unref (buf);

  /* Second packet: no extension, but the SSRC was learned from the first. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_no_ext, sizeof (rtp_no_ext))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 2);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);

  while ((buf = r_queue_pop (&fixture->bob.rtp)) != NULL)
    r_buffer_unref (buf);
}
RTEST_END;

RTEST_F (rrtc, listener_rid_demux_learns_ssrc, RTEST_FAST)
{
  /* A simulcast encoding (RFC 8852) announces its RID in an RFC 8285 header
   * extension, and its SSRC may be unsignalled.  The listener must route the
   * first packet on the RID, learn the SSRC so a later extension-less packet
   * takes the SSRC fast path, ignore a RID no encoding claims, and route an
   * RTX stream by its repaired-RID. */
  static const ruint8 rtp_rid_hi[] = {
    0x90, 0x00, 0x00, 0x01,  /* v=2 x=1, m=0 pt=0, seq */
    0x00, 0x00, 0x00, 0x00,  /* timestamp */
    0xca, 0xfe, 0xba, 0xbe,  /* SSRC (not registered up front) */
    0xbe, 0xde, 0x00, 0x01,  /* ext: profile 0xBEDE, 1 word */
    0x21, 'h', 'i', 0x00,    /* one-byte elem id=2 len=2, RID "hi" + pad */
    0x00                     /* payload */
  };
  static const ruint8 rtp_rid_unknown[] = {
    0x90, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x00,
    0x11, 0x11, 0x11, 0x11,  /* different SSRC */
    0xbe, 0xde, 0x00, 0x01,
    0x21, 'x', 'x', 0x00,    /* RID "xx" -- no encoding has this rid */
    0x00
  };
  static const ruint8 rtp_no_ext[] = {
    0x80, 0x00, 0x00, 0x03,  /* no extension bit */
    0x00, 0x00, 0x00, 0x00,
    0xca, 0xfe, 0xba, 0xbe,  /* same SSRC as the RID packet above */
    0x00
  };
  static const ruint8 rtp_rrid_hi[] = {
    0x90, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00,
    0xdd, 0xdd, 0xdd, 0xdd,  /* RTX SSRC */
    0xbe, 0xde, 0x00, 0x01,
    0x31, 'h', 'i', 0x00,    /* elem id=3, repaired-RID "hi" */
    0x00
  };
  RBuffer * buf;
  RRtcRtpParameters * p;
  RRtcRtpEncodingParameters * enc;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (p,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", 2), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (p,
        "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id", 3), ==, R_RTC_OK);
  /* A codec whose PT (8) never matches the PT-0 packets, so the empty-map
   * broadcast and the PT fallback are both off and routing must go through
   * the RID / learned-SSRC paths. */
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (p,
        "PCMA", R_RTP_PT_PCMA, 8000, 1), ==, R_RTC_OK);
  /* One simulcast encoding "hi" with no signalled SSRC. */
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (p, 0,
        R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpptr ((enc = r_rtc_rtp_parameters_get_encoding (p, 0)), !=, NULL);
  r_strcpy (enc->id, "hi");

  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  /* First packet: routed by its RID extension. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_rid_hi, sizeof (rtp_rid_hi))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_buffer_unref (buf);

  /* A RID no encoding claims is dropped, not broadcast. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_rid_unknown, sizeof (rtp_rid_unknown))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_buffer_unref (buf);

  /* Extension-less packet: SSRC was learned from the first RID packet. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_no_ext, sizeof (rtp_no_ext))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 2);
  r_buffer_unref (buf);

  /* RTX stream routed by its repaired-RID. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_rrid_hi, sizeof (rtp_rrid_hi))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 3);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);

  while ((buf = r_queue_pop (&fixture->bob.rtp)) != NULL)
    r_buffer_unref (buf);
}
RTEST_END;

typedef struct { RRtcRtpReceiver * recv; ruint count; } TestRidRecv;

static void test_rid_ev (rpointer data, rpointer ctx) { (void) data; (void) ctx; }
static void test_rid_rtp (rpointer data, RBuffer * buf, rpointer ctx)
{
  (void) buf; (void) ctx;
  ((TestRidRecv *) data)->count++;
}

RTEST_F (rrtc, listener_rid_scoped_within_mid, RTEST_FAST)
{
  /* A RID is only unique within an m-line (RFC 8852): two receivers on the
   * same transport may share a RID string, disambiguated by MID.  A bundled
   * simulcast packet carries both -- MID must select the receiver, and the
   * RID only the encoding within it.  With a transport-wide RID match the
   * packet would land on whichever receiver registered the RID last. */
  static const ruint8 rtp_mid_audio_rid_hi[] = {
    0x90, 0x00, 0x00, 0x01,  /* v=2 x=1, m=0 pt=0, seq */
    0x00, 0x00, 0x00, 0x00,  /* timestamp */
    0xca, 0xfe, 0xba, 0xbe,  /* SSRC */
    0xbe, 0xde, 0x00, 0x03,  /* ext: profile 0xBEDE, 3 words */
    0x14, 'a', 'u', 'd', 'i', 'o',  /* elem id=1 len=5, MID "audio" */
    0x21, 'h', 'i',          /* elem id=2 len=2, RID "hi" */
    0x00, 0x00, 0x00,        /* padding to a 4-byte boundary */
    0x00                     /* payload */
  };
  const RRtcRtpReceiverCallbacks vid_cbs = {
    test_rid_ev, test_rid_ev, test_rid_rtp, test_rid_rtp
  };
  TestRidRecv vid = { NULL, 0 };
  RBuffer * buf;
  RRtcRtpParameters * pa, * pv;
  RRtcRtpEncodingParameters * enc;

  /* A second receiver on bob's transport, MID "video", same RID "hi". */
  r_assert_cmpptr ((vid.recv = r_rtc_session_create_rtp_receiver (fixture->bob.session,
          R_STR_WITH_SIZE_ARGS ("video"), &vid_cbs, &vid, NULL,
          fixture->bob.crypto, fixture->bob.crypto)), !=, NULL);

  r_assert_cmpptr ((pa = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (pa,
        "urn:ietf:params:rtp-hdrext:sdes:mid", 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (pa,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", 2), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (pa,
        "PCMA", R_RTP_PT_PCMA, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (pa, 0, R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpptr ((enc = r_rtc_rtp_parameters_get_encoding (pa, 0)), !=, NULL);
  r_strcpy (enc->id, "hi");

  r_assert_cmpptr ((pv = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("video"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (pv,
        "urn:ietf:params:rtp-hdrext:sdes:mid", 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_hdrext_simple (pv,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id", 2), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_codec_simple (pv,
        "PCMA", R_RTP_PT_PCMA, 8000, 1), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (pv, 0, R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_strcpy (r_rtc_rtp_parameters_get_encoding (pv, 0)->id, "hi");

  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, pa, fixture->loop), ==, R_RTC_OK);
  /* bob.recv started last would win a transport-wide RID map; start it
   * first so "video" is the last RID registrant and MID must override. */
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, pa, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (vid.recv, pv, fixture->loop), ==, R_RTC_OK);

  /* MID "audio" selects bob.recv even though "video" registered RID "hi" last. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtp_mid_audio_rid_hi,
          sizeof (rtp_mid_audio_rid_hi))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->alice.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->bob.rtp), ==, 1);
  r_assert_cmpuint (vid.count, ==, 0);
  /* The RID scoped the encoding within bob.recv, so its SSRC was learned. */
  r_assert_cmphex (enc->ssrc, ==, 0xcafebabe);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (vid.recv), ==, R_RTC_OK);
  r_rtc_rtp_receiver_unref (vid.recv);
  r_rtc_rtp_parameters_unref (pa);
  r_rtc_rtp_parameters_unref (pv);

  while ((buf = r_queue_pop (&fixture->bob.rtp)) != NULL)
    r_buffer_unref (buf);
}
RTEST_END;

RTEST_F (rrtc, sender_receives_rtcp, RTEST_FAST)
{
  /* Incoming RTCP feedback (RR / NACK / PLI) names the sending SSRC it
   * concerns in a report block.  The listener routes the compound to the
   * sender that owns that SSRC via send_ssrcmap -- and only that sender,
   * not every sender on the transport. */
  static const ruint8 rtcp_rr_deadbeef[] = {
    /* V=2 P=0 RC=1; PT=201 (RR); length=7 (32 bytes) */
    0x81, 0xc9, 0x00, 0x07,
    0xb0, 0xb0, 0xb0, 0xb0,  /* reporter SSRC (bob) */
    0xde, 0xad, 0xbe, 0xef,  /* report block source SSRC == alice's sender */
    0x00, 0x00, 0x00, 0x00,  /* fraction + cumulative lost */
    0x00, 0x00, 0x00, 0x00,  /* extended highest seq */
    0x00, 0x00, 0x00, 0x00,  /* interarrival jitter */
    0x00, 0x00, 0x00, 0x00,  /* last SR */
    0x00, 0x00, 0x00, 0x00   /* delay since last SR */
  };
  static const ruint8 rtcp_rr_other[] = {
    0x81, 0xc9, 0x00, 0x07,
    0xb0, 0xb0, 0xb0, 0xb0,
    0x11, 0x11, 0x11, 0x11,  /* report block for an SSRC alice does not send */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };
  RBuffer * buf, * pop;
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (p, 0xdeadbeef,
        R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  /* A report block for a different SSRC must not reach alice's sender. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtcp_rr_other, sizeof (rtcp_rr_other))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->bob.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->alice.send_rtcp), ==, 0);
  r_buffer_unref (buf);

  /* A report block naming alice's sending SSRC is delivered to her sender. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (rtcp_rr_deadbeef, sizeof (rtcp_rr_deadbeef))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->bob.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->alice.send_rtcp), ==, 1);
  r_assert_cmpptr ((pop = r_queue_pop (&fixture->alice.send_rtcp)), !=, NULL);
  r_buffer_unref (pop);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);
}
RTEST_END;

RTEST_F (rrtc, sender_receives_xr, RTEST_FAST)
{
  /* An Extended Report (RFC 3611) names a sending SSRC in its per-source
   * blocks -- here a DLRR sub-block.  The listener resolves it via
   * send_ssrcmap and routes the compound to the owning sender only.  The XR
   * rides in a compound behind an empty RR so the RTP/RTCP demux (which keys
   * on the first packet) delivers it as RTCP. */
  static const ruint8 xr_deadbeef[] = {
    /* V=2 P=0 RC=0; PT=201 (RR); length=1 (8 bytes) */
    0x80, 0xc9, 0x00, 0x01,
    0xb0, 0xb0, 0xb0, 0xb0,  /* reporter SSRC (bob) */
    /* V=2 P=0; PT=207 (XR); length=5 (24 bytes) */
    0x80, 0xcf, 0x00, 0x05,
    0xb0, 0xb0, 0xb0, 0xb0,  /* reporter SSRC (bob) */
    0x05, 0x00, 0x00, 0x03,  /* DLRR block, one sub-block */
    0xde, 0xad, 0xbe, 0xef,  /* sub-block SSRC == alice's sender */
    0x00, 0x00, 0x00, 0x00,  /* last RR */
    0x00, 0x00, 0x00, 0x00   /* delay since last RR */
  };
  static const ruint8 xr_other[] = {
    0x80, 0xc9, 0x00, 0x01,
    0xb0, 0xb0, 0xb0, 0xb0,
    0x80, 0xcf, 0x00, 0x05,
    0xb0, 0xb0, 0xb0, 0xb0,
    0x05, 0x00, 0x00, 0x03,
    0x11, 0x11, 0x11, 0x11,  /* DLRR sub-block for an SSRC alice does not send */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };
  RBuffer * buf, * pop;
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (p, 0xdeadbeef,
        R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  /* An XR block for a different SSRC must not reach alice's sender. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (xr_other, sizeof (xr_other))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->bob.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->alice.send_rtcp), ==, 0);
  r_buffer_unref (buf);

  /* An XR block naming alice's sending SSRC is delivered to her sender. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (xr_deadbeef, sizeof (xr_deadbeef))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->bob.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->alice.send_rtcp), ==, 1);
  r_assert_cmpptr ((pop = r_queue_pop (&fixture->alice.send_rtcp)), !=, NULL);
  r_buffer_unref (pop);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);
}
RTEST_END;

RTEST_F (rrtc, sender_receives_bare_xr, RTEST_FAST)
{
  /* Reduced-size RTCP (RFC 5506): an XR not led by SR/RR still demuxes as RTCP
   * (RFC 5761 -- its first byte's payload type is in the RTCP range) and routes
   * to the sender its DLRR names.  Unlike a feedback packet, a bare XR's first
   * byte has no CSRC count set, so only the payload-type check distinguishes it
   * from RTP. */
  static const ruint8 xr_deadbeef[] = {
    /* V=2 P=0; PT=207 (XR); length=5 (24 bytes) */
    0x80, 0xcf, 0x00, 0x05,
    0xb0, 0xb0, 0xb0, 0xb0,  /* reporter SSRC (bob) */
    0x05, 0x00, 0x00, 0x03,  /* DLRR block, one sub-block */
    0xde, 0xad, 0xbe, 0xef,  /* sub-block SSRC == alice's sender */
    0x00, 0x00, 0x00, 0x00,  /* last RR */
    0x00, 0x00, 0x00, 0x00   /* delay since last RR */
  };
  static const ruint8 xr_other[] = {
    0x80, 0xcf, 0x00, 0x05,
    0xb0, 0xb0, 0xb0, 0xb0,
    0x05, 0x00, 0x00, 0x03,
    0x11, 0x11, 0x11, 0x11,  /* DLRR sub-block for an SSRC alice does not send */
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  };
  RBuffer * buf, * pop;
  RRtcRtpParameters * p;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (p, 0xdeadbeef,
        R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  /* A bare XR for a different SSRC must not reach alice's sender. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (xr_other, sizeof (xr_other))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->bob.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->alice.send_rtcp), ==, 0);
  r_buffer_unref (buf);

  /* A bare XR naming alice's sending SSRC is delivered to her sender. */
  r_assert_cmpptr ((buf = r_buffer_new_dup (xr_deadbeef, sizeof (xr_deadbeef))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->bob.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->alice.send_rtcp), ==, 1);
  r_assert_cmpptr ((pop = r_queue_pop (&fixture->alice.send_rtcp)), !=, NULL);
  r_buffer_unref (pop);
  r_buffer_unref (buf);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);
}
RTEST_END;

RTEST_F (rrtc, sender_receives_only_own_report_blocks, RTEST_FAST)
{
  /* The sender is handed a fresh RR containing only the report blocks that
   * name one of its SSRCs, not the whole compound: a two-block RR (one for
   * alice's SSRC, one for an SSRC she does not send) yields a single-block RR
   * carrying just alice's block, with the report sender's SSRC preserved. */
  static const ruint8 rr_two[] = {
    /* V=2 P=0 RC=2; PT=201 (RR); length=13 (56 bytes) */
    0x82, 0xc9, 0x00, 0x0d,
    0xb0, 0xb0, 0xb0, 0xb0,  /* reporter SSRC (bob) */
    /* report block 1: alice's sending SSRC */
    0xde, 0xad, 0xbe, 0xef,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* report block 2: an SSRC alice does not send */
    0x11, 0x11, 0x11, 0x11,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  RBuffer * buf, * pop;
  RRtcRtpParameters * p;
  RRTCPBuffer rtcp = R_RTCP_BUFFER_INIT;
  RRTCPPacket * pkt;
  RRTCPReportBlock rb;

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_parameters_add_encoding_simple (p, 0xdeadbeef,
        R_RTP_PT_PCMU), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->bob.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  r_assert_cmpptr ((buf = r_buffer_new_dup (rr_two, sizeof (rr_two))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_send (fixture->bob.send, buf), ==, R_RTC_OK);
  r_assert_cmpuint (r_queue_size (&fixture->alice.send_rtcp), ==, 1);
  r_assert_cmpptr ((pop = r_queue_pop (&fixture->alice.send_rtcp)), !=, NULL);
  r_buffer_unref (buf);

  /* alice receives one RR carrying only her block. */
  r_assert (r_rtcp_buffer_map (&rtcp, pop, R_MEM_MAP_READ));
  r_assert_cmpptr ((pkt = r_rtcp_buffer_get_next_packet (&rtcp, NULL)), !=, NULL);
  r_assert_cmpuint (r_rtcp_packet_get_type (pkt), ==, R_RTCP_PT_RR);
  r_assert_cmphex (r_rtcp_packet_rr_get_ssrc (pkt), ==, 0xb0b0b0b0);
  r_assert_cmpuint (r_rtcp_packet_rr_get_rb_count (pkt), ==, 1);
  r_assert (r_rtcp_packet_rr_get_report_block (pkt, 0, &rb));
  r_assert_cmphex (rb.ssrc, ==, 0xdeadbeef);
  r_assert_cmpptr (r_rtcp_buffer_get_next_packet (&rtcp, pkt), ==, NULL);
  r_assert (r_rtcp_buffer_unmap (&rtcp, pop));
  r_buffer_unref (pop);

  r_assert_cmpint (r_rtc_rtp_sender_stop (fixture->alice.send), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_stop (fixture->bob.recv), ==, R_RTC_OK);
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

RTEST_F (rrtc, crypto_transport_close, RTEST_FAST)
{
  /* r_rtc_crypto_transport_close closes the underlying ICE transport and
   * notifies the RTP listener, so every started sender / receiver on that
   * transport gets its close callback.  (The symbol was previously declared
   * in the public header but compiled out, i.e. an undefined symbol.) */
  RRtcRtpParameters * p;

  r_assert_cmpint (r_rtc_crypto_transport_close (NULL), ==, R_RTC_INVAL);

  r_assert_cmpptr ((p = r_rtc_rtp_parameters_new (R_STR_WITH_SIZE_ARGS ("audio"))), !=, NULL);
  r_assert_cmpint (r_rtc_rtp_sender_start (fixture->alice.send, p, fixture->loop), ==, R_RTC_OK);
  r_assert_cmpint (r_rtc_rtp_receiver_start (fixture->alice.recv, p, fixture->loop), ==, R_RTC_OK);
  r_rtc_rtp_parameters_unref (p);

  r_assert_cmpuint (fixture->alice.recv_closed, ==, 0);
  r_assert_cmpuint (fixture->alice.send_closed, ==, 0);

  r_assert_cmpint (r_rtc_crypto_transport_close (fixture->alice.crypto), ==, R_RTC_OK);

  r_assert_cmpuint (fixture->alice.recv_closed, ==, 1);
  r_assert_cmpuint (fixture->alice.send_closed, ==, 1);

  /* bob shares no transport with alice, so its endpoints are untouched. */
  r_assert_cmpuint (fixture->bob.recv_closed, ==, 0);
  r_assert_cmpuint (fixture->bob.send_closed, ==, 0);
}
RTEST_END;

