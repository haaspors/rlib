#include <rlib/rnet.h>
#include <rlib/rcrypto.h>

/* Self-signed test certificate + matching RSA private key (CN=rlib). */
static const rchar testcertpem[] =
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

static const rchar testpkpem[] =
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

RTEST_FIXTURE_STRUCT (rtlsclient)
{
  RTLSServer * server;
  RTLSClient * client;

  rboolean srv_hs_done, cli_hs_done;
  rboolean srv_error, cli_error;
  ruint verify_calls;
  rboolean verify_result;

  RClock * clock;
  REvLoop * evloop;
  RPrng * prng;

  RQueue srv_out, cli_out;       /* records each side emits */
  RQueue srv_app, cli_app;       /* decrypted application data each side received */
};

static void
r_tlsclient_test_srv_hs_done (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->srv_hs_done = TRUE;
}

static void
r_tlsclient_test_cli_hs_done (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->cli_hs_done = TRUE;
}

static void
r_tlsclient_test_srv_error (rpointer ctx, RTLSAlertType alert, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) alert; (void) session;
  fixture->srv_error = TRUE;
}

static void
r_tlsclient_test_cli_error (rpointer ctx, RTLSAlertType alert, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) alert; (void) session;
  fixture->cli_error = TRUE;
}

static rboolean
r_tlsclient_test_srv_out (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->srv_out, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_cli_out (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->cli_out, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_srv_app (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->srv_app, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_cli_app (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->cli_app, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_verify_cert (rpointer ctx, RCryptoCert * const * chain, ruint count)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) chain; (void) count;
  fixture->verify_calls++;
  return fixture->verify_result;
}

RTEST_FIXTURE_SETUP (rtlsclient)
{
  static RTLSCallbacks srvcbs = {
    NULL,
    r_tlsclient_test_srv_hs_done,
    r_tlsclient_test_srv_out,
    r_tlsclient_test_srv_app,
    r_tlsclient_test_srv_error,
    NULL,
  };
  static RTLSCallbacks clicbs = {
    NULL,
    r_tlsclient_test_cli_hs_done,
    r_tlsclient_test_cli_out,
    r_tlsclient_test_cli_app,
    r_tlsclient_test_cli_error,
    r_tlsclient_test_verify_cert,
  };
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((fixture->evloop = r_ev_loop_new_full (fixture->clock, NULL)), !=, NULL);

  fixture->srv_hs_done = fixture->cli_hs_done = FALSE;
  fixture->srv_error = fixture->cli_error = FALSE;
  fixture->verify_calls = 0;
  fixture->verify_result = TRUE;

  r_queue_init (&fixture->srv_out);
  r_queue_init (&fixture->cli_out);
  r_queue_init (&fixture->srv_app);
  r_queue_init (&fixture->cli_app);

  r_assert_cmpptr ((fixture->server = r_tls_server_new (&srvcbs, fixture, NULL)), !=, NULL);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_server_set_cert (fixture->server, cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
}

RTEST_FIXTURE_TEARDOWN (rtlsclient)
{
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);

  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);
  r_queue_clear (&fixture->srv_app, r_buffer_unref);
  r_queue_clear (&fixture->cli_app, r_buffer_unref);

  r_ev_loop_unref (fixture->evloop);
  r_clock_unref (fixture->clock);
  r_prng_unref (fixture->prng);
}

/* Shuttle records between the two endpoints until neither has anything more
 * to send. Each out callback emits one record per buffer, so feeding them
 * back individually works for both TLS and DTLS. */
static void
r_test_tls_loopback_pump (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  RBuffer * buf;
  ruint i;

  for (i = 0; i < 64; i++) {
    rboolean progress = FALSE;

    while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
      r_tls_server_incoming_data (fixture->server, buf);
      r_buffer_unref (buf);
      progress = TRUE;
    }
    while ((buf = r_queue_pop (&fixture->srv_out)) != NULL) {
      r_tls_client_incoming_data (fixture->client, buf);
      r_buffer_unref (buf);
      progress = TRUE;
    }

    if (!progress)
      break;
  }
}

static RBuffer *
r_test_tls_queue_agg (RQueue * q)
{
  RBuffer * ret, * cur;

  if (r_queue_is_empty (q))
    return NULL;
  if ((ret = r_buffer_new ()) != NULL) {
    while ((cur = r_queue_pop (q)) != NULL) {
      r_buffer_append_mem_from_buffer (ret, cur);
      r_buffer_unref (cur);
    }
  }
  return ret;
}

/* Assert @q delivered exactly @data. */
static void
r_test_tls_assert_appdata (RQueue * q, const ruint8 * data, rsize size)
{
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  r_assert_cmpptr ((buf = r_test_tls_queue_agg (q)), !=, NULL);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, size);
  r_assert_cmpint (r_memcmp (info.data, data, size), ==, 0);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);
}

static void
r_test_tls_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture, RTLSVersion version)
{
  static const ruint8 c2s[] = { 'h', 'e', 'l', 'l', 'o', ' ', 's', 'e', 'r', 'v', 'e', 'r' };
  static const ruint8 s2c[] = { 'h', 'i', ' ', 'c', 'l', 'i', 'e', 'n', 't' };
  RBuffer * app;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, version);
  r_assert_cmpptr (r_tls_client_get_cipher_suite (fixture->client), !=, NULL);

  /* Application data, client -> server. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  /* Application data, server -> client. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

RTEST_F (rtlsclient, tls_loopback, RTEST_FAST)
{
  r_test_tls_loopback (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_loopback, RTEST_FAST)
{
  r_test_tls_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* A rejecting verify_cert aborts the handshake: the client emits a fatal
 * alert and never reports handshake_done. */
RTEST_F (rtlsclient, tls_verify_cert_reject, RTEST_FAST)
{
  fixture->verify_result = FALSE;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert (!fixture->cli_hs_done);
  r_assert (fixture->cli_error);
}
RTEST_END;
