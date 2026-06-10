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

/* Self-signed P-256 ECDSA test certificate + matching PKCS#8 key (CN=rlib-ecdsa).
 * Keep the serial small (the parser stores it as a ruint64) and the validity in
 * UTCTime range (< year 2050, no GeneralizedTime) when regenerating, or the
 * certificate will not parse. */
static const rchar testcertpem_ecdsa[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBazCCARKgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApybGliLWVj\n"
  "ZHNhMB4XDTI2MDYxMDE2MzEwNVoXDTQ4MDUwNTE2MzEwNVowFTETMBEGA1UEAwwK\n"
  "cmxpYi1lY2RzYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHmc5lmycwenV7C+\n"
  "7Z8tpwNH4WqfCYE2ngzLa8mn0MK+UeGkAOMj30dPnRd9Y2mi7ypVo1y0aAb/HJYF\n"
  "/q6z4pijUzBRMB0GA1UdDgQWBBR6XBE2U7nNA9t9ll5AacMs4bTZazAfBgNVHSME\n"
  "GDAWgBR6XBE2U7nNA9t9ll5AacMs4bTZazAPBgNVHRMBAf8EBTADAQH/MAoGCCqG\n"
  "SM49BAMCA0cAMEQCIBbHM2jgY1m9lhDtyIUZJA1Pf8faLunxtb3ysQvorcEyAiAQ\n"
  "MI/3ana2mn80+oVJfVU6vFEOYVJ84K16whK8g3e7Fg==\n"
  "-----END CERTIFICATE-----\n";

static const rchar testpkpem_ecdsa[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoTATtTsWuzOwzu8p\n"
  "lD/YJFTfjLKmPB52UDdl6/X+V42hRANCAAR5nOZZsnMHp1ewvu2fLacDR+FqnwmB\n"
  "Np4My2vJp9DCvlHhpADjI99HT50XfWNpou8qVaNctGgG/xyWBf6us+KY\n"
  "-----END PRIVATE KEY-----\n";

RTEST_FIXTURE_STRUCT (rtlsclient)
{
  RTLSServer * server;
  RTLSClient * client;

  rboolean srv_hs_done, cli_hs_done;
  rboolean srv_error, cli_error;
  rboolean srv_closed, cli_closed;
  ruint verify_calls;
  rboolean verify_result;
  RTLSCipherSuite force_suite;   /* pin both endpoints to one suite; NONE = defaults */

  RClock * clock;
  REvLoop * evloop;
  RPrng * prng;

  RQueue srv_out, cli_out;       /* records each side emits */
  RQueue srv_app, cli_app;       /* decrypted application data each side received */
};

static rboolean
r_tlsclient_test_prefer_ecdhe (rpointer ctx, RTLSVersion ver,
    RTLSCipherSuite * cs, rsize * count)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) ver;
  if (fixture->force_suite == R_TLS_CS_NONE)
    return FALSE;                /* follow the library defaults (ECDHE-first) */
  *count = 1;
  cs[0] = fixture->force_suite;
  return TRUE;
}

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

static void
r_tlsclient_test_srv_closed (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->srv_closed = TRUE;
}

static void
r_tlsclient_test_cli_closed (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->cli_closed = TRUE;
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
    r_tlsclient_test_prefer_ecdhe,
    r_tlsclient_test_srv_hs_done,
    r_tlsclient_test_srv_out,
    r_tlsclient_test_srv_app,
    r_tlsclient_test_srv_error,
    NULL,
    r_tlsclient_test_srv_closed,
  };
  static RTLSCallbacks clicbs = {
    r_tlsclient_test_prefer_ecdhe,
    r_tlsclient_test_cli_hs_done,
    r_tlsclient_test_cli_out,
    r_tlsclient_test_cli_app,
    r_tlsclient_test_cli_error,
    r_tlsclient_test_verify_cert,
    r_tlsclient_test_cli_closed,
  };
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((fixture->evloop = r_ev_loop_new_full (fixture->clock, NULL)), !=, NULL);

  fixture->srv_hs_done = fixture->cli_hs_done = FALSE;
  fixture->srv_error = fixture->cli_error = FALSE;
  fixture->srv_closed = fixture->cli_closed = FALSE;
  fixture->verify_calls = 0;
  fixture->verify_result = TRUE;
  fixture->force_suite = R_TLS_CS_NONE;

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

/* Assert @buf is an alert record. The close_notify is emitted post-handshake,
 * so its body is encrypted (only the record content type is in the clear); the
 * decrypted warning/close_notify bytes are asserted in the rtlsserver suite. */
static void
r_test_tls_assert_alert_record (RBuffer * buf)
{
  RTLSParser parser = R_TLS_PARSER_INIT;

  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_tls_parser_clear (&parser);
}

/* Drive a handshake, then have one endpoint cleanly close: it emits a warning
 * close_notify, the peer auto-responds (RFC 5246 7.2.1) and reports the orderly
 * close through its closed callback, and neither side accepts further app data.
 * The initiator is not itself notified (it requested the close). */
static void
r_test_tls_close_notify (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version, rboolean server_initiates)
{
  static const ruint8 payload[] = { 'x' };
  RBuffer * buf;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);

  if (server_initiates) {
    r_assert (r_tls_server_close (fixture->server));
    r_assert (!r_tls_server_close (fixture->server));  /* idempotent: a no-op */
    /* The server queued exactly its warning close_notify; deliver it. */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->srv_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_tls_client_incoming_data (fixture->client, buf);
    r_buffer_unref (buf);
    r_assert (fixture->cli_closed);
    r_assert (!fixture->cli_error);
    r_assert (!fixture->srv_closed);                   /* initiator not notified */
    /* The client auto-responded with its own warning close_notify. */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->cli_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_buffer_unref (buf);
  } else {
    r_assert (r_tls_client_close (fixture->client));
    r_assert (!r_tls_client_close (fixture->client));  /* idempotent: a no-op */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->cli_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_tls_server_incoming_data (fixture->server, buf);
    r_buffer_unref (buf);
    r_assert (fixture->srv_closed);
    r_assert (!fixture->srv_error);
    r_assert (!fixture->cli_closed);                   /* initiator not notified */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->srv_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_buffer_unref (buf);
  }

  /* A closed session refuses application data in either direction. */
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)payload, sizeof (payload), sizeof (payload), 0, NULL, NULL)), !=, NULL);
  r_assert (!r_tls_client_send_appdata (fixture->client, buf));
  r_assert (!r_tls_server_send_appdata (fixture->server, buf));
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
  /* Both endpoints default to ECDHE-first: forward secrecy out of the box. */
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_ECDHE_RSA);

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

RTEST_F (rtlsclient, tls_close_notify_client, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_TLS_1_2, FALSE);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_close_notify_client, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_DTLS_1_2, FALSE);
}
RTEST_END;

RTEST_F (rtlsclient, tls_close_notify_server, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_TLS_1_2, TRUE);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_close_notify_server, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_DTLS_1_2, TRUE);
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

/* Mutual TLS: the server requires a client certificate, the client presents
 * one, and the handshake completes with each side holding the other's leaf. */
static void
r_test_tls_mtls_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture, RTLSVersion version)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_cert (fixture->client, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server,
        R_TLS_CLIENT_CERT_MODE_REQUIRE), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  /* Each side validated and kept the other's leaf certificate. */
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), !=, NULL);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
}

RTEST_F (rtlsclient, tls_mtls_loopback, RTEST_FAST)
{
  r_test_tls_mtls_loopback (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_mtls_loopback, RTEST_FAST)
{
  r_test_tls_mtls_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* The server requires a client certificate but the client has none: it answers
 * with an empty Certificate and the server aborts the handshake. */
RTEST_F (rtlsclient, tls_mtls_require_no_client_cert, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server,
        R_TLS_CLIENT_CERT_MODE_REQUIRE), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (!fixture->srv_hs_done);
  r_assert (!fixture->cli_hs_done);
  r_assert (fixture->srv_error);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), ==, NULL);
}
RTEST_END;

/* ECDHE_RSA end-to-end: both endpoints offer only the ECDHE suite, so the
 * handshake exercises the ServerKeyExchange signature, the ephemeral ECDH
 * agreement, and the variable-length premaster on both sides. */
static void
r_test_tls_ecdhe_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture, RTLSVersion version)
{
  static const ruint8 c2s[] = { 'e', 'c', 'd', 'h', 'e' };
  static const ruint8 s2c[] = { 'o', 'k' };
  const RTLSCipherSuiteInfo * info;
  RBuffer * app;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* Forward secrecy: both sides negotiated the ephemeral-ECDH suite. */
  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_RSA);
  r_assert_cmpptr ((info = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_RSA);

  /* Application data round-trips over the established keys. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

RTEST_F (rtlsclient, tls_ecdhe_loopback, RTEST_FAST)
{
  r_test_tls_ecdhe_loopback (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdhe_loopback, RTEST_FAST)
{
  r_test_tls_ecdhe_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* A duplicated ServerKeyExchange must abort the handshake: the client accepts
 * exactly one SKE (a second would otherwise replace the ephemeral keys). */
RTEST_F (rtlsclient, tls_ecdhe_duplicate_ske, RTEST_FAST)
{
  RBuffer * buf;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  /* ClientHello -> server; then replay the server's SKE record to the client. */
  while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
    r_tls_server_incoming_data (fixture->server, buf);
    r_buffer_unref (buf);
  }
  while ((buf = r_queue_pop (&fixture->srv_out)) != NULL) {
    RTLSParser parser = R_TLS_PARSER_INIT;
    RTLSHandshakeType type = (RTLSHandshakeType)0;
    rboolean is_ske;

    r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
    is_ske = r_tls_parser_parse_handshake_peek_type (&parser, &type) == R_TLS_ERROR_OK &&
        type == R_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE;
    r_tls_parser_clear (&parser);

    r_tls_client_incoming_data (fixture->client, buf);
    if (is_ske)
      r_tls_client_incoming_data (fixture->client, buf);
    r_buffer_unref (buf);
  }

  r_assert (fixture->cli_error);
  r_assert (!fixture->cli_hs_done);
}
RTEST_END;

/* Static RSA still works end to end when pinned explicitly (the default
 * preference is ECDHE-first, so this exercises the legacy key exchange). */
RTEST_F (rtlsclient, tls_rsa_loopback, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_RSA);
}
RTEST_END;

/* AES-256-CBC exercises the wider key expansion (32-byte write keys) over a
 * full ECDHE handshake with application data. */
RTEST_F (rtlsclient, tls_ecdhe_aes256_loopback, RTEST_FAST)
{
  static const ruint8 c2s[] = { 'a', 'e', 's', '2', '5', '6' };
  RBuffer * app;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->suite,
      ==, R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
  r_assert_cmpuint (r_tls_client_get_cipher_suite (fixture->client)->cipher->keybits, ==, 256);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));
}
RTEST_END;

/* AEAD (AES-GCM) end to end for one suite/version: handshake completes, the
 * negotiated suite is the forced GCM suite, and app data round-trips through
 * the AEAD record path. The SHA-384 suites also exercise the per-suite PRF and
 * transcript hash. */
static void
r_test_tls_gcm_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version, RTLSCipherSuite suite)
{
  static const ruint8 c2s[] = { 'g', 'c', 'm', '-', 'p', 'i', 'n', 'g' };
  static const ruint8 s2c[] = { 'g', 'c', 'm', '-', 'p', 'o', 'n', 'g' };
  const RTLSCipherSuiteInfo * info;
  RBuffer * app;

  fixture->force_suite = suite;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->suite, ==, suite);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);
  r_assert_cmpptr ((info = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpint (info->suite, ==, suite);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

RTEST_F (rtlsclient, tls_gcm_ecdhe_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_ecdhe_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, tls_gcm_ecdhe_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_ecdhe_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, tls_gcm_rsa_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_rsa_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, tls_gcm_rsa_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_rsa_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

/* A tampered AEAD record must fail the tag check: complete a GCM handshake,
 * then flip a byte in a client application-data record before it reaches the
 * server. The server reports bad_record_mac and never surfaces the payload. */
RTEST_F (rtlsclient, gcm_tampered_record, RTEST_FAST)
{
  static const ruint8 c2s[] = { 's', 'e', 'c', 'r', 'e', 't' };
  RBuffer * app, * rec;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);

  /* Client emits one encrypted application-data record. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);

  /* Corrupt the last byte (inside the GCM tag) before delivering it. */
  r_assert_cmpptr ((rec = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert (r_buffer_map (rec, &info, R_MEM_MAP_RW));
  info.data[info.size - 1] ^= 0xff;
  r_buffer_unmap (rec, &info);

  r_tls_server_incoming_data (fixture->server, rec);
  r_buffer_unref (rec);

  r_assert (fixture->srv_error);
  r_assert (r_queue_is_empty (&fixture->srv_app));
}
RTEST_END;

/* Replace the fixture's default RSA server cert with the ECDSA one. */
static void
r_test_tls_use_ecdsa_server_cert (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_crypto_key_get_algo (pk), ==, R_CRYPTO_ALGO_ECDSA);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
}

/* ECDHE_ECDSA end to end with an ECDSA server certificate: the handshake
 * completes, the negotiated suite authenticates with ECDSA, and app data
 * round-trips. The SHA-384 GCM suite also exercises the per-suite PRF. */
static void
r_test_tls_ecdsa_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version, RTLSCipherSuite suite)
{
  static const ruint8 c2s[] = { 'e', 'c', 'd', 's', 'a' };
  const RTLSCipherSuiteInfo * info;
  RBuffer * app;

  r_test_tls_use_ecdsa_server_cert (fixture);
  fixture->force_suite = suite;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->suite, ==, suite);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
  r_assert_cmpptr ((info = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));
}

RTEST_F (rtlsclient, tls_ecdsa_gcm128, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdsa_gcm128, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, tls_ecdsa_gcm256_sha384, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdsa_gcm256_sha384, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, tls_ecdsa_cbc128_sha256, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdsa_cbc128_sha256, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
}
RTEST_END;

/* With an ECDSA certificate and no forced suite, the default negotiation must
 * pick an ECDHE_ECDSA suite (the auth gate keeps the RSA/ECDHE_RSA suites out). */
RTEST_F (rtlsclient, tls_ecdsa_default_negotiation, RTEST_FAST)
{
  const RTLSCipherSuiteInfo * info;

  r_test_tls_use_ecdsa_server_cert (fixture);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
}
RTEST_END;

/* Auth-type mismatch: an ECDSA cert cannot satisfy a forced ECDHE_RSA suite,
 * and the default RSA cert cannot satisfy a forced ECDHE_ECDSA suite. Either
 * way negotiation finds no common suite and the handshake aborts. */
RTEST_F (rtlsclient, tls_ecdsa_cert_rsa_suite_fails, RTEST_FAST)
{
  r_test_tls_use_ecdsa_server_cert (fixture);
  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (!fixture->cli_hs_done);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

RTEST_F (rtlsclient, tls_rsa_cert_ecdsa_suite_fails, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (!fixture->cli_hs_done);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

/* Mutual TLS with ECDSA on both ends: server requires a client cert, both
 * present ECDSA certs, the handshake completes and each side holds the other's
 * leaf. Exercises the ECDSA CertificateVerify sign + verify path. */
RTEST_F (rtlsclient, tls_ecdsa_mutual, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_test_tls_use_ecdsa_server_cert (fixture);

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_cert (fixture->client, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server,
        R_TLS_CLIENT_CERT_MODE_REQUIRE), ==, R_TLS_ERROR_OK);
  fixture->force_suite = R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), !=, NULL);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
}
RTEST_END;
