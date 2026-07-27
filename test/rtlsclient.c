#include <rlib/rnet.h>
#include <rlib/rcrypto.h>

#include "rtlstestcerts.h"

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
  RTLSAlertType srv_alert, cli_alert;   /* alert each side raised at its error */
  rboolean srv_closed, cli_closed;
  ruint verify_calls;
  rboolean verify_result;
  RTLSCipherSuite force_suite;   /* pin both endpoints to one suite; NONE = defaults */

  rboolean sni_cb_called;        /* server's SNI selection cb fired */
  rchar sni_seen[128];           /* SNI host the server's cb received ("" if NULL) */
  RCryptoCert * sni_cert;        /* cert the cb installs for the SNI host, or NULL */
  RCryptoKey * sni_key;

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
  (void) session;
  fixture->srv_error = TRUE;
  fixture->srv_alert = alert;
}

static void
r_tlsclient_test_cli_error (rpointer ctx, RTLSAlertType alert, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->cli_error = TRUE;
  fixture->cli_alert = alert;
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

/* Server-side SNI selection: record the requested name and, if the fixture has
 * one staged, install a per-name certificate for this connection. */
static RTLSError
r_tlsclient_test_sni (rpointer ctx, const rchar * name, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  fixture->sni_cb_called = TRUE;
  if (name != NULL)
    r_strncpy (fixture->sni_seen, name, sizeof (fixture->sni_seen));
  if (fixture->sni_cert != NULL)
    return r_tls_server_set_cert ((RTLSServer *) session,
        fixture->sni_cert, fixture->sni_key);
  return R_TLS_ERROR_OK;
}

static const RTLSCallbacks srvcbs = {
  r_tlsclient_test_prefer_ecdhe,
  r_tlsclient_test_srv_hs_done,
  r_tlsclient_test_srv_out,
  r_tlsclient_test_srv_app,
  r_tlsclient_test_srv_error,
  NULL,
  r_tlsclient_test_srv_closed,
};
static const RTLSCallbacks clicbs = {
  r_tlsclient_test_prefer_ecdhe,
  r_tlsclient_test_cli_hs_done,
  r_tlsclient_test_cli_out,
  r_tlsclient_test_cli_app,
  r_tlsclient_test_cli_error,
  r_tlsclient_test_verify_cert,
  r_tlsclient_test_cli_closed,
};

RTEST_FIXTURE_SETUP (rtlsclient)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((fixture->evloop = r_ev_loop_new_full (fixture->clock, NULL)), !=, NULL);

  fixture->srv_hs_done = fixture->cli_hs_done = FALSE;
  fixture->srv_error = fixture->cli_error = FALSE;
  fixture->srv_alert = fixture->cli_alert = R_TLS_ALERT_TYPE_CLOSE_NOTIFY;
  fixture->srv_closed = fixture->cli_closed = FALSE;
  fixture->verify_calls = 0;
  fixture->verify_result = TRUE;
  fixture->force_suite = R_TLS_CS_NONE;
  fixture->sni_cb_called = FALSE;
  fixture->sni_seen[0] = '\0';
  fixture->sni_cert = NULL;
  fixture->sni_key = NULL;

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
  if (fixture->sni_cert != NULL)
    r_crypto_cert_unref (fixture->sni_cert);
  if (fixture->sni_key != NULL)
    r_crypto_key_unref (fixture->sni_key);
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

/* TLS 1.3 1-RTT loopback. The 1.3 suites have no entry in the 1.2-shaped
 * cipher-suite table, so get_cipher_suite is NULL here; we assert the handshake
 * completes, the negotiated version, the peer certificate, and an
 * application-data round-trip in both directions. */
static void
r_test_tls13_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  static const ruint8 c2s[] = { 'h', 'e', 'l', 'l', 'o', ' ', '1', '.', '3' };
  static const ruint8 s2c[] = { 'h', 'i', ' ', '1', '.', '3' };
  RBuffer * app;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_3);
  /* The negotiated 1.3 suite is reported (it has a cipher-suite table entry). */
  r_assert_cmpptr (r_tls_client_get_cipher_suite (fixture->client), !=, NULL);
  r_assert (r_tls_client_get_cipher_suite (fixture->client)->suite ==
        R_TLS_CS_AES_128_GCM_SHA256 ||
      r_tls_client_get_cipher_suite (fixture->client)->suite ==
        R_TLS_CS_AES_256_GCM_SHA384);

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

/* RSA server certificate: 1.3 CertificateVerify uses rsa_pss_rsae_sha256. */
RTEST_F (rtlsclient, tls13_loopback_rsa, RTEST_FAST)
{
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* ECDSA server certificate: 1.3 CertificateVerify uses ecdsa_secp256r1_sha256. */
RTEST_F (rtlsclient, tls13_loopback_ecdsa, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Force AES_256_GCM_SHA384 to exercise the SHA-384 key schedule end to end. */
RTEST_F (rtlsclient, tls13_loopback_aes256, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_AES_256_GCM_SHA384;
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* TLS 1.3 post-handshake KeyUpdate (RFC 8446 4.6.3). After the handshake each
 * endpoint rekeys its sending direction; the peer must track the rotation for
 * records to keep decrypting. A key_update requesting a peer update makes the
 * peer answer with its own KeyUpdate, rotating both directions. An app-data
 * round trip after each rotation proves the keys stayed in sync. */
RTEST_F (rtlsclient, tls13_key_update, RTEST_FAST)
{
  static const ruint8 a[] = { 'a', 'f', 't', 'e', 'r', '1' };
  static const ruint8 b[] = { 'a', 'f', 't', 'e', 'r', '2' };
  RBuffer * app;

  /* KeyUpdate is refused before the session is established. */
  r_assert (!r_tls_client_key_update (fixture->client, FALSE));

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);

  /* Client rekeys its sending direction; the peer need not respond. */
  r_assert (r_tls_client_key_update (fixture->client, FALSE));
  r_test_tls_loopback_pump (fixture);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* client -> server still decrypts under the client's new send key. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)a, sizeof (a), sizeof (a), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, a, sizeof (a));

  /* Server rekeys and asks the client to rekey too: the client's auto-response
   * KeyUpdate rotates the remaining direction, so both are now fresh. */
  r_assert (r_tls_server_key_update (fixture->server, TRUE));
  r_test_tls_loopback_pump (fixture);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* server -> client under the server's new send key. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)b, sizeof (b), sizeof (b), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, b, sizeof (b));

  /* client -> server under the client's twice-rotated send key. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)a, sizeof (a), sizeof (a), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, a, sizeof (a));

  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
}
RTEST_END;

/* ALPN (RFC 7301): the client offers a protocol list, the server selects by its
 * own preference from the overlap, and both endpoints report the same choice.
 * Parameterised by @version to cover the 1.2 ServerHello and the 1.3
 * EncryptedExtensions carrier. */
static void
r_test_tls_alpn_negotiated (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version)
{
  static const rchar * srv[] = { "h2", "http/1.1" };
  static const rchar * cli[] = { "http/1.1", "h2" };
  const rchar * sel;
  rsize sellen = 0;

  r_assert_cmpint (r_tls_server_set_alpn_protocols (fixture->server,
        srv, R_N_ELEMENTS (srv)), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_alpn_protocols (fixture->client,
        cli, R_N_ELEMENTS (cli)), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        version), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* Server preference wins: "h2" is the server's first choice and the client
   * offers it too, so both sides agree on "h2". */
  sel = r_tls_client_get_alpn_selected (fixture->client, &sellen);
  r_assert_cmpptr (sel, !=, NULL);
  r_assert_cmpuint (sellen, ==, 2);
  r_assert_cmpint (r_memcmp (sel, "h2", 2), ==, 0);

  sel = r_tls_server_get_alpn_selected (fixture->server, &sellen);
  r_assert_cmpptr (sel, !=, NULL);
  r_assert_cmpuint (sellen, ==, 2);
  r_assert_cmpint (r_memcmp (sel, "h2", 2), ==, 0);
}

RTEST_F (rtlsclient, tls_alpn, RTEST_FAST)
{
  r_test_tls_alpn_negotiated (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, tls13_alpn, RTEST_FAST)
{
  r_test_tls_alpn_negotiated (fixture, R_TLS_VERSION_TLS_1_3);
}
RTEST_END;

/* The client offers ALPN but the server has none configured: no protocol is
 * negotiated and the handshake still completes. Input validation of the
 * protocol list is exercised alongside. */
RTEST_F (rtlsclient, tls13_alpn_server_unconfigured, RTEST_FAST)
{
  static const rchar * cli[] = { "h2" };
  static const rchar * bad[] = { "" };
  rsize sellen = 1;

  r_assert_cmpint (r_tls_client_set_alpn_protocols (fixture->client, bad, 1),
      ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_client_set_alpn_protocols (fixture->client,
        cli, R_N_ELEMENTS (cli)), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpptr (r_tls_client_get_alpn_selected (fixture->client, &sellen), ==, NULL);
  r_assert_cmpuint (sellen, ==, 0);
}
RTEST_END;

/* The server requires secp256r1 but the client offers an x25519 key_share, so
 * the server answers with a HelloRetryRequest and the client retries with a
 * secp256r1 share. The handshake can only complete if the retry worked. */
RTEST_F (rtlsclient, tls13_loopback_hrr, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_SECP256R1), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Drive CH1 -> HelloRetryRequest with a server that requires secp256r1 while
 * the client first offers x25519. Returns the (still-owned) HRR record and
 * leaves the client having consumed nothing yet. */
static RBuffer *
r_test_tls13_hrr_drive (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  RBuffer * ch1, * hrr;

  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_SECP256R1), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_assert_cmpptr ((ch1 = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch1);
  r_buffer_unref (ch1);
  r_assert_cmpptr ((hrr = r_queue_pop (&fixture->srv_out)), !=, NULL);
  return hrr;
}

/* A second HelloRetryRequest is illegal (RFC 8446 4.1.4): once the client has
 * answered one HRR, replaying it aborts with unexpected_message. */
RTEST_F (rtlsclient, tls13_hrr_second_rejected, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);

  /* First HRR: the client retries (CH2), no error. */
  r_tls_client_incoming_data (fixture->client, hrr);
  r_assert (!fixture->cli_error);

  /* Replaying the HRR is a second one -- reject it. */
  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);

  r_assert (fixture->cli_error);
  r_assert_cmpuint (fixture->cli_alert, ==, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
  r_assert (!fixture->cli_hs_done);
}
RTEST_END;

/* After a HelloRetryRequest the ServerHello must keep the suite the HRR
 * committed to; a changed suite is illegal_parameter (RFC 8446 4.1.4). */
RTEST_F (rtlsclient, tls13_hrr_serverhello_suite_mismatch, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);
  RBuffer * ch2, * sh;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize csoff;
  ruint16 cur;

  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);

  /* CH2 -> server sends its second flight; the ServerHello is the first record. */
  r_assert_cmpptr ((ch2 = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch2);
  r_buffer_unref (ch2);
  r_assert_cmpptr ((sh = r_queue_pop (&fixture->srv_out)), !=, NULL);

  /* Rewrite the ServerHello cipher_suite to a different (valid) 1.3 suite. The
   * field sits after record hdr(5) + hs hdr(4) + version(2) + random(32) +
   * legacy_session_id (1-byte length + echo). */
  r_assert (r_buffer_map (sh, &info, R_MEM_MAP_WRITE));
  r_assert_cmpuint (info.data[0], ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (info.data[5], ==, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO);
  csoff = 44 + info.data[43];
  cur = r_load_be16 (info.data + csoff);
  r_store_be16 (info.data + csoff, cur == R_TLS_CS_AES_128_GCM_SHA256 ?
      (ruint16) R_TLS_CS_AES_256_GCM_SHA384 : (ruint16) R_TLS_CS_AES_128_GCM_SHA256);
  r_assert (r_buffer_unmap (sh, &info));

  r_tls_client_incoming_data (fixture->client, sh);
  r_buffer_unref (sh);

  r_assert (fixture->cli_error);
  r_assert_cmpuint (fixture->cli_alert, ==, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
  r_assert (!fixture->cli_hs_done);
}
RTEST_END;

/* The retry ClientHello must echo the HelloRetryRequest cookie verbatim; a
 * corrupted echo is rejected by the server with illegal_parameter. */
RTEST_F (rtlsclient, tls13_hrr_cookie_mismatch, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);
  RBuffer * ch2;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RTLSHelloExt ext;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  const ruint8 * cookie = NULL;
  ruint16 cookielen = 0;
  ruint8 ckcopy[64];
  rsize i, off = 0;
  rboolean found = FALSE;
  RTLSError e;

  /* Read the cookie the HRR carries. */
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, hrr), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&hello, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_COOKIE) {
      cookie = r_tls_hello_ext_cookie (&ext, &cookielen);
      r_assert_cmpuint (cookielen, >, 0);
      r_assert_cmpuint (cookielen, <=, sizeof (ckcopy));
      r_memcpy (ckcopy, cookie, cookielen);
      found = TRUE;
    }
  }
  r_assert (found);
  r_tls_parser_clear (&parser);

  /* Client retries (CH2), echoing the cookie. */
  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);
  r_assert_cmpptr ((ch2 = r_queue_pop (&fixture->cli_out)), !=, NULL);

  /* Locate the echoed cookie in CH2 and flip one of its bytes. */
  r_assert (r_buffer_map (ch2, &info, R_MEM_MAP_WRITE));
  found = FALSE;
  for (i = 0; i + cookielen <= info.size; i++) {
    if (r_memcmp (info.data + i, ckcopy, cookielen) == 0) { off = i; found = TRUE; break; }
  }
  r_assert (found);
  info.data[off] ^= 0xff;
  r_assert (r_buffer_unmap (ch2, &info));

  r_tls_server_incoming_data (fixture->server, ch2);
  r_buffer_unref (ch2);

  r_assert (fixture->srv_error);
  r_assert_cmpuint (fixture->srv_alert, ==, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

/* The retry ClientHello must carry a key_share for the group the
 * HelloRetryRequest asked for; a retry that still omits it (here its share is
 * repointed to another group) leaves the server with no usable share and it
 * aborts with handshake_failure rather than issuing a second HRR. */
RTEST_F (rtlsclient, tls13_hrr_retry_missing_share, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);
  RBuffer * ch2;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RTLSHelloExt ext;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize ksoff = 0;
  rboolean found = FALSE;
  RTLSError e;

  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);
  r_assert_cmpptr ((ch2 = r_queue_pop (&fixture->cli_out)), !=, NULL);

  /* Find the first KeyShareEntry's group id -- ext.data opens with the
   * client_shares vector length(2), then group(2) -- and repoint it. */
  r_assert (r_buffer_map (ch2, &info, R_MEM_MAP_READ));
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, ch2), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&hello, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_KEY_SHARE) {
      ksoff = (rsize) (ext.data - info.data) + 2;
      found = TRUE;
    }
  }
  r_tls_parser_clear (&parser);
  r_assert (found);
  r_assert (r_buffer_unmap (ch2, &info));

  r_assert (r_buffer_map (ch2, &info, R_MEM_MAP_WRITE));
  r_assert_cmpuint (r_load_be16 (info.data + ksoff), ==, R_TLS_SUPPORTED_GROUP_SECP256R1);
  r_store_be16 (info.data + ksoff, (ruint16) R_TLS_SUPPORTED_GROUP_X25519);
  r_assert (r_buffer_unmap (ch2, &info));

  r_tls_server_incoming_data (fixture->server, ch2);
  r_buffer_unref (ch2);

  r_assert (fixture->srv_error);
  r_assert_cmpuint (fixture->srv_alert, ==, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

/* Build a fresh server pre-loaded with the test cert and @keys (shared so a
 * later connection can open a ticket the first sealed). */
static RTLSServer *
r_test_tls13_new_server (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSSessionTicketKeys * keys)
{
  RTLSServer * s = r_tls_server_new (&srvcbs, fixture, NULL);
  RCryptoCert * cert = r_pem_parse_cert_from_data (testcertpem, -1);
  RCryptoKey * pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0);
  r_assert_cmpint (r_tls_server_set_cert (s, cert, pk), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (s, keys), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  return s;
}

/* Full 1.3 handshake yields a NewSessionTicket; a second connection resumes
 * from it with an abbreviated handshake (no certificate exchanged) that still
 * carries application data both ways. The two servers share a ticket-key store,
 * as separate server instances would in production. */
RTEST_F (rtlsclient, tls13_resumption, RTEST_FAST)
{
  static const ruint8 c2s[] = { 'r', 'e', 's', 'u', 'm', 'e' };
  static const ruint8 s2c[] = { 'o', 'k' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First (full) handshake. The server issues a NewSessionTicket. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  r_assert_cmpuint (fixture->verify_calls, ==, 1);   /* full handshake verified a cert */

  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* Fresh endpoints (sharing the key store) for the resumed handshake. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_3);
  /* Resumption authenticates via the PSK: no Certificate, so verify_cert was
   * not called again and no peer certificate was received. */
  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), ==, NULL);

  /* The resumed session carries application data both ways. */
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

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* A resumption ClientHello whose pre_shared_key binder does not match the one
 * the server recomputes over the ticket PSK is rejected: the server opens the
 * ticket, fails the binder check and aborts with a fatal decrypt_error alert
 * instead of completing the abbreviated handshake. */
RTEST_F (rtlsclient, tls13_resumption_bad_binder, RTEST_FAST)
{
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;
  RBuffer * ch, * alert;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First (full) handshake to obtain a ticket. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* Fresh endpoints sharing the key store; the ticket opens but we corrupt the
   * binder on the wire. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  fixture->cli_error = fixture->srv_error = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  /* The ClientHello ends with the binder (pre_shared_key is last); flipping its
   * final byte leaves the transcript the server hashes intact but breaks the
   * binder value. */
  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert (r_buffer_map (ch, &info, R_MEM_MAP_WRITE));
  info.data[info.size - 1] ^= 0xff;
  r_assert (r_buffer_unmap (ch, &info));

  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);

  r_assert (fixture->srv_error);
  r_assert (!fixture->srv_hs_done);

  r_assert_cmpptr ((alert = r_queue_pop (&fixture->srv_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_DECRYPT_ERROR);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* A ticket the resuming server cannot open (its key store never sealed it) is
 * silently declined: the pre_shared_key offer is ignored and the handshake
 * falls back to a full one, verifying the certificate again. */
RTEST_F (rtlsclient, tls13_resumption_ticket_declined, RTEST_FAST)
{
  RTLSSessionTicketKeys * keys, * otherkeys;
  RTLSClientSession * session;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First (full) handshake seals a ticket under @keys. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* The resuming server holds an unrelated key store, so the ticket will not
   * open. */
  r_assert_cmpptr ((otherkeys = r_tls_session_ticket_keys_new ()), !=, NULL);
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, otherkeys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  /* Full handshake ran instead: no error, a certificate was verified again and
   * a peer certificate is present. */
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_3);
  r_assert_cmpuint (fixture->verify_calls, ==, 2);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
  r_tls_session_ticket_keys_unref (otherkeys);
}
RTEST_END;

/* A first handshake against an early-data-enabled server yields a ticket that
 * permits 0-RTT; the resumed connection sends early data after the ClientHello,
 * the server accepts it (echoes early_data) and delivers it via appdata before
 * the handshake completes. */
RTEST_F (rtlsclient, tls13_early_data_accepted, RTEST_FAST)
{
  static const ruint8 early[] = { 'G', 'E', 'T', ' ', '/' };
  static const ruint8 s2c[] = { 'o', 'k' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First handshake: the server offers 0-RTT, so its ticket advertises it. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* Fresh endpoints (sharing the key store); the client offers 0-RTT data. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)early, sizeof (early), sizeof (early), 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_early_data (fixture->client, app), ==, R_TLS_ERROR_OK);
  r_buffer_unref (app);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  fixture->verify_calls = 0;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  /* Both endpoints agree 0-RTT was accepted; the certificate was not re-sent. */
  r_assert (r_tls_client_get_early_data_accepted (fixture->client));
  r_assert (r_tls_server_get_early_data_accepted (fixture->server));
  r_assert_cmpuint (fixture->verify_calls, ==, 0);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), ==, NULL);
  /* The early data reached the server as application data during the handshake. */
  r_test_tls_assert_appdata (&fixture->srv_app, early, sizeof (early));

  /* 1-RTT data still flows afterwards. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* When the resuming server declines 0-RTT (early data disabled), the client's
 * early-data records are discarded and the payload is transparently resent as
 * ordinary application data once the handshake completes. */
RTEST_F (rtlsclient, tls13_early_data_rejected, RTEST_FAST)
{
  static const ruint8 early[] = { 'P', 'I', 'N', 'G' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First handshake against an early-data-enabled server: the ticket permits
   * 0-RTT, so the client will actually put early data on the wire. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* The resuming server does NOT enable 0-RTT, so it declines the offer. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)early, sizeof (early), sizeof (early), 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_early_data (fixture->client, app), ==, R_TLS_ERROR_OK);
  r_buffer_unref (app);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  /* Neither side saw 0-RTT accepted, yet the payload was delivered once, resent
   * as 1-RTT application data. */
  r_assert (!r_tls_client_get_early_data_accepted (fixture->client));
  r_assert (!r_tls_server_get_early_data_accepted (fixture->server));
  r_test_tls_assert_appdata (&fixture->srv_app, early, sizeof (early));

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* The resuming server accepts 0-RTT but has a smaller max_early_data_size than
 * the ticket originally advertised; a client payload that overshoots that limit
 * is rejected on the server rather than delivered (RFC 8446 4.2.10). */
RTEST_F (rtlsclient, tls13_early_data_exceeds_max, RTEST_FAST)
{
  static const ruint8 early[] = { 'T', 'O', 'O', 'M', 'U', 'C', 'H', '!' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First handshake advertises a generous limit, so the ticket permits enough
   * early data for the payload below. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* The resuming server now enforces a limit of 4 bytes, below the 8-byte
   * payload the client offers as 0-RTT. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 4),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)early, sizeof (early), sizeof (early), 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_early_data (fixture->client, app), ==, R_TLS_ERROR_OK);
  r_buffer_unref (app);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  fixture->cli_error = fixture->srv_error = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  /* The server aborted the handshake on the over-long early data; the oversized
   * record was never delivered to the application. */
  r_assert (fixture->srv_error);
  r_assert (!fixture->srv_hs_done);
  r_assert_cmpuint (r_queue_size (&fixture->srv_app), ==, 0);

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* In 1.3, alerts after the handshake are AEAD-protected (RFC 8446 5): the
 * server's close_notify goes out as an application_data record, the client
 * decrypts it, reports the orderly close and auto-responds with its own
 * protected close_notify. */
RTEST_F (rtlsclient, tls13_close_notify, RTEST_FAST)
{
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);

  r_assert (r_tls_server_close (fixture->server));
  r_assert_cmpptr ((buf = r_queue_pop (&fixture->srv_out)), !=, NULL);
  /* Protected: the record carries application_data, not a cleartext alert. */
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_APPLICATION_DATA);
  r_tls_parser_clear (&parser);

  r_tls_client_incoming_data (fixture->client, buf);
  r_buffer_unref (buf);
  r_assert (fixture->cli_closed);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_closed);   /* the initiator is not itself notified */

  /* The client auto-responded with its own protected close_notify. */
  r_assert_cmpptr ((buf = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_APPLICATION_DATA);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_loopback, RTEST_FAST)
{
  r_test_tls_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* The client offers SNI; the server's selection callback sees the name and
 * installs a per-name certificate, which the client then receives. */
RTEST_F (rtlsclient, sni_selects_cert, RTEST_FAST)
{
  RCryptoCert * peer;

  r_assert_cmpptr ((fixture->sni_cert =
      r_pem_parse_cert_from_data (rtest_leaf_root_pem, -1)), !=, NULL);
  r_assert_cmpptr ((fixture->sni_key =
      r_pem_parse_key_from_data (rtest_leaf_root_key_pem, -1, NULL, 0)), !=, NULL);

  r_assert_cmpint (r_tls_server_set_server_name_cb (fixture->server,
      r_tlsclient_test_sni), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client,
      "host.example.com"), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop,
      fixture->prng), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop,
      fixture->prng, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (fixture->sni_cb_called);
  r_assert_cmpstr (fixture->sni_seen, ==, "host.example.com");
  /* the server exposes the requested name, and presented the selected cert */
  r_assert_cmpstr (r_tls_server_get_server_name (fixture->server), ==,
      "host.example.com");
  r_assert_cmpptr ((peer = r_tls_client_get_peer_cert (fixture->client)), !=, NULL);
  r_assert_cmpstr (r_crypto_x509_cert_subject (peer), ==, "CN=localhost");
}
RTEST_END;

/* No SNI: the callback still fires (with a NULL name) and the default cert
 * stands; the server-name getter reports NULL. */
RTEST_F (rtlsclient, sni_absent_keeps_default, RTEST_FAST)
{
  RCryptoCert * peer;

  r_assert_cmpint (r_tls_server_set_server_name_cb (fixture->server,
      r_tlsclient_test_sni), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop,
      fixture->prng), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop,
      fixture->prng, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (fixture->sni_cb_called);
  r_assert_cmpstr (fixture->sni_seen, ==, "");
  r_assert_cmpptr (r_tls_server_get_server_name (fixture->server), ==, NULL);
  r_assert_cmpptr ((peer = r_tls_client_get_peer_cert (fixture->client)), !=, NULL);
  r_assert_cmpstr (r_crypto_x509_cert_subject (peer), ==, "CN=rlib");
}
RTEST_END;

/* An over-long SNI host is rejected (it would not fit a host name / the record);
 * a 255-byte name is accepted. */
RTEST_F (rtlsclient, sni_name_length_capped, RTEST_FAST)
{
  rchar name[300];
  rsize i;

  for (i = 0; i < sizeof (name) - 1; i++)
    name[i] = 'a';

  name[256] = '\0';   /* 256 bytes -> rejected */
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client, name), ==,
      R_TLS_ERROR_INVAL);
  name[255] = '\0';   /* 255 bytes -> accepted */
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client, name), ==,
      R_TLS_ERROR_OK);
}
RTEST_END;

/* The SNI hook runs before cipher negotiation, so installing an ECDSA cert for
 * the requested host makes the server negotiate an ECDHE_ECDSA suite (the client
 * offers both ECDSA and RSA) -- i.e. the SNI-selected cert's key type drives the
 * cipher choice. The fixture default cert is RSA, so without the early hook the
 * suite would have been chosen against the wrong key. */
RTEST_F (rtlsclient, sni_cert_key_type_drives_cipher, RTEST_FAST)
{
  r_assert_cmpptr ((fixture->sni_cert =
      r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((fixture->sni_key =
      r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);

  r_assert_cmpint (r_tls_server_set_server_name_cb (fixture->server,
      r_tlsclient_test_sni), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client,
      "ecdsa.example.com"), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop,
      fixture->prng), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop,
      fixture->prng, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
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

/* RFC 8446 4.1.3 downgrade protection: a 1.3-capable server that settles on
 * TLS 1.2 stamps the downgrade sentinel into its ServerHello.random, and a
 * client that offered 1.3 but is answered with that ServerHello aborts with a
 * fatal illegal_parameter alert rather than completing the downgrade. */
RTEST_F (rtlsclient, tls_downgrade_protection, RTEST_FAST)
{
  RBuffer * ch, * sh, * alert;
  RTLSClient * victim;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  /* Drive the 1.2 ClientHello into the server so it emits its flight. */
  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);

  /* The first server record is the ServerHello; its random carries the
   * "DOWNGRD\x01" sentinel because the 1.3-capable server settled on 1.2. */
  r_assert_cmpptr ((sh = r_queue_pop (&fixture->srv_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, sh), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_assert (r_tls13_random_is_downgrade (hello.random));
  r_assert_cmpmem (hello.random + R_TLS_HELLO_RANDOM_BYTES - 8, ==,
      "\x44\x4f\x57\x4e\x47\x52\x44\x01", 8);
  r_tls_parser_clear (&parser);

  /* A fresh client that offered 1.3 detects the downgrade in that ServerHello
   * and aborts instead of accepting 1.2. */
  r_assert_cmpptr ((victim = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_start (victim, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);   /* drop victim's ClientHello */
  fixture->cli_error = fixture->cli_hs_done = FALSE;

  r_tls_client_incoming_data (victim, sh);
  r_assert (fixture->cli_error);
  r_assert (!fixture->cli_hs_done);

  /* It signalled the peer with a fatal illegal_parameter alert. */
  r_assert_cmpptr ((alert = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);

  r_tls_client_unref (victim);
  r_buffer_unref (sh);
}
RTEST_END;

/* The client offers both 1.3 and 1.2 in one ClientHello. Against the default
 * (1.3-capable) server it negotiates 1.3. */
RTEST_F (rtlsclient, tls_hybrid_negotiates_tls13, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_3);
  r_assert_cmpuint (r_tls_server_get_version (fixture->server), ==, R_TLS_VERSION_TLS_1_3);
}
RTEST_END;

/* Same hybrid client, but the server is capped at 1.2 -- a genuine 1.2 peer
 * that neither speaks 1.3 nor stamps the downgrade sentinel. The client falls
 * back to a full 1.2 handshake (no false downgrade abort) and data flows. */
RTEST_F (rtlsclient, tls_hybrid_falls_back_to_tls12, RTEST_FAST)
{
  static const ruint8 c2s[] = { 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k' };
  static const ruint8 s2c[] = { 'o', 'k', ' ', '1', '.', '2' };
  RBuffer * app;

  r_assert_cmpint (r_tls_server_set_version_range (fixture->server,
        R_TLS_VERSION_TLS_1_2, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpuint (r_tls_server_get_version (fixture->server), ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
  /* 1.2 with the default ECDHE-first preference: forward secrecy preserved. */
  r_assert_cmpptr (r_tls_client_get_cipher_suite (fixture->client), !=, NULL);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_ECDHE_RSA);

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
RTEST_END;

/* A server that requires 1.3 rejects a 1.2-only client with a fatal
 * protocol_version alert. */
RTEST_F (rtlsclient, tls_server_requires_tls13, RTEST_FAST)
{
  RBuffer * ch, * alert;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_set_version_range (fixture->server,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);

  r_assert (fixture->srv_error);
  r_assert (!fixture->srv_hs_done);

  r_assert_cmpptr ((alert = r_queue_pop (&fixture->srv_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_PROTOCOL_VERSION);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);
}
RTEST_END;

/* r_tls_client_set_version_range accepts the 1.2..1.3 window and rejects
 * inverted, out-of-window and DTLS bounds. */
RTEST_F (rtlsclient, tls_client_version_range_validation, RTEST_FAST)
{
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_2, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_VERSION);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_0, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_VERSION);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_DTLS_1_2, R_TLS_VERSION_DTLS_1_2), ==, R_TLS_ERROR_VERSION);
}
RTEST_END;

/* A client pinned to 1.3 (no fallback) rejects a 1.2 ServerHello as out of its
 * offered range, aborting with protocol_version rather than downgrading. A
 * pinned client offers no 1.2 suites, so a genuine 1.2 server could not answer
 * it at all; the rejection guards the case where a server (or an attacker)
 * replies 1.2 regardless. The 1.2 ServerHello is sourced from the capped server
 * answering a hybrid client. */
RTEST_F (rtlsclient, tls_client_requires_tls13, RTEST_FAST)
{
  RBuffer * ch, * sh, * alert;
  RTLSClient * victim;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_set_version_range (fixture->server,
        R_TLS_VERSION_TLS_1_2, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  /* A hybrid client so the capped server produces a real (sentinel-free) 1.2
   * ServerHello. */
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);
  r_assert_cmpptr ((sh = r_queue_pop (&fixture->srv_out)), !=, NULL);

  /* Pinned-1.3 client fed that 1.2 ServerHello aborts. */
  r_assert_cmpptr ((victim = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_version_range (victim,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (victim, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);   /* drop victim's ClientHello */
  fixture->cli_error = fixture->cli_hs_done = FALSE;

  r_tls_client_incoming_data (victim, sh);
  r_assert (fixture->cli_error);
  r_assert (!fixture->cli_hs_done);

  r_assert_cmpptr ((alert = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_PROTOCOL_VERSION);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);

  r_tls_client_unref (victim);
  r_buffer_unref (sh);
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
