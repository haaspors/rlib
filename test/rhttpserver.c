#include <rlib/rnet.h>
#include <rlib/rev.h>
#include <rlib/rcrypto.h>

#include "rtlstestcerts.h"

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

static void
r_test_http_server_stop (rpointer data, REvLoop * loop)
{
  (void) loop;
  r_http_server_stop (data, NULL, NULL, NULL);
}

RTEST (rhttpserver, listen, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RSocketAddress * addr;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  /* Ephemeral port: a fixed port collides with a previous run's socket still
   * in TIME_WAIT (notably under meson test --repeat). */
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);

  r_assert (r_http_server_add_listen_addr (srv, addr));
  r_socket_address_unref (addr);

  r_ev_loop_add_callback (loop, FALSE, r_test_http_server_stop,
      r_http_server_ref (srv), r_http_server_unref);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);

  r_http_server_unref (srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

static void
r_test_http_response_ready (rpointer data, RHttpResponse * res, RHttpServer * server)
{
  RHttpResponse ** out = data;
  (void) server;
  *out = r_http_response_ref (res);
}

RTEST (rhttpserver, process, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpRequest * req;
  RHttpResponse * res = NULL;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);

  r_assert (!r_http_server_process_request (srv, NULL, NULL, NULL, NULL, NULL));

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://example.org", NULL, NULL)), !=, NULL);
  r_assert (r_http_server_process_request (srv, req, NULL,
        r_test_http_response_ready, &res, NULL));
  r_http_request_unref (req);

  r_assert_cmpptr (res, ==, NULL);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_assert_cmpptr (res, !=, NULL);

  /* No handlers means 404 Not Found */
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_NOT_FOUND);

  r_http_response_unref (res);
  r_http_server_unref (srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

static RHttpResponse *
r_test_http_simple_status_handler (rpointer data,
    RHttpRequest * req, RSocketAddress * addr, RHttpServer * server)
{
  RHttpResponse * ret;

  (void) server;

  if ((ret = r_http_response_new (req, (RHttpStatus)RPOINTER_TO_UINT (data),
          NULL, NULL, NULL)) != NULL) {
    rchar * str = r_socket_address_to_str (addr);
    RBuffer * buf;

    if ((buf = r_buffer_new_take (str, r_strlen (str))) != NULL) {
      r_http_response_set_body_buffer (ret, buf);
      r_buffer_unref (buf);
    } else {
      r_free (str);
    }
  }

  return ret;
}

RTEST (rhttpserver, handle_GET, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpRequest * req;
  RHttpResponse * res = NULL;
  RSocketAddress * addr;
  rchar * body, * addrstr;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (10, 0, 0, 1, 34567)), !=, NULL);

  r_assert (!r_http_server_set_handler (srv, NULL, 0, NULL, NULL, NULL));
  r_assert (!r_http_server_set_handler (srv, "/", -1, NULL, NULL, NULL));
  r_assert (r_http_server_set_handler (srv, "/", -1,
        r_test_http_simple_status_handler, RUINT_TO_POINTER (R_HTTP_STATUS_BAD_REQUEST), NULL));

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://example.org", NULL, NULL)), !=, NULL);
  r_assert (r_http_server_process_request (srv, req, addr,
        r_test_http_response_ready, &res, NULL));
  r_http_request_unref (req);

  r_assert_cmpptr (res, ==, NULL);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_assert_cmpptr (res, !=, NULL);

  /* Handler should give 400 Bad Request */
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_BAD_REQUEST);
  r_assert_cmpstr ((body = r_http_response_get_body (res, NULL)), ==,
      (addrstr = r_socket_address_to_str (addr)));
  r_free (body); r_free (addrstr);

  r_http_request_unref (addr);
  r_http_response_unref (res);
  r_http_server_unref (srv);
  r_ev_loop_unref (loop);
}
RTEST_END;


/* A raw client that sends @p two bare HTTP/1.1 requests (no Connection header)
 * on one socket, counting responses; the second only arrives if the server
 * kept the connection alive. */
typedef struct {
  RSocketAddress * addr;
  int responses;
  rboolean done;
} RTestPersistClient;

static rpointer
r_test_persist_client (rpointer data)
{
  RTestPersistClient * c = data;
  static const rchar req[] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  RSocket * s;

  if ((s = r_socket_new (R_SOCKET_FAMILY_IPV4, R_SOCKET_TYPE_STREAM,
          R_SOCKET_PROTOCOL_TCP)) != NULL) {
    r_socket_set_blocking (s, TRUE);
    if (r_socket_connect (s, c->addr) == R_SOCKET_OK) {
      int i;
      for (i = 0; i < 2; i++) {
        ruint8 buf[2048];
        rsize n = 0;
        if (r_socket_send (s, (const ruint8 *) req, sizeof (req) - 1, &n) != R_SOCKET_OK)
          break;
        if (r_socket_receive (s, buf, sizeof (buf), &n) != R_SOCKET_OK || n == 0)
          break;                  /* connection closed -> not persistent */
        c->responses++;
      }
    }
    r_socket_close (s);
    r_socket_unref (s);
  }
  c->done = TRUE;
  return NULL;
}

/* An HTTP/1.1 request without a Connection header is persistent by default, so
 * a second request is served on the same connection. */
RTEST (rhttpserver, keepalive_default_http11, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RSocketAddress * addr;
  RThread * thread;
  RTestPersistClient c = { NULL, 0, FALSE };

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert (r_http_server_set_handler (srv, "/", -1,
        r_test_http_simple_status_handler,
        RUINT_TO_POINTER (R_HTTP_STATUS_OK), NULL));
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)),
      !=, NULL);
  r_assert (r_http_server_add_listen_addr (srv, addr));
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_http_server_get_local_address (srv)), !=, NULL);

  c.addr = addr;
  r_assert_cmpptr ((thread = r_thread_new (NULL, r_test_persist_client, &c)),
      !=, NULL);

  /* Drive the server until the raw client has finished both exchanges. */
  while (!c.done)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_thread_join (thread);
  r_thread_unref (thread);
  r_assert_cmpint (c.responses, ==, 2);   /* connection persisted across requests */

  r_http_server_stop (srv, NULL, NULL, NULL);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_http_server_unref (srv);
  r_socket_address_unref (addr);
  r_ev_loop_unref (loop);
}
RTEST_END;


/* A TLS client driven over a real loopback REvTCP, all on one event loop: it
 * connects, runs the handshake, sends one GET on handshake completion and
 * captures the decrypted HTTP response. */
typedef struct {
  REvLoop * loop;
  REvTCP * tcp;
  RTLSClient * tls;
  RPrng * prng;
  RBuffer * resp;            /* decrypted response bytes, accumulated */
  RTLSVersion version;
  const RTLSCipherSuiteInfo * cipher;
  rboolean got_response;
  rboolean eos;
} RTestTLSClient;

static rboolean
r_test_tls_client_out (rpointer data, RBuffer * buf, rpointer session)
{
  RTestTLSClient * c = data;
  (void) session;
  /* Borrowed buffer: the send path queues its own reference. */
  r_ev_tcp_send_and_forget (c->tcp, buf);
  return TRUE;
}

static void
r_test_tls_client_hs_done (rpointer data, rpointer session)
{
  static const rchar req[] =
      "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
  RTestTLSClient * c = data;
  RBuffer * buf;
  (void) session;

  c->version = r_tls_client_get_version (c->tls);
  c->cipher = r_tls_client_get_cipher_suite (c->tls);

  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer) req, sizeof (req) - 1, sizeof (req) - 1, 0, NULL, NULL)),
      !=, NULL);
  r_tls_client_send_appdata (c->tls, buf);
  r_buffer_unref (buf);
}

static rboolean
r_test_tls_client_appdata (rpointer data, RBuffer * buf, rpointer session)
{
  RTestTLSClient * c = data;
  (void) session;

  r_buffer_append_mem_from_buffer (c->resp, buf);
  if (r_buffer_get_size (c->resp) >= 12 &&
      r_buffer_memcmp (c->resp, 0, "HTTP/1.1 200", 12) == 0)
    c->got_response = TRUE;
  return TRUE;
}

static const RTLSCallbacks g_test_tls_client_cbs = {
  NULL, r_test_tls_client_hs_done, r_test_tls_client_out,
  r_test_tls_client_appdata, NULL, NULL, NULL,
};

static void
r_test_tls_client_recv (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RTestTLSClient * c = data;
  (void) evtcp;

  if (buf == NULL) {
    c->eos = TRUE;
    return;
  }
  r_tls_client_incoming_data (c->tls, buf);
}

static void
r_test_tls_client_connected (rpointer data, REvTCP * evtcp, int status)
{
  RTestTLSClient * c = data;
  (void) evtcp;

  r_assert_cmpint (status, ==, R_SOCKET_OK);
  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_client_start (c->tls, c->loop, c->prng, R_TLS_VERSION_TLS_1_2));
  r_assert (r_ev_tcp_recv_start (c->tcp, NULL, r_test_tls_client_recv, c, NULL));
}

RTEST (rhttpserver, https_get, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RSocketAddress * addr;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RTestTLSClient c = { NULL, NULL, NULL, NULL, NULL, R_TLS_VERSION_UNKNOWN, NULL, FALSE, FALSE };

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);

  r_assert (r_http_server_set_handler (srv, "/", -1,
        r_test_http_simple_status_handler,
        RUINT_TO_POINTER (R_HTTP_STATUS_OK), NULL));
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_http_server_add_tls_listen_addr (srv, addr, cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_http_server_get_local_address (srv)), !=, NULL);

  r_assert_cmpptr ((c.prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((c.resp = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((c.tls = r_tls_client_new (&g_test_tls_client_cbs, &c, NULL)), !=, NULL);
  c.loop = loop;
  r_assert_cmpptr ((c.tcp = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_connect (c.tcp, addr,
        r_test_tls_client_connected, &c, NULL), >=, R_SOCKET_OK);

  while (!c.got_response && !c.eos)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert (c.got_response);
  r_assert_cmpint (c.version, ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpptr (c.cipher, !=, NULL);

  r_ev_tcp_close (c.tcp, NULL, NULL, NULL);
  r_ev_tcp_unref (c.tcp);
  r_tls_client_unref (c.tls);
  r_buffer_unref (c.resp);
  r_prng_unref (c.prng);

  r_http_server_stop (srv, NULL, NULL, NULL);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_http_server_unref (srv);
  r_socket_address_unref (addr);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* A plaintext HTTP request against a TLS listener: the bytes are not a valid
 * TLS record, so the server aborts the connection rather than answering. */
typedef struct {
  REvTCP * tcp;
  RBuffer * resp;
  rboolean got_response;
  rboolean eos;
} RTestPlainClient;

static void
r_test_plain_client_recv (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RTestPlainClient * c = data;
  (void) evtcp;

  if (buf == NULL) {
    c->eos = TRUE;
    return;
  }
  r_buffer_append_mem_from_buffer (c->resp, buf);
  if (r_buffer_get_size (c->resp) >= 12 &&
      r_buffer_memcmp (c->resp, 0, "HTTP/1.1 200", 12) == 0)
    c->got_response = TRUE;
}

static void
r_test_plain_client_connected (rpointer data, REvTCP * evtcp, int status)
{
  static const rchar req[] = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  RTestPlainClient * c = data;
  RBuffer * buf;
  (void) evtcp;

  r_assert_cmpint (status, ==, R_SOCKET_OK);
  r_assert (r_ev_tcp_recv_start (c->tcp, NULL, r_test_plain_client_recv, c, NULL));
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer) req, sizeof (req) - 1, sizeof (req) - 1, 0, NULL, NULL)),
      !=, NULL);
  r_ev_tcp_send_and_forget (c->tcp, buf);
  r_buffer_unref (buf);
}

RTEST (rhttpserver, https_rejects_plaintext, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RSocketAddress * addr;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RTestPlainClient c = { NULL, NULL, FALSE, FALSE };

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);

  r_assert (r_http_server_set_handler (srv, "/", -1,
        r_test_http_simple_status_handler,
        RUINT_TO_POINTER (R_HTTP_STATUS_OK), NULL));
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_http_server_add_tls_listen_addr (srv, addr, cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_http_server_get_local_address (srv)), !=, NULL);

  r_assert_cmpptr ((c.resp = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((c.tcp = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_connect (c.tcp, addr,
        r_test_plain_client_connected, &c, NULL), >=, R_SOCKET_OK);

  while (!c.eos)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert (c.eos);                 /* server dropped the connection */
  r_assert (!c.got_response);       /* never answered the plaintext request */

  r_ev_tcp_close (c.tcp, NULL, NULL, NULL);
  r_ev_tcp_unref (c.tcp);
  r_buffer_unref (c.resp);

  r_http_server_stop (srv, NULL, NULL, NULL);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_http_server_unref (srv);
  r_socket_address_unref (addr);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* --- mutual TLS (client certificate verification) ------------------------ */

typedef struct {
  rchar * peer_subject;   /* subject DN the handler saw, or NULL */
  rboolean handled;
} RTestMtls;

static RHttpResponse *
r_test_mtls_handler (rpointer data, RHttpRequest * req, RSocketAddress * addr,
    RHttpServer * server)
{
  RTestMtls * m = data;
  RCryptoCert * peer = r_http_server_get_peer_cert (server, req);
  (void) addr;

  m->handled = TRUE;
  if (peer != NULL)
    m->peer_subject = r_strdup (r_crypto_x509_cert_subject (peer));
  return r_http_response_new (req, R_HTTP_STATUS_OK, NULL, NULL, NULL);
}

/* Drive one mutual-TLS attempt on a loopback loop: a server presenting the PKI
 * leaf (chaining to the test root) in client-cert @p mode with @p trust_pem
 * anchored (NULL = empty store), and a client presenting @p cli_cert_pem /
 * @p cli_key_pem (NULL = no client certificate). Reports whether the GET was
 * answered and the client subject the handler observed. */
static void
r_test_mtls_run (RTLSClientCertMode mode, rboolean configure_store,
    const rchar * trust_pem, const rchar * cli_cert_pem, const rchar * cli_key_pem,
    rboolean * got_response, rchar ** peer_subject)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RTrustStore * trust;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RSocketAddress * addr;
  RTestMtls m = { NULL, FALSE };
  RTestTLSClient c = { NULL, NULL, NULL, NULL, NULL, R_TLS_VERSION_UNKNOWN, NULL,
      FALSE, FALSE };

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert (r_http_server_set_handler (srv, "/", -1, r_test_mtls_handler, &m, NULL));

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (rtest_leaf_root_pem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (rtest_leaf_root_key_pem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_http_server_add_tls_listen_addr (srv, addr, cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_socket_address_unref (addr);

  r_http_server_set_client_cert_mode (srv, mode);
  /* configure_store == FALSE leaves the server with no client trust store,
   * exercising the fail-closed path. */
  if (configure_store) {
    r_assert_cmpptr ((trust = r_trust_store_new_certs ()), !=, NULL);
    if (trust_pem != NULL)
      r_assert_cmpint (r_trust_store_add_pem (trust, trust_pem, -1), ==, 1);
    r_http_server_set_client_trust_store (srv, trust);
    r_trust_store_unref (trust);
  }

  r_assert_cmpptr ((addr = r_http_server_get_local_address (srv)), !=, NULL);

  r_assert_cmpptr ((c.prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((c.resp = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((c.tls = r_tls_client_new (&g_test_tls_client_cbs, &c, NULL)), !=, NULL);
  if (cli_cert_pem != NULL) {
    RCryptoCert * cc = r_pem_parse_cert_from_data (cli_cert_pem, -1);
    RCryptoKey * ck = r_pem_parse_key_from_data (cli_key_pem, -1, NULL, 0);
    r_assert_cmpptr (cc, !=, NULL);
    r_assert_cmpptr (ck, !=, NULL);
    r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_client_set_cert (c.tls, cc, ck));
    r_crypto_key_unref (ck);
    r_crypto_cert_unref (cc);
  }
  c.loop = loop;
  r_assert_cmpptr ((c.tcp = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_connect (c.tcp, addr,
        r_test_tls_client_connected, &c, NULL), >=, R_SOCKET_OK);

  while (!c.got_response && !c.eos)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  *got_response = c.got_response;
  *peer_subject = m.peer_subject;   /* ownership transferred to caller */

  r_ev_tcp_close (c.tcp, NULL, NULL, NULL);
  r_ev_tcp_unref (c.tcp);
  r_tls_client_unref (c.tls);
  r_buffer_unref (c.resp);
  r_prng_unref (c.prng);

  r_http_server_stop (srv, NULL, NULL, NULL);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_http_server_unref (srv);
  r_socket_address_unref (addr);
  r_ev_loop_unref (loop);
}

/* A trusted client certificate (clientAuth, chains to the anchored root) is
 * accepted under REQUIRE, and the handler sees the verified subject. */
RTEST (rhttpserver, mtls_trusted_client, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE;
  rchar * subject = NULL;

  r_test_mtls_run (R_TLS_CLIENT_CERT_MODE_REQUIRE, TRUE, rtest_root_pem,
      rtest_leaf_clientauth_pem, rtest_leaf_clientauth_key_pem, &got, &subject);

  r_assert (got);
  r_assert_cmpptr (subject, !=, NULL);
  r_assert_cmpstr (subject, ==, "CN=rlib Test Client");
  r_free (subject);
}
RTEST_END;

/* REQUIRE with no client certificate aborts the handshake. */
RTEST (rhttpserver, mtls_missing_client_cert, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE;
  rchar * subject = NULL;

  r_test_mtls_run (R_TLS_CLIENT_CERT_MODE_REQUIRE, TRUE, rtest_root_pem,
      NULL, NULL, &got, &subject);

  r_assert (!got);
  r_assert_cmpptr (subject, ==, NULL);
}
RTEST_END;

/* A client certificate lacking the clientAuth EKU is rejected. */
RTEST (rhttpserver, mtls_wrong_eku, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE;
  rchar * subject = NULL;

  /* leaf_root carries serverAuth, not clientAuth. */
  r_test_mtls_run (R_TLS_CLIENT_CERT_MODE_REQUIRE, TRUE, rtest_root_pem,
      rtest_leaf_root_pem, rtest_leaf_root_key_pem, &got, &subject);

  r_assert (!got);
  r_assert_cmpptr (subject, ==, NULL);
}
RTEST_END;

/* A client certificate that does not chain to the configured anchor is
 * rejected (empty trust store). */
RTEST (rhttpserver, mtls_untrusted_client, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE;
  rchar * subject = NULL;

  r_test_mtls_run (R_TLS_CLIENT_CERT_MODE_REQUIRE, TRUE, NULL,
      rtest_leaf_clientauth_pem, rtest_leaf_clientauth_key_pem, &got, &subject);

  r_assert (!got);
  r_assert_cmpptr (subject, ==, NULL);
}
RTEST_END;

/* REQUEST mode serves a client that presents no certificate (unauthenticated);
 * the handler sees no peer certificate. */
RTEST (rhttpserver, mtls_request_optional, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE;
  rchar * subject = NULL;

  r_test_mtls_run (R_TLS_CLIENT_CERT_MODE_REQUEST, TRUE, rtest_root_pem,
      NULL, NULL, &got, &subject);

  r_assert (got);
  r_assert_cmpptr (subject, ==, NULL);
}
RTEST_END;

/* REQUEST mode with a trusted client certificate: the connection is served and
 * the handler sees the verified peer certificate. */
RTEST (rhttpserver, mtls_request_with_cert, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE;
  rchar * subject = NULL;

  r_test_mtls_run (R_TLS_CLIENT_CERT_MODE_REQUEST, TRUE, rtest_root_pem,
      rtest_leaf_clientauth_pem, rtest_leaf_clientauth_key_pem, &got, &subject);

  r_assert (got);
  r_assert_cmpptr (subject, !=, NULL);
  r_assert_cmpstr (subject, ==, "CN=rlib Test Client");
  r_free (subject);
}
RTEST_END;

/* REQUIRE with no trust store configured fails closed: a presented, otherwise
 * valid client certificate is rejected because nothing anchors it. */
RTEST (rhttpserver, mtls_require_no_trust_store, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE;
  rchar * subject = NULL;

  r_test_mtls_run (R_TLS_CLIENT_CERT_MODE_REQUIRE, FALSE, NULL,
      rtest_leaf_clientauth_pem, rtest_leaf_clientauth_key_pem, &got, &subject);

  r_assert (!got);
  r_assert_cmpptr (subject, ==, NULL);
}
RTEST_END;

/* Drive one HTTPS attempt against a server with SNI virtual hosts. The default
 * listener serves CN=rlib (client-cert NONE); vhost "localhost" and the wildcard
 * "*.example.com" both serve the CN=localhost PKI leaf, but the wildcard
 * additionally REQUIREs a client cert anchored at the test root. Reports whether
 * the GET was answered, the server cert the client saw, and the client subject
 * the handler observed. */
static void
r_test_vhost_run (RTLSClientCertMode server_mode, const rchar * sni,
    const rchar * cli_cert_pem, const rchar * cli_key_pem,
    rboolean * got_response, rchar ** server_subject, rchar ** client_subject)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RTrustStore * trust;
  RCryptoCert * cert, * peer;
  RCryptoKey * pk;
  RSocketAddress * addr;
  RTestMtls m = { NULL, FALSE };
  RTestTLSClient c = { NULL, NULL, NULL, NULL, NULL, R_TLS_VERSION_UNKNOWN, NULL,
      FALSE, FALSE };

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert (r_http_server_set_handler (srv, "/", -1, r_test_mtls_handler, &m, NULL));

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_http_server_add_tls_listen_addr (srv, addr, cert, pk));
  r_socket_address_unref (addr);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (rtest_leaf_root_pem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (rtest_leaf_root_key_pem, -1, NULL, 0)), !=, NULL);
  r_assert (r_http_server_add_vhost (srv, "localhost", cert, pk));
  r_assert (r_http_server_add_vhost (srv, "*.example.com", cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_assert_cmpptr ((trust = r_trust_store_new_certs ()), !=, NULL);
  r_assert_cmpint (r_trust_store_add_pem (trust, rtest_root_pem, -1), ==, 1);
  /* whole-server policy: the "localhost" vhost (no per-vhost mTLS) inherits it */
  r_http_server_set_client_cert_mode (srv, server_mode);
  if (server_mode != R_TLS_CLIENT_CERT_MODE_NONE)
    r_http_server_set_client_trust_store (srv, trust);
  /* the wildcard vhost overrides with its own REQUIRE + trust */
  r_assert (r_http_server_set_vhost_client_cert_mode (srv, "*.example.com",
        R_TLS_CLIENT_CERT_MODE_REQUIRE));
  r_assert (r_http_server_set_vhost_client_trust_store (srv, "*.example.com", trust));
  r_trust_store_unref (trust);

  r_assert_cmpptr ((addr = r_http_server_get_local_address (srv)), !=, NULL);

  r_assert_cmpptr ((c.prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((c.resp = r_buffer_new ()), !=, NULL);
  r_assert_cmpptr ((c.tls = r_tls_client_new (&g_test_tls_client_cbs, &c, NULL)), !=, NULL);
  if (sni != NULL)
    r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_client_set_server_name (c.tls, sni));
  if (cli_cert_pem != NULL) {
    RCryptoCert * cc = r_pem_parse_cert_from_data (cli_cert_pem, -1);
    RCryptoKey * ck = r_pem_parse_key_from_data (cli_key_pem, -1, NULL, 0);
    r_assert_cmpptr (cc, !=, NULL);
    r_assert_cmpptr (ck, !=, NULL);
    r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_client_set_cert (c.tls, cc, ck));
    r_crypto_key_unref (ck);
    r_crypto_cert_unref (cc);
  }
  c.loop = loop;
  r_assert_cmpptr ((c.tcp = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_connect (c.tcp, addr,
        r_test_tls_client_connected, &c, NULL), >=, R_SOCKET_OK);

  while (!c.got_response && !c.eos)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  *got_response = c.got_response;
  *client_subject = m.peer_subject;   /* ownership transferred to caller */
  *server_subject = ((peer = r_tls_client_get_peer_cert (c.tls)) != NULL) ?
      r_strdup (r_crypto_x509_cert_subject (peer)) : NULL;

  r_ev_tcp_close (c.tcp, NULL, NULL, NULL);
  r_ev_tcp_unref (c.tcp);
  r_tls_client_unref (c.tls);
  r_buffer_unref (c.resp);
  r_prng_unref (c.prng);

  r_http_server_stop (srv, NULL, NULL, NULL);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_http_server_unref (srv);
  r_socket_address_unref (addr);
  r_ev_loop_unref (loop);
}

/* SNI matching an exact vhost selects that vhost's certificate. */
RTEST (rhttpserver, vhost_sni_exact, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE; rchar * srv = NULL, * cli = NULL;
  r_test_vhost_run (R_TLS_CLIENT_CERT_MODE_NONE, "localhost", NULL, NULL, &got, &srv, &cli);
  r_assert (got);
  r_assert_cmpstr (srv, ==, "CN=localhost");
  r_assert_cmpptr (cli, ==, NULL);   /* this vhost requests no client cert */
  r_free (srv); r_free (cli);
}
RTEST_END;

/* SNI matching no vhost falls back to the listener certificate. */
RTEST (rhttpserver, vhost_sni_fallback, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE; rchar * srv = NULL, * cli = NULL;
  r_test_vhost_run (R_TLS_CLIENT_CERT_MODE_NONE, "unknown.host", NULL, NULL, &got, &srv, &cli);
  r_assert (got);
  r_assert_cmpstr (srv, ==, "CN=rlib");
  r_free (srv); r_free (cli);
}
RTEST_END;

/* No SNI uses the listener certificate and the whole-server (NONE) policy. */
RTEST (rhttpserver, vhost_no_sni_default, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE; rchar * srv = NULL, * cli = NULL;
  r_test_vhost_run (R_TLS_CLIENT_CERT_MODE_NONE, NULL, NULL, NULL, &got, &srv, &cli);
  r_assert (got);
  r_assert_cmpstr (srv, ==, "CN=rlib");
  r_free (srv); r_free (cli);
}
RTEST_END;

/* A wildcard vhost is matched and enforces its own REQUIRE policy: a trusted
 * client certificate is accepted and reaches the handler. */
RTEST (rhttpserver, vhost_wildcard_mtls_trusted, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE; rchar * srv = NULL, * cli = NULL;
  r_test_vhost_run (R_TLS_CLIENT_CERT_MODE_NONE, "api.example.com", rtest_leaf_clientauth_pem,
      rtest_leaf_clientauth_key_pem, &got, &srv, &cli);
  r_assert (got);
  r_assert_cmpstr (srv, ==, "CN=localhost");
  r_assert_cmpstr (cli, ==, "CN=rlib Test Client");
  r_free (srv); r_free (cli);
}
RTEST_END;

/* The wildcard vhost REQUIREs a client cert, so a connection without one fails
 * even though the default listener policy is NONE. */
RTEST (rhttpserver, vhost_wildcard_mtls_missing_cert, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE; rchar * srv = NULL, * cli = NULL;
  r_test_vhost_run (R_TLS_CLIENT_CERT_MODE_NONE, "api.example.com", NULL, NULL, &got, &srv, &cli);
  r_assert (!got);
  r_assert_cmpptr (cli, ==, NULL);
  r_free (srv); r_free (cli);
}
RTEST_END;

/* A vhost with no per-vhost mTLS inherits the whole-server REQUIRE + trust:
 * a trusted client cert is required and reaches the handler. (The old
 * NONE-default would have requested no cert -> the handler would see none.) */
RTEST (rhttpserver, vhost_inherits_whole_server_mtls, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE; rchar * srv = NULL, * cli = NULL;
  r_test_vhost_run (R_TLS_CLIENT_CERT_MODE_REQUIRE, "localhost",
      rtest_leaf_clientauth_pem, rtest_leaf_clientauth_key_pem, &got, &srv, &cli);
  r_assert (got);
  r_assert_cmpstr (srv, ==, "CN=localhost");
  r_assert_cmpstr (cli, ==, "CN=rlib Test Client");
  r_free (srv); r_free (cli);
}
RTEST_END;

/* The inherited REQUIRE is enforced: a connection to that vhost without a client
 * certificate is rejected. */
RTEST (rhttpserver, vhost_inherits_require_rejects_no_cert, RTEST_FAST | RTEST_SYSTEM)
{
  rboolean got = FALSE; rchar * srv = NULL, * cli = NULL;
  r_test_vhost_run (R_TLS_CLIENT_CERT_MODE_REQUIRE, "localhost", NULL, NULL,
      &got, &srv, &cli);
  r_assert (!got);
  r_assert_cmpptr (cli, ==, NULL);
  r_free (srv); r_free (cli);
}
RTEST_END;

/* Vhost host names are case-insensitive: a case-variant is a duplicate, and the
 * config setters find a vhost regardless of case. */
RTEST (rhttpserver, vhost_host_case_insensitive, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);
  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (rtest_leaf_root_pem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (rtest_leaf_root_key_pem, -1, NULL, 0)), !=, NULL);

  r_assert (r_http_server_add_vhost (srv, "Example.com", cert, pk));
  r_assert (!r_http_server_add_vhost (srv, "example.COM", cert, pk)); /* dup */
  r_assert (r_http_server_set_vhost_client_cert_mode (srv, "EXAMPLE.com",
        R_TLS_CLIENT_CERT_MODE_REQUIRE));                             /* found */
  r_assert (!r_http_server_set_vhost_client_cert_mode (srv, "other.com",
        R_TLS_CLIENT_CERT_MODE_REQUIRE));                            /* absent */

  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  r_http_server_unref (srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

typedef struct {
  RHttpRequest * other;     /* a request that is not the one being handled */
  rboolean null_for_req;    /* get_peer_cert (server, req) was NULL */
  rboolean null_for_other;  /* get_peer_cert (server, other) was NULL */
} RTestPeerCertNull;

static RHttpResponse *
r_test_peer_cert_null_handler (rpointer data, RHttpRequest * req,
    RSocketAddress * addr, RHttpServer * server)
{
  RTestPeerCertNull * p = data;
  (void) addr;

  /* An injected request never carries a peer certificate, and a request other
   * than the one in flight must not borrow this handler's (absent) cert. */
  p->null_for_req = r_http_server_get_peer_cert (server, req) == NULL;
  p->null_for_other = r_http_server_get_peer_cert (server, p->other) == NULL;
  return r_http_response_new (req, R_HTTP_STATUS_OK, NULL, NULL, NULL);
}

/* r_http_server_get_peer_cert returns NULL outside any handler, and inside a
 * handler for both an injected (certificate-less) request and a mismatched
 * request handle. */
RTEST (rhttpserver, get_peer_cert_null, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpRequest * req, * other;
  RHttpResponse * res = NULL;
  RTestPeerCertNull p = { NULL, FALSE, FALSE };

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);

  /* Called outside any handler: no request is in flight. */
  r_assert_cmpptr ((other = r_http_request_new (R_HTTP_METHOD_GET,
          "http://example.org", NULL, NULL)), !=, NULL);
  r_assert_cmpptr (r_http_server_get_peer_cert (srv, other), ==, NULL);

  p.other = other;
  r_assert (r_http_server_set_handler (srv, "/", -1,
        r_test_peer_cert_null_handler, &p, NULL));

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://example.org", NULL, NULL)), !=, NULL);
  r_assert (r_http_server_process_request (srv, req, NULL,
        r_test_http_response_ready, &res, NULL));
  r_http_request_unref (req);

  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_assert_cmpptr (res, !=, NULL);
  r_assert (p.null_for_req);
  r_assert (p.null_for_other);

  r_http_response_unref (res);
  r_http_request_unref (other);
  r_http_server_unref (srv);
  r_ev_loop_unref (loop);
}
RTEST_END;
