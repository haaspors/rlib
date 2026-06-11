#include <rlib/rnet.h>
#include <rlib/rev.h>
#include <rlib/rcrypto.h>

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
