#include <rlib/rnet.h>
#include <rlib/rev.h>

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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 4242)), !=, NULL);

  r_assert (r_http_server_listen (srv, addr));
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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 4243)),
      !=, NULL);
  r_assert (r_http_server_listen (srv, addr));

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
