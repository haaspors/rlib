#include <rlib/rnet.h>
#include <rlib/rev.h>

/* Each test uses a distinct port: on Windows rtest runs single-process, so a
 * shared port can collide with a previous test's not-yet-torn-down socket. */
#define R_TEST_HTTP_CLIENT_BODY   "hello from rlib"

typedef struct {
  RHttpResponse * res;
  RHttpClientResult result;
  rboolean done;
  REvLoop * loop;
} RTestHttpSyncState;

static void
r_test_http_send_cb (rpointer data, RHttpResponse * res,
    RHttpClientResult result, RHttpClient * client)
{
  RTestHttpSyncState * st = data;
  (void) client;
  st->result = result;
  st->res = (res != NULL) ? r_http_response_ref (res) : NULL;
  st->done = TRUE;
  r_ev_loop_stop (st->loop);
}

/* Issue an async request and drive @loop until it completes. The in-process
 * tests put server and client on one shared loop, so a blocking
 * RHttpClientSync (which owns a private loop) can't drive the server here. */
static RHttpResponse *
r_test_http_send (REvLoop * loop, RHttpClient * client, RHttpRequest * req,
    const RSocketAddress * addr, RHttpClientResult * result)
{
  RTestHttpSyncState st = { NULL, R_HTTP_CLIENT_CONNECT_FAILED, FALSE, loop };

  if (!r_http_client_send (client, req, addr, r_test_http_send_cb, &st, NULL)) {
    if (result != NULL)
      *result = R_HTTP_CLIENT_CONNECT_FAILED;
    return NULL;
  }
  while (!st.done)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  if (result != NULL)
    *result = st.result;
  return st.res;
}

static RHttpResponse *
r_test_http_client_handler (rpointer data, RHttpRequest * req,
    RSocketAddress * addr, RHttpServer * server)
{
  RHttpResponse * res;

  (void) addr;
  (void) server;

  if ((res = r_http_response_new (req, (RHttpStatus) RPOINTER_TO_UINT (data),
          NULL, NULL, NULL)) != NULL) {
    RBuffer * buf = r_buffer_new_dup (R_STR_WITH_SIZE_ARGS (R_TEST_HTTP_CLIENT_BODY));
    if (buf != NULL) {
      r_http_response_set_body_buffer_full (res, buf, "text/plain", -1, TRUE);
      r_buffer_unref (buf);
    }
  }

  return res;
}

/* Build a listening server with a handler at @p path returning @p status
 * (with a body); the address to connect to is returned in *out. */
static RHttpServer *
r_test_http_client_server (REvLoop * loop, ruint16 port, const rchar * path,
    RHttpStatus status, RSocketAddress ** out)
{
  RHttpServer * srv;
  RSocketAddress * addr;

  if ((srv = r_http_server_new (loop)) == NULL)
    return NULL;

  r_assert (r_http_server_set_handler (srv, path, -1,
        r_test_http_client_handler, RUINT_TO_POINTER (status), NULL));

  addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, port);
  r_assert_cmpptr (addr, !=, NULL);
  r_assert (r_http_server_listen (srv, addr));

  *out = addr;
  return srv;
}

static void
r_test_http_client_teardown (REvLoop * loop, RHttpClient * client,
    RHttpServer * srv)
{
  /* Stop the server and drain the loop so every socket close completes. */
  if (client != NULL)
    r_http_client_unref (client);
  if (srv != NULL) {
    r_http_server_stop (srv, NULL, NULL, NULL);
    r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
    r_http_server_unref (srv);
  }
}

RTEST (rhttpclient, request_get, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;
  rchar * body;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_test_http_client_server (loop, 47654, "/",
          R_HTTP_STATUS_OK, &addr)), !=, NULL);
  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  r_assert (r_http_request_add_header (req, "Host", -1, "127.0.0.1", -1));

  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_assert_cmpptr (res, !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);
  r_assert_cmpstr ((body = r_http_response_get_body (res, NULL)), ==,
      R_TEST_HTTP_CLIENT_BODY);
  r_free (body);
  r_http_response_unref (res);

  r_socket_address_unref (addr);
  r_test_http_client_teardown (loop, client, srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (rhttpclient, request_not_found, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  /* Handler is registered at "/specific"; request an unrelated path so no
   * handler (nor any parent with one) matches -> 404. */
  r_assert_cmpptr ((srv = r_test_http_client_server (loop, 47655, "/specific",
          R_HTTP_STATUS_OK, &addr)), !=, NULL);
  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/other", NULL, NULL)), !=, NULL);
  r_assert (r_http_request_add_header (req, "Host", -1, "127.0.0.1", -1));

  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_assert_cmpptr (res, !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_NOT_FOUND);
  r_http_response_unref (res);

  r_socket_address_unref (addr);
  r_test_http_client_teardown (loop, client, srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (rhttpclient, connect_refused, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);

  /* No listener on this port -> the connection is refused. */
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1,
          47656)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);

  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_CONNECT_FAILED);
  r_assert_cmpptr (res, ==, NULL);

  r_socket_address_unref (addr);
  r_test_http_client_teardown (loop, client, NULL);
  r_ev_loop_unref (loop);
}
RTEST_END;

#define R_TEST_HTTP_CLIENT_BIG    (300 * 1024)

static RHttpResponse *
r_test_http_client_big_handler (rpointer data, RHttpRequest * req,
    RSocketAddress * addr, RHttpServer * server)
{
  RHttpResponse * res;

  (void) data;
  (void) addr;
  (void) server;

  if ((res = r_http_response_new (req, R_HTTP_STATUS_OK, NULL, NULL, NULL)) != NULL) {
    ruint8 * mem = r_malloc (R_TEST_HTTP_CLIENT_BIG);
    RBuffer * buf;
    rsize i;
    for (i = 0; i < R_TEST_HTTP_CLIENT_BIG; i++)
      mem[i] = (ruint8) (i & 0xff);
    if ((buf = r_buffer_new_take (mem, R_TEST_HTTP_CLIENT_BIG)) != NULL) {
      r_http_response_set_body_buffer_full (res, buf,
          "application/octet-stream", -1, TRUE);
      r_buffer_unref (buf);
    } else {
      r_free (mem);
    }
  }

  return res;
}

/* A body larger than a single TCP segment forces the response across several
 * recv callbacks, exercising the incremental accumulate + Content-Length
 * (SIZED) "wait for more body" path. */
RTEST (rhttpclient, request_large_body, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;
  rchar * body;
  rsize bsize, i;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert (r_http_server_set_handler (srv, "/", -1,
        r_test_http_client_big_handler, NULL, NULL));
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1,
          47657)), !=, NULL);
  r_assert (r_http_server_listen (srv, addr));

  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  r_assert (r_http_request_add_header (req, "Host", -1, "127.0.0.1", -1));

  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_assert_cmpptr (res, !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);
  r_assert_cmpptr ((body = r_http_response_get_body (res, &bsize)), !=, NULL);
  r_assert_cmpuint (bsize, ==, R_TEST_HTTP_CLIENT_BIG);
  for (i = 0; i < bsize; i++)
    r_assert_cmpuint ((ruint8) body[i], ==, (ruint8) (i & 0xff));
  r_free (body);
  r_http_response_unref (res);

  r_socket_address_unref (addr);
  r_test_http_client_teardown (loop, client, srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* A HEAD response has no body regardless of Content-Length; the client must
 * complete on the headers alone (SIZED with size 0). */
RTEST (rhttpclient, request_head, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;
  rchar * body;
  rsize bsize;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_test_http_client_server (loop, 47658, "/",
          R_HTTP_STATUS_OK, &addr)), !=, NULL);
  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_HEAD,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  r_assert (r_http_request_add_header (req, "Host", -1, "127.0.0.1", -1));

  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_assert_cmpptr (res, !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);
  body = r_http_response_get_body (res, &bsize);
  r_assert_cmpuint (bsize, ==, 0);
  r_free (body);
  r_http_response_unref (res);

  r_socket_address_unref (addr);
  r_test_http_client_teardown (loop, client, srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

static RHttpResponse *
r_test_http_client_stop_handler (rpointer data, RHttpRequest * req,
    RSocketAddress * addr, RHttpServer * server)
{
  (void) data;
  (void) addr;

  /* Stop the server while this connection is still active: exercises the
   * close-with-in-flight-connection teardown path in r_http_server_stop. */
  r_http_server_stop (server, NULL, NULL, NULL);
  return r_http_response_new (req, R_HTTP_STATUS_OK, NULL, NULL, NULL);
}

RTEST (rhttpclient, server_stop_during_request, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_http_server_new (loop)), !=, NULL);
  r_assert (r_http_server_set_handler (srv, "/", -1,
        r_test_http_client_stop_handler, NULL, NULL));
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1,
          47659)), !=, NULL);
  r_assert (r_http_server_listen (srv, addr));

  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);

  /* The point is that stopping mid-request neither hangs nor corrupts memory
   * (the latter caught under the sanitizer job); the exact outcome races the
   * force-close, so accept a delivered response or a transport error. */
  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);
  r_assert (result == R_HTTP_CLIENT_OK || result == R_HTTP_CLIENT_RECV_FAILED);
  if (res != NULL)
    r_http_response_unref (res);

  r_socket_address_unref (addr);
  r_http_client_unref (client);
  r_http_server_unref (srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* A minimal raw-TCP "server" that sends a fixed byte blob and closes, used to
 * feed the client responses RHttpServer cannot itself produce. */
typedef struct {
  REvTCP * listen;
  REvTCP * conn;
  const rchar * blob;
  rsize blen;
} RTestRawServer;

static void
r_test_raw_sent (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  (void) data;
  (void) buf;
  /* Close after the blob is written so a client still waiting sees EOS. */
  r_ev_tcp_close (evtcp, NULL, NULL, NULL);
}

static void
r_test_raw_conn_ready (rpointer data, REvTCP * newtcp, REvTCP * listening)
{
  RTestRawServer * s = data;
  (void) listening;
  s->conn = r_ev_tcp_ref (newtcp);
  r_ev_tcp_send_dup (newtcp, s->blob, s->blen, r_test_raw_sent, NULL, NULL);
}

static RTestRawServer *
r_test_raw_server_new (REvLoop * loop, ruint16 port, const rchar * blob,
    rsize blen, RSocketAddress ** out)
{
  RTestRawServer * s = r_mem_new0 (RTestRawServer);

  *out = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, port);
  r_assert_cmpptr (*out, !=, NULL);
  s->blob = blob;
  s->blen = blen;
  r_assert_cmpptr ((s->listen = r_ev_tcp_new_bind (*out, loop)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (s->listen, R_SOCKET_DEFAULT_BACKLOG,
        r_test_raw_conn_ready, s, NULL), >=, R_SOCKET_OK);
  return s;
}

static void
r_test_raw_server_free (RTestRawServer * s)
{
  if (s->conn != NULL) {
    r_ev_tcp_close (s->conn, NULL, NULL, NULL);
    r_ev_tcp_unref (s->conn);
  }
  r_ev_tcp_close (s->listen, NULL, NULL, NULL);
  r_ev_tcp_unref (s->listen);
  r_free (s);
}

static RHttpClientResult
r_test_http_client_raw_body (ruint16 port, const rchar * blob,
    const rchar * expect_body)
{
  REvLoop * loop;
  RClock * clock;
  RTestRawServer * raw;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  raw = r_test_raw_server_new (loop, port, blob, r_strlen (blob), &addr);
  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);

  res = r_test_http_send (loop, client, req, addr, &result);
  if (expect_body != NULL && result == R_HTTP_CLIENT_OK) {
    const rchar * body;
    r_assert_cmpptr (res, !=, NULL);
    r_assert_cmpstr ((body = r_http_response_get_body (res, NULL)), ==, expect_body);
  }
  r_http_request_unref (req);
  if (res != NULL)
    r_http_response_unref (res);

  r_socket_address_unref (addr);
  r_http_client_unref (client);
  r_test_raw_server_free (raw);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_ev_loop_unref (loop);
  return result;
}

static RHttpClientResult
r_test_http_client_raw (ruint16 port, const rchar * blob)
{
  return r_test_http_client_raw_body (port, blob, NULL);
}

/* A chunked response is decoded back into the reassembled body. */
RTEST (rhttpclient, response_chunked, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpint (r_test_http_client_raw_body (47660,
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", "Wikipedia"),
      ==, R_HTTP_CLIENT_OK);
}
RTEST_END;

/* A response that is not valid HTTP is a parse failure. */
RTEST (rhttpclient, response_malformed, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpint (r_test_http_client_raw (47661,
        "totally not a http response\r\n\r\n"), ==, R_HTTP_CLIENT_PARSE_FAILED);
}
RTEST_END;

/* A blocking-socket HTTP responder run on its own thread so a blocking
 * RHttpClientSync (which drives its own private loop) has a peer to talk to:
 * accept one connection, read the request, send a fixed response, close. */
static rpointer
r_test_http_blocking_responder (rpointer data)
{
  RSocket * listen = data;
  RSocket * conn;
  static const rchar resp[] =
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";

  if ((conn = r_socket_accept (listen, NULL)) != NULL) {
    ruint8 buf[1024];
    rsize n = 0;
    r_socket_set_blocking (conn, TRUE);
    /* A small GET arrives in one segment; drain it before replying. */
    r_socket_receive (conn, buf, sizeof (buf), &n);
    r_socket_send (conn, (const ruint8 *) resp, sizeof (resp) - 1, &n);
    r_socket_close (conn);
    r_socket_unref (conn);
  }

  return NULL;
}

RTEST (rhttpclientsync, request, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * listen;
  RSocketAddress * addr;
  RThread * thread;
  RHttpClientSync * sync;
  RHttpRequest * req;
  RHttpResponse * res;
  RHttpClientResult result;
  rchar * body;

  r_assert_cmpptr ((listen = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1,
          47662)), !=, NULL);
  r_assert_cmpint (r_socket_bind (listen, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_listen (listen), ==, R_SOCKET_OK);
  /* Block in accept until the client connects (the thread starts first). */
  r_assert (r_socket_set_blocking (listen, TRUE));
  r_assert_cmpptr ((thread = r_thread_new (NULL,
          r_test_http_blocking_responder, listen)), !=, NULL);

  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  r_assert (r_http_request_add_header (req, "Host", -1, "127.0.0.1", -1));

  res = r_http_client_sync_request (sync, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_assert_cmpptr (res, !=, NULL);
  r_assert_cmpint (r_http_response_get_status (res), ==, R_HTTP_STATUS_OK);
  r_assert_cmpstr ((body = r_http_response_get_body (res, NULL)), ==, "hi");
  r_free (body);
  r_http_response_unref (res);

  r_thread_join (thread);
  r_thread_unref (thread);
  r_http_client_sync_unref (sync);
  r_socket_close (listen);
  r_socket_unref (listen);
  r_socket_address_unref (addr);
}
RTEST_END;

RTEST (rhttpclientsync, connect_refused, RTEST_FAST | RTEST_SYSTEM)
{
  RHttpClientSync * sync;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;

  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1,
          47663)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);

  res = r_http_client_sync_request (sync, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_CONNECT_FAILED);
  r_assert_cmpptr (res, ==, NULL);

  r_socket_address_unref (addr);
  r_http_client_sync_unref (sync);
}
RTEST_END;
