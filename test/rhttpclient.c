#include <rlib/rnet.h>
#include <rlib/rev.h>

/* Servers here bind an ephemeral port (0) and read back the OS-assigned port
 * (see r_test_http_listen_ephemeral): a fixed port collides with a previous
 * run's socket still in TIME_WAIT -- notably under meson test --repeat, and on
 * Windows where rtest runs single-process. */
#define R_TEST_HTTP_CLIENT_BODY   "hello from rlib"

typedef struct {
  RHttpResponse * res;
  RHttpClientResult result;
  rboolean done;
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
}

/* Issue an async request and drive @loop until it completes. The in-process
 * tests put server and client on one shared loop, so a blocking
 * RHttpClientSync (which owns a private loop) can't drive the server here. */
static RHttpResponse *
r_test_http_send (REvLoop * loop, RHttpClient * client, RHttpRequest * req,
    const RSocketAddress * addr, RHttpClientResult * result)
{
  RTestHttpSyncState st = { NULL, R_HTTP_CLIENT_CONNECT_FAILED, FALSE };

  if (!r_http_client_request_to_addr (client, req, addr, r_test_http_send_cb, &st, NULL)) {
    if (result != NULL)
      *result = R_HTTP_CLIENT_CONNECT_FAILED;
    return NULL;
  }
  /* RUN_ONCE (not RUN_LOOP+stop): stopping is sticky, so the loop stays
   * reusable for a follow-up request on the same loop. */
  while (!st.done)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  if (result != NULL)
    *result = st.result;
  return st.res;
}

/* As r_test_http_send, but targets the host/port derived from req's URI. */
static RHttpResponse *
r_test_http_send_uri (REvLoop * loop, RHttpClient * client, RHttpRequest * req,
    RHttpClientResult * result)
{
  RTestHttpSyncState st = { NULL, R_HTTP_CLIENT_RESOLVE_FAILED, FALSE };

  if (!r_http_client_request (client, req, r_test_http_send_cb, &st, NULL)) {
    if (result != NULL)
      *result = R_HTTP_CLIENT_RESOLVE_FAILED;
    return NULL;
  }
  /* RUN_ONCE (not RUN_LOOP+stop): stopping is sticky, so the loop stays
   * reusable for a follow-up request on the same loop. */
  while (!st.done)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
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

/* Listen on an ephemeral port (the OS picks it) and return the bound address
 * the caller must unref. A fixed port collides with the previous run's socket
 * still in TIME_WAIT -- notably under meson test --repeat and single-process
 * rtest -- so every server here binds 0 and reads back the real port. */
static RSocketAddress *
r_test_http_listen_ephemeral (RHttpServer * srv)
{
  RSocketAddress * addr, * bound = NULL;

  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)),
      !=, NULL);
  if (r_http_server_add_listen_addr (srv, addr))
    bound = r_http_server_get_local_address (srv);
  r_socket_address_unref (addr);

  return bound;
}

/* Build a listening server with a handler at @p path returning @p status
 * (with a body); the address to connect to is returned in *out. */
static RHttpServer *
r_test_http_client_server (REvLoop * loop, const rchar * path,
    RHttpStatus status, RSocketAddress ** out)
{
  RHttpServer * srv;

  if ((srv = r_http_server_new (loop)) == NULL)
    return NULL;

  r_assert (r_http_server_set_handler (srv, path, -1,
        r_test_http_client_handler, RUINT_TO_POINTER (status), NULL));

  *out = r_test_http_listen_ephemeral (srv);
  r_assert_cmpptr (*out, !=, NULL);
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

  r_assert_cmpptr ((srv = r_test_http_client_server (loop, "/",
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

/* The target is derived from the request URI (host:port) and resolved on the
 * loop; 127.0.0.1 resolves numerically without touching DNS. */
RTEST (rhttpclient, request_get_uri, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;
  rchar * body, * uri;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_test_http_client_server (loop, "/",
          R_HTTP_STATUS_OK, &addr)), !=, NULL);
  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);

  uri = r_strprintf ("http://127.0.0.1:%u/",
      r_socket_address_ipv4_get_port (addr));
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET, uri, NULL,
          NULL)), !=, NULL);
  r_free (uri);

  res = r_test_http_send_uri (loop, client, req, &result);
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

/* A scheme that is neither http nor https with no explicit port has no usable
 * target: the request is rejected before it starts (FALSE), so notify is never
 * called. */
RTEST (rhttpclient, request_uri_unsupported, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpClient * client;
  RHttpRequest * req;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "ftp://127.0.0.1/", NULL, NULL)), !=, NULL);

  r_assert (!r_http_client_request (client, req, r_test_http_send_cb, NULL, NULL));

  r_http_request_unref (req);
  r_http_client_unref (client);
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
  r_assert_cmpptr ((srv = r_test_http_client_server (loop, "/specific",
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
  r_assert_cmpptr ((addr = r_test_http_listen_ephemeral (srv)), !=, NULL);

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

  r_assert_cmpptr ((srv = r_test_http_client_server (loop, "/",
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
  r_assert_cmpptr ((addr = r_test_http_listen_ephemeral (srv)), !=, NULL);

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

/* Stopping a server whose connection is idle but still open (the keepalive case)
 * must force-close it and report it -- distinct from stopping mid-request. */
RTEST (rhttpclient, server_stop_idle, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RSocketAddress * addr;
  RHttpClientResult result;
  rsize closed;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_test_http_client_server (loop, "/",
          R_HTTP_STATUS_OK, &addr)), !=, NULL);
  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);
  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);   /* completed cleanly */
  r_assert_cmpptr (res, !=, NULL);
  r_http_response_unref (res);

  /* The connection is now idle but still open; stop must close it. */
  closed = r_http_server_stop (srv, NULL, NULL, NULL);
  r_assert_cmpuint (closed, ==, 1);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);

  r_socket_address_unref (addr);
  r_http_client_unref (client);
  r_http_server_unref (srv);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* Stop must force-close every open connection at once, not just one. */
RTEST (rhttpclient, server_stop_multi_connection, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RHttpServer * srv;
  RSocketAddress * addr;
  RHttpClient * clients[3];
  RHttpClientResult result;
  rsize closed;
  ruint i;
  const ruint n = 3;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((srv = r_test_http_client_server (loop, "/",
          R_HTTP_STATUS_OK, &addr)), !=, NULL);

  /* Each client opens its own connection and leaves it open (keepalive). */
  for (i = 0; i < n; i++) {
    RHttpRequest * req;
    RHttpResponse * res;
    r_assert_cmpptr ((clients[i] = r_http_client_new (loop)), !=, NULL);
    r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
            "http://127.0.0.1/", NULL, NULL)), !=, NULL);
    res = r_test_http_send (loop, clients[i], req, addr, &result);
    r_http_request_unref (req);
    r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
    r_http_response_unref (res);
  }

  closed = r_http_server_stop (srv, NULL, NULL, NULL);
  r_assert_cmpuint (closed, ==, n);     /* all closed in one stop */
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);

  for (i = 0; i < n; i++)
    r_http_client_unref (clients[i]);
  r_socket_address_unref (addr);
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
r_test_raw_server_new (REvLoop * loop, const rchar * blob,
    rsize blen, RSocketAddress ** out)
{
  RTestRawServer * s = r_mem_new0 (RTestRawServer);
  RSocketAddress * bind;

  /* Ephemeral port (read back from the listener) -- see the comment on
   * r_test_http_listen_ephemeral. */
  r_assert_cmpptr ((bind = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)),
      !=, NULL);
  s->blob = blob;
  s->blen = blen;
  r_assert_cmpptr ((s->listen = r_ev_tcp_new_bind (bind, loop)), !=, NULL);
  r_socket_address_unref (bind);
  r_assert_cmpint (r_ev_tcp_listen (s->listen, R_SOCKET_DEFAULT_BACKLOG,
        r_test_raw_conn_ready, s, NULL), >=, R_SOCKET_OK);
  *out = r_ev_tcp_get_local_address (s->listen);
  r_assert_cmpptr (*out, !=, NULL);
  return s;
}

static void
r_test_raw_server_free (RTestRawServer * s)
{
  if (s->conn != NULL) {
    r_ev_tcp_abort (s->conn, NULL, NULL, NULL);
    r_ev_tcp_unref (s->conn);
  }
  r_ev_tcp_abort (s->listen, NULL, NULL, NULL);
  r_ev_tcp_unref (s->listen);
  r_free (s);
}

static RHttpClientResult
r_test_http_client_raw_body (const rchar * blob, const rchar * expect_body)
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

  raw = r_test_raw_server_new (loop, blob, r_strlen (blob), &addr);
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
r_test_http_client_raw (const rchar * blob)
{
  return r_test_http_client_raw_body (blob, NULL);
}

/* A chunked response is decoded back into the reassembled body. */
RTEST (rhttpclient, response_chunked, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpint (r_test_http_client_raw_body (
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", "Wikipedia"),
      ==, R_HTTP_CLIENT_OK);
}
RTEST_END;

/* A response that is not valid HTTP is a parse failure. */
RTEST (rhttpclient, response_malformed, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpint (r_test_http_client_raw (
        "totally not a http response\r\n\r\n"), ==, R_HTTP_CLIENT_PARSE_FAILED);
}
RTEST_END;

/* A server that drops the connection mid-response -- promising more body than
 * it sends -- is a transport failure; the client must not report success on a
 * short read. */
RTEST (rhttpclient, response_truncated_body, RTEST_FAST | RTEST_SYSTEM)
{
  r_assert_cmpint (r_test_http_client_raw (
        "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort"),
      ==, R_HTTP_CLIENT_RECV_FAILED);
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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)),
      !=, NULL);
  r_assert_cmpint (r_socket_bind (listen, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_listen (listen), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_socket_get_local_address (listen)), !=, NULL);
  /* Block in accept until the client connects (the thread starts first). */
  r_assert (r_socket_set_blocking (listen, TRUE));
  r_assert_cmpptr ((thread = r_thread_new (NULL,
          r_test_http_blocking_responder, listen)), !=, NULL);

  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  r_assert (r_http_request_add_header (req, "Host", -1, "127.0.0.1", -1));

  res = r_http_client_sync_request_to_addr (sync, req, addr, &result);
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

/* The blocking client derives and resolves the target from the request URI. */
RTEST (rhttpclientsync, request_uri, RTEST_FAST | RTEST_SYSTEM)
{
  RSocket * listen;
  RSocketAddress * addr;
  RThread * thread;
  RHttpClientSync * sync;
  RHttpRequest * req;
  RHttpResponse * res;
  RHttpClientResult result;
  rchar * body, * uri;

  r_assert_cmpptr ((listen = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)),
      !=, NULL);
  r_assert_cmpint (r_socket_bind (listen, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_listen (listen), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_socket_get_local_address (listen)), !=, NULL);
  r_assert (r_socket_set_blocking (listen, TRUE));
  r_assert_cmpptr ((thread = r_thread_new (NULL,
          r_test_http_blocking_responder, listen)), !=, NULL);

  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);
  uri = r_strprintf ("http://127.0.0.1:%u/",
      r_socket_address_ipv4_get_port (addr));
  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET, uri, NULL,
          NULL)), !=, NULL);
  r_free (uri);

  res = r_http_client_sync_request (sync, req, &result);
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

  res = r_http_client_sync_request_to_addr (sync, req, addr, &result);
  r_http_request_unref (req);

  r_assert_cmpint (result, ==, R_HTTP_CLIENT_CONNECT_FAILED);
  r_assert_cmpptr (res, ==, NULL);

  r_socket_address_unref (addr);
  r_http_client_sync_unref (sync);
}
RTEST_END;

/* A keep-alive-capable raw responder: accept connections and serve a fixed
 * response per request on each, until @max_requests have been served. Counts
 * accepted connections and served requests so a test can prove reuse (one
 * connection, many requests) or a reconnect (a new connection). With
 * @close_each it closes the connection after every response, so a pooled
 * connection the client tries to reuse is already dead. */
typedef struct {
  RSocket * listen;
  int max_requests;
  rboolean close_each;
  int connections;
  int requests;
  rboolean chunked;       /* reply chunked instead of Content-Length */
} RTestKaServer;

static rpointer
r_test_ka_responder (rpointer data)
{
  RTestKaServer * s = data;
  static const rchar resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
  static const rchar chunkedresp[] =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
  const rchar * r = s->chunked ? chunkedresp : resp;
  rsize rlen = (s->chunked ? sizeof (chunkedresp) : sizeof (resp)) - 1;

  while (s->requests < s->max_requests) {
    RSocket * conn;
    if ((conn = r_socket_accept (s->listen, NULL)) == NULL)
      break;
    s->connections++;
    r_socket_set_blocking (conn, TRUE);
    for (;;) {
      ruint8 buf[2048];
      rsize n = 0;
      if (r_socket_receive (conn, buf, sizeof (buf), &n) != R_SOCKET_OK || n == 0)
        break;                              /* peer closed / error */
      r_socket_send (conn, (const ruint8 *) r, rlen, &n);
      s->requests++;
      if (s->close_each || s->requests >= s->max_requests)
        break;
    }
    r_socket_close (conn);
    r_socket_unref (conn);
  }

  return NULL;
}

static RThread *
r_test_ka_start (RTestKaServer * s, RSocketAddress ** out)
{
  RSocketAddress * addr;

  r_assert_cmpptr ((s->listen = r_socket_new (R_SOCKET_FAMILY_IPV4,
          R_SOCKET_TYPE_STREAM, R_SOCKET_PROTOCOL_TCP)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)),
      !=, NULL);
  r_assert_cmpint (r_socket_bind (s->listen, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_socket_listen (s->listen), ==, R_SOCKET_OK);
  r_assert (r_socket_set_blocking (s->listen, TRUE));
  r_socket_address_unref (addr);
  *out = r_socket_get_local_address (s->listen);
  r_assert_cmpptr (*out, !=, NULL);
  return r_thread_new (NULL, r_test_ka_responder, s);
}

static void
r_test_ka_request (RHttpClientSync * sync, const RSocketAddress * addr)
{
  RHttpRequest * req;
  RHttpResponse * res;
  RHttpClientResult result;
  rchar * body;

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  res = r_http_client_sync_request_to_addr (sync, req, addr, &result);
  r_http_request_unref (req);
  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_assert_cmpptr (res, !=, NULL);
  r_assert_cmpstr ((body = r_http_response_get_body (res, NULL)), ==, "hi");
  r_free (body);
  r_http_response_unref (res);
}

/* Two requests to one destination reuse a single pooled connection. */
RTEST (rhttpclientsync, keepalive_reuse, RTEST_FAST | RTEST_SYSTEM)
{
  RTestKaServer s = { NULL, 2, FALSE, 0, 0, FALSE };
  RThread * thread;
  RSocketAddress * addr;
  RHttpClientSync * sync;

  thread = r_test_ka_start (&s, &addr);
  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);

  r_test_ka_request (sync, addr);
  r_test_ka_request (sync, addr);

  r_thread_join (thread);
  r_thread_unref (thread);
  r_assert_cmpint (s.requests, ==, 2);
  r_assert_cmpint (s.connections, ==, 1);   /* both served on one connection */

  r_http_client_sync_unref (sync);
  r_socket_close (s.listen);
  r_socket_unref (s.listen);
  r_socket_address_unref (addr);
}
RTEST_END;

/* A chunked (Transfer-Encoding) response is self-delimited, so its connection
 * is pooled and reused like a Content-Length one. */
RTEST (rhttpclientsync, keepalive_reuse_chunked, RTEST_FAST | RTEST_SYSTEM)
{
  RTestKaServer s = { NULL, 2, FALSE, 0, 0, TRUE };   /* chunked replies */
  RThread * thread;
  RSocketAddress * addr;
  RHttpClientSync * sync;

  thread = r_test_ka_start (&s, &addr);
  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);

  r_test_ka_request (sync, addr);
  r_test_ka_request (sync, addr);

  r_thread_join (thread);
  r_thread_unref (thread);
  r_assert_cmpint (s.requests, ==, 2);
  r_assert_cmpint (s.connections, ==, 1);   /* chunked response reused */

  r_http_client_sync_unref (sync);
  r_socket_close (s.listen);
  r_socket_unref (s.listen);
  r_socket_address_unref (addr);
}
RTEST_END;

/* With keep-alive disabled each request opens (and closes) its own connection. */
RTEST (rhttpclientsync, keepalive_disabled, RTEST_FAST | RTEST_SYSTEM)
{
  RTestKaServer s = { NULL, 2, FALSE, 0, 0, FALSE };
  RThread * thread;
  RSocketAddress * addr;
  RHttpClientSync * sync;

  thread = r_test_ka_start (&s, &addr);
  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);
  r_assert (r_http_client_sync_get_keepalive (sync));   /* on by default */
  r_http_client_sync_set_keepalive (sync, FALSE);
  r_assert (!r_http_client_sync_get_keepalive (sync));

  r_test_ka_request (sync, addr);
  r_test_ka_request (sync, addr);

  r_thread_join (thread);
  r_thread_unref (thread);
  r_assert_cmpint (s.requests, ==, 2);
  r_assert_cmpint (s.connections, ==, 2);   /* not pooled: a connection each */

  r_http_client_sync_unref (sync);
  r_socket_close (s.listen);
  r_socket_unref (s.listen);
  r_socket_address_unref (addr);
}
RTEST_END;

/* When a pooled connection has been closed by the peer, the next request
 * transparently reconnects and still succeeds. */
RTEST (rhttpclientsync, keepalive_retry_stale, RTEST_FAST | RTEST_SYSTEM)
{
  RTestKaServer s = { NULL, 2, TRUE, 0, 0, FALSE };   /* close after each response */
  RThread * thread;
  RSocketAddress * addr;
  RHttpClientSync * sync;

  thread = r_test_ka_start (&s, &addr);
  r_assert_cmpptr ((sync = r_http_client_sync_new ()), !=, NULL);

  r_test_ka_request (sync, addr);   /* pools the connection */
  r_test_ka_request (sync, addr);   /* reuses it, finds it dead, retries */

  r_thread_join (thread);
  r_thread_unref (thread);
  r_assert_cmpint (s.requests, ==, 2);
  r_assert_cmpint (s.connections, ==, 2);   /* second request reconnected */

  r_http_client_sync_unref (sync);
  r_socket_close (s.listen);
  r_socket_unref (s.listen);
  r_socket_address_unref (addr);
}
RTEST_END;

/* An idle pooled connection is evicted once its timeout elapses, so a later
 * request opens a fresh connection. */
RTEST (rhttpclient, keepalive_idle_timeout, RTEST_FAST | RTEST_SYSTEM)
{
  RTestKaServer s = { NULL, 2, FALSE, 0, 0, FALSE };
  RThread * thread;
  RSocketAddress * addr;
  REvLoop * loop;
  RClock * clock;
  RHttpClient * client;
  RHttpRequest * req;
  RHttpResponse * res;
  RHttpClientResult result;
  int i;

  thread = r_test_ka_start (&s, &addr);
  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_assert_cmpptr ((client = r_http_client_new (loop)), !=, NULL);
  r_http_client_set_idle_timeout (client, 5 * R_SECOND);

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);
  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_http_response_unref (res);

  /* Advance past the idle timeout and pump the loop so the timer fires, the
   * connection is evicted and the deferred close runs. */
  r_test_clock_update_time (clock, 100 * R_SECOND);
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_assert_cmpptr ((req = r_http_request_new (R_HTTP_METHOD_GET,
          "http://127.0.0.1/", NULL, NULL)), !=, NULL);
  res = r_test_http_send (loop, client, req, addr, &result);
  r_http_request_unref (req);
  r_assert_cmpint (result, ==, R_HTTP_CLIENT_OK);
  r_http_response_unref (res);

  r_thread_join (thread);
  r_thread_unref (thread);
  r_assert_cmpint (s.connections, ==, 2);   /* eviction forced a reconnect */

  r_clock_unref (clock);
  r_http_client_unref (client);
  r_ev_loop_unref (loop);
  r_socket_address_unref (addr);
}
RTEST_END;
