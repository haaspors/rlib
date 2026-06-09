#include <rlib/rev.h>

static void
new_connection_ready (rpointer data, REvTCP * newtcp, REvTCP * listening)
{
  (void) listening;
  *((REvTCP **)data) = r_ev_tcp_ref (newtcp);
}

static void
client_connected (rpointer data, REvTCP * evtcp, int status)
{
  (void) status;
  (void) evtcp;

  *((rboolean *)data) = TRUE;
}

static void
data_received (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RBuffer ** b = data;

  (void) evtcp;

  if (buf == NULL)
    return;
  if (*b != NULL)
    r_buffer_unref (*b);
  *b = r_buffer_ref (buf);
}

static void
data_counted (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  (void) evtcp;
  if (buf != NULL)
    *((rsize *)data) += r_buffer_get_size (buf);
}

typedef struct {
  rsize bytes;
  rboolean eos;
} RTestRecvCount;

/* Count received bytes and note end-of-stream (recv NULL -- a clean FIN, or the
 * fallback delivered when a peer reset arrives with no error handler set). */
static void
data_count_eos (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RTestRecvCount * c = data;
  (void) evtcp;
  if (buf == NULL) {
    c->eos = TRUE;
    return;
  }
  c->bytes += r_buffer_get_size (buf);
}

/* Accept then immediately close, to churn pollset add/remove. The accept path
 * drops its own ref after this returns; close holds its own until teardown. */
static void
accept_and_close (rpointer data, REvTCP * newtcp, REvTCP * listening)
{
  (void) data;
  (void) listening;
  r_ev_tcp_close (newtcp, NULL, NULL, NULL);
}

/* Helpers for the recv-error tests below, gated to the same backends -- see
 * the comment there for why only a Windows rpoll build is excluded. */
#if !(defined (R_OS_WIN32) && defined (R_EV_USE_RPOLL))
static void
error_received (rpointer data, REvTCP * evtcp, RSocketStatus error)
{
  (void) evtcp;
  *((RSocketStatus *)data) = error;
}

static void
eos_received (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  (void) evtcp;
  if (buf == NULL)
    *((rboolean *)data) = TRUE;
}
#endif

static void
error_noop (rpointer data, REvTCP * evtcp, RSocketStatus error)
{
  (void) data;
  (void) evtcp;
  (void) error;
}

static void
mark_true (rpointer data)
{
  *((rboolean *)data) = TRUE;
}

/* A server holding several recv-armed accepted connections tears the whole set
 * down -- listener and every client -- from inside one connection's recv
 * callback (what an HTTP request handler that stops the server does
 * mid-dispatch). Aborting the other, idle connections from within this dispatch
 * must remove each from the loop's pollset; a slot left behind points at a freed
 * watcher and makes the next poll fail. Holds a ref on each so the abort path
 * (not a final unref) drives teardown. */
typedef struct {
  REvTCP *  server;        /* the listener */
  REvTCP *  accepted[8];   /* server-side accepted connections, recv-armed */
  rsize     naccepted;
  rboolean  fired;
} RTestStopBurst;

static void stop_burst_recv (rpointer data, RBuffer * buf, REvTCP * evtcp);

/* Accept every incoming connection, hold a ref, and recv-arm it so each sits
 * idle in the loop's pollset until the burst tears the whole set down. */
static void
stop_burst_accept (rpointer data, REvTCP * newtcp, REvTCP * listening)
{
  RTestStopBurst * b = data;
  (void) listening;
  b->accepted[b->naccepted] = r_ev_tcp_ref (newtcp);
  r_ev_tcp_recv_start (b->accepted[b->naccepted], NULL, stop_burst_recv, b, NULL);
  b->naccepted++;
}

static void
stop_burst_recv (rpointer data, RBuffer * buf, REvTCP * evtcp)
{
  RTestStopBurst * b = data;
  rsize i;

  (void) buf;
  (void) evtcp;
  if (b->fired)
    return;
  b->fired = TRUE;

  /* Tear everything down from inside this dispatch, like r_http_server_stop:
   * the listener first, then every accepted connection (including this one). */
  r_ev_tcp_abort (b->server, NULL, NULL, NULL);
  for (i = 0; i < b->naccepted; i++)
    r_ev_tcp_abort (b->accepted[i], NULL, NULL, NULL);
}

RTEST (revtcp, server_stop_burst_during_recv, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server;
  REvTCP * client[3] = { NULL, NULL, NULL };
  const rsize n = 3;
  RTestStopBurst burst = { NULL, { NULL }, 0, FALSE };
  rboolean conn[3] = { FALSE, FALSE, FALSE };
  rsize i;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  burst.server = server;
  r_assert_cmpint (r_ev_tcp_listen (server, 10, stop_burst_accept, &burst, NULL), ==, R_SOCKET_OK);

  /* Open n connections; the listener accepts and recv-arms each so all sit idle
   * in the pollset, then send on the last to trigger the burst from its
   * server-side recv callback. */
  for (i = 0; i < n; i++)
    r_assert_cmpptr ((client[i] = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  for (i = 0; i < n; i++)
    r_assert_cmpint (r_ev_tcp_connect (client[i], addr, client_connected, &conn[i], NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (burst.naccepted < n)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  /* Send on the last client: its server-side recv callback runs the burst. */
  r_assert (r_ev_tcp_send_dup (client[n - 1], "go", 2, NULL, NULL, NULL));

  /* The loop must drain to zero -- no orphaned dead fd left spinning select(). */
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);

  for (i = 0; i < burst.naccepted; i++)
    r_ev_tcp_unref (burst.accepted[i]);
  for (i = 0; i < n; i++) {
    r_ev_tcp_abort (client[i], NULL, NULL, NULL);
    r_ev_tcp_unref (client[i]);
  }
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_ev_tcp_unref (server);
  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (revtcp, listen_connect_accept_send_recv, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server, * servcli = NULL, * client;
  rboolean conn = FALSE;
  RBuffer * buf = NULL;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);

  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpptr (servcli, ==, NULL);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), >, 0);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  r_assert (r_ev_tcp_send_dup (client, "foobar", 6, NULL, NULL, NULL));
  r_assert (r_ev_tcp_recv_start (servcli, NULL, data_received, &buf, NULL));
  while (buf == NULL)
    r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), >, 0);
  r_assert (r_ev_tcp_recv_stop (servcli));

  r_assert_cmpbufsstr (buf, 0, -1, ==, "foobar");
  r_buffer_unref (buf);

  r_assert (r_ev_tcp_close (client, NULL, NULL, NULL));
  r_assert (r_ev_tcp_close (servcli, NULL, NULL, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);

  r_ev_tcp_unref (client);
  r_ev_tcp_unref (servcli);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* Queue several sends back-to-back and confirm every byte arrives, exercising
 * the ordered send queue (a completion backend posts one send at a time and
 * re-arms the next from each completion) and repeated receive completions. */
RTEST (revtcp, queued_send_recv, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server, * servcli = NULL, * client;
  rboolean conn = FALSE;
  rsize received = 0;
  ruint8 chunk[1024];
  ruint i;
  const ruint nsends = 8;

  r_memset (chunk, 0x5a, sizeof (chunk));

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), >, 0);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  r_assert (r_ev_tcp_recv_start (servcli, NULL, data_counted, &received, NULL));
  for (i = 0; i < nsends; i++)
    r_assert (r_ev_tcp_send_dup (client, chunk, sizeof (chunk), NULL, NULL, NULL));

  while (received < (rsize)nsends * sizeof (chunk))
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  r_assert_cmpuint (received, ==, (rsize)nsends * sizeof (chunk));
  r_assert (r_ev_tcp_recv_stop (servcli));

  r_assert (r_ev_tcp_close (client, NULL, NULL, NULL));
  r_assert (r_ev_tcp_close (servcli, NULL, NULL, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);

  r_ev_tcp_unref (client);
  r_ev_tcp_unref (servcli);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* These two exercise an abortive close (peer RST) and assert the client
 * observes it promptly. Every backend manages this except a forced Windows
 * rpoll build: there, an abortive RST on a loopback socket is intermittently
 * not surfaced by the Windows stack (recv keeps returning WOULDBLOCK) until a
 * multi-second TCP abort timeout. Linux poll surfaces it via the recv error,
 * and the Windows IOCP default pre-posts overlapped reads, so gate the pair off
 * Windows rpoll only. */
#if !(defined (R_OS_WIN32) && defined (R_EV_USE_RPOLL))
RTEST (revtcp, recv_error_handler, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server, * servcli = NULL, * client;
  rboolean conn = FALSE;
  RBuffer * buf = NULL;
  RSocketStatus err = R_SOCKET_OK;
  ruint i;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), >, 0);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  /* Client just receives + reports errors. It deliberately does not send:
   * a pending client send racing the peer's reset makes the client discover
   * the dead connection via its own retransmission timeout (~tens of seconds)
   * rather than via the incoming RST, which is what made this flaky. */
  r_ev_tcp_set_error_handler (client, error_received, &err, NULL);
  r_assert (r_ev_tcp_recv_start (client, NULL, data_received, &buf, NULL));

  /* Abort servcli so the idle client observes a connection-reset error rather
   * than EOF. SO_LINGER with a zero timeout makes the closing handle send a
   * TCP RST immediately and deterministically (abort adds no FIN that would
   * pre-empt it). */
  r_assert (r_socket_set_linger (r_ev_tcp_get_socket (servcli), TRUE, 0));
  r_assert (r_ev_tcp_abort (servcli, NULL, NULL, NULL));
  r_ev_tcp_unref (servcli);

  /* Process the deferred close (which sends the RST) and the reset the
   * client then observes; fall back to a blocking run if the reset has
   * not landed yet. */
  for (i = 0; i < 16 && err == R_SOCKET_OK; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  while (err == R_SOCKET_OK)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert_cmpint (err, !=, R_SOCKET_OK);
  r_assert_cmpptr (buf, ==, NULL);          /* no data, only the error */

  r_assert (r_ev_tcp_close (client, NULL, NULL, NULL));
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_ev_tcp_unref (client);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* Same reset as above, but with no error handler installed: the receive
 * error must fall back to the end-of-stream notification (recv NULL)
 * rather than abort or stall. */
RTEST (revtcp, recv_error_no_handler, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server, * servcli = NULL, * client;
  rboolean conn = FALSE, eos = FALSE;
  ruint i;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), >, 0);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  /* Idle client (no pending send, see recv_error_handler); force an immediate,
   * deterministic RST from the peer. */
  r_assert (r_ev_tcp_recv_start (client, NULL, eos_received, &eos, NULL));
  r_assert (r_socket_set_linger (r_ev_tcp_get_socket (servcli), TRUE, 0));
  r_assert (r_ev_tcp_abort (servcli, NULL, NULL, NULL));
  r_ev_tcp_unref (servcli);

  for (i = 0; i < 16 && !eos; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  while (!eos)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert (eos);

  r_assert (r_ev_tcp_close (client, NULL, NULL, NULL));
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_ev_tcp_unref (client);
  r_ev_loop_unref (loop);
}
RTEST_END;
#endif /* !(R_OS_WIN32 && R_EV_USE_RPOLL) */

/* The error handler's data is released (via datanotify) both when it is
 * replaced and when the socket is freed. */
RTEST (revtcp, error_handler_data_freed, RTEST_FAST)
{
  REvLoop * loop;
  RClock * clock;
  REvTCP * evtcp;
  rboolean freed = FALSE;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((evtcp = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);

  r_ev_tcp_set_error_handler (evtcp, error_noop, &freed, mark_true);
  r_ev_tcp_set_error_handler (evtcp, NULL, NULL, NULL);   /* replace -> frees old */
  r_assert (freed);

  freed = FALSE;
  r_ev_tcp_set_error_handler (evtcp, error_noop, &freed, mark_true);
  r_ev_tcp_unref (evtcp);                                  /* free -> frees data */
  r_assert (freed);

  r_ev_loop_unref (loop);
}
RTEST_END;

/* A graceful close with data still queued must flush every queued byte before
 * the half-close: the peer receives all of it, then EOF. r_ev_tcp_send only
 * queues and defers the write, so closing in the same tick leaves the queue
 * non-empty and exercises the deferred-finalize path (close-with-pending-send),
 * which no other test reaches. */
RTEST (revtcp, close_flushes_pending_send, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server, * servcli = NULL, * client;
  rboolean conn = FALSE;
  RTestRecvCount rc = { 0, FALSE };
  ruint8 chunk[4096];
  ruint i;
  const ruint nsends = 16;

  r_memset (chunk, 0x5a, sizeof (chunk));

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  r_assert (r_ev_tcp_recv_start (servcli, NULL, data_count_eos, &rc, NULL));

  /* Queue, then close in the same tick: the queue is non-empty, so close must
   * drain it before the half-close. */
  for (i = 0; i < nsends; i++)
    r_assert (r_ev_tcp_send_dup (client, chunk, sizeof (chunk), NULL, NULL, NULL));
  r_assert (r_ev_tcp_close (client, NULL, NULL, NULL));

  while (!rc.eos)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert_cmpuint (rc.bytes, ==, (rsize)nsends * sizeof (chunk));

  r_assert (r_ev_tcp_close (servcli, NULL, NULL, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_ev_tcp_unref (client);
  r_ev_tcp_unref (servcli);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* abort() discards everything still queued, so the peer must NOT receive the
 * full payload. Many sends are queued; a completion backend posts only the
 * head, a readiness backend posts none -- either way the bulk is dropped. */
RTEST (revtcp, abort_drops_pending_send, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server, * servcli = NULL, * client;
  rboolean conn = FALSE;
  RTestRecvCount rc = { 0, FALSE };
  ruint8 chunk[4096];
  ruint i;
  const ruint nsends = 32;

  r_memset (chunk, 0x5a, sizeof (chunk));

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  r_assert (r_ev_tcp_recv_start (servcli, NULL, data_count_eos, &rc, NULL));

  for (i = 0; i < nsends; i++)
    r_assert (r_ev_tcp_send_dup (client, chunk, sizeof (chunk), NULL, NULL, NULL));
  r_assert (r_ev_tcp_abort (client, NULL, NULL, NULL));
  /* Drop our ref now: a proactor backend defers the socket close until its
   * cancelled overlapped ops drain, so the peer only sees the end once the last
   * ref goes. A reactor backend already closed inside abort. */
  r_ev_tcp_unref (client);

  while (!rc.eos)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);

  r_assert_cmpuint (rc.bytes, <, (rsize)nsends * sizeof (chunk));

  r_assert (r_ev_tcp_close (servcli, NULL, NULL, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_ev_tcp_unref (servcli);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* Connect, exchange, and tear down repeatedly on one loop. Each round releases
 * the client and accepted fds, which the OS recycles into the next round --
 * exercising synchronous pollset removal and the recycled-handle guard. */
RTEST (revtcp, reconnect_same_loop, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server, * servcli = NULL;
  ruint round, j;
  const ruint rounds = 6;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);

  for (round = 0; round < rounds; round++) {
    REvTCP * client;
    rboolean conn = FALSE;
    RBuffer * buf = NULL;

    servcli = NULL;
    r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
    r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);

    while (servcli == NULL)
      r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
    r_assert (conn);

    r_assert (r_ev_tcp_recv_start (servcli, NULL, data_received, &buf, NULL));
    r_assert (r_ev_tcp_send_dup (client, "x", 1, NULL, NULL, NULL));
    while (buf == NULL)
      r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE);
    r_assert_cmpbufsstr (buf, 0, -1, ==, "x");
    r_buffer_unref (buf);
    r_assert (r_ev_tcp_recv_stop (servcli));

    r_assert (r_ev_tcp_close (client, NULL, NULL, NULL));
    r_assert (r_ev_tcp_close (servcli, NULL, NULL, NULL));
    r_ev_tcp_unref (client);
    r_ev_tcp_unref (servcli);
    /* Process the deferred teardowns so both fds are released (and recyclable)
     * before the next round. The listener stays active, so a full RUN_LOOP
     * would never return -- a few non-blocking ticks suffice. */
    for (j = 0; j < 4; j++)
      r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  }

  r_socket_address_unref (addr);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_ev_tcp_unref (server);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* Hammer connect+teardown on one loop: half the clients are torn down while the
 * connect is still in flight (half-open teardown), alternating close and abort,
 * while the server accepts and immediately closes each. The loop must drain to
 * zero with no hang and no leak. */
RTEST (revtcp, open_close_churn, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvTCP * server;
  ruint i;
  const ruint n = 64;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((server = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_tcp_get_local_address (server)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_listen (server, R_SOCKET_DEFAULT_BACKLOG, accept_and_close, NULL, NULL), ==, R_SOCKET_OK);

  for (i = 0; i < n; i++) {
    REvTCP * client;
    rboolean conn = FALSE;

    r_assert_cmpptr ((client = r_ev_tcp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
    r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);

    /* Even rounds tear down mid-connect; odd rounds let the handshake settle. */
    if (i & 1)
      r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
    if (i & 2)
      r_assert (r_ev_tcp_abort (client, NULL, NULL, NULL));
    else
      r_assert (r_ev_tcp_close (client, NULL, NULL, NULL));
    r_ev_tcp_unref (client);
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  }

  r_socket_address_unref (addr);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP), ==, 0);
  r_ev_tcp_unref (server);
  r_ev_loop_unref (loop);
}
RTEST_END;

