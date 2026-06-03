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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x6363)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);

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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x6364)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), >, 0);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  /* Client receives + reports errors; it sends data the server side
   * never reads. */
  r_ev_tcp_set_error_handler (client, error_received, &err, NULL);
  r_assert (r_ev_tcp_recv_start (client, NULL, data_received, &buf, NULL));
  r_assert (r_ev_tcp_send_dup (client, "foobar", 6, NULL, NULL, NULL));

  /* Let the datagram reach the server's socket, then close it abruptly:
   * closing with unread data makes the kernel send an RST, which the
   * client observes as a connection-reset error rather than EOF. */
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  r_assert (r_ev_tcp_close (servcli, NULL, NULL, NULL));
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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x6365)), !=, NULL);
  r_assert_cmpint (r_ev_tcp_bind (server, addr, TRUE), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_listen (server, 10, new_connection_ready, &servcli, NULL), ==, R_SOCKET_OK);
  r_assert_cmpint (r_ev_tcp_connect (client, addr, client_connected, &conn, NULL), ==, R_SOCKET_WOULD_BLOCK);
  r_socket_address_unref (addr);

  while (servcli == NULL)
    r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), >, 0);
  r_assert (conn);
  r_assert (r_ev_tcp_close (server, NULL, NULL, NULL));
  r_ev_tcp_unref (server);

  r_assert (r_ev_tcp_recv_start (client, NULL, eos_received, &eos, NULL));
  r_assert (r_ev_tcp_send_dup (client, "foobar", 6, NULL, NULL, NULL));
  for (i = 0; i < 8; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);
  r_assert (r_ev_tcp_close (servcli, NULL, NULL, NULL));
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

