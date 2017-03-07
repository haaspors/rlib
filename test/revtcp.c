#include <rlib/rlib.h>

#if defined (R_OS_WIN32)
SKIP_RTEST (revtcp, dummy, RTEST_FAST)
{
}
RTEST_END;
#else

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

  if (*b != NULL)
    r_buffer_unref (*b);
  *b = r_buffer_ref (buf);
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
#endif

