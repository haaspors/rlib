#include <rlib/rev.h>

typedef struct {
  RList * buffers;
  RList * addrs;
  rauint recvd;       /* bumped last in buffer_recv; lets a waiter on another
                         thread observe delivery and synchronize-with the
                         writes above (task_recv delivers off the loop thread). */
} REvUDPTestRecvCtx;

static void
buffer_recv (rpointer user, RBuffer * buf, RSocketAddress * addr, REvUDP * evudp)
{
  REvUDPTestRecvCtx * ctx = user;
  (void) evudp;
  (void) addr;

  ctx->buffers = r_list_append (ctx->buffers, r_buffer_ref (buf));
  ctx->addrs = r_list_append (ctx->addrs, r_socket_address_ref (addr));
  r_atomic_uint_fetch_add (&ctx->recvd, 1);
}

static void
buffer_send_done (rpointer user, RBuffer * buf, RSocketAddress * addr, REvUDP * evudp)
{
  (void) evudp;
  (void) addr;

  *((RBuffer **)user) = r_buffer_ref (buf);
}
RTEST (revudp, bind_recv, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvUDP * evudp;
  REvUDPTestRecvCtx ctx;
  RSocket * sendsock;
  ruint8 sendbuf[512];
  rsize sent;

  r_memclear (&ctx, sizeof (REvUDPTestRecvCtx));
  r_memset (sendbuf, 0x42, 512);
  sent = 0;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((evudp = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_ev_udp_bind (evudp, addr, TRUE));
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_udp_get_local_address (evudp)), !=, NULL);

  r_assert (r_ev_udp_recv_start (evudp, NULL, buffer_recv, &ctx, NULL));

  r_assert_cmpptr ((sendsock = r_socket_new (R_SOCKET_FAMILY_IPV4, R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);
  r_assert_cmpint (r_socket_send_to (sendsock, addr, sendbuf, sizeof (sendbuf), &sent), ==, R_SOCKET_OK);
  r_assert_cmpuint (sent, ==, 512);
  r_socket_close (sendsock);
  r_socket_unref (sendsock);
  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), ==, 1);

  r_assert (r_ev_udp_recv_stop (evudp));

  r_assert_cmpuint (r_list_len (ctx.buffers), ==, 1);
  r_assert_cmpuint (r_list_len (ctx.addrs), ==, 1);
  r_assert_cmpbufmem (ctx.buffers->data, 0, -1, ==, sendbuf, 512);

  r_list_destroy_full (ctx.buffers, r_buffer_unref);
  r_list_destroy_full (ctx.addrs, r_socket_address_unref);

  r_socket_address_unref (addr);
  r_ev_udp_unref (evudp);
  /* Drain the cancelled in-flight recv: a completion backend reaps its aborted
   * completion here, releasing the socket so it cannot linger bound to the port
   * into the next test. No-op on a readiness backend (nothing outstanding). */
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (revudp, send_recv, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvUDP * udp1, * udp2;
  REvUDPTestRecvCtx ctx;
  ruint8 sendbuf[512];
  RBuffer * sentbuf;

  r_memclear (&ctx, sizeof (REvUDPTestRecvCtx));
  r_memset (sendbuf, 0x42, 512);
  sentbuf = NULL;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((udp1 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_ev_udp_bind (udp1, addr, TRUE));
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_udp_get_local_address (udp1)), !=, NULL);

  r_assert (r_ev_udp_recv_start (udp1, NULL, buffer_recv, &ctx, NULL));

  r_assert_cmpptr ((udp2 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_send_take (udp2, r_memdup (sendbuf, 512), 512, addr, buffer_send_done, &sentbuf, NULL));

  /* Drive the loop until the datagram round-trips. A completion (proactor)
   * backend delivers the send and recv completions independently with no
   * ordering guarantee, so this may span more than one iteration. NOWAIT (don't
   * block): a blocking run-once after the datagram is delivered would wait
   * forever for a second one. */
  while (sentbuf == NULL || ctx.buffers == NULL)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_assert (r_ev_udp_recv_stop (udp1));

  r_assert_cmpptr (sentbuf, !=, NULL);
  r_assert_cmpbufmem (sentbuf, 0, -1, ==, sendbuf, 512);

  r_assert_cmpuint (r_list_len (ctx.buffers), ==, 1);
  r_assert_cmpuint (r_list_len (ctx.addrs), ==, 1);
  r_assert_cmpbufmem (ctx.buffers->data, 0, -1, ==, sendbuf, 512);

  r_list_destroy_full (ctx.buffers, r_buffer_unref);
  r_list_destroy_full (ctx.addrs, r_socket_address_unref);

  r_buffer_unref (sentbuf);
  r_socket_address_unref (addr);
  r_ev_udp_unref (udp1);
  r_ev_udp_unref (udp2);
  /* Drain the cancelled in-flight recv (see bind_recv). */
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_ev_loop_unref (loop);
}
RTEST_END;

/* Several datagrams in flight at once, exercising the re-armed receive (a
 * completion backend posts the next WSARecvFrom from each completion). */
RTEST (revudp, send_recv_multi, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvUDP * udp1, * udp2;
  REvUDPTestRecvCtx ctx;
  ruint8 sendbuf[512];
  ruint i;
  const ruint ndatagrams = 4;

  r_memclear (&ctx, sizeof (REvUDPTestRecvCtx));
  r_memset (sendbuf, 0x37, 512);

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((udp1 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_ev_udp_bind (udp1, addr, TRUE));
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_udp_get_local_address (udp1)), !=, NULL);
  r_assert (r_ev_udp_recv_start (udp1, NULL, buffer_recv, &ctx, NULL));

  r_assert_cmpptr ((udp2 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  for (i = 0; i < ndatagrams; i++)
    r_assert (r_ev_udp_send_take (udp2, r_memdup (sendbuf, 512), 512, addr, NULL, NULL, NULL));

  while (r_atomic_uint_load (&ctx.recvd) < ndatagrams)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_assert (r_ev_udp_recv_stop (udp1));
  r_assert_cmpuint (r_list_len (ctx.buffers), ==, ndatagrams);
  r_assert_cmpuint (r_list_len (ctx.addrs), ==, ndatagrams);
  r_assert_cmpbufmem (ctx.buffers->data, 0, -1, ==, sendbuf, 512);

  r_list_destroy_full (ctx.buffers, r_buffer_unref);
  r_list_destroy_full (ctx.addrs, r_socket_address_unref);
  r_socket_address_unref (addr);
  r_ev_udp_unref (udp1);
  r_ev_udp_unref (udp2);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (revudp, task_recv, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RTaskQueue * tq;
  RSocketAddress * addr;
  REvUDP * udp1, * udp2;
  REvUDPTestRecvCtx ctx;
  ruint8 sendbuf[512];
  RBuffer * sentbuf;

  r_memclear (&ctx, sizeof (REvUDPTestRecvCtx));
  r_memset (sendbuf, 0x42, 512);
  sentbuf = NULL;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((tq = r_task_queue_new_pin_on_each_cpu (NULL, 1)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, tq)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((udp1 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0)), !=, NULL);
  r_assert (r_ev_udp_bind (udp1, addr, TRUE));
  r_socket_address_unref (addr);
  r_assert_cmpptr ((addr = r_ev_udp_get_local_address (udp1)), !=, NULL);

  r_assert (r_ev_udp_task_recv_start (udp1, 0, NULL, buffer_recv, &ctx, NULL));

  r_assert_cmpptr ((udp2 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_send_take (udp2, r_memdup (sendbuf, 512), 512, addr, buffer_send_done, &sentbuf, NULL));

  /* Drive the loop until the datagram round-trips (see the note in send_recv).
   * The recv is delivered on a task-group thread, so wait on the atomic counter
   * rather than reading the lists directly -- it both signals delivery and
   * synchronizes-with the worker's writes to ctx. */
  while (sentbuf == NULL || r_atomic_uint_load (&ctx.recvd) == 0)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_assert (r_ev_udp_recv_stop (udp1));

  r_assert_cmpptr (sentbuf, !=, NULL);
  r_assert_cmpbufmem (sentbuf, 0, -1, ==, sendbuf, 512);

  r_assert_cmpuint (r_list_len (ctx.buffers), ==, 1);
  r_assert_cmpuint (r_list_len (ctx.addrs), ==, 1);
  r_assert_cmpbufmem (ctx.buffers->data, 0, -1, ==, sendbuf, 512);

  r_list_destroy_full (ctx.buffers, r_buffer_unref);
  r_list_destroy_full (ctx.addrs, r_socket_address_unref);

  r_buffer_unref (sentbuf);
  r_socket_address_unref (addr);
  r_ev_udp_unref (udp1);
  r_ev_udp_unref (udp2);
  /* Drain the cancelled in-flight recv (see bind_recv). */
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);
  r_task_queue_unref (tq);
  r_ev_loop_unref (loop);
}
RTEST_END;


static void
udp_error_received (rpointer data, REvUDP * evudp, RSocketStatus error)
{
  (void) evudp;
  *((RSocketStatus *)data) = error;
}

RTEST (revudp, send_error_handler, RTEST_FAST | RTEST_SYSTEM)
{
  REvLoop * loop;
  RClock * clock;
  RSocketAddress * addr;
  REvUDP * evudp;
  RSocketStatus err = R_SOCKET_OK;
  ruint i;

  r_assert_cmpptr ((clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, NULL)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((evudp = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4243)), !=, NULL);
  r_ev_udp_set_error_handler (evudp, udp_error_received, &err, NULL);

  /* A datagram larger than the IPv4 UDP maximum (65507) cannot be sent;
   * the failed datagram is dropped and reported, the socket stays usable. */
  r_assert (r_ev_udp_send_take (evudp, r_malloc0 (70000), 70000, addr, NULL, NULL, NULL));

  for (i = 0; i < 8 && err == R_SOCKET_OK; i++)
    r_ev_loop_run (loop, R_EV_LOOP_RUN_NOWAIT);

  r_assert_cmpint (err, ==, R_SOCKET_MSG_SIZE);

  r_socket_address_unref (addr);
  r_ev_udp_unref (evudp);
  r_ev_loop_unref (loop);
}
RTEST_END;
