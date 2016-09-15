#include <rlib/rlib.h>

#if defined (R_OS_WIN32)
SKIP_RTEST (revudp, dummy, RTEST_FAST)
{
}
RTEST_END;
#else
typedef struct {
  RList * buffers;
  RList * addrs;
} REvUDPTestRecvCtx;

static void
buffer_recv (rpointer user, RBuffer * buf, const RSocketAddress * addr, REvUDP * evudp)
{
  REvUDPTestRecvCtx * ctx = user;
  (void) evudp;
  (void) addr;

  ctx->buffers = r_list_append (ctx->buffers, r_buffer_ref (buf));
  ctx->addrs = r_list_append (ctx->addrs, r_socket_address_copy (addr));
}

static void
buffer_send_done (rpointer user, RBuffer * buf, const RSocketAddress * addr, REvUDP * evudp)
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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert (r_ev_udp_bind (evudp, addr, TRUE));

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
  r_assert_cmpint (r_buffer_memcmp (r_list_data (ctx.buffers), 0, sendbuf, 512), ==, 0);

  r_list_destroy_full (ctx.buffers, r_buffer_unref);
  r_list_destroy_full (ctx.addrs, r_socket_address_unref);

  r_socket_address_unref (addr);
  r_ev_udp_unref (evudp);
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
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert (r_ev_udp_bind (udp1, addr, TRUE));

  r_assert (r_ev_udp_recv_start (udp1, NULL, buffer_recv, &ctx, NULL));

  r_assert_cmpptr ((udp2 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_send_take (udp2, r_memdup (sendbuf, 512), 512, addr, buffer_send_done, &sentbuf, NULL));

  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), ==, 1);

  r_assert (r_ev_udp_recv_stop (udp1));

  r_assert_cmpptr (sentbuf, !=, NULL);
  r_assert_cmpint (r_buffer_memcmp (sentbuf, 0, sendbuf, 512), ==, 0);

  r_assert_cmpuint (r_list_len (ctx.buffers), ==, 1);
  r_assert_cmpuint (r_list_len (ctx.addrs), ==, 1);
  r_assert_cmpint (r_buffer_memcmp (r_list_data (ctx.buffers), 0, sendbuf, 512), ==, 0);

  r_list_destroy_full (ctx.buffers, r_buffer_unref);
  r_list_destroy_full (ctx.addrs, r_socket_address_unref);

  r_buffer_unref (sentbuf);
  r_socket_address_unref (addr);
  r_ev_udp_unref (udp1);
  r_ev_udp_unref (udp2);
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
  r_assert_cmpptr ((tq = r_task_queue_new_per_cpu_simple (1)), !=, NULL);
  r_assert_cmpptr ((loop = r_ev_loop_new_full (clock, tq)), !=, NULL);
  r_clock_unref (clock);

  r_assert_cmpptr ((udp1 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert (r_ev_udp_bind (udp1, addr, TRUE));

  r_assert (r_ev_udp_task_recv_start (udp1, 0, NULL, buffer_recv, &ctx, NULL));

  r_assert_cmpptr ((udp2 = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert (r_ev_udp_send_take (udp2, r_memdup (sendbuf, 512), 512, addr, buffer_send_done, &sentbuf, NULL));

  r_assert_cmpuint (r_ev_loop_run (loop, R_EV_LOOP_RUN_ONCE), ==, 1);

  r_assert (r_ev_udp_recv_stop (udp1));

  r_assert_cmpptr (sentbuf, !=, NULL);
  r_assert_cmpint (r_buffer_memcmp (sentbuf, 0, sendbuf, 512), ==, 0);

  r_assert_cmpuint (r_list_len (ctx.buffers), ==, 1);
  r_assert_cmpuint (r_list_len (ctx.addrs), ==, 1);
  r_assert_cmpint (r_buffer_memcmp (r_list_data (ctx.buffers), 0, sendbuf, 512), ==, 0);

  r_list_destroy_full (ctx.buffers, r_buffer_unref);
  r_list_destroy_full (ctx.addrs, r_socket_address_unref);

  r_buffer_unref (sentbuf);
  r_socket_address_unref (addr);
  r_ev_udp_unref (udp1);
  r_ev_udp_unref (udp2);
  r_task_queue_unref (tq);
  r_ev_loop_unref (loop);
}
RTEST_END;
#endif

