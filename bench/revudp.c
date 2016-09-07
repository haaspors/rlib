#include <rlib/rlib.h>

#define INTERVAL  (10 * R_SECOND)
#define TOTAL_LENGTH  (30 * R_SECOND)

typedef struct {
  rsize packets;
  rsize failed;
  rsize bytes;
} REvUDPStats;

typedef struct {
  REvUDP * evudp;
  RSocketAddress * addr;
  rboolean running;
  RThread * tsnd;
  RClockTime start;
  RClockTime ts;
  REvUDPStats rx, tx;
  REvUDPStats rx_, tx_;
} REvUDPBenchCtx;

static rpointer
udp_send (rpointer data)
{
  REvUDPBenchCtx * ctx = data;
  RSocket * sock;
  ruint8 sendbuf[1024];
  rsize sent;

  r_assert_cmpptr ((sock = r_socket_new (R_SOCKET_FAMILY_IPV4, R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);
  r_assert (r_socket_set_blocking (sock, TRUE));
  while (ctx->running) {
    if (r_socket_send_to (sock, ctx->addr, sendbuf, sizeof (sendbuf), &sent) == R_SOCKET_OK) {
      ctx->tx.bytes += sent;
      ctx->tx.packets++;
    } else {
      ctx->tx.failed++;
    }
  }

  r_socket_close (sock);
  r_socket_unref (sock);

  return NULL;
}

static void
udp_recv (rpointer user, RBuffer * buf, const RSocketAddress * addr, REvUDP * evudp)
{
  REvUDPBenchCtx * ctx = user;
  (void) evudp;
  (void) addr;

  ctx->rx.packets++;
  ctx->rx.bytes += r_buffer_get_size (buf);
}

static void
print_udp_bench_ctx_stats (REvUDPBenchCtx * ctx, RClockTime now)
{
  RClockTimeDiff cd = R_CLOCK_DIFF (ctx->ts, now);

  r_print ("%"R_TIME_FORMAT
      "  TX: %12"RSIZE_FMT" (%5"RSIZE_FMT") %16"RSIZE_FMT" pps: %8"RSIZE_FMT" bps: %12"RSIZE_FMT"\n"
      "                 "
      "  RX: %12"RSIZE_FMT" (%5"RSIZE_FMT") %16"RSIZE_FMT" pps: %8"RSIZE_FMT" bps: %12"RSIZE_FMT"\n",
      R_TIME_ARGS (now - ctx->start),
      ctx->tx.packets, ctx->tx.failed, ctx->tx.bytes,
      ((ctx->tx.packets - ctx->tx_.packets) * R_SECOND) / cd,
      (((ctx->tx.bytes - ctx->tx_.bytes) * R_SECOND) / cd) * 8,

      ctx->rx.packets, ctx->rx.failed, ctx->rx.bytes,
      ((ctx->rx.packets - ctx->rx_.packets) * R_SECOND) / cd,
      (((ctx->rx.bytes - ctx->rx_.bytes) * R_SECOND) / cd) * 8);
}

static void
timer_cb_single (rpointer data, REvLoop * loop)
{
  REvUDPBenchCtx * ctx = data;
  RClockTime now = r_time_get_ts_monotonic ();

  print_udp_bench_ctx_stats (ctx, now);
  if (R_CLOCK_DIFF (ctx->start, now) < TOTAL_LENGTH) {
    ctx->ts = now;
    r_memcpy (&ctx->rx_, &ctx->rx, sizeof (REvUDPStats));
    r_memcpy (&ctx->tx_, &ctx->tx, sizeof (REvUDPStats));
    r_assert (r_ev_loop_add_callback_later (loop, NULL, INTERVAL, timer_cb_single, ctx, NULL));
  } else {
    r_assert (r_ev_udp_recv_stop (ctx->evudp));
  }
}

RTEST_BENCH (revudp, single_loopback_receive, RTEST_FASTSLOW | RTEST_SYSTEM)
{
  REvLoop * loop;
  REvUDPBenchCtx ctx;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_memclear (&ctx, sizeof (REvUDPBenchCtx));
  ctx.start = ctx.ts = r_time_get_ts_monotonic ();
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);

  r_assert_cmpptr ((ctx.evudp = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((ctx.addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert (r_ev_udp_bind (ctx.evudp, ctx.addr, TRUE));

  ctx.running = TRUE;
  r_assert (r_ev_udp_recv_start (ctx.evudp, NULL, udp_recv, &ctx, NULL));
  r_assert_cmpptr ((ctx.tsnd = r_thread_new ("send udp packets", udp_send, &ctx)), !=, NULL);

  timer_cb_single (&ctx, loop);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);

  ctx.running = FALSE;
  r_thread_join (ctx.tsnd);
  r_thread_unref (ctx.tsnd);

  r_socket_address_unref (ctx.addr);
  r_ev_udp_unref (ctx.evudp);
  r_ev_loop_unref (loop);
}
RTEST_END;

static void
stop_16 (rpointer data, REvLoop * loop)
{
  REvUDPBenchCtx * ctx = data;
  ruint i;
  (void) loop;

  for (i = 0; i < 16; i++)
    r_assert (r_ev_udp_recv_stop (ctx[i].evudp));
}

RTEST_BENCH (revudp, 16_loopback_receive, RTEST_FASTSLOW | RTEST_SYSTEM)
{
  REvLoop * loop;
  REvUDPBenchCtx ctx[16];
  ruint i;
  RClockTime ts;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_memclear (ctx, R_N_ELEMENTS (ctx) * sizeof (REvUDPBenchCtx));

  ts = r_time_get_ts_monotonic ();
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);

  for (i = 0; i < R_N_ELEMENTS (ctx); i++) {
    ctx[i].start = ctx[i].ts = ts;
    r_assert_cmpptr ((ctx[i].evudp = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
    r_assert_cmpptr ((ctx[i].addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242 + i)), !=, NULL);
    r_assert (r_ev_udp_bind (ctx[i].evudp, ctx[i].addr, TRUE));

    ctx[i].running = TRUE;
    r_assert (r_ev_udp_recv_start (ctx[i].evudp, NULL, udp_recv, &ctx[i], NULL));
    r_assert_cmpptr ((ctx[i].tsnd = r_thread_new ("send udp packets", udp_send, &ctx[i])), !=, NULL);
  }

  r_assert (r_ev_loop_add_callback_later (loop, NULL, TOTAL_LENGTH, stop_16, ctx, NULL));
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);

  ts = r_time_get_ts_monotonic ();
  for (i = 0; i < R_N_ELEMENTS (ctx); i++) {
    print_udp_bench_ctx_stats (&ctx[i], ts);
    ctx[i].running = FALSE;
    r_thread_join (ctx[i].tsnd);
    r_thread_unref (ctx[i].tsnd);
    r_socket_address_unref (ctx[i].addr);
    r_ev_udp_unref (ctx[i].evudp);
  }
  r_ev_loop_unref (loop);
}
RTEST_END;

