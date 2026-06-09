#include <rlib/rev.h>
#include <rlib/ros.h>

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
  RClockTime start;
  RClockTime ts;
  REvUDPStats rx, tx;
  REvUDPStats rx_, tx_;
} REvUDPBenchCtx;

typedef struct {
  REvUDPBenchCtx * ctx;
  rsize count;

  rboolean running;
  RThread * tsnd;
} REvUDPBenchThreadCtx;

static rpointer
udp_send (rpointer data)
{
  REvUDPBenchThreadCtx * tctx = data;
  RSocket ** sock;
  ruint8 sendbuf[1024];
  rsize i, sent;

  r_assert_cmpptr ((sock = r_alloca (sizeof (RSocket *) * tctx->count)), !=, NULL);

  for (i = 0; i < tctx->count; i++) {
    r_assert_cmpptr ((sock[i] = r_socket_new (R_SOCKET_FAMILY_IPV4, R_SOCKET_TYPE_DATAGRAM, R_SOCKET_PROTOCOL_UDP)), !=, NULL);
    r_assert (r_socket_set_blocking (sock[i], TRUE));
  }

  while (tctx->running) {
    for (i = 0; i < tctx->count; i++) {
      REvUDPBenchCtx * ctx = &tctx->ctx[i];
      if (r_socket_send_to (sock[i], ctx->addr, sendbuf, sizeof (sendbuf), &sent) == R_SOCKET_OK) {
        ctx->tx.bytes += sent;
        ctx->tx.packets++;
      } else {
        ctx->tx.failed++;
      }
    }
  }

  for (i = 0; i < tctx->count; i++) {
    r_socket_close (sock[i]);
    r_socket_unref (sock[i]);
  }

  return NULL;
}

static void
udp_recv (rpointer user, RBuffer * buf, RSocketAddress * addr, REvUDP * evudp)
{
  REvUDPBenchCtx * ctx = user;
  rsize size;
  (void) evudp;
  (void) addr;

  size = r_buffer_get_size (buf);
  ctx->rx.packets++;
  ctx->rx.bytes += size;
}

static void
print_udp_bench_ctx_stats (REvUDPBenchCtx * ctx, RClockTime now)
{
  RClockTimeDiff cd = R_CLOCK_DIFF (ctx->ts, now);

  r_print ("%"R_TIME_FORMAT
      "  TX: %12"RSIZE_FMT" (%5"RSIZE_FMT") %16"RSIZE_FMT" pps: %8"RUINT64_FMT" bps: %12"RUINT64_FMT"\n"
      "                 "
      "  RX: %12"RSIZE_FMT" (%5"RSIZE_FMT") %16"RSIZE_FMT" pps: %8"RUINT64_FMT" bps: %12"RUINT64_FMT"\n",
      R_TIME_ARGS (now - ctx->start),
      ctx->tx.packets, ctx->tx.failed, ctx->tx.bytes,
      ((ruint64)(ctx->tx.packets - ctx->tx_.packets) * R_SECOND) / cd,
      (((ruint64)(ctx->tx.bytes - ctx->tx_.bytes) * R_SECOND) / cd) * 8,

      ctx->rx.packets, ctx->rx.failed, ctx->rx.bytes,
      ((ruint64)(ctx->rx.packets - ctx->rx_.packets) * R_SECOND) / cd,
      (((ruint64)(ctx->rx.bytes - ctx->rx_.bytes) * R_SECOND) / cd) * 8);
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
  REvUDPBenchThreadCtx tctx;
  REvUDPBenchCtx ctx;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  tctx.ctx = &ctx;
  tctx.count = 1;

  r_memclear (&ctx, sizeof (REvUDPBenchCtx));
  ctx.start = ctx.ts = r_time_get_ts_monotonic ();
  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);

  r_assert_cmpptr ((ctx.evudp = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
  r_assert_cmpptr ((ctx.addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242)), !=, NULL);
  r_assert (r_ev_udp_bind (ctx.evudp, ctx.addr, TRUE));

  tctx.running = TRUE;
  r_assert (r_ev_udp_recv_start (ctx.evudp, NULL, udp_recv, &ctx, NULL));
  r_assert_cmpptr ((tctx.tsnd = r_thread_new ("send udp packets", udp_send, &tctx)), !=, NULL);

  timer_cb_single (&ctx, loop);
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);

  tctx.running = FALSE;
  r_thread_join (tctx.tsnd);
  r_thread_unref (tctx.tsnd);

  r_socket_address_unref (ctx.addr);
  r_ev_udp_unref (ctx.evudp);
  r_ev_loop_unref (loop);
}
RTEST_END;

