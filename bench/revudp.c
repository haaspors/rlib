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
aggregate_ctx_stats (REvUDPStats * dst, const REvUDPStats * add)
{
  dst->packets += add->packets;
  dst->failed += add->failed;
  dst->bytes += add->bytes;
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


#define UDP_MULTI_SOCKETS     16
static void
stop_multi (rpointer data, REvLoop * loop)
{
  REvUDPBenchCtx * ctx = data;
  ruint i;
  (void) loop;

  for (i = 0; i < UDP_MULTI_SOCKETS; i++)
    r_assert (r_ev_udp_recv_stop (ctx[i].evudp));
}

RTEST_BENCH (revudp, multi_loopback_receive, RTEST_FASTSLOW | RTEST_SYSTEM)
{
  REvLoop * loop;
  REvUDPBenchCtx ctx[UDP_MULTI_SOCKETS];
  REvUDPBenchThreadCtx * tctx;
  REvUDPStats tx_aggr, rx_aggr;
  RTaskQueue * tq;
  rsize cpus, tctxcount, d;
  ruint i;
  RClockTime ts;
  RBitset * cpuset;

  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);

  r_memclear (ctx, R_N_ELEMENTS (ctx) * sizeof (REvUDPBenchCtx));
  r_assert (r_bitset_init_stack (cpuset, r_sys_cpuset_max_count ()));
  r_assert (r_sys_cpuset_allowed (cpuset));
  r_assert_cmpptr ((cpus = r_bitset_popcount (cpuset)), >, 0);
  tctxcount = CLAMP ((cpus / 2), 1, R_N_ELEMENTS (ctx));
  r_assert_cmpptr ((tctx = r_alloca (sizeof (REvUDPBenchThreadCtx) * tctxcount)), !=, NULL);

  r_assert_cmpptr ((tq = r_task_queue_new_thread_per_group (tctxcount)), !=, NULL);
  r_print ("\tTaskQueue with %u threads and %u groups\n",
      r_task_queue_thread_count (tq), r_task_queue_group_count (tq));

  ts = r_time_get_ts_monotonic ();
  r_assert_cmpptr ((loop = r_ev_loop_new_full (NULL, tq)), !=, NULL);

  d = R_N_ELEMENTS (ctx) / tctxcount;
  if ((R_N_ELEMENTS (ctx) % tctxcount) > 0) d++;
  for (i = 0; i < tctxcount; i++) {
    tctx[i].count = d;
    tctx[i].ctx = &ctx[i * d];
  }
  if (i * d > R_N_ELEMENTS (ctx))
    tctx[i - 1].count = i * d - R_N_ELEMENTS (ctx);
  for (i = 0; i < tctxcount; i++)
    r_print ("\tSend thread %u: %u sockets\n", (ruint)i, (ruint)tctx[i].count);

  for (i = 0; i < R_N_ELEMENTS (ctx); i++) {
    ctx[i].start = ctx[i].ts = ts;
    r_assert_cmpptr ((ctx[i].evudp = r_ev_udp_new (R_SOCKET_FAMILY_IPV4, loop)), !=, NULL);
    r_assert_cmpptr ((ctx[i].addr = r_socket_address_ipv4_new_uint8 (127, 0, 0, 1, 0x4242 + i)), !=, NULL);
    r_assert (r_ev_udp_bind (ctx[i].evudp, ctx[i].addr, TRUE));

    r_assert (r_ev_udp_task_recv_start (ctx[i].evudp,
          i % r_ev_loop_task_group_count (loop),
          NULL, udp_recv, &ctx[i], NULL));
  }
  for (i = 0; i < tctxcount; i++) {
    tctx[i].running = TRUE;
    r_assert_cmpptr ((tctx[i].tsnd = r_thread_new ("multi-udp-send",
            udp_send, &tctx[i])), !=, NULL);
  }

  r_assert (r_ev_loop_add_callback_later (loop, NULL, TOTAL_LENGTH, stop_multi, ctx, NULL));
  r_ev_loop_run (loop, R_EV_LOOP_RUN_LOOP);

  for (i = 0; i < tctxcount; i++) {
    tctx[i].running = FALSE;
    r_thread_join (tctx[i].tsnd);
    r_thread_unref (tctx[i].tsnd);
  }

  r_memclear (&tx_aggr, sizeof (REvUDPStats));
  r_memclear (&rx_aggr, sizeof (REvUDPStats));
  ts = r_time_get_ts_monotonic ();
  for (i = 0; i < R_N_ELEMENTS (ctx); i++) {
    print_udp_bench_ctx_stats (&ctx[i], ts);
    aggregate_ctx_stats (&tx_aggr, &ctx[i].tx);
    aggregate_ctx_stats (&rx_aggr, &ctx[i].rx);
    r_socket_address_unref (ctx[i].addr);
    r_ev_udp_unref (ctx[i].evudp);
  }

  ts = r_time_get_ts_monotonic ();
  r_print ("%"R_TIME_FORMAT" --------------------------------------------------------------\n"
      "                 "
      "  TX: %12"RSIZE_FMT" (%5"RSIZE_FMT") %16"RSIZE_FMT"\n"
      "                 "
      "  RX: %12"RSIZE_FMT" (%5"RSIZE_FMT") %16"RSIZE_FMT"\n",
      R_TIME_ARGS (ts - ctx->start),
      tx_aggr.packets, tx_aggr.failed, tx_aggr.bytes,
      rx_aggr.packets, rx_aggr.failed, rx_aggr.bytes);
  r_task_queue_unref (tq);
  r_ev_loop_unref (loop);
}
RTEST_END;

