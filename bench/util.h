#ifndef __RLIB_BENCH_UTIL_H__
#define __RLIB_BENCH_UTIL_H__

#include <rlib/rlib.h>

/* Shared microbench output formatters. All RTEST_BENCH bodies in
 * the crypto benches end with one of these two calls; centralising
 * the math + format here keeps every result line identical and
 * comparable across primitives.
 *
 * Callers build a descriptive label (e.g. "RSA-2048 decrypt",
 * "ECDH secp256r1 compute_shared", "AES-128 CBC") and pass it as
 * the first argument. */

/* "<label>: X.XXX ms/op, Y.Y ops/sec (iters in s)" — use for
 * asymmetric ops where per-call cost is the metric. */
static inline void
bench_print_ops (const rchar * label, ruint iters, RClockTime elapsed)
{
  rdouble elapsed_s = (rdouble)elapsed / (rdouble)R_SECOND;
  rdouble per_op_ms = elapsed_s * 1000.0 / (rdouble)iters;
  rdouble ops_per_sec = (rdouble)iters / elapsed_s;

  r_print ("%"R_TIME_FORMAT"  %s: %.3f ms/op, %.1f ops/sec "
      "(%u iters in %.3f s)\n",
      R_TIME_ARGS (elapsed), label, per_op_ms, ops_per_sec,
      iters, elapsed_s);
}

/* "<label>: X.X MiB/s (iters x block-byte blocks in s)" — use
 * for symmetric / hash primitives where throughput is the metric. */
static inline void
bench_print_throughput (const rchar * label, ruint iters,
    rsize block_bytes, RClockTime elapsed)
{
  rdouble elapsed_s = (rdouble)elapsed / (rdouble)R_SECOND;
  rdouble total_mib = (rdouble)(iters * block_bytes) / (1024.0 * 1024.0);
  rdouble mib_per_s = total_mib / elapsed_s;

  r_print ("%"R_TIME_FORMAT"  %s: %.1f MiB/s "
      "(%u x %"RSIZE_FMT"-byte blocks in %.3f s)\n",
      R_TIME_ARGS (elapsed), label, mib_per_s,
      iters, block_bytes, elapsed_s);
}

#endif /* __RLIB_BENCH_UTIL_H__ */
