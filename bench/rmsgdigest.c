#include <rlib/rlib.h>
#include "util.h"

/* 16 KiB per hash call - large enough to amortise the per-call
 * setup cost, small enough to fit comfortably in L1 cache. */
#define DIGEST_BENCH_BLOCKSIZE  (16 * 1024)
#define DIGEST_BENCH_ITERS      2000

/* Hash @c DIGEST_BENCH_BLOCKSIZE bytes per iteration. The digest is
 * reset between iterations so each loop body exercises one full
 * compression-function pass over the buffer. The buffer + digest
 * object are allocated once outside the timed region. */
static void
run_digest_bench (RMsgDigestType type, const rchar * label)
{
  RMsgDigest * md;
  ruint8 * input;
  ruint8 out[64];        /* SHA-512 = 64 bytes; covers anything smaller */
  rsize out_size;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((md = r_msg_digest_new (type)), !=, NULL);
  r_assert_cmpptr ((input = r_malloc (DIGEST_BENCH_BLOCKSIZE)), !=, NULL);
  for (i = 0; i < DIGEST_BENCH_BLOCKSIZE; i++)
    input[i] = (ruint8)i;

  /* Warm up */
  for (i = 0; i < 5; i++) {
    r_msg_digest_reset (md);
    r_assert (r_msg_digest_update (md, input, DIGEST_BENCH_BLOCKSIZE));
    r_assert (r_msg_digest_finish (md));
    r_assert (r_msg_digest_get_data (md, out, sizeof (out), &out_size));
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < DIGEST_BENCH_ITERS; i++) {
    r_msg_digest_reset (md);
    r_assert (r_msg_digest_update (md, input, DIGEST_BENCH_BLOCKSIZE));
    r_assert (r_msg_digest_finish (md));
    r_assert (r_msg_digest_get_data (md, out, sizeof (out), &out_size));
  }
  end = r_time_get_ts_monotonic ();

  bench_print_throughput (label, DIGEST_BENCH_ITERS, DIGEST_BENCH_BLOCKSIZE,
      end - start);

  r_free (input);
  r_msg_digest_free (md);
}

RTEST_BENCH (rmsgdigest, sha256, RTEST_FAST | RTEST_SYSTEM)
{
  /* SHA-256 bulk throughput. 32-bit-word compression function;
   * the workhorse digest for nearly every protocol in rlib (TLS,
   * SSH, sign / verify, HKDF). Establishes a baseline before any
   * future hash-perf or hardware-accel work. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_digest_bench (R_MSG_DIGEST_TYPE_SHA256, "SHA-256");
}
RTEST_END;

RTEST_BENCH (rmsgdigest, sha512, RTEST_FAST | RTEST_SYSTEM)
{
  /* SHA-512 bulk throughput. 64-bit-word compression function;
   * faster than SHA-256 on 64-bit hosts despite the larger digest
   * because it processes 128-byte blocks at a time (vs SHA-256's
   * 64). The MiB/s delta against SHA-256 surfaces whether the
   * 64-bit advantage actually lands. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_digest_bench (R_MSG_DIGEST_TYPE_SHA512, "SHA-512");
}
RTEST_END;

/* The remaining four are legacy digests carried for compatibility
 * (MD5 / SHA-1) or as the short-output cousins of the workhorses
 * (SHA-224 truncates SHA-256, SHA-384 truncates SHA-512). They
 * share the same compression-function families as the workhorses
 * so the numbers should be near-identical to their full-output
 * siblings - the benches are here mostly so regressions on the
 * legacy primitives don't go unnoticed. */

RTEST_BENCH (rmsgdigest, md5, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_digest_bench (R_MSG_DIGEST_TYPE_MD5, "MD5");
}
RTEST_END;

RTEST_BENCH (rmsgdigest, sha1, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_digest_bench (R_MSG_DIGEST_TYPE_SHA1, "SHA-1");
}
RTEST_END;

RTEST_BENCH (rmsgdigest, sha224, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_digest_bench (R_MSG_DIGEST_TYPE_SHA224, "SHA-224");
}
RTEST_END;

RTEST_BENCH (rmsgdigest, sha384, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_digest_bench (R_MSG_DIGEST_TYPE_SHA384, "SHA-384");
}
RTEST_END;

/* SHAKE256 doesn't fit the fixed-output bench helper above (it uses
 * r_msg_digest_squeeze, not _get_data, and the per-call output length
 * is the caller's choice). Throughput is reported over the absorb +
 * squeeze of a 16 KiB input and a 32-byte output to match the rest
 * of the digest family on the absorb side. */
static void
run_shake256_bench (void)
{
  RMsgDigest * md;
  ruint8 * input;
  ruint8 out[32];
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((input = r_malloc (DIGEST_BENCH_BLOCKSIZE)), !=, NULL);
  for (i = 0; i < DIGEST_BENCH_BLOCKSIZE; i++)
    input[i] = (ruint8)i;

  for (i = 0; i < 5; i++) {
    r_assert_cmpptr ((md = r_msg_digest_new_shake256 ()), !=, NULL);
    r_assert (r_msg_digest_update (md, input, DIGEST_BENCH_BLOCKSIZE));
    r_assert (r_msg_digest_squeeze (md, out, sizeof (out)));
    r_msg_digest_free (md);
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < DIGEST_BENCH_ITERS; i++) {
    r_assert_cmpptr ((md = r_msg_digest_new_shake256 ()), !=, NULL);
    r_assert (r_msg_digest_update (md, input, DIGEST_BENCH_BLOCKSIZE));
    r_assert (r_msg_digest_squeeze (md, out, sizeof (out)));
    r_msg_digest_free (md);
  }
  end = r_time_get_ts_monotonic ();

  bench_print_throughput ("SHAKE256 (32B squeeze)", DIGEST_BENCH_ITERS,
      DIGEST_BENCH_BLOCKSIZE, end - start);

  r_free (input);
}

RTEST_BENCH (rmsgdigest, shake256, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_shake256_bench ();
}
RTEST_END;
