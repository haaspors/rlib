#include <rlib/rlib.h>
#include <rlib/crypto/rhmac.h>
#include "util.h"

/* 16 KiB per HMAC call - matches the digest / cipher benches so the
 * MiB/s numbers are directly comparable. */
#define HMAC_BENCH_BLOCKSIZE  (16 * 1024)
#define HMAC_BENCH_ITERS      2000

/* Fixed 32-byte key. HMAC's key schedule depends on key length but
 * not on the key bits, so any 32-byte buffer gives a representative
 * SHA-256-block-sized key. */
static const ruint8 hmac_bench_key[32] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/* HMAC over @c HMAC_BENCH_BLOCKSIZE bytes per iteration, parameterised
 * on the inner digest type so the per-variant wrappers are one line. */
static void
run_hmac_bench (RMsgDigestType type, const rchar * label)
{
  RHmac * hmac;
  ruint8 * input;
  ruint8 out[64];        /* SHA-512 = 64 bytes; covers anything smaller */
  rsize out_size;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((hmac = r_hmac_new (type, hmac_bench_key,
        sizeof (hmac_bench_key))), !=, NULL);
  r_assert_cmpptr ((input = r_malloc (HMAC_BENCH_BLOCKSIZE)), !=, NULL);
  for (i = 0; i < HMAC_BENCH_BLOCKSIZE; i++)
    input[i] = (ruint8)i;

  for (i = 0; i < 5; i++) {
    r_hmac_reset (hmac);
    r_assert (r_hmac_update (hmac, input, HMAC_BENCH_BLOCKSIZE));
    r_assert (r_hmac_get_data (hmac, out, sizeof (out), &out_size));
  }

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < HMAC_BENCH_ITERS; i++) {
    r_hmac_reset (hmac);
    r_assert (r_hmac_update (hmac, input, HMAC_BENCH_BLOCKSIZE));
    r_assert (r_hmac_get_data (hmac, out, sizeof (out), &out_size));
  }
  end = r_time_get_ts_monotonic ();

  bench_print_throughput (label, HMAC_BENCH_ITERS, HMAC_BENCH_BLOCKSIZE,
      end - start);

  r_free (input);
  r_hmac_free (hmac);
}

RTEST_BENCH (rhmac, sha256, RTEST_FAST | RTEST_SYSTEM)
{
  /* HMAC-SHA256 bulk throughput. Thin wrapper over two SHA-256
   * passes (inner over @c K^ipad ++ msg, outer over @c K^opad ++
   * inner-digest), so this number tracks closely with the raw
   * SHA-256 throughput minus the constant per-call HMAC overhead.
   * Comparing against @c rmsgdigest/sha256 surfaces the cost of
   * the HMAC scaffolding itself. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_hmac_bench (R_MSG_DIGEST_TYPE_SHA256, "HMAC-SHA256");
}
RTEST_END;

RTEST_BENCH (rhmac, sha1, RTEST_FAST | RTEST_SYSTEM)
{
  /* HMAC-SHA1 bulk throughput. Legacy MAC kept for compat with the
   * protocols that still need it (TLS-PRF, S3 signature v2,
   * OAuth 1.0a, etc.); not for new use. Tracks raw SHA-1
   * throughput the same way HMAC-SHA256 tracks raw SHA-256. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_hmac_bench (R_MSG_DIGEST_TYPE_SHA1, "HMAC-SHA1");
}
RTEST_END;
