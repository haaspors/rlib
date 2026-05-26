#include <rlib/rlib.h>
#include <rlib/rcrc.h>
#include "util.h"

/* 16 KiB per call - matches the digest / cipher benches for
 * directly-comparable MiB/s numbers. */
#define CRC_BENCH_BLOCKSIZE  (16 * 1024)
#define CRC_BENCH_ITERS      2000

/* CRC update function family - all three variants share the same
 * "running crc, buffer, size -> updated crc" shape, so the bench
 * body is parameterised on the function pointer. */
typedef ruint32 (*RCrcUpdateFn) (ruint32 crc, rconstpointer buffer, rsize size);

static void
run_crc_bench (RCrcUpdateFn fn, const rchar * label)
{
  ruint8 * input;
  ruint32 crc = R_CRC32_INIT;
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((input = r_malloc (CRC_BENCH_BLOCKSIZE)), !=, NULL);
  for (i = 0; i < CRC_BENCH_BLOCKSIZE; i++)
    input[i] = (ruint8)i;

  for (i = 0; i < 5; i++)
    crc = fn (R_CRC32_INIT, input, CRC_BENCH_BLOCKSIZE);

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < CRC_BENCH_ITERS; i++)
    crc = fn (R_CRC32_INIT, input, CRC_BENCH_BLOCKSIZE);
  end = r_time_get_ts_monotonic ();

  bench_print_throughput (label, CRC_BENCH_ITERS, CRC_BENCH_BLOCKSIZE,
      end - start);

  /* Silence -Wunused-but-set-variable; the indirect call through fn
   * is opaque to the compiler so the loop body can't be elided. */
  (void)crc;
  r_free (input);
}

RTEST_BENCH (rcrc, crc32, RTEST_FAST | RTEST_SYSTEM)
{
  /* IEEE 802.3 / zlib / PNG CRC32 (reflected, polynomial
   * 0x04C11DB7). Table-driven implementation; the throughput
   * floor here is essentially the L1 read bandwidth into the
   * lookup table. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_crc_bench (r_crc32_update, "CRC32");
}
RTEST_END;

RTEST_BENCH (rcrc, crc32c, RTEST_FAST | RTEST_SYSTEM)
{
  /* Castagnoli CRC32 (reflected, polynomial 0x1EDC6F41). Used by
   * SCTP, iSCSI, Btrfs, etc. Same table-driven implementation as
   * the IEEE variant, so the throughput numbers should be near
   * identical. x86-64 SSE4.2 ships a single-cycle CRC32C
   * instruction that's ~10x faster than the software table, but
   * rlib does not currently wire it in - this number reflects the
   * software path. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_crc_bench (r_crc32c_update, "CRC32C");
}
RTEST_END;

RTEST_BENCH (rcrc, crc32bzip2, RTEST_FAST | RTEST_SYSTEM)
{
  /* CRC32 bzip2 - same polynomial as IEEE CRC32 but non-reflected.
   * Used by the bzip2 compressor. Same table-driven cost shape
   * as the IEEE variant. */
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_crc_bench (r_crc32bzip2_update, "CRC32-bzip2");
}
RTEST_END;
