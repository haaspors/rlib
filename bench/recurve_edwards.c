#include <rlib/rlib.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/recurve-edwards.h>
#include "util.h"

#define EDWARDS_BENCH_ITERS_25519  500
#define EDWARDS_BENCH_ITERS_448    100

static void
run_edwards_scalar_mul_bench (REcurveID curve_id, const rchar * curve_name,
    ruint scalar_bits, ruint iters)
{
  REcurveEdwards curve;
  REcurveEdwardsPoint out;
  RPrng * prng;
  ruint8 scalar[56];
  RClockTime start, end;
  ruint i;

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (r_ecurve_edwards_init (&curve, curve_id));
  r_assert (r_prng_fill (prng, scalar, curve.coord_bytes));

  for (i = 0; i < 5; i++)
    r_ecurve_edwards_point_scalar_mul (&out, scalar, curve.coord_bytes,
        scalar_bits, &curve.B, &curve);

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++)
    r_ecurve_edwards_point_scalar_mul (&out, scalar, curve.coord_bytes,
        scalar_bits, &curve.B, &curve);
  end = r_time_get_ts_monotonic ();

  {
    rchar * label = r_strprintf ("Edwards %s scalar_mul", curve_name);
    bench_print_ops (label, iters, end - start);
    r_free (label);
  }

  r_ecurve_edwards_clear (&curve);
  r_prng_unref (prng);
}

RTEST_BENCH (recurve_edwards, scalar_mul_edwards25519,
    RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_edwards_scalar_mul_bench (R_ECURVE_ID_X25519, "edwards25519", 255,
      EDWARDS_BENCH_ITERS_25519);
}
RTEST_END;

RTEST_BENCH (recurve_edwards, scalar_mul_edwards448,
    RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_edwards_scalar_mul_bench (R_ECURVE_ID_X448, "edwards448", 448,
      EDWARDS_BENCH_ITERS_448);
}
RTEST_END;
