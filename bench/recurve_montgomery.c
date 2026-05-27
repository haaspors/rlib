#include <rlib/rlib.h>
#include <rlib/crypto/recurve.h>
#include <rlib/crypto/recurve-montgomery.h>
#include "util.h"

#define MONT_BENCH_ITERS_25519  500
#define MONT_BENCH_ITERS_448    200

static void
run_montgomery_ladder_bench (REcurveID curve_id, const rchar * curve_name,
    ruint iters)
{
  REcurveMontgomery curve;
  RPrng * prng;
  ruint8 scalar[56], in_u[56], out_u[56];
  RClockTime start, end;
  ruint i;
  rsize cb;

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (r_ecurve_montgomery_init (&curve, curve_id));
  cb = curve.coord_bytes;

  /* Random scalar; base point as input u-coordinate. */
  r_assert (r_prng_fill (prng, scalar, cb));
  r_memset (in_u, 0, sizeof (in_u));
  in_u[0] = (curve_id == R_ECURVE_ID_X25519) ? 9u : 5u;

  /* Warm-up. */
  for (i = 0; i < 5; i++)
    r_assert (r_ecurve_montgomery_ladder (out_u, scalar, in_u, &curve));

  start = r_time_get_ts_monotonic ();
  for (i = 0; i < iters; i++)
    r_assert (r_ecurve_montgomery_ladder (out_u, scalar, in_u, &curve));
  end = r_time_get_ts_monotonic ();

  {
    rchar * label = r_strprintf ("Montgomery %s ladder", curve_name);
    bench_print_ops (label, iters, end - start);
    r_free (label);
  }

  r_ecurve_montgomery_clear (&curve);
  r_prng_unref (prng);
}

RTEST_BENCH (recurve_montgomery, ladder_x25519, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_montgomery_ladder_bench (R_ECURVE_ID_X25519, "Curve25519",
      MONT_BENCH_ITERS_25519);
}
RTEST_END;

RTEST_BENCH (recurve_montgomery, ladder_x448, RTEST_FAST | RTEST_SYSTEM)
{
  r_print ("%"R_TIME_FORMAT" --- %s ---\n", R_TIME_ARGS (0), R_STRFUNC);
  run_montgomery_ladder_bench (R_ECURVE_ID_X448, "Curve448",
      MONT_BENCH_ITERS_448);
}
RTEST_END;
