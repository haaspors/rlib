#include <rlib/rlib.h>

RTEST (rcpufeatures, features_is_cached, RTEST_FAST)
{
  r_assert_cmpuint (r_cpu_features (), ==, r_cpu_features ());
  r_assert (!r_cpu_has (R_CPU_FEATURE_NONE));
}
RTEST_END;

RTEST (rcpufeatures, has_matches_features_bitmask, RTEST_FAST)
{
  RCpuFeature features = r_cpu_features ();
  rsize i, n;
  const RCpuFeature * all = r_cpu_features_all (&n);

  r_assert_cmpuint (n, >, 0);
  for (i = 0; i < n; i++) {
    rboolean masked = (features & all[i]) != 0;
    r_assert_cmpint (r_cpu_has (all[i]), ==, masked);
  }
}
RTEST_END;

RTEST (rcpufeatures, all_flags_are_single_bits, RTEST_FAST)
{
  rsize i, n;
  const RCpuFeature * all = r_cpu_features_all (&n);

  for (i = 0; i < n; i++) {
    RCpuFeature f = all[i];
    r_assert_cmpuint (f, !=, 0);
    /* x & (x - 1) == 0 iff x is a power of two. */
    r_assert_cmpuint (f & (f - 1), ==, 0);
  }
}
RTEST_END;

RTEST (rcpufeatures, all_flags_are_unique, RTEST_FAST)
{
  rsize i, n;
  const RCpuFeature * all = r_cpu_features_all (&n);
  RCpuFeature combined = 0;

  for (i = 0; i < n; i++) {
    r_assert_cmpuint (combined & all[i], ==, 0);
    combined |= all[i];
  }
}
RTEST_END;

RTEST (rcpufeatures, feature_name_round_trips, RTEST_FAST)
{
  rsize i, n;
  const RCpuFeature * all = r_cpu_features_all (&n);

  for (i = 0; i < n; i++) {
    const rchar * name = r_cpu_feature_name (all[i]);
    r_assert_cmpptr (name, !=, NULL);
    r_assert_cmpstr (name, !=, "Unknown");
    r_assert_cmpstr (name, !=, "");
  }
}
RTEST_END;

RTEST (rcpufeatures, feature_name_invalid_input, RTEST_FAST)
{
  r_assert_cmpstr (r_cpu_feature_name (R_CPU_FEATURE_NONE), ==, "None");
  r_assert_cmpstr (r_cpu_feature_name (R_CPU_FEATURE_SSE | R_CPU_FEATURE_SSE2),
      ==, "Unknown");
  r_assert_cmpstr (r_cpu_feature_name ((RCpuFeature)1 << 62), ==, "Unknown");
}
RTEST_END;

RTEST (rcpufeatures, arch_groups_disjoint, RTEST_FAST)
{
  /* No real CPU has x86 and AArch64 extensions reported at the same
   * time - the detection backends are mutually exclusive per arch. */
  RCpuFeature x86_mask = R_CPU_FEATURE_SSE        | R_CPU_FEATURE_SSE2     |
                         R_CPU_FEATURE_SSE3       | R_CPU_FEATURE_SSSE3    |
                         R_CPU_FEATURE_SSE4_1     | R_CPU_FEATURE_SSE4_2   |
                         R_CPU_FEATURE_AES_NI     | R_CPU_FEATURE_PCLMUL   |
                         R_CPU_FEATURE_AVX        | R_CPU_FEATURE_AVX2     |
                         R_CPU_FEATURE_AVX512F    | R_CPU_FEATURE_AVX512BW |
                         R_CPU_FEATURE_AVX512DQ   | R_CPU_FEATURE_AVX512VL |
                         R_CPU_FEATURE_SHA_NI     | R_CPU_FEATURE_BMI1     |
                         R_CPU_FEATURE_BMI2       | R_CPU_FEATURE_POPCNT   |
                         R_CPU_FEATURE_F16C       | R_CPU_FEATURE_RDRAND   |
                         R_CPU_FEATURE_RDSEED;
  RCpuFeature arm_mask = R_CPU_FEATURE_ARM_NEON   | R_CPU_FEATURE_ARM_AES  |
                         R_CPU_FEATURE_ARM_PMULL  | R_CPU_FEATURE_ARM_SHA1 |
                         R_CPU_FEATURE_ARM_SHA2   |
                         R_CPU_FEATURE_ARM_SHA512 | R_CPU_FEATURE_ARM_SHA3 |
                         R_CPU_FEATURE_ARM_CRC32  | R_CPU_FEATURE_ARM_LSE  |
                         R_CPU_FEATURE_ARM_DOTPROD| R_CPU_FEATURE_ARM_FPHP |
                         R_CPU_FEATURE_ARM_ASIMDHP| R_CPU_FEATURE_ARM_BF16 |
                         R_CPU_FEATURE_ARM_I8MM   | R_CPU_FEATURE_ARM_SVE  |
                         R_CPU_FEATURE_ARM_SVE2;
  RCpuFeature features = r_cpu_features ();

  r_assert (!((features & x86_mask) && (features & arm_mask)));
}
RTEST_END;
