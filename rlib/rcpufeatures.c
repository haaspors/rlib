/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/rcpufeatures.h>
#include <rlib/rthreads.h>            /* ROnce */

#if defined(R_ARCH_X86_64) || defined(R_ARCH_X86)
# if defined(_MSC_VER)
#  include <intrin.h>
#  include <immintrin.h>           /* _xgetbv */
# else
#  include <cpuid.h>
# endif
#endif

#if defined(R_ARCH_AARCH64)
# if defined(R_OS_LINUX)
#  include <sys/auxv.h>
#  if defined(__has_include) && __has_include(<asm/hwcap.h>)
#   include <asm/hwcap.h>
#  endif
# elif defined(R_OS_DARWIN)
#  include <sys/sysctl.h>
# elif defined(R_OS_WIN32)
#  include <windows.h>
# endif
#endif

/* Single source of truth for {flag, name} pairs - the known-feature
 * list and the name lookup both expand from this so they can't drift. */
#define R_CPU_FOREACH_FEATURE(F)                          \
  F(SSE,         "SSE")                                   \
  F(SSE2,        "SSE2")                                  \
  F(SSE3,        "SSE3")                                  \
  F(SSSE3,       "SSSE3")                                 \
  F(SSE4_1,      "SSE4.1")                                \
  F(SSE4_2,      "SSE4.2")                                \
  F(AES_NI,      "AES-NI")                                \
  F(PCLMUL,      "PCLMUL")                                \
  F(AVX,         "AVX")                                   \
  F(AVX2,        "AVX2")                                  \
  F(AVX512F,     "AVX-512F")                              \
  F(AVX512BW,    "AVX-512BW")                             \
  F(AVX512DQ,    "AVX-512DQ")                             \
  F(AVX512VL,    "AVX-512VL")                             \
  F(SHA_NI,      "SHA-NI")                                \
  F(BMI1,        "BMI1")                                  \
  F(BMI2,        "BMI2")                                  \
  F(POPCNT,      "POPCNT")                                \
  F(F16C,        "F16C")                                  \
  F(RDRAND,      "RDRAND")                                \
  F(RDSEED,      "RDSEED")                                \
  F(ARM_NEON,    "ARM_NEON")                              \
  F(ARM_AES,     "ARM_AES")                               \
  F(ARM_PMULL,   "ARM_PMULL")                             \
  F(ARM_SHA1,    "ARM_SHA1")                              \
  F(ARM_SHA2,    "ARM_SHA2")                              \
  F(ARM_SHA512,  "ARM_SHA512")                            \
  F(ARM_SHA3,    "ARM_SHA3")                              \
  F(ARM_CRC32,   "ARM_CRC32")                             \
  F(ARM_LSE,     "ARM_LSE")                               \
  F(ARM_DOTPROD, "ARM_DOTPROD")                           \
  F(ARM_FPHP,    "ARM_FPHP")                              \
  F(ARM_ASIMDHP, "ARM_ASIMDHP")                           \
  F(ARM_BF16,    "ARM_BF16")                              \
  F(ARM_I8MM,    "ARM_I8MM")                              \
  F(ARM_SVE,     "ARM_SVE")                               \
  F(ARM_SVE2,    "ARM_SVE2")

static const RCpuFeature g__r_cpu_features_known[] = {
#define R_CPU_FEATURE_ENUM_ENTRY(name, str)  R_CPU_FEATURE_##name,
  R_CPU_FOREACH_FEATURE (R_CPU_FEATURE_ENUM_ENTRY)
#undef R_CPU_FEATURE_ENUM_ENTRY
};

static ROnce       g__r_cpu_features_once = R_ONCE_INIT;
static RCpuFeature g__r_cpu_features = 0;

#if defined(R_ARCH_X86_64) || defined(R_ARCH_X86)

static rboolean
r_cpu_x86_cpuid (ruint32 leaf, ruint32 * eax, ruint32 * ebx,
    ruint32 * ecx, ruint32 * edx)
{
# if defined(_MSC_VER)
  int regs[4] = { 0, 0, 0, 0 };
  __cpuid (regs, (int)leaf);
  *eax = (ruint32)regs[0]; *ebx = (ruint32)regs[1];
  *ecx = (ruint32)regs[2]; *edx = (ruint32)regs[3];
  return TRUE;
# else
  return __get_cpuid (leaf, eax, ebx, ecx, edx) != 0;
# endif
}

static rboolean
r_cpu_x86_cpuid_count (ruint32 leaf, ruint32 sub,
    ruint32 * eax, ruint32 * ebx, ruint32 * ecx, ruint32 * edx)
{
# if defined(_MSC_VER)
  int regs[4] = { 0, 0, 0, 0 };
  __cpuidex (regs, (int)leaf, (int)sub);
  *eax = (ruint32)regs[0]; *ebx = (ruint32)regs[1];
  *ecx = (ruint32)regs[2]; *edx = (ruint32)regs[3];
  return TRUE;
# else
  return __get_cpuid_count (leaf, sub, eax, ebx, ecx, edx) != 0;
# endif
}

static ruint64
r_cpu_x86_xgetbv (void)
{
# if defined(_MSC_VER)
  return (ruint64)_xgetbv (0);
# else
  ruint32 eax_lo, edx_hi;
  __asm__ volatile ("xgetbv"
      : "=a" (eax_lo), "=d" (edx_hi)
      : "c" (0));
  return ((ruint64)edx_hi << 32) | (ruint64)eax_lo;
# endif
}

static RCpuFeature
r_cpu_detect (void)
{
  RCpuFeature ret = 0;
  ruint32 eax = 0, ebx = 0, ecx = 0, edx = 0;
  ruint32 max_leaf;

  /* Leaf 0 EAX is the max-supported-leaf marker; gates the leaf-7
   * probe below so older CPUs don't return garbage there. */
  if (!r_cpu_x86_cpuid (0, &max_leaf, &ebx, &ecx, &edx))
    return 0;

  if (!r_cpu_x86_cpuid (1, &eax, &ebx, &ecx, &edx))
    return 0;

  if (edx & (1u << 25)) ret |= R_CPU_FEATURE_SSE;
  if (edx & (1u << 26)) ret |= R_CPU_FEATURE_SSE2;

  if (ecx & (1u <<  0)) ret |= R_CPU_FEATURE_SSE3;
  if (ecx & (1u <<  9)) ret |= R_CPU_FEATURE_SSSE3;
  if (ecx & (1u << 19)) ret |= R_CPU_FEATURE_SSE4_1;
  if (ecx & (1u << 20)) ret |= R_CPU_FEATURE_SSE4_2;
  if (ecx & (1u << 25)) ret |= R_CPU_FEATURE_AES_NI;
  if (ecx & (1u <<  1)) ret |= R_CPU_FEATURE_PCLMUL;
  if (ecx & (1u << 23)) ret |= R_CPU_FEATURE_POPCNT;
  if (ecx & (1u << 30)) ret |= R_CPU_FEATURE_RDRAND;

  /* AVX-family flags require the OS to have enabled the wider
   * XSAVE state - issuing AVX instructions without that corrupts FP
   * state across a context switch. cpuid alone is not enough;
   * OSXSAVE plus the relevant xcr0 bits gate the report. */
  rboolean osxsave = (ecx & (1u << 27)) != 0;
  rboolean cpuid_avx = (ecx & (1u << 28)) != 0;
  ruint64 xcr0 = 0;
  rboolean os_avx = FALSE, os_avx512 = FALSE;

  if (osxsave) {
    xcr0 = r_cpu_x86_xgetbv ();
    os_avx    = (xcr0 & 0x6) == 0x6;
    os_avx512 = (xcr0 & 0xE6) == 0xE6;
  }

  if (cpuid_avx && os_avx)
    ret |= R_CPU_FEATURE_AVX;
  /* F16C piggybacks on VEX/YMM, so it inherits the AVX OS gate. */
  if ((ecx & (1u << 29)) && os_avx)
    ret |= R_CPU_FEATURE_F16C;

  /* Leaf 7 sub-leaf 0: AVX2, AVX-512 family, BMI1/2, SHA-NI, RDSEED. */
  if (max_leaf >= 7 &&
      r_cpu_x86_cpuid_count (7, 0, &eax, &ebx, &ecx, &edx)) {
    if (ebx & (1u <<  3))             ret |= R_CPU_FEATURE_BMI1;
    if (ebx & (1u <<  8))             ret |= R_CPU_FEATURE_BMI2;
    if (ebx & (1u << 18))             ret |= R_CPU_FEATURE_RDSEED;
    if ((ebx & (1u << 29)))           ret |= R_CPU_FEATURE_SHA_NI;
    if ((ebx & (1u <<  5)) && os_avx) ret |= R_CPU_FEATURE_AVX2;
    if (os_avx512) {
      if (ebx & (1u << 16)) ret |= R_CPU_FEATURE_AVX512F;
      if (ebx & (1u << 17)) ret |= R_CPU_FEATURE_AVX512DQ;
      if (ebx & (1u << 30)) ret |= R_CPU_FEATURE_AVX512BW;
      if (ebx & (1u << 31)) ret |= R_CPU_FEATURE_AVX512VL;
    }
  }

  (void)edx;
  return ret;
}

#elif defined(R_ARCH_AARCH64)

# if defined(R_OS_LINUX)

/* The kernel never reuses HWCAP bits, but a newer extension may not
 * be in our build's <asm/hwcap.h>. Local fallbacks match the canonical
 * Linux UAPI bit positions. */
#  ifndef HWCAP_ASIMD
#   define HWCAP_ASIMD      (1u <<  1)
#  endif
#  ifndef HWCAP_AES
#   define HWCAP_AES        (1u <<  3)
#  endif
#  ifndef HWCAP_PMULL
#   define HWCAP_PMULL      (1u <<  4)
#  endif
#  ifndef HWCAP_SHA1
#   define HWCAP_SHA1       (1u <<  5)
#  endif
#  ifndef HWCAP_SHA2
#   define HWCAP_SHA2       (1u <<  6)
#  endif
#  ifndef HWCAP_CRC32
#   define HWCAP_CRC32      (1u <<  7)
#  endif
#  ifndef HWCAP_ATOMICS
#   define HWCAP_ATOMICS    (1u <<  8)
#  endif
#  ifndef HWCAP_FPHP
#   define HWCAP_FPHP       (1u <<  9)
#  endif
#  ifndef HWCAP_ASIMDHP
#   define HWCAP_ASIMDHP    (1u << 10)
#  endif
#  ifndef HWCAP_SHA3
#   define HWCAP_SHA3       (1u << 17)
#  endif
#  ifndef HWCAP_ASIMDDP
#   define HWCAP_ASIMDDP    (1u << 20)
#  endif
#  ifndef HWCAP_SHA512
#   define HWCAP_SHA512     (1u << 21)
#  endif
#  ifndef HWCAP_SVE
#   define HWCAP_SVE        (1u << 22)
#  endif
#  ifndef HWCAP2_SVE2
#   define HWCAP2_SVE2      (1u <<  1)
#  endif
#  ifndef HWCAP2_I8MM
#   define HWCAP2_I8MM      (1u << 13)
#  endif
#  ifndef HWCAP2_BF16
#   define HWCAP2_BF16      (1u << 14)
#  endif
#  ifndef AT_HWCAP2
#   define AT_HWCAP2  26
#  endif

static RCpuFeature
r_cpu_detect (void)
{
  RCpuFeature ret = 0;
  unsigned long hwcap = getauxval (AT_HWCAP);
  unsigned long hwcap2 = getauxval (AT_HWCAP2);

  if (hwcap & HWCAP_ASIMD)    ret |= R_CPU_FEATURE_ARM_NEON;
  if (hwcap & HWCAP_AES)      ret |= R_CPU_FEATURE_ARM_AES;
  if (hwcap & HWCAP_PMULL)    ret |= R_CPU_FEATURE_ARM_PMULL;
  if (hwcap & HWCAP_SHA1)     ret |= R_CPU_FEATURE_ARM_SHA1;
  if (hwcap & HWCAP_SHA2)     ret |= R_CPU_FEATURE_ARM_SHA2;
  if (hwcap & HWCAP_SHA512)   ret |= R_CPU_FEATURE_ARM_SHA512;
  if (hwcap & HWCAP_SHA3)     ret |= R_CPU_FEATURE_ARM_SHA3;
  if (hwcap & HWCAP_CRC32)    ret |= R_CPU_FEATURE_ARM_CRC32;
  if (hwcap & HWCAP_ATOMICS)  ret |= R_CPU_FEATURE_ARM_LSE;
  if (hwcap & HWCAP_ASIMDDP)  ret |= R_CPU_FEATURE_ARM_DOTPROD;
  if (hwcap & HWCAP_FPHP)     ret |= R_CPU_FEATURE_ARM_FPHP;
  if (hwcap & HWCAP_ASIMDHP)  ret |= R_CPU_FEATURE_ARM_ASIMDHP;
  if (hwcap & HWCAP_SVE)      ret |= R_CPU_FEATURE_ARM_SVE;
  if (hwcap2 & HWCAP2_BF16)   ret |= R_CPU_FEATURE_ARM_BF16;
  if (hwcap2 & HWCAP2_I8MM)   ret |= R_CPU_FEATURE_ARM_I8MM;
  if (hwcap2 & HWCAP2_SVE2)   ret |= R_CPU_FEATURE_ARM_SVE2;
  return ret;
}

# elif defined(R_OS_DARWIN)

static rboolean
r_cpu_sysctl_present (const char * name)
{
  int val = 0;
  size_t size = sizeof (val);
  return (sysctlbyname (name, &val, &size, NULL, 0) == 0 && val != 0);
}

static RCpuFeature
r_cpu_detect (void)
{
  /* NEON is mandatory on AArch64. */
  RCpuFeature ret = R_CPU_FEATURE_ARM_NEON;

  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_AES"))
    ret |= R_CPU_FEATURE_ARM_AES;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_PMULL"))
    ret |= R_CPU_FEATURE_ARM_PMULL;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_SHA1"))
    ret |= R_CPU_FEATURE_ARM_SHA1;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_SHA256"))
    ret |= R_CPU_FEATURE_ARM_SHA2;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_SHA512"))
    ret |= R_CPU_FEATURE_ARM_SHA512;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_SHA3"))
    ret |= R_CPU_FEATURE_ARM_SHA3;
  /* Apple's legacy "armv8_crc32" key predates "arm.FEAT_CRC32"; honour
   * both so older OS versions report correctly. */
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_CRC32") ||
      r_cpu_sysctl_present ("hw.optional.armv8_crc32"))
    ret |= R_CPU_FEATURE_ARM_CRC32;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_LSE"))
    ret |= R_CPU_FEATURE_ARM_LSE;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_DotProd"))
    ret |= R_CPU_FEATURE_ARM_DOTPROD;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_FP16"))
    ret |= R_CPU_FEATURE_ARM_FPHP | R_CPU_FEATURE_ARM_ASIMDHP;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_BF16"))
    ret |= R_CPU_FEATURE_ARM_BF16;
  if (r_cpu_sysctl_present ("hw.optional.arm.FEAT_I8MM"))
    ret |= R_CPU_FEATURE_ARM_I8MM;
  return ret;
}

# elif defined(R_OS_WIN32)

#  ifndef PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE
#   define PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE   34
#  endif
#  ifndef PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE
#   define PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE  30
#  endif

static RCpuFeature
r_cpu_detect (void)
{
  /* NEON is mandatory on AArch64. */
  RCpuFeature ret = R_CPU_FEATURE_ARM_NEON;
  if (IsProcessorFeaturePresent (PF_ARM_V8_CRC32_INSTRUCTIONS_AVAILABLE))
    ret |= R_CPU_FEATURE_ARM_CRC32;
  /* Windows bundles AES + PMULL + SHA1/2 under a single "crypto
   * extensions" predicate; treat them as a quartet. */
  if (IsProcessorFeaturePresent (PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE))
    ret |= R_CPU_FEATURE_ARM_AES | R_CPU_FEATURE_ARM_PMULL |
           R_CPU_FEATURE_ARM_SHA1 | R_CPU_FEATURE_ARM_SHA2;
  return ret;
}

# else

static RCpuFeature r_cpu_detect (void) { return 0; }

# endif

#else

static RCpuFeature r_cpu_detect (void) { return 0; }

#endif

static rpointer
r_cpu_features_detect_once (rpointer user)
{
  (void)user;
  g__r_cpu_features = r_cpu_detect ();
  return NULL;
}

RCpuFeature
r_cpu_features (void)
{
  r_call_once (&g__r_cpu_features_once, r_cpu_features_detect_once, NULL);
  return g__r_cpu_features;
}

rboolean
r_cpu_has (RCpuFeature feature)
{
  return (r_cpu_features () & feature) != 0;
}

const rchar *
r_cpu_feature_name (RCpuFeature feature)
{
  if (feature == R_CPU_FEATURE_NONE)
    return "None";
  switch (feature) {
#define R_CPU_FEATURE_NAME_CASE(name, str) \
    case R_CPU_FEATURE_##name: return str;
    R_CPU_FOREACH_FEATURE (R_CPU_FEATURE_NAME_CASE)
#undef R_CPU_FEATURE_NAME_CASE
    default: return "Unknown";
  }
}

const RCpuFeature *
r_cpu_features_all (rsize * count)
{
  *count = R_N_ELEMENTS (g__r_cpu_features_known);
  return g__r_cpu_features_known;
}
