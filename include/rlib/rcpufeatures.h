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
#ifndef __R_CPUFEATURES_H__
#define __R_CPUFEATURES_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

/**
 * @defgroup r_cpufeatures CPU feature detection
 * @brief Runtime queries for the host CPU's optional instruction-set
 * extensions.
 * @{
 */

/**
 * @file rlib/rcpufeatures.h
 * @brief Runtime CPU feature detection.
 *
 * Bitmask of optional CPU extensions probed once at first use and
 * cached for the process lifetime. The set is intentionally broader
 * than what rlib's own code dispatches on - callers can use it to
 * pick algorithm variants, gate diagnostic output, or surface the
 * host's capabilities in @c --version-style banners.
 *
 * **Detection sources:**
 *  - **x86 / x86_64**: @c cpuid leaf 1 (legacy SSE / AES / AVX / etc.)
 *    and leaf 7 sub-leaf 0 (AVX2 / AVX-512 / BMI / SHA-NI). AVX-family
 *    flags are gated on the OS having enabled @c OSXSAVE and the
 *    corresponding @c xcr0 state bits (XMM, YMM, opmask, ZMM_hi256,
 *    Hi16_ZMM), so a true bit guarantees that issuing those
 *    instructions won't fault on a context switch.
 *  - **AArch64 Linux**: @c getauxval (@c AT_HWCAP and @c AT_HWCAP2).
 *  - **AArch64 Darwin**: @c sysctlbyname ("hw.optional.arm.FEAT_*").
 *  - **AArch64 Windows**: @c IsProcessorFeaturePresent.
 *
 * On architectures with no detection backend the result is always 0
 * and every @c r_cpu_has call returns @c FALSE; callers that dispatch
 * on a feature flag transparently fall back to their software path.
 *
 * **Bit layout** (32 bits total, x86 in 0-23, AArch64 in 24-47):
 *  - x86 base SSE family: bits 0-7
 *  - x86 AVX / AVX-512 family: bits 8-15
 *  - x86 misc (SHA-NI, BMI, POPCNT, F16C, RDRAND): bits 16-23
 *  - AArch64 base + crypto: bits 24-39
 *  - AArch64 misc (atomics, dotprod, SVE): bits 40-47
 */

/**
 * @brief Bitmask of CPU extension flags.
 *
 * Treat as an opaque bitfield - combine with bitwise-OR, query with
 * bitwise-AND or @c r_cpu_has. Underlying type is @c ruint64 to leave
 * headroom for future flags beyond the 32-bit cutoff.
 */
typedef ruint64 RCpuFeature;

/** @brief Sentinel: no extensions detected (always 0). */
#define R_CPU_FEATURE_NONE              ((RCpuFeature)0)

/** @internal Shift helper - keeps the bit width explicit so flags
 * past bit 31 don't accidentally fall back to int and truncate. */
#define R_CPU_BIT_(n)                   (((RCpuFeature)1) << (n))

/* x86 / x86_64 base SSE family (bits 0-7) */

/** @brief x86 SSE (Pentium III+); 128-bit XMM single-precision FP. */
#define R_CPU_FEATURE_SSE               R_CPU_BIT_( 0)
/** @brief x86 SSE2 (Pentium 4+); 128-bit integer + double-precision FP. */
#define R_CPU_FEATURE_SSE2              R_CPU_BIT_( 1)
/** @brief x86 SSE3 (Prescott+); horizontal add, @c LDDQU, @c MWAIT. */
#define R_CPU_FEATURE_SSE3              R_CPU_BIT_( 2)
/** @brief x86 SSSE3 (Core 2+); byte shuffle (@c PSHUFB), align right. */
#define R_CPU_FEATURE_SSSE3             R_CPU_BIT_( 3)
/** @brief x86 SSE4.1 (Penryn+); blend, dot product, packed compare. */
#define R_CPU_FEATURE_SSE4_1            R_CPU_BIT_( 4)
/** @brief x86 SSE4.2 (Nehalem+); @c CRC32 instruction (hardware
 * Castagnoli CRC32C), string compare, @c PCMPGTQ. */
#define R_CPU_FEATURE_SSE4_2            R_CPU_BIT_( 5)
/** @brief x86 AES-NI; single-instruction AES round operations
 * (@c AESENC / @c AESENCLAST / @c AESDEC / @c AESDECLAST + key
 * schedule helpers). */
#define R_CPU_FEATURE_AES_NI            R_CPU_BIT_( 6)
/** @brief x86 PCLMULQDQ; carry-less multiply used for GHASH (AES-GCM)
 * and PCLMUL-folding CRC variants. */
#define R_CPU_FEATURE_PCLMUL            R_CPU_BIT_( 7)

/* x86 / x86_64 AVX / AVX-512 family (bits 8-15) */

/** @brief x86 AVX (Sandy Bridge+); 256-bit YMM vector ops. Only set
 * when the OS has enabled AVX-state context switching - using AVX
 * without that would corrupt FP state across a thread switch. */
#define R_CPU_FEATURE_AVX               R_CPU_BIT_( 8)
/** @brief x86 AVX2 (Haswell+); 256-bit integer vector ops. Same OS
 * precondition as @c R_CPU_FEATURE_AVX. */
#define R_CPU_FEATURE_AVX2              R_CPU_BIT_( 9)
/** @brief x86 AVX-512 Foundation (Skylake-X+); 512-bit ZMM vector
 * ops. Only set when the OS has additionally enabled AVX-512 state
 * (@c xcr0 bits 5-7). */
#define R_CPU_FEATURE_AVX512F           R_CPU_BIT_(10)
/** @brief x86 AVX-512BW; byte/word integer ops on ZMM. Implies F. */
#define R_CPU_FEATURE_AVX512BW          R_CPU_BIT_(11)
/** @brief x86 AVX-512DQ; double-word/quad-word ops, fast scatter/
 * gather. Implies F. */
#define R_CPU_FEATURE_AVX512DQ          R_CPU_BIT_(12)
/** @brief x86 AVX-512VL; lets 128/256-bit ops use AVX-512 features
 * (masking, extended register file). Implies F. */
#define R_CPU_FEATURE_AVX512VL          R_CPU_BIT_(13)

/* x86 / x86_64 misc (bits 16-23) */

/** @brief x86 SHA-NI (Goldmont+, Zen+); hardware SHA-1 and SHA-256
 * round instructions. */
#define R_CPU_FEATURE_SHA_NI            R_CPU_BIT_(16)
/** @brief x86 BMI1 (Haswell+, Piledriver+); @c ANDN, @c BEXTR,
 * @c BLSI, @c BLSMSK, @c BLSR, @c TZCNT. */
#define R_CPU_FEATURE_BMI1              R_CPU_BIT_(17)
/** @brief x86 BMI2 (Haswell+, Zen+); @c BZHI, @c MULX, @c PDEP,
 * @c PEXT, @c RORX, @c SARX / @c SHLX / @c SHRX. */
#define R_CPU_FEATURE_BMI2              R_CPU_BIT_(18)
/** @brief x86 POPCNT (Nehalem+); single-instruction population count. */
#define R_CPU_FEATURE_POPCNT            R_CPU_BIT_(19)
/** @brief x86 F16C (Ivy Bridge+, Piledriver+); FP16 ⇄ FP32 conversion
 * (@c VCVTPH2PS / @c VCVTPS2PH). */
#define R_CPU_FEATURE_F16C              R_CPU_BIT_(20)
/** @brief x86 RDRAND (Ivy Bridge+); hardware random number source. */
#define R_CPU_FEATURE_RDRAND            R_CPU_BIT_(21)
/** @brief x86 RDSEED (Broadwell+); slower-but-stronger RNG paired with
 * RDRAND - draws from the raw entropy source rather than the
 * conditioned stream. */
#define R_CPU_FEATURE_RDSEED            R_CPU_BIT_(22)

/* AArch64 base + crypto (bits 24-39) */

/** @brief AArch64 NEON / Advanced SIMD; 128-bit integer + FP vector
 * ops. Architecturally mandatory on AArch64 so this is always set on
 * the AArch64 backends - exposed for completeness. */
#define R_CPU_FEATURE_ARM_NEON          R_CPU_BIT_(24)
/** @brief ARMv8 AES (@c AESE / @c AESD / @c AESMC / @c AESIMC); the
 * AArch64 analogue of x86 AES-NI. */
#define R_CPU_FEATURE_ARM_AES           R_CPU_BIT_(25)
/** @brief ARMv8 polynomial multiply (@c PMULL / @c PMULL2); the
 * AArch64 analogue of x86 PCLMULQDQ. */
#define R_CPU_FEATURE_ARM_PMULL         R_CPU_BIT_(26)
/** @brief ARMv8 SHA-1 instructions. */
#define R_CPU_FEATURE_ARM_SHA1          R_CPU_BIT_(27)
/** @brief ARMv8 SHA-256 instructions. */
#define R_CPU_FEATURE_ARM_SHA2          R_CPU_BIT_(28)
/** @brief ARMv8.2 SHA-512 instructions. */
#define R_CPU_FEATURE_ARM_SHA512        R_CPU_BIT_(29)
/** @brief ARMv8.2 SHA-3 instructions (Keccak round helpers). */
#define R_CPU_FEATURE_ARM_SHA3          R_CPU_BIT_(30)
/** @brief ARMv8 CRC32 extension; single-cycle @c CRC32C{B,H,W,X}
 * instructions for hardware Castagnoli CRC32C. */
#define R_CPU_FEATURE_ARM_CRC32         R_CPU_BIT_(31)

/* AArch64 misc (bits 32-47) */

/** @brief ARMv8.1 LSE atomics; @c LDADD / @c CAS / @c SWP exclusive-
 * monitor-free atomics. */
#define R_CPU_FEATURE_ARM_LSE           R_CPU_BIT_(32)
/** @brief ARMv8.2 dot product (@c UDOT / @c SDOT); 8-bit signed/
 * unsigned dot product into 32-bit accumulator. */
#define R_CPU_FEATURE_ARM_DOTPROD       R_CPU_BIT_(33)
/** @brief ARMv8.2 half-precision FP arithmetic. */
#define R_CPU_FEATURE_ARM_FPHP          R_CPU_BIT_(34)
/** @brief ARMv8.2 half-precision SIMD arithmetic. */
#define R_CPU_FEATURE_ARM_ASIMDHP       R_CPU_BIT_(35)
/** @brief ARMv8.6 BFloat16 vector ops (@c BFDOT / @c BFMMLA / etc.). */
#define R_CPU_FEATURE_ARM_BF16          R_CPU_BIT_(36)
/** @brief ARMv8.6 8-bit integer matrix multiply (@c USMMLA / @c UMMLA /
 * @c SMMLA). */
#define R_CPU_FEATURE_ARM_I8MM          R_CPU_BIT_(37)
/** @brief ARMv8.2 Scalable Vector Extension (variable-width vectors). */
#define R_CPU_FEATURE_ARM_SVE           R_CPU_BIT_(38)
/** @brief ARMv9 SVE2; SVE plus extended integer / crypto operations. */
#define R_CPU_FEATURE_ARM_SVE2          R_CPU_BIT_(39)

R_BEGIN_DECLS

/**
 * @brief Return the bitmask of detected CPU features.
 *
 * Detection runs once at library load (constructor / DllMain) so
 * this call is a single cached load - O(1), lock-free, and
 * trivially thread-safe.
 *
 * @return Bitwise-OR of zero or more @c R_CPU_FEATURE_* values.
 * Returns 0 on architectures with no detection backend (the safe
 * answer that routes every caller to its software fallback).
 */
R_API RCpuFeature r_cpu_features (void);

/**
 * @brief Test whether the CPU has the given feature.
 *
 * Shorthand for @c (r_cpu_features() @c & @c feature) @c != @c 0.
 * Use for dispatch-site predicates where the branch is on a single
 * feature; for multi-feature checks (e.g. "AES-NI and PCLMUL"), call
 * @c r_cpu_features directly and AND the desired mask in one go.
 *
 * @param feature  One of the @c R_CPU_FEATURE_* values.
 * @return @c TRUE if the bit is set in the detected bitmask,
 * @c FALSE otherwise.
 */
R_API rboolean r_cpu_has (RCpuFeature feature);

/**
 * @brief Return a short canonical name for a single feature flag.
 *
 * Names are stable, ASCII-only, suitable for logs / banners / unit
 * tests (e.g. @c "SSE4.2", @c "AES-NI", @c "ARM_CRC32"). The string
 * has static storage; callers must not free it.
 *
 * @param feature  Exactly one @c R_CPU_FEATURE_* flag - not a bitmask
 * of multiple. Passing 0 or an OR of flags returns @c "Unknown".
 * @return Pointer to a static C string. Never @c NULL.
 */
R_API const rchar * r_cpu_feature_name (RCpuFeature feature);

/**
 * @brief Return a static array of every feature this build knows
 * about.
 *
 * The array contains one entry per defined @c R_CPU_FEATURE_* flag
 * (not the @c NONE sentinel), in declaration order. Combine with
 * @c r_cpu_has and @c r_cpu_feature_name to enumerate the present
 * subset, e.g. for a @c --version-style listing:
 *
 * @code
 * rsize n;
 * const RCpuFeature * all = r_cpu_features_all (&n);
 * for (rsize i = 0; i < n; i++) {
 *   if (r_cpu_has (all[i]))
 *     printf ("  %s\n", r_cpu_feature_name (all[i]));
 * }
 * @endcode
 *
 * @param[out] count  Number of entries in the returned array.
 * Must not be @c NULL.
 * @return Pointer to a static read-only array. Never @c NULL.
 */
R_API const RCpuFeature * r_cpu_features_all (rsize * count);

R_END_DECLS

/** @} */ /* r_cpufeatures group */

#endif /* __R_CPUFEATURES_H__ */
