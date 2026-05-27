/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
/**
 * @defgroup r_mem Memory allocation and operations
 * @brief Heap / stack allocators, byte-buffer operations, and
 * pattern-based memory scanning.
 * @{
 */

/**
 * @file rlib/rmem.h
 * @brief Memory allocation, byte-buffer operations, and pattern
 * scanning.
 *
 * Contains:
 *  - **Heap allocator wrappers** (@c r_malloc, @c r_calloc, ...)
 *    routed through an installable @c RMemVTable so a process can
 *    redirect every rlib allocation to a custom backend (test
 *    harnesses, leak trackers, debug allocators).
 *  - **Stack allocator macros** (@c r_alloca, @c r_mem_newa, ...)
 *    that paper over the platform-specific @c alloca / @c _alloca /
 *    @c __builtin_alloca declarations.
 *  - **Byte-buffer ops** (@c r_memcpy, @c r_memset, ...) as static
 *    inlines around the libc intrinsics, with NULL-pointer guards.
 *    The constant-time variant @c r_memcmp_ct and the optimiser-
 *    resistant @c r_memclear_secure live here too.
 *  - **Variadic aggregator helpers** (@c r_memagg, @c r_memdup_agg)
 *    that concatenate a NULL-terminated list of (ptr, size) pairs.
 *  - **Byte / pattern scanners** for searching memory regions.
 */
#ifndef __R_MEM_H__
#define __R_MEM_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <stdlib.h>
#include <stdarg.h>

#if defined(__BIONIC__) && defined (RLIB_HAVE_ALLOCA_H)
#include <alloca.h>
#elif defined(__GNUC__)
#undef alloca
#define alloca(size)   __builtin_alloca (size)
#elif defined(RLIB_HAVE_ALLOCA_H)
#include <alloca.h>
#elif defined(_MSC_VER) || defined(__DMC__)
#include <malloc.h>
#define alloca _alloca
#elif defined(_AIX)
#pragma alloca
#elif !defined(alloca)
R_BEGIN_DECLS
char *alloca ();
R_END_DECLS
#endif


R_BEGIN_DECLS

/**
 * @brief Pointer + length view of a memory region.
 *
 * Plain aggregate, no ownership semantics: callers manage @p data's
 * lifetime themselves. Used as a value type in @c RMemScanToken.
 */
typedef struct {
  ruint8 * data;        /**< Pointer to the first byte of the region. */
  rsize size;           /**< Region length in bytes. */
} RMemChunk;


/* ----- Stack allocations ------------------------------------------- */

/**
 * @brief Allocate @p size bytes on the stack frame of the caller.
 *
 * Thin portability shim around @c alloca / @c _alloca /
 * @c __builtin_alloca. Storage lives until the enclosing function
 * returns; do not return or hand the pointer to code outside the
 * caller's lifetime.
 *
 * @param size Number of bytes (typically a small constant - large
 *             requests risk stack overflow).
 */
#define r_alloca(size)        alloca (size)

/** @brief Stack-allocate @p size bytes and zero-fill them. */
#define r_alloca0(size)       r_memclear (r_alloca (size), size)

/** @brief Stack-allocate an array of @p n elements of @p type. */
#define r_mem_newa_n(type, n) ((type*) r_alloca (sizeof (type) * (rsize) (n)))

/** @brief Stack-allocate a zeroed array of @p n elements of @p type. */
#define r_mem_newa0_n(type, n)((type*) (r_alloca0 (sizeof (type) * (rsize) (n)))

/** @brief Stack-allocate a single instance of @p type. */
#define r_mem_newa(type)      r_mem_newa_n (type, 1)

/** @brief Stack-allocate a single zeroed instance of @p type. */
#define r_mem_newa0(type)     r_mem_newa_n0 (type, 1)


/* ----- Heap allocations -------------------------------------------- */

/**
 * @brief Release a heap allocation obtained from @c r_malloc /
 * @c r_malloc0 / @c r_calloc / @c r_realloc.
 *
 * Routes through the currently-installed @c RMemVTable. A @c NULL
 * @p ptr is a no-op (matches libc @c free).
 *
 * @param ptr Allocation to release.
 */
R_API void     r_free     (rpointer ptr);

/**
 * @brief Allocate @p size uninitialised bytes on the heap.
 *
 * Routes through the currently-installed @c RMemVTable.
 *
 * @param size Number of bytes (zero is implementation-defined).
 * @return Allocation pointer, or @c NULL on failure.
 */
R_API rpointer r_malloc   (rsize size) R_ATTR_MALLOC R_ATTR_ALLOC_SIZE_ARG(1);

/**
 * @brief Allocate @p size zero-initialised bytes on the heap.
 *
 * Implemented as @c calloc(1, size) through the active vtable.
 *
 * @param size Number of bytes.
 * @return Allocation pointer, or @c NULL on failure.
 */
R_API rpointer r_malloc0  (rsize size) R_ATTR_MALLOC R_ATTR_ALLOC_SIZE_ARG(1);

/**
 * @brief Allocate @p count zero-initialised elements of @p size bytes.
 *
 * Mirrors libc @c calloc semantics: the allocation is zeroed and
 * @c count * @c size is computed with overflow checking by the
 * underlying allocator.
 *
 * @param count Number of elements.
 * @param size  Size of each element in bytes.
 * @return Allocation pointer, or @c NULL on failure.
 */
R_API rpointer r_calloc   (rsize count, rsize size) R_ATTR_ALLOC_SIZE_ARGS(1, 2);

/**
 * @brief Resize an existing allocation to @p size bytes.
 *
 * Mirrors libc @c realloc semantics, including the "@p ptr is
 * @c NULL → fresh allocation" and "@p size is zero → may free"
 * corners. The returned pointer is annotated
 * @c R_ATTR_WARN_UNUSED_RESULT because forgetting to capture it
 * leaks the prior allocation if @c realloc moved the block.
 *
 * @param ptr  Existing allocation (or @c NULL).
 * @param size New size in bytes.
 * @return New allocation pointer (which may equal @p ptr), or
 *         @c NULL on failure (in which case @p ptr is untouched).
 */
R_API rpointer r_realloc  (rpointer ptr, rsize size) R_ATTR_WARN_UNUSED_RESULT;

/** @brief Allocate an array of @p n elements of @p type. */
#define r_mem_new_n(type, n)  ((type*) r_malloc (sizeof (type) * (rsize) (n)))

/** @brief Allocate a zeroed array of @p n elements of @p type. */
#define r_mem_new0_n(type, n) ((type*) r_malloc0 (sizeof (type) * (rsize) (n)))

/** @brief Allocate a single instance of @p type. */
#define r_mem_new(type)       r_mem_new_n (type, 1)

/** @brief Allocate a single zeroed instance of @p type. */
#define r_mem_new0(type)      r_mem_new0_n (type, 1)


/* ----- Pluggable allocator vtable ---------------------------------- */

/**
 * @brief Allocator backend slots routed through by every rlib
 * heap helper.
 *
 * The function-pointer signatures match libc @c malloc / @c calloc /
 * @c realloc / @c free verbatim, so the default vtable is just the
 * libc entries. A process may install a custom vtable (debug
 * allocator, leak tracker, fixed-pool allocator, ...) at startup via
 * @c r_mem_set_vtable.
 */
typedef struct {
  rpointer (*malloc)  (rsize size);                     /**< @c libc-malloc-equivalent slot. */
  rpointer (*calloc)  (rsize count, rsize size);        /**< @c libc-calloc-equivalent slot. */
  rpointer (*realloc) (rpointer ptr, rsize size);       /**< @c libc-realloc-equivalent slot. */
  void     (*free)    (rpointer ptr);                   /**< @c libc-free-equivalent slot. */
} RMemVTable;

/**
 * @brief Replace the active allocator vtable.
 *
 * Every subsequent @c r_malloc / @c r_calloc / @c r_realloc /
 * @c r_free call routes through the new slots. Intended to be called
 * once at process start; switching mid-flight risks freeing a pointer
 * with a different backend than the one that allocated it.
 *
 * A @c NULL @p vtable, or a vtable with any @c NULL slot, is rejected
 * (the active vtable is left untouched). This catches the otherwise-
 * common bug of installing an incomplete vtable that crashes on the
 * next allocation rather than at the install call.
 *
 * @param vtable Fully-populated vtable (must have all four slots
 *               non-NULL).
 */
R_API void r_mem_set_vtable (RMemVTable * vtable);

/**
 * @brief Copy the active vtable into @p *out.
 *
 * Pairs with @c r_mem_set_vtable so a caller (typically a test) can
 * save the active vtable, swap in its own, then restore exactly the
 * pointers it saw. Restoring via @c r_mem_set_vtable with locally-
 * typed @c { malloc, @c calloc, @c realloc, @c free } is not safe
 * across DLL boundaries on Windows - the test binary's import thunks
 * resolve to different addresses than the rlib DLL's.
 *
 * @param out Destination vtable (must be non-NULL).
 */
R_API void r_mem_get_vtable (RMemVTable * out);

/**
 * @brief Whether the active vtable still points at libc.
 *
 * Useful as a sanity guard in code that absolutely must allocate
 * through libc (e.g. interop with foreign code that will @c free
 * the pointer itself).
 *
 * @return @c TRUE if the active vtable is the libc default,
 *         @c FALSE if a custom vtable has been installed.
 */
R_API rboolean r_mem_using_system_default (void);


/**
 * @brief Constant-time variant of @c r_memcmp.
 *
 * Returns 0 iff every byte matches, non-zero otherwise. No early-out
 * on the first mismatch, so wall-clock latency depends only on
 * @p size and not on which bytes (if any) differ - suitable for
 * comparing MAC tags, signature digests, and similar secret-derived
 * material against attacker-supplied values.
 *
 * Does **not** preserve @c memcmp's sign semantics; only the zero /
 * non-zero distinction is meaningful. Stays extern so the volatile-
 * pointer loop in the implementation isn't sniffed apart by the
 * optimiser.
 *
 * The non-constant-time @c r_memcmp / @c r_memset / @c r_memcpy /
 * @c r_memmove inline primitives live in @c rlib/types/rmemops.h
 * (transitively pulled in through this header) - that placement is
 * forced by their use inside the @c rendianness.h load / store
 * helpers, which are processed earlier in the include chain.
 *
 * @param a    First buffer (may be @c NULL).
 * @param b    Second buffer (may be @c NULL).
 * @param size Number of bytes to compare.
 * @return 0 if @p a and @p b are byte-equal across @p size bytes,
 *         non-zero otherwise.
 */
R_API int       r_memcmp_ct (rconstpointer a, rconstpointer b, rsize size);

/**
 * @brief Zero @p size bytes at @p ptr in a way the compiler can't
 * elide.
 *
 * A regular @c memset before a @c free is provably unobservable from
 * the caller's perspective and gets removed by the optimiser ("dead
 * store elimination") - which is exactly the wrong outcome for
 * wiping secret material. Use this for buffers that contained keys,
 * scalars, nonces, plaintexts, etc. before they're released.
 *
 * Stays extern so the platform-specific guarantees
 * (@c SecureZeroMemory on Win32, @c explicit_bzero on glibc / *BSD /
 * musl, volatile-loop fallback elsewhere) live in one place and the
 * optimiser can't see through them.
 *
 * @param ptr  Destination buffer (may be @c NULL or @p size 0; both
 *             are silent no-ops).
 * @param size Number of bytes to wipe.
 */
R_API void      r_memclear_secure (rpointer ptr, rsize size);

/**
 * @brief Heap-allocate a copy of @p size bytes at @p src.
 *
 * Behaves like @c malloc + @c memcpy. A @c NULL @p src or zero
 * @p size returns @c NULL (no allocation).
 *
 * @param src  Source bytes (may be @c NULL).
 * @param size Number of bytes to duplicate.
 * @return Newly-allocated copy, or @c NULL on @c NULL @p src,
 *         zero @p size, or out-of-memory.
 */
R_API rpointer  r_memdup (rconstpointer src, rsize size) R_ATTR_MALLOC;

/**
 * @brief Aggregate (concatenate) a NULL-terminated list of byte
 * chunks into @p dst.
 *
 * Variadic args are pairs of @c (rconstpointer, @c rsize) and the
 * list terminates with a @c NULL pointer. Each chunk that fits within
 * the remaining space in @p dst is copied and tallied; the first
 * chunk that would overflow ends the aggregation. The total bytes
 * written are returned via @p *out.
 *
 * @param dst  Destination buffer.
 * @param size Capacity of @p dst in bytes.
 * @param out  Receives the total bytes written (may be @c NULL).
 * @return Number of chunks copied (which may be less than the number
 *         supplied if @p dst filled up).
 */
R_API rsize     r_memagg (rpointer dst, rsize size, rsize * out, ...) R_ATTR_NULL_TERMINATED;

/**
 * @brief @c va_list variant of @c r_memagg.
 *
 * @param dst  Destination buffer.
 * @param size Capacity of @p dst in bytes.
 * @param out  Receives the total bytes written (may be @c NULL).
 * @param args Pre-started @c va_list - the caller owns the
 *             @c va_start / @c va_end book-keeping.
 * @return Number of chunks copied.
 */
R_API rsize     r_memaggv (rpointer dst, rsize size, rsize * out, va_list args);

/**
 * @brief Aggregate a NULL-terminated list of byte chunks into a
 * freshly-allocated buffer.
 *
 * The allocation is sized to exactly fit the supplied chunks (sum of
 * all sizes in the variadic list). The total bytes written are
 * returned via @p *out. Returns @c NULL on out-of-memory or if the
 * list is empty.
 *
 * @param out Receives the total allocation size (may be @c NULL).
 * @return Newly-allocated, fully-populated buffer, or @c NULL.
 */
R_API rpointer  r_memdup_agg (rsize * out, ...) R_ATTR_NULL_TERMINATED R_ATTR_MALLOC;

/**
 * @brief @c va_list variant of @c r_memdup_agg.
 *
 * @param out  Receives the total allocation size (may be @c NULL).
 * @param args Pre-started @c va_list.
 * @return Newly-allocated, fully-populated buffer, or @c NULL.
 */
R_API rpointer  r_memdup_aggv (rsize * out, va_list args) R_ATTR_MALLOC;


/* ----- Byte / pattern scanning ------------------------------------- */

/**
 * @brief Find the first occurrence of byte @p byte in @p mem.
 *
 * Equivalent in semantics to @c memchr but with rlib's NULL-tolerant
 * convention.
 *
 * @param mem  Memory region (may be @c NULL).
 * @param size Region length in bytes.
 * @param byte Byte to search for.
 * @return Pointer to the first match, or @c NULL if not found
 *         (or @p mem is @c NULL).
 */
R_API rpointer r_mem_scan_byte (rconstpointer mem, rsize size, ruint8 byte);

/**
 * @brief Find the first byte in @p mem that matches any byte in the
 * @p byte set.
 *
 * @param mem   Memory region (may be @c NULL).
 * @param size  Region length in bytes.
 * @param byte  Set of bytes to match (may be @c NULL).
 * @param bytes Number of bytes in @p byte.
 * @return Pointer to the first match, or @c NULL.
 */
R_API rpointer r_mem_scan_byte_any (rconstpointer mem, rsize size,
    const ruint8 * byte, rsize bytes);

/**
 * @brief Find the first occurrence of @p datasize-byte sequence
 * @p data within @p mem.
 *
 * Naive byte-at-a-time search anchored on the first byte of @p data;
 * suitable for small needles. For pattern matching with wildcards use
 * @c r_mem_scan_pattern.
 *
 * @param mem      Haystack (may be @c NULL).
 * @param size     Haystack length in bytes.
 * @param data     Needle bytes (may be @c NULL).
 * @param datasize Needle length in bytes.
 * @return Pointer to the first match within @p mem, or @c NULL.
 */
R_API rpointer r_mem_scan_data (rconstpointer mem, rsize size,
    rconstpointer data, rsize datasize);


/**
 * @brief Token classes produced by the @c r_mem_scan_pattern parser.
 *
 * The pattern grammar reads as ASCII tokens separated by whitespace:
 *  - @c "AA" hex pair → @c R_MEM_TOKEN_BYTES (run of literal bytes)
 *  - @c "??" → @c R_MEM_TOKEN_WILDCARD_SIZED (run of N wildcard bytes)
 *  - @c "*" → @c R_MEM_TOKEN_WILDCARD (variable-length wildcard)
 */
typedef enum {
  R_MEM_TOKEN_NONE = -1,            /**< Pattern terminator / parse error. */
  R_MEM_TOKEN_BYTES,                /**< Literal byte run (one or more hex pairs). */
  R_MEM_TOKEN_WILDCARD,             /**< Variable-length wildcard (`*`). */
  R_MEM_TOKEN_WILDCARD_SIZED,       /**< Fixed-length wildcard (run of `??`). */
  R_MEM_TOKEN_COUNT
} RMemTokenType;

/**
 * @brief Status codes returned by @c r_mem_scan_pattern.
 */
typedef enum {
  R_MEM_SCAN_RESULT_INVAL             = -4,   /**< @c NULL @p mem / @p pattern / @p result. */
  R_MEM_SCAN_RESULT_OOM               = -3,   /**< Allocator returned @c NULL for the result struct. */
  R_MEM_SCAN_RESULT_INVALID_PATTERN   = -2,   /**< Pattern failed to parse. */
  R_MEM_SCAN_RESULT_PATTERN_NOT_IMPL  = -1,   /**< Pattern uses a feature not supported by this build. */
  R_MEM_SCAN_RESULT_OK                =  0,   /**< Match found; @p *result populated. */
  R_MEM_SCAN_RESULT_NOT_FOUND                 /**< Parsed cleanly, no match in @p mem. */
} RMemScanResultType;

/**
 * @brief One token of a parsed scan pattern.
 *
 * @c type identifies the token class; @c pattern points back at the
 * pattern string for the token's text; @c chunk locates the matching
 * bytes inside the haystack once the scan succeeds.
 */
typedef struct _RMemScanToken {
  RMemTokenType type;               /**< Token class. */
  const rchar * pattern;            /**< Borrowed pointer into the original pattern string. */
  RMemChunk chunk;                  /**< Matched bytes inside the haystack. */
} RMemScanToken;

/**
 * @brief Result of a successful @c r_mem_scan_pattern call.
 *
 * Allocated by @c r_mem_scan_pattern, owned by the caller -
 * release with @c r_free. @c tokens is the parsed-token count; the
 * variable-length @c token[] holds one @c RMemScanToken per pattern
 * token, in order.
 *
 * @c ptr / @c end span the full match inside the haystack (closed-
 * open interval).
 */
typedef struct _RMemScanResult {
  rpointer ptr;                     /**< First byte of the overall match. */
  rpointer end;                     /**< One past the last byte of the overall match. */
  rsize tokens;                     /**< Number of entries in @c token[]. */
  RMemScanToken token[0];           /**< Per-token chunks, length @c tokens. */
} RMemScanResult;

/**
 * @brief Find the first match for @p pattern in @p mem (simple form).
 *
 * Wraps @c r_mem_scan_pattern for the common case where the caller
 * only wants the match start (and optionally end) and doesn't need
 * the per-token breakdown.
 *
 * @param mem     Haystack.
 * @param size    Haystack length in bytes.
 * @param pattern NUL-terminated pattern string.
 * @param end     If non-NULL, receives one past the last byte of the
 *                match.
 * @return Pointer to the first byte of the match, or @c NULL on no
 *         match / parse error / OOM.
 */
R_API rpointer r_mem_scan_simple_pattern (rconstpointer mem, rsize size,
    const rchar * pattern, rpointer * end);

/**
 * @brief Find the first match for @p pattern in @p mem, returning
 * full per-token detail.
 *
 * Allocates an @c RMemScanResult sized to the parsed token count;
 * the caller releases it with @c r_free. See @c RMemTokenType for the
 * pattern grammar.
 *
 * @param mem     Haystack (must be non-NULL).
 * @param size    Haystack length in bytes.
 * @param pattern NUL-terminated pattern string (must be non-NULL).
 * @param result  Receives the freshly-allocated result struct (must
 *                be non-NULL). Set to @c NULL if no allocation was
 *                attempted.
 * @return @c R_MEM_SCAN_RESULT_OK on match,
 *         @c R_MEM_SCAN_RESULT_NOT_FOUND if the pattern parsed but
 *         didn't match,
 *         a negative @c RMemScanResultType code on error.
 */
R_API RMemScanResultType r_mem_scan_pattern (rconstpointer mem, rsize size,
    const rchar * pattern, RMemScanResult ** result);

R_END_DECLS

/** @} */

#endif /* __R_MEM_H__ */

