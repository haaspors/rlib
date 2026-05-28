/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
 * @defgroup r_mem_allocator Refcounted memory chunks and pluggable allocators
 * @ingroup r_mem
 * @brief Abstract memory-chunk type (@c RMem) with a pluggable
 * backend (@c RMemAllocator). Inspired by GStreamer's @c GstMemory /
 * @c GstAllocator design.
 * @{
 */

/**
 * @file rlib/rmemallocator.h
 * @brief Refcounted memory-chunk abstraction with allocator vtables.
 *
 * @c RMem wraps a byte region (with @p allocsize total bytes plus a
 * visible @p offset / @p size window) and routes operations through
 * an @c RMemAllocator vtable - so the same client-side API works on
 * heap memory, shared memory, GPU-mapped buffers, file mappings,
 * etc. Each chunk carries flags (read-only, view-prohibited, zero-
 * prefixed / -padded) that the high-level helpers honour.
 *
 * Allocators are looked up by name (@c R_MEM_ALLOCATOR_SYSTEM is the
 * default heap allocator). Custom allocators register themselves at
 * init time and become discoverable via @c r_mem_allocator_find.
 *
 * **Reference counting**: both @c RMem and @c RMemAllocator are
 * @c RRef-based; use the @c _ref / @c _unref helpers.
 *
 * **Mapping**: to read or write the underlying bytes, wrap accesses
 * in @c r_mem_map / @c r_mem_unmap - the @c RMemMapInfo carries the
 * data pointer plus the allocator-specific bookkeeping that
 * @c unmap needs.
 *
 * The implementation of @c RMem and @c RMemAllocator is heavily
 * inspired by the GStreamer equivalents.
 */
#ifndef __R_MEM_ALLOCATOR_H__
#define __R_MEM_ALLOCATOR_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

#include <rlib/rtypes.h>
#include <rlib/rmem.h>
#include <rlib/rref.h>

#include <stdarg.h>

R_BEGIN_DECLS

/**
 * @brief Per-chunk flags carried on every @c RMem.
 *
 * Combined as a bitmask in @c RMemFlags. Honoured by the high-level
 * helpers (read-only chunks reject @c r_mem_resize and write
 * mappings; view-prohibited chunks reject @c r_mem_view).
 */
typedef enum {
  R_MEM_FLAG_NONE             = 0,            /**< No flags. */
  R_MEM_FLAG_READONLY         = (1 << 0),     /**< Underlying bytes are immutable. */
  R_MEM_FLAG_NO_VIEWS         = (1 << 1),     /**< @c r_mem_view will refuse to create aliased subviews. */
  R_MEM_FLAG_ZERO_PREFIXED    = (1 << 2),     /**< The bytes before @p offset are known to be zero. */
  R_MEM_FLAG_ZERO_PADDED      = (1 << 3),     /**< The bytes after @p offset+@p size are known to be zero. */
} RMemFlag;

/** @brief Bitmask of @c RMemFlag values. */
typedef ruint32 RMemFlags;

/**
 * @brief Mapping-access flags passed to @c r_mem_map.
 *
 * Choose @c R_MEM_MAP_READ for read-only access, @c R_MEM_MAP_WRITE
 * for write-only, or @c R_MEM_MAP_RW for both. Allocator-specific
 * extensions may use bits up to @c R_MEM_MAP_FLAG_LAST.
 */
typedef enum {
  R_MEM_MAP_READ      = (1 << 0),             /**< Caller will read from the mapping. */
  R_MEM_MAP_WRITE     = (1 << 1),             /**< Caller will write to the mapping. */
  R_MEM_MAP_FLAG_LAST = (1 << 8)              /**< Reserved cutoff; allocator-specific bits live below. */
} RMemMapFlag;

/** @brief Convenience: read + write access. */
#define R_MEM_MAP_RW    (R_MEM_MAP_READ | R_MEM_MAP_WRITE)

/** @brief Bitmask of @c RMemMapFlag values. */
typedef ruint32 RMemMapFlags;

/** @brief Name of the built-in system / heap allocator. */
#define R_MEM_ALLOCATOR_SYSTEM        "system"

/** @brief Opaque handle to an allocator backend. */
typedef struct RMemAllocator         RMemAllocator;
/** @brief Opaque handle to a refcounted memory chunk. */
typedef struct RMem                  RMem;

/**
 * @brief Allocation-time constraints passed to @c r_mem_allocator_alloc
 * and the merge / take helpers.
 *
 * @c flags seed the resulting chunk; @c alignmask, @c prefix and
 * @c padding constrain the layout (alignment of the visible region
 * plus pad bytes before / after).
 */
typedef struct {
  RMemFlags       flags;            /**< Initial flags on the produced chunk. */
  rsize           alignmask;        /**< Power-of-two-minus-one alignment of the visible region (e.g. 0x0F = 16-byte aligned). */
  rsize           prefix;           /**< Bytes of guaranteed-zero padding before the visible region. */
  rsize           padding;          /**< Bytes of guaranteed-zero padding after the visible region. */
} RMemAllocationParams;

/** @brief Zero-init for an @c RMemMapInfo declared on the stack. */
#define R_MEM_MAP_INFO_INIT { NULL, 0, 0, 0, NULL }

/**
 * @brief Scope object carried by an active mapping.
 *
 * Populated by @c r_mem_map, passed back unchanged to
 * @c r_mem_unmap so the allocator can release whatever resources the
 * mapping acquired (file handles, GPU sync points, etc.). @c data is
 * the bytes the caller can touch; @c size is the visible-window
 * length, @c allocsize is the underlying allocation length.
 */
typedef struct {
  ruint8 *      data;               /**< Pointer to the first visible byte. */
  rsize         size;               /**< Visible window length in bytes. */
  rsize         allocsize;          /**< Underlying allocation length in bytes. */
  RMemMapFlags  flags;              /**< Mapping access flags supplied to @c r_mem_map. */
  RMem *        mem;                /**< Owning chunk (refcounted by @c r_mem_map, released by @c r_mem_unmap). */
} RMemMapInfo;


/******************************************************************************/
/* RMem - Memory chunks                                                       */
/******************************************************************************/

/**
 * @brief Wrap an existing pointer in an @c RMem without copying.
 *
 * Used to hand raw bytes to a system that expects @c RMem-shaped
 * input (e.g. zero-copy ingestion of a parsed file). The
 * @p usernotify callback runs (with @p user as argument) when the
 * last reference drops, so the caller controls cleanup.
 *
 * @param flags      Initial @c RMemFlags (typically @c R_MEM_FLAG_READONLY
 *                   for borrowed buffers).
 * @param data       Pointer to the first byte.
 * @param allocsize  Underlying allocation length in bytes.
 * @param size       Visible window length in bytes.
 * @param offset     Visible window offset within @p data.
 * @param user       Cookie passed to @p usernotify on free.
 * @param usernotify Destroy callback (may be @c NULL for borrowed memory).
 * @return New @c RMem reference, or @c NULL on allocation failure.
 */
R_API RMem * r_mem_new_wrapped (RMemFlags flags, rpointer data, rsize allocsize,
    rsize size, rsize offset, rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;

/**
 * @brief Wrap an existing heap allocation in an @c RMem and transfer
 * ownership.
 *
 * Convenience for the common case where the wrapped buffer was
 * obtained from @c r_malloc: when the last reference drops the
 * wrapper calls @c r_free on @p data. Equivalent to
 * @c r_mem_new_wrapped @c (flags, data, allocsize, size, offset,
 * data, r_free).
 */
static inline RMem * r_mem_new_take(RMemFlags flags, rpointer data,
    rsize allocsize, rsize size, rsize offset)
{
  return r_mem_new_wrapped (flags, data, allocsize, size, offset, data, r_free);
}

/* Abstract RMem functionality */

/** @brief Acquire a new reference to an @c RMem. */
#define r_mem_ref     r_ref_ref

/** @brief Release a reference; frees the chunk when the last drops. */
#define r_mem_unref   r_ref_unref

/**
 * @brief Adjust the visible window inside @p mem.
 *
 * Moves @p offset and / or shrinks / grows @p size within the
 * underlying allocation. Refuses to operate on read-only chunks or
 * to expand past the allocation bounds. Clears
 * @c R_MEM_FLAG_ZERO_PREFIXED / @c R_MEM_FLAG_ZERO_PADDED when the
 * window moves over the corresponding zero region.
 *
 * @param mem    Chunk to resize (must be writable).
 * @param offset New visible-window offset (bytes from start of
 *               allocation).
 * @param size   New visible-window size in bytes.
 * @return @c TRUE on success, @c FALSE on read-only chunk or
 *         out-of-bounds @p offset + @p size.
 */
R_API rboolean  r_mem_resize (RMem * mem, rsize offset, rsize size);

/**
 * @brief Open a scoped mapping over @p mem's bytes.
 *
 * Acquires an extra reference on @p mem (released by
 * @c r_mem_unmap) and populates @p info with a pointer the caller
 * may read from / write to per @p flags. Write mappings are refused
 * on read-only chunks.
 *
 * @param mem   Chunk to map.
 * @param info  Output @c RMemMapInfo - typically stack-allocated and
 *              initialised with @c R_MEM_MAP_INFO_INIT.
 * @param flags Access flags (@c R_MEM_MAP_READ, @c R_MEM_MAP_WRITE,
 *              or @c R_MEM_MAP_RW).
 * @return @c TRUE on success, @c FALSE on conflicting flags or
 *         allocator-level mapping failure.
 */
R_API rboolean  r_mem_map   (RMem * mem, RMemMapInfo * info, RMemMapFlags flags);

/**
 * @brief Close a mapping previously opened with @c r_mem_map.
 *
 * Calls the allocator's @c unmap callback and releases the @c RMem
 * reference recorded in @p info.
 *
 * @param mem  Chunk that was mapped (must match @p info->mem).
 * @param info The same @c RMemMapInfo that @c r_mem_map populated.
 * @return @c TRUE on successful release, @c FALSE if the allocator
 *         refused (rare; typically a programming error).
 */
R_API rboolean  r_mem_unmap (RMem * mem, RMemMapInfo * info);

/**
 * @brief Deep-copy a byte range from @p mem into a fresh @c RMem.
 *
 * Negative @p offset / @p size are interpreted relative to the
 * chunk's bounds (allocator-specific convention; commonly @p size
 * < 0 means "to end").
 *
 * @param mem    Source chunk.
 * @param offset Offset within @p mem (signed).
 * @param size   Length (signed; negative often means "to end").
 * @return Newly-allocated chunk, or @c NULL on failure.
 */
R_API RMem *    r_mem_copy  (RMem * mem, rssize offset, rssize size) R_ATTR_WARN_UNUSED_RESULT;

/**
 * @brief Create an aliased view onto a byte range of @p mem.
 *
 * The view shares the underlying allocation with @p mem (no copy).
 * Refused if @p mem has @c R_MEM_FLAG_NO_VIEWS.
 *
 * @param mem    Source chunk.
 * @param offset Offset within @p mem (signed).
 * @param size   Length (signed; negative often means "to end").
 * @return New @c RMem reference aliasing @p mem, or @c NULL.
 */
R_API RMem *    r_mem_view  (RMem * mem, rssize offset, rssize size) R_ATTR_WARN_UNUSED_RESULT;

/**
 * @brief Concatenate two or more chunks into a fresh @c RMem.
 *
 * Variadic args are @c RMem* terminated by @c NULL. The inputs are
 * left unchanged (their refcounts are unaffected). Use @c r_mem_take
 * for the equivalent that consumes the inputs.
 *
 * @param params Allocation constraints for the result (may be @c NULL
 *               for defaults).
 * @param a      First chunk (must be non-NULL).
 * @param ...    Remaining chunks, terminated by @c NULL.
 * @return Newly-allocated, fully-populated chunk, or @c NULL.
 */
R_API RMem *    r_mem_merge (const RMemAllocationParams * params,
    RMem * a, ...) R_ATTR_NULL_TERMINATED R_ATTR_WARN_UNUSED_RESULT;

/** @brief @c va_list variant of @c r_mem_merge. */
R_API RMem *    r_mem_mergev (const RMemAllocationParams * params,
    RMem * a, va_list args) R_ATTR_WARN_UNUSED_RESULT;

/** @brief Array variant of @c r_mem_merge - @p mems is a @p count-long array of chunk pointers. */
R_API RMem *    r_mem_merge_array (const RMemAllocationParams * params,
    RMem ** mems, ruint count) R_ATTR_WARN_UNUSED_RESULT;

/**
 * @brief Concatenate chunks (as @c r_mem_merge) but @c unref the inputs.
 *
 * Transfers ownership: on success the supplied chunks are
 * @c r_mem_unref'd. Convenient pattern for assembling a buffer from
 * intermediate scratch chunks the caller doesn't want to keep.
 *
 * @param params Allocation constraints for the result (may be @c NULL).
 * @param a      First chunk.
 * @param ...    Remaining chunks, terminated by @c NULL.
 * @return Newly-allocated chunk, or @c NULL (in which case input
 *         refcounts are untouched).
 */
R_API RMem *    r_mem_take (const RMemAllocationParams * params,
    RMem * a, ...) R_ATTR_NULL_TERMINATED R_ATTR_WARN_UNUSED_RESULT;

/** @brief @c va_list variant of @c r_mem_take. */
R_API RMem *    r_mem_takev (const RMemAllocationParams * params,
    RMem * a, va_list args) R_ATTR_WARN_UNUSED_RESULT;

/** @brief Array variant of @c r_mem_take - consumes references in @p mems on success. */
R_API RMem *    r_mem_take_array (const RMemAllocationParams * params,
    RMem ** mems, ruint count) R_ATTR_WARN_UNUSED_RESULT;

/** @brief @c TRUE if @p mem carries @c R_MEM_FLAG_READONLY. */
#define r_mem_is_readonly(mem)        (mem->flags & R_MEM_FLAG_READONLY)

/** @brief @c TRUE if @p mem can accept writes. */
#define r_mem_is_writable(mem)       ((mem->flags & R_MEM_FLAG_READONLY) == 0)

/** @brief @c TRUE if @p mem carries @c R_MEM_FLAG_ZERO_PREFIXED. */
#define r_mem_is_zero_prefixed(mem)   (mem->flags & R_MEM_FLAG_ZERO_PREFIXED)

/** @brief @c TRUE if @p mem carries @c R_MEM_FLAG_ZERO_PADDED. */
#define r_mem_is_zero_padded(mem)     (mem->flags & R_MEM_FLAG_ZERO_PADDED)

/**
 * @brief Concrete layout of an @c RMem chunk.
 *
 * Fields are visible because allocator implementations need to fill
 * them in; client code should treat the struct as opaque and use the
 * accessor macros (@c r_mem_is_*).
 */
struct RMem {
  RRef            ref;              /**< Refcount base (handled by @c r_ref_ref / @c r_ref_unref). */
  RMemFlags       flags;            /**< @c RMemFlag bitmask. */
  RMemAllocator * allocator;        /**< Backend that produced this chunk. */
  RMem *          parent;           /**< Parent chunk for view aliases, @c NULL otherwise. */

  rsize           allocsize;        /**< Total underlying allocation length. */
  rsize           size;             /**< Visible window length. */
  rsize           alignmask;        /**< Alignment guarantee on the visible region (power-of-two minus one). */
  rsize           offset;           /**< Visible window offset within @c allocsize. */
};

/**
 * @brief Allocator-implementation helper: populate an @c RMem's
 * common fields and arm its destructor.
 *
 * Intended only for use inside an @c RMemAllocator's @c alloc
 * callback. Not part of the public client API.
 *
 * @param mem        Memory chunk to initialise.
 * @param notify     Destroy callback invoked when the last reference drops.
 * @param flags      Initial @c RMemFlags.
 * @param allocator  Owning allocator (must be ref-counted).
 * @param parent     Parent chunk for view aliases, @c NULL otherwise.
 * @param allocsize  Underlying allocation length.
 * @param size       Visible window length.
 * @param alignmask  Alignment guarantee on the visible region.
 * @param offset     Visible window offset within @p allocsize.
 */
R_API void      r_mem_init  (RMem * mem, RDestroyNotify notify,
    RMemFlags flags, RMemAllocator * allocator, RMem * parent,
    rsize allocsize, rsize size, rsize alignmask, rsize offset);

/**
 * @brief Allocator-implementation helper: release the references an
 * @c RMem holds (parent, allocator).
 *
 * Intended only for use inside an @c RMemAllocator's @c free
 * callback before it releases the chunk's backing storage.
 *
 * @param mem Memory chunk being torn down.
 */
R_API void      r_mem_clear (RMem * mem);


/******************************************************************************/
/* RMemAllocator - Memory allocator                                           */
/******************************************************************************/

/**
 * @brief Convenience for the built-in system / heap allocator.
 *
 * Equivalent to @c r_mem_allocator_find(@c R_MEM_ALLOCATOR_SYSTEM).
 */
#define r_mem_allocator_default() r_mem_allocator_find (R_MEM_ALLOCATOR_SYSTEM)

/**
 * @brief Look up a registered allocator by name.
 *
 * Returns a new reference on success (caller releases with
 * @c r_mem_allocator_unref).
 *
 * @param name Allocator name (e.g. @c R_MEM_ALLOCATOR_SYSTEM).
 * @return New allocator reference, or @c NULL if no allocator with
 *         that name is registered.
 */
R_API RMemAllocator * r_mem_allocator_find            (const rchar * name) R_ATTR_WARN_UNUSED_RESULT;

/**
 * @brief Register an allocator so it can be looked up by name.
 *
 * Adds @p allocator to the process-wide registry under @p allocator->mem_type.
 * The registry takes a reference; the caller may safely drop its
 * own reference afterwards.
 *
 * @param allocator Allocator to register (must have a non-NULL
 *                  @c mem_type).
 */
R_API void            r_mem_allocator_register        (RMemAllocator * allocator);

/* Abstract RMemAllocator functionality */

/** @brief Acquire a new reference to an @c RMemAllocator. */
#define r_mem_allocator_ref   r_ref_ref

/** @brief Release a reference to an @c RMemAllocator. */
#define r_mem_allocator_unref r_ref_unref

/**
 * @brief Allocate a new @c RMem chunk via @p allocator.
 *
 * @param allocator Allocator to use (must be non-NULL).
 * @param size      Visible window size in bytes.
 * @param params    Allocation constraints (alignment, prefix /
 *                  padding, initial flags).
 * @return New chunk reference, or @c NULL on failure.
 */
R_API RMem * r_mem_allocator_alloc_full (RMemAllocator * allocator, rsize size,
    const RMemAllocationParams * params) R_ATTR_WARN_UNUSED_RESULT;

/**
 * @brief Convenience for @c r_mem_allocator_alloc_full with the
 * params spelled out as individual arguments.
 */
static inline RMem *
r_mem_allocator_alloc (RMemAllocator * allocator, RMemFlags flags, rsize size,
    rsize prefix, rsize padding, rsize alignmask)
{
  RMemAllocationParams params = { flags, alignmask, prefix, padding };
  return r_mem_allocator_alloc_full (allocator, size, &params);
}

/**
 * @brief Concrete layout of an @c RMemAllocator.
 *
 * Allocator implementations fill in the @c mem_type / @c alignmask
 * fields and the seven vtable slots. Client code treats the struct
 * as opaque and goes through the helpers above.
 */
struct RMemAllocator {
  RRef            ref;              /**< Refcount base. */
  const rchar *   mem_type;         /**< Registry name (e.g. @c R_MEM_ALLOCATOR_SYSTEM). */
  rsize           alignmask;        /**< Native alignment guarantee of this allocator. */

  RMem *    (*alloc)  (RMemAllocator * allocator, rsize size, const RMemAllocationParams * params);  /**< Produce a new chunk. */
  rboolean  (*free)   (RMemAllocator * allocator, RMem * mem);                                       /**< Release a chunk's backing storage. */
  rpointer  (*map)    (RMem * mem, const RMemMapInfo * info);                                        /**< Acquire a data pointer for @c r_mem_map. */
  rboolean  (*unmap)  (RMem * mem, const RMemMapInfo * info);                                        /**< Release the data pointer for @c r_mem_unmap. */
  RMem *    (*merge)  (const RMemAllocationParams * params, RMem ** mems, ruint count);              /**< Concatenate @p mems into a fresh chunk. */
  RMem *    (*copy)   (RMem * mem, rssize offset, rssize size);                                      /**< Deep-copy a byte range. */
  RMem *    (*view)   (RMem * mem, rssize offset, rssize size);                                      /**< Create an aliased view. */
};


R_END_DECLS

/** @} */

#endif /* __R_MEM_ALLOCATOR_H__ */

