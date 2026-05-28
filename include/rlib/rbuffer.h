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
#ifndef __R_BUFFER_H__
#define __R_BUFFER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rbuffer.h
 * @brief Refcounted, multi-segment byte buffer backed by pluggable
 * @c RMemAllocator chunks.
 */

#include <rlib/rtypes.h>
#include <rlib/rmemallocator.h>
#include <rlib/rref.h>

#include <stdarg.h>

/**
 * @defgroup r_buffer Buffers (RBuffer)
 * @ingroup r_mem
 *
 * @brief Refcounted byte container that holds an ordered list of
 * @c RMem chunks.
 *
 * Inspired by GStreamer's @c GstBuffer: a single logical byte stream
 * composed of multiple @c RMem segments, each backed by a possibly
 * different @c RMemAllocator. Operations like @ref r_buffer_view,
 * @ref r_buffer_merge_take and @ref r_buffer_append_view manipulate
 * the segment list without copying the underlying memory when
 * possible.
 *
 * To read or write contiguous bytes, map a range with
 * @ref r_buffer_map (or one of the @c _range variants) and pair
 * with @ref r_buffer_unmap. For one-shot scalar copies use
 * @ref r_buffer_fill / @ref r_buffer_extract.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted multi-segment byte buffer. */
typedef struct RBuffer RBuffer;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_buffer_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_buffer_unref  r_ref_unref

/** @name Construction
 *  @{ */
/** @brief Empty buffer with no segments. */
R_API RBuffer * r_buffer_new (void);
/** @brief Buffer with one fresh segment allocated by @p allocator. */
R_API RBuffer * r_buffer_new_alloc (RMemAllocator * allocator, rsize allocsize,
    const RMemAllocationParams * params);
/**
 * @brief Wrap an externally-owned buffer.
 *
 * @param flags       Memory flags to apply to the wrapped segment.
 * @param data        Pointer to the user-owned bytes.
 * @param allocsize   Size of the allocation backing @p data.
 * @param size        Initial usable size (<= @p allocsize).
 * @param offset      Initial offset into @p data.
 * @param user        Opaque pointer forwarded to @p usernotify.
 * @param usernotify  Destructor called when the wrapping segment
 *                    is freed; receives @p user.
 */
R_API RBuffer * r_buffer_new_wrapped (RMemFlags flags, rpointer data,
    rsize allocsize, rsize size, rsize offset, rpointer user, RDestroyNotify usernotify);
/** @brief Wrap @p data and free it with @ref r_free when the segment dies. */
static inline RBuffer * r_buffer_new_take (rpointer data, rsize size)
{ return r_buffer_new_wrapped (R_MEM_FLAG_NONE, data, size, size, 0, data, r_free); }
/** @brief Allocate-and-copy @p data, returning a wrapping buffer. */
static inline RBuffer * r_buffer_new_dup (rconstpointer data, rsize size)
{ return r_buffer_new_take (r_memdup (data, size), size); }
/** @brief Zero-copy view of @p size bytes from @p from at @p offset. */
R_API RBuffer * r_buffer_view (RBuffer * from, rsize offset, rssize size);
/** @brief Deep copy of @p size bytes from @p from at @p offset. */
R_API RBuffer * r_buffer_copy (RBuffer * from, rsize offset, rssize size);
/** @} */

/** @name Inspection
 *  @{ */
/** @brief @c TRUE iff every segment is writable (refcount 1, no read-only flag). */
R_API rboolean r_buffer_is_all_writable (const RBuffer * buffer);
/** @brief @c TRUE iff the segment at @p idx is writable. */
R_API rboolean r_buffer_mem_is_writable (const RBuffer * buffer, ruint idx);
/** @brief Total usable byte count summed over all segments. */
R_API rsize r_buffer_get_size (const RBuffer * buffer);
/** @brief Total allocated byte count summed over all segments. */
R_API rsize r_buffer_get_allocsize (const RBuffer * buffer);
/** @brief Sum of the per-segment leading offsets. */
R_API rsize r_buffer_get_offset (const RBuffer * buffer);
/** @} */

/** @name Segment manipulation
 *  @{ */
/** @brief Number of @c RMem segments in @p buffer. */
R_API ruint r_buffer_mem_count (const RBuffer * buffer);
/** @brief Insert @p mem at segment position @p idx. */
R_API rboolean r_buffer_mem_insert (RBuffer * buffer, RMem * mem, ruint idx);
/** @brief Prepend @p mem as the new first segment. */
R_API rboolean r_buffer_mem_prepend (RBuffer * buffer, RMem * mem);
/** @brief Append @p mem as the new last segment. */
R_API rboolean r_buffer_mem_append (RBuffer * buffer, RMem * mem);
/**
 * @brief Replace @p mem_count segments starting at @p idx with @p mem.
 * @param buffer    Target buffer.
 * @param idx       Position of the first segment to replace.
 * @param mem_count Number of segments to replace, or @c -1 for all.
 * @param mem       Replacement segment.
 */
R_API rboolean r_buffer_mem_replace_range (RBuffer * buffer,
    ruint idx, int mem_count, RMem * mem) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Replace one segment at @p idx with @p mem. */
#define r_buffer_mem_replace(buf, idx, mem) \
  r_buffer_mem_replace_range (buf, idx, 1, mem)
/** @brief Replace every segment with a single @p mem. */
#define r_buffer_mem_replace_all(buf, mem) \
  r_buffer_mem_replace_range (buf, 0, -1, mem)
/** @brief Peek at the segment at @p idx (caller takes a reference). */
R_API RMem * r_buffer_mem_peek (RBuffer * buffer, ruint idx) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Remove and return the segment at @p idx. */
R_API RMem * r_buffer_mem_remove (RBuffer * buffer, ruint idx) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Drop every segment from @p buffer. */
R_API void r_buffer_mem_clear (RBuffer * buffer);
/**
 * @brief Locate the segments that cover @p size bytes starting at @p offset.
 *
 * Sets @p idx to the first covering segment, @p count to how many
 * are needed, @p first_offset to the byte offset inside the first
 * segment, and @p last_size to the bytes used inside the last.
 */
R_API rboolean r_buffer_mem_find (const RBuffer * buffer, rsize offset, rssize size,
    ruint * idx, ruint * count, rsize * first_offset, rsize * last_size);
/** @} */

/** @name Append, merge and replace
 *  @{ */
/** @brief Append all of @p from's segments onto @p buffer (zero-copy). */
R_API rboolean r_buffer_append_mem_from_buffer (RBuffer * buffer, RBuffer * from);
/** @brief Append a view of @p from's byte range onto @p buffer (zero-copy). */
R_API rboolean r_buffer_append_view (RBuffer * buffer, RBuffer * from,
    rsize offset, rssize size);
/**
 * @brief Merge a @c NULL-terminated list of buffers; takes ownership
 * of every input.
 */
R_API RBuffer * r_buffer_merge_take (RBuffer * a, ...) R_ATTR_NULL_TERMINATED R_ATTR_WARN_UNUSED_RESULT;
/** @brief @c va_list variant of @ref r_buffer_merge_take. */
R_API RBuffer * r_buffer_merge_takev (RBuffer * a, va_list args) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Array variant of @ref r_buffer_merge_take. */
R_API RBuffer * r_buffer_merge_take_array (RBuffer ** a, ruint count) R_ATTR_WARN_UNUSED_RESULT;
/**
 * @brief Splice @p from into @p buffer over the byte range
 * [@p offset, @p offset + @p size).
 * @return A new buffer; the inputs are left unchanged.
 */
R_API RBuffer * r_buffer_replace_byte_range (RBuffer * buffer,
    rsize offset, rssize size, RBuffer * from) R_ATTR_WARN_UNUSED_RESULT;
/** @} */

/** @name Resize
 *  @{ */
/** @brief Adjust @p buffer to view @p size bytes starting at @p offset. */
R_API rboolean r_buffer_resize (RBuffer * buffer, rsize offset, rsize size);
/** @brief Truncate @p buffer down to @p size bytes. */
R_API rboolean r_buffer_shrink (RBuffer * buffer, rsize size);
/** @brief Alias for @ref r_buffer_shrink. */
#define r_buffer_set_size(buf, size) r_buffer_shrink (buf, size)
/** @} */

/** @name Mapping (contiguous access)
 *  @{ */
/** @brief Map the entire buffer with @p flags. */
#define r_buffer_map(buf, info, flags) \
  r_buffer_map_mem_range (buf, 0, -1, info, flags)
/**
 * @brief Map a segment range. If the range spans multiple segments
 * a temporary contiguous copy is built; @ref r_buffer_unmap writes
 * it back when needed.
 */
R_API rboolean r_buffer_map_mem_range (RBuffer * buffer, ruint idx, int mem_count,
    RMemMapInfo * info, RMemMapFlags flags);
/** @brief Map a byte range; offsets / sizes can straddle segment boundaries. */
R_API rboolean r_buffer_map_byte_range (RBuffer * buffer, rsize offset, rssize size,
    RMemMapInfo * info, RMemMapFlags flags);
/** @brief Release a mapping; commits writes if the map was writable. */
R_API rboolean r_buffer_unmap (RBuffer * buffer, RMemMapInfo * info);
/** @} */

/** @name Bulk copy
 *  @{ */
/** @brief Copy @p size bytes from @p src into @p buffer at @p offset. */
R_API rsize r_buffer_fill (RBuffer * buffer, rsize offset, rconstpointer src, rsize size);
/** @brief Copy @p size bytes (or @c -1 for all) from @p buffer at @p offset into @p dst. */
R_API rsize r_buffer_extract (RBuffer * buffer, rsize offset, rpointer dst, rssize size);
/**
 * @brief Allocate-and-copy @p size bytes from @p buffer.
 * @param buffer  Source buffer.
 * @param offset  Starting offset.
 * @param size    Byte count to extract, or @c -1 for the rest.
 * @param dstsize Optional out-pointer that receives the actual byte count.
 */
R_API rpointer r_buffer_extract_dup (RBuffer * buffer, rsize offset, rssize size, rsize * dstsize);
/** @brief @ref r_buffer_extract_dup over the whole buffer. */
#define r_buffer_extract_dup_all(buf, dstsize) r_buffer_extract_dup (buf, 0, -1, dstsize)
/** @brief @c memcmp across two buffers. */
R_API int   r_buffer_cmp (RBuffer * buf1, rsize offset1, RBuffer * buf2, rsize offset2, rsize size);
/** @brief @c memcmp between a buffer and a flat byte array. */
R_API int   r_buffer_memcmp (RBuffer * buffer, rsize offset, rconstpointer mem, rsize size);
/** @brief @c memset @p val into @p buffer starting at @p offset. */
R_API rsize r_buffer_memset (RBuffer * buffer, rsize offset, ruint8 val, rsize size);
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_BUFFER_H__ */

