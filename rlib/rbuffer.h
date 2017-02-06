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

#include <rlib/rtypes.h>
#include <rlib/rmemallocator.h>
#include <rlib/rref.h>

#include <stdarg.h>

/**
 * The implementation of RBuffer is heavily inspired by GStreamer equivalent,
 * namely GstBuffer. RBuffer is an abstraction of memory chunks backed by
 * different RMemAllocator backends. Default is the system memory allocator.
 */

R_BEGIN_DECLS

typedef struct _RBuffer RBuffer;
#define r_buffer_ref    r_ref_ref
#define r_buffer_unref  r_ref_unref

R_API RBuffer * r_buffer_new (void);
R_API RBuffer * r_buffer_new_alloc (RMemAllocator * allocator, rsize allocsize,
    const RMemAllocationParams * params);
R_API RBuffer * r_buffer_new_wrapped (RMemFlags flags, rpointer data,
    rsize allocsize, rsize size, rsize offset, rpointer user, RDestroyNotify usernotify);
static inline RBuffer * r_buffer_new_take (rpointer data, rsize size)
{ return r_buffer_new_wrapped (R_MEM_FLAG_NONE, data, size, size, 0, data, r_free); }
static inline RBuffer * r_buffer_new_dup (rconstpointer data, rsize size)
{ return r_buffer_new_take (r_memdup (data, size), size); }
R_API RBuffer * r_buffer_view (RBuffer * from, rsize offset, rssize size);
R_API RBuffer * r_buffer_copy (RBuffer * from, rsize offset, rssize size);

R_API rboolean r_buffer_is_all_writable (const RBuffer * buffer);
R_API rboolean r_buffer_mem_is_writable (const RBuffer * buffer, ruint idx);
R_API rsize r_buffer_get_size (const RBuffer * buffer);
R_API rsize r_buffer_get_allocsize (const RBuffer * buffer);
R_API rsize r_buffer_get_offset (const RBuffer * buffer);

R_API ruint r_buffer_mem_count (const RBuffer * buffer);
R_API rboolean r_buffer_mem_insert (RBuffer * buffer, RMem * mem, ruint idx);
R_API rboolean r_buffer_mem_prepend (RBuffer * buffer, RMem * mem);
R_API rboolean r_buffer_mem_append (RBuffer * buffer, RMem * mem);
R_API rboolean r_buffer_mem_replace_range (RBuffer * buffer,
    ruint idx, int mem_count, RMem * mem) R_ATTR_WARN_UNUSED_RESULT;
#define r_buffer_mem_replace(buf, idx, mem) \
  r_buffer_mem_replace_range (buf, idx, 1, mem)
#define r_buffer_mem_replace_all(buf, mem) \
  r_buffer_mem_replace_range (buf, 0, -1, mem)
R_API RMem * r_buffer_mem_peek (RBuffer * buffer, ruint idx) R_ATTR_WARN_UNUSED_RESULT;
R_API RMem * r_buffer_mem_remove (RBuffer * buffer, ruint idx) R_ATTR_WARN_UNUSED_RESULT;
R_API void r_buffer_mem_clear (RBuffer * buffer);
R_API rboolean r_buffer_mem_find (const RBuffer * buffer, rsize offset, rssize size,
    ruint * idx, ruint * count, rsize * first_offset, rsize * last_size);

R_API rboolean r_buffer_append_mem_from_buffer (RBuffer * buffer, RBuffer * from);
R_API rboolean r_buffer_append_view (RBuffer * buffer, RBuffer * from,
    rsize offset, rssize size);
R_API RBuffer * r_buffer_merge_take (RBuffer * a, ...) R_ATTR_NULL_TERMINATED R_ATTR_WARN_UNUSED_RESULT;
R_API RBuffer * r_buffer_merge_takev (RBuffer * a, va_list args) R_ATTR_WARN_UNUSED_RESULT;
R_API RBuffer * r_buffer_merge_take_array (RBuffer ** a, ruint count) R_ATTR_WARN_UNUSED_RESULT;
R_API RBuffer * r_buffer_replace_byte_range (RBuffer * buffer,
    rsize offset, rssize size, RBuffer * from) R_ATTR_WARN_UNUSED_RESULT;

R_API rboolean r_buffer_resize (RBuffer * buffer, rsize offset, rsize size);
R_API rboolean r_buffer_shrink (RBuffer * buffer, rsize size);
#define r_buffer_set_size(buf, size) r_buffer_shrink (buf, size)

#define r_buffer_map(buf, info, flags) \
  r_buffer_map_mem_range (buf, 0, -1, info, flags)
R_API rboolean r_buffer_map_mem_range (RBuffer * buffer, ruint idx, int mem_count,
    RMemMapInfo * info, RMemMapFlags flags);
R_API rboolean r_buffer_map_byte_range (RBuffer * buffer, rsize offset, rssize size,
    RMemMapInfo * info, RMemMapFlags flags);
R_API rboolean r_buffer_unmap (RBuffer * buffer, RMemMapInfo * info);

R_API rsize r_buffer_fill (RBuffer * buffer, rsize offset, rconstpointer src, rsize size);
R_API rsize r_buffer_extract (RBuffer * buffer, rsize offset, rpointer dst, rssize size);
R_API rpointer r_buffer_extract_dup (RBuffer * buffer, rsize offset, rssize size, rsize * dstsize);
#define r_buffer_extract_dup_all(buf, dstsize) r_buffer_extract_dup (buf, 0, -1, dstsize)
R_API int   r_buffer_cmp (RBuffer * buf1, rsize offset1, RBuffer * buf2, rsize offset2, rsize size);
R_API int   r_buffer_memcmp (RBuffer * buffer, rsize offset, rconstpointer mem, rsize size);
R_API rsize r_buffer_memset (RBuffer * buffer, rsize offset, ruint8 val, rsize size);

R_END_DECLS

#endif /* __R_BUFFER_H__ */

