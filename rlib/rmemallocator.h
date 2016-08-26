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
#ifndef __R_MEM_ALLOCATOR_H__
#define __R_MEM_ALLOCATOR_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <stdarg.h>

R_BEGIN_DECLS

typedef enum {
  R_MEM_FLAG_NONE             = 0,
  R_MEM_FLAG_READONLY         = (1 << 0),
  R_MEM_FLAG_NO_VIEWS         = (1 << 1),
  R_MEM_FLAG_ZERO_PREFIXED    = (1 << 2),
  R_MEM_FLAG_ZERO_PADDED      = (1 << 3),
} RMemFlag;
typedef ruint32 RMemFlags;

typedef enum {
  R_MEM_MAP_READ      = (1 << 0),
  R_MEM_MAP_WRITE     = (1 << 1),
} RMemMapFlag;
#define R_MEM_MAP_RW    (R_MEM_MAP_READ | R_MEM_MAP_WRITE)
typedef ruint32 RMemMapFlags;

#define R_MEM_ALLOCATOR_SYSTEM        "system"
typedef struct _RMemAllocator         RMemAllocator;
typedef struct _RMem                  RMem;

typedef struct {
  RMemFlags       flags;
  rsize           alignmask;
  rsize           prefix;
  rsize           padding;
} RMemAllocationParams;

#define R_MEM_MAP_INFO_INIT { NULL, 0, 0, 0, NULL }
typedef struct {
  ruint8 *      data;
  rsize         size;
  rsize         allocsize;
  RMemMapFlags  flags;
  RMem *        mem;
} RMemMapInfo;


/******************************************************************************/
/* RMem - Memory chunks                                                       */
/******************************************************************************/

/* Convenience for wrapping normal system memory */
R_API RMem * r_mem_new_wrapped (RMemFlags flags, rpointer data, rsize allocsize,
    rsize size, rsize offset, rpointer user, RDestroyNotify usernotify) R_ATTR_WARN_UNUSED_RESULT;
#define r_mem_new_take(flags, data, allocsize, size, offset)                  \
  r_mem_new_wrapped (flags, data, allocsize, size, offset, data, r_free)

/* Abstract RMem functionality */

#define r_mem_ref     r_ref_ref
#define r_mem_unref   r_ref_unref
R_API rboolean  r_mem_resize (RMem * mem, rsize offset, rsize size);
R_API rboolean  r_mem_map   (RMem * mem, RMemMapInfo * info, RMemMapFlags flags);
R_API rboolean  r_mem_unmap (RMem * mem, RMemMapInfo * info);
R_API RMem *    r_mem_copy  (RMem * mem, rssize offset, rssize size) R_ATTR_WARN_UNUSED_RESULT;
R_API RMem *    r_mem_view  (RMem * mem, rssize offset, rssize size) R_ATTR_WARN_UNUSED_RESULT;
R_API RMem *    r_mem_merge (const RMemAllocationParams * params,
    RMem * a, ...) R_ATTR_NULL_TERMINATED R_ATTR_WARN_UNUSED_RESULT;
R_API RMem *    r_mem_mergev (const RMemAllocationParams * params,
    RMem * a, va_list args) R_ATTR_WARN_UNUSED_RESULT;
R_API RMem *    r_mem_merge_array (const RMemAllocationParams * params,
    RMem ** mems, ruint count) R_ATTR_WARN_UNUSED_RESULT;
#define r_mem_is_readonly(mem)        (mem->flags & R_MEM_FLAG_READONLY)
#define r_mem_is_writable(mem)       ((mem->flags & R_MEM_FLAG_READONLY) == 0)
#define r_mem_is_zero_prefixed(mem)   (mem->flags & R_MEM_FLAG_ZERO_PREFIXED)
#define r_mem_is_zero_padded(mem)     (mem->flags & R_MEM_FLAG_ZERO_PADDED)

struct _RMem {
  RRef            ref;
  RMemFlags       flags;
  RMemAllocator * allocator;
  RMem *          parent;

  rsize           allocsize;
  rsize           size;
  rsize           alignmask;
  rsize           offset;
};

/* Theses should only be called from the spesific RMem implementations */
R_API void      r_mem_init  (RMem * mem, RDestroyNotify notify,
    RMemFlags flags, RMemAllocator * allocator, RMem * parent,
    rsize allocsize, rsize size, rsize alignmask, rsize offset);
R_API void      r_mem_clear (RMem * mem);


/******************************************************************************/
/* RMemAllocator - Memory allocator                                           */
/******************************************************************************/

/* Getting/finding and registering allocators */
#define r_mem_allocator_default() r_mem_allocator_find (R_MEM_ALLOCATOR_SYSTEM)
R_API RMemAllocator * r_mem_allocator_find            (const rchar * name) R_ATTR_WARN_UNUSED_RESULT;
R_API void            r_mem_allocator_register        (RMemAllocator * allocator);

/* Abstract RMemAllocator functionality */
#define r_mem_allocator_ref   r_ref_ref
#define r_mem_allocator_unref r_ref_unref
R_API RMem * r_mem_allocator_alloc_full (RMemAllocator * allocator, rsize size,
    const RMemAllocationParams * params) R_ATTR_WARN_UNUSED_RESULT;
static inline RMem *
r_mem_allocator_alloc (RMemAllocator * allocator, RMemFlags flags, rsize size,
    rsize prefix, rsize padding, rsize alignmask)
{
  RMemAllocationParams params = { flags, alignmask, prefix, padding };
  return r_mem_allocator_alloc_full (allocator, size, &params);
}

struct _RMemAllocator {
  RRef            ref;
  const rchar *   mem_type;
  rsize           alignmask;

  RMem *    (*alloc)  (RMemAllocator * allocator, rsize size, const RMemAllocationParams * params);
  rboolean  (*free)   (RMemAllocator * allocator, RMem * mem);
  rpointer  (*map)    (RMem * mem, const RMemMapInfo * info);
  rboolean  (*unmap)  (RMem * mem, const RMemMapInfo * info);
  RMem *    (*merge)  (const RMemAllocationParams * params, RMem ** mems, ruint count);
  RMem *    (*copy)   (RMem * mem, rssize offset, rssize size);
  RMem *    (*view)   (RMem * mem, rssize offset, rssize size);
};


R_END_DECLS

#endif /* __R_MEM_ALLOCATOR_H__ */

