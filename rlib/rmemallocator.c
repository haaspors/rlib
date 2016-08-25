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

#include "config.h"
#include "rlib-private.h"
#include <rlib/rmemallocator.h>

#include <rlib/rassert.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

static RMemAllocator ** g__r_mem_allocator = NULL;
static rsize g__r_mem_allocator_size = 0;
static rsize g__r_mem_allocator_idx = 0;
static const RMemAllocationParams g__r_mem_defparams = { R_MEM_FLAG_NONE, 0, 0, 0 };

#define R_MEM_ALLOCATOR_SYSTEM_ALIGNMASK    0x0f

typedef struct {
  RMem mem;
  ruint8 * data;

  rpointer user;
  RDestroyNotify usernotify;
} RSystemMem;

static void
r_system_mem_free (RSystemMem * mem)
{
  if (mem->usernotify != NULL)
    mem->usernotify (mem->user);

  r_mem_clear ((RMem *) mem);
}

static void
r_system_mem_init (RSystemMem * mem, RMemFlags flags,
    RMemAllocator * allocator, RMem * parent,
    rsize allocsize, rsize size, rsize alignmask, rsize offset,
    ruint8 * data, rpointer user, RDestroyNotify usernotify)
{
  r_mem_init (&mem->mem, (RDestroyNotify) r_system_mem_free,
      flags, allocator, parent, allocsize, size, alignmask, offset);
  mem->data = data;
  mem->user = user;
  mem->usernotify = usernotify;
}

static RMem *
r_system_mem_allocator_alloc (RMemAllocator * allocator, rsize size,
    const RMemAllocationParams * params)
{
  rsize allocsize = size + params->prefix + params->padding;
  rsize align = allocator->alignmask | params->alignmask;
  RSystemMem * sysmem = r_malloc (sizeof (RSystemMem) + allocsize + align);
  ruint8 * data = (ruint8 *)(sysmem + 1);
  rsize aoff;

  if ((aoff = RPOINTER_TO_SIZE (data) & align) > 0)
    data += align + 1 - aoff;

  r_system_mem_init (sysmem, params->flags, allocator, NULL,
      allocsize, size, align, params->prefix, data, NULL, NULL);

  if ((params->flags & R_MEM_FLAG_ZERO_PREFIXED) && params->prefix > 0)
    r_memset (data, 0, params->prefix);
  if ((params->flags & R_MEM_FLAG_ZERO_PADDED) && params->padding > 0)
    r_memset (data + params->prefix + size, 0, params->padding);

  return (RMem *)sysmem;
}

static rboolean
r_system_mem_allocator_free (RMemAllocator * allocator, RMem * mem)
{
  (void) allocator;
  r_free (mem);
  return TRUE;
}

static rpointer
r_system_mem_allocator_map (RMem * mem, const RMemMapInfo * info)
{
  RSystemMem * sysmem = (RSystemMem *) mem;
  (void) info;

  return sysmem->data;
}

static rboolean
r_system_mem_allocator_unmap (RMem * mem, const RMemMapInfo * info)
{
  (void) mem;
  (void) info;

  return TRUE;
}

static RMem *
r_system_mem_allocator_copy (RMem * mem, rssize offset, rssize size)
{
  RSystemMem * sysmem = (RSystemMem *) mem;
  RMem * ret;
  RMemAllocationParams params;

  if (R_UNLIKELY (offset < 0 && (rsize)-offset > mem->offset)) return NULL;
  if (size < 0) {
    size = mem->size - offset;
    if (R_UNLIKELY (size < 0)) return NULL;
  }
  if (R_UNLIKELY ((rsize)(offset + size) > mem->allocsize - mem->offset)) return NULL;

  params.flags = R_MEM_FLAG_NONE;
  params.prefix = 0;
  params.padding = 0;
  params.alignmask = mem->alignmask;
  if ((ret = r_system_mem_allocator_alloc (mem->allocator, size, &params)) != NULL)
    r_memcpy (((RSystemMem *)ret)->data, sysmem->data + mem->offset + offset, size);

  return ret;
}

static RMem *
r_system_mem_allocator_view (RMem * mem, rssize offset, rssize size)
{
  RMem * parent;
  RSystemMem * ret;

  if (R_UNLIKELY (mem == NULL)) return NULL;
  parent = mem->parent != NULL ? mem->parent : mem;

  if (R_UNLIKELY (offset < 0 && (rsize)-offset > mem->offset)) return NULL;
  if (size < 0) {
    size = mem->size - offset;
    if (R_UNLIKELY (size < 0)) return NULL;
  }
  if (R_UNLIKELY ((rsize)(offset + size) > mem->allocsize - mem->offset)) return NULL;

  if ((ret = r_mem_new (RSystemMem)) != NULL) {
    r_system_mem_init (ret, parent->flags | R_MEM_FLAG_READONLY,
        parent->allocator, parent, sizeof (RSystemMem), size, parent->alignmask,
        mem->offset + offset, ((RSystemMem *) parent)->data, NULL, NULL);
  }

  return (RMem *) ret;
}


static RMem *
r_system_mem_allocator_merge (const RMemAllocationParams * params,
    RMem ** mems, ruint count)
{
  RMem * ret;
  rsize size;
  ruint i;

  for (i = 0, size = 0; i < count; i++)
    size += mems[i]->size;

  if ((ret = r_system_mem_allocator_alloc (mems[0]->allocator, size, params)) != NULL) {
    ruint8 * dst = ((RSystemMem *) ret)->data + ret->offset;
    RMemMapInfo info;
    for (i = 0; i < count; i++) {
      if (r_mem_map (mems[i], &info, R_MEM_MAP_READ)) {
        r_memcpy (dst, info.data, info.size);
        dst += info.size;
        r_mem_unmap (mems[i], &info);
      } else {
        goto map_error;
      }
    }
  }

  return ret;
map_error:
  r_mem_unref (ret);
  /* R_LOG_WARNING (); */
  return NULL;
}


static RMemAllocator g__r_mem_allocator_system = {
  { 0, NULL },
  R_MEM_ALLOCATOR_SYSTEM, R_MEM_ALLOCATOR_SYSTEM_ALIGNMASK,
  r_system_mem_allocator_alloc,
  r_system_mem_allocator_free,
  r_system_mem_allocator_map,
  r_system_mem_allocator_unmap,
  r_system_mem_allocator_merge,
  r_system_mem_allocator_copy,
  r_system_mem_allocator_view
};

void
r_mem_allocator_init (void)
{
  r_mem_allocator_register (&g__r_mem_allocator_system);
}

void
r_mem_allocator_deinit (void)
{
  rsize i;
  for (i = 0; i < g__r_mem_allocator_idx; i++)
    r_mem_allocator_unref (g__r_mem_allocator[i]);

  r_free (g__r_mem_allocator);
}

RMemAllocator *
r_mem_allocator_find (const rchar * name)
{
  rsize i;
  for (i = 0; i < g__r_mem_allocator_size; i++) {
    if (r_str_equals (g__r_mem_allocator[i]->mem_type, name))
      return r_mem_allocator_ref (g__r_mem_allocator[i]);
  }

  return NULL;
}

void
r_mem_allocator_register (RMemAllocator * allocator)
{
  rsize idx;

  r_assert_cmpuint (RSIZE_POPCOUNT (allocator->alignmask), ==,
      sizeof (rsize) * 8 - RSIZE_CLZ (allocator->alignmask));

  if ((idx = g__r_mem_allocator_idx++) >= g__r_mem_allocator_size) {
    g__r_mem_allocator_size += 16;
    g__r_mem_allocator = r_realloc (g__r_mem_allocator,
        g__r_mem_allocator_size * sizeof (RMemAllocator *));
  }

  g__r_mem_allocator[idx] = allocator;
}

RMem *
r_mem_allocator_alloc_full (RMemAllocator * allocator, rsize size,
    const RMemAllocationParams * params)
{
  if (RSIZE_POPCOUNT (params->alignmask) != sizeof (rsize) * 8 - RSIZE_CLZ (params->alignmask))
    return NULL;

  if (allocator == NULL)
    allocator = &g__r_mem_allocator_system;
  return allocator->alloc (allocator, size, params);
}

void
r_mem_init  (RMem * mem, RDestroyNotify notify, RMemFlags flags,
    RMemAllocator * allocator, RMem * parent,
    rsize allocsize, rsize size, rsize alignmask, rsize offset)
{
  r_ref_init (mem, notify);

  mem->flags = flags;
  mem->allocator = r_mem_allocator_ref (allocator);
  mem->parent = parent != NULL ? r_mem_ref (parent) : NULL;
  mem->allocsize = allocsize;
  mem->size = size;
  mem->alignmask = alignmask;
  mem->offset = offset;
}

void
r_mem_clear (RMem * mem)
{
  RMemAllocator * allocator = mem->allocator;
  if (mem->parent != NULL)
    r_mem_unref (mem->parent);
  allocator->free (allocator, mem);
  r_mem_allocator_unref (allocator);
}

rboolean
r_mem_map (RMem * mem, RMemMapInfo * info, RMemMapFlags flags)
{
  rboolean ret;
  if (R_UNLIKELY (mem == NULL)) return FALSE;
  if (R_UNLIKELY (info == NULL)) return FALSE;

  if (mem->flags & R_MEM_FLAG_READONLY && flags & R_MEM_MAP_WRITE)
    return FALSE;

  info->data = NULL;
  info->flags = flags;
  info->mem = r_mem_ref (mem);
  info->allocsize = mem->allocsize;
  info->size = mem->size;

  if ((ret = (info->data = mem->allocator->map (mem, info)) != NULL))
    info->data += mem->offset;

  return ret;
}

rboolean
r_mem_unmap (RMem * mem, RMemMapInfo * info)
{
  rboolean ret;
  if (R_UNLIKELY (mem == NULL)) return FALSE;
  if (R_UNLIKELY (info == NULL)) return FALSE;

  if ((ret = mem->allocator->unmap (mem, info))) {
    r_mem_unref (info->mem);
    info->mem = NULL;
  }

  return ret;
}

RMem *
r_mem_copy (RMem * mem, rssize offset, rssize size)
{
  if (R_UNLIKELY (mem == NULL)) return NULL;
  return mem->allocator->copy (mem, offset, size);
}

RMem *
r_mem_view (RMem * mem, rssize offset, rssize size)
{
  if (R_UNLIKELY (mem == NULL)) return NULL;
  if (R_UNLIKELY (mem->flags & R_MEM_FLAG_NO_VIEWS)) return NULL;
  return mem->allocator->view (mem, offset, size);
}

RMem *
r_mem_new_wrapped (RMemFlags flags, rpointer data, rsize allocsize,
    rsize size, rsize offset, rpointer user, RDestroyNotify usernotify)
{
  RSystemMem * sysmem;

  if (R_UNLIKELY (data == NULL)) return NULL;
  if (R_UNLIKELY (size + offset > allocsize)) return NULL;

  if ((sysmem = r_mem_new (RSystemMem)) != NULL) {
    r_system_mem_init (sysmem, flags, &g__r_mem_allocator_system, NULL,
        allocsize, size, 0, offset, data, user, usernotify);
  }

  return (RMem *) sysmem;
}

RMem *
r_mem_merge (const RMemAllocationParams * params, RMem * a, ...)
{
  va_list args;
  RMem * ret;

  va_start (args, a);
  ret = r_mem_mergev (params, a, args);
  va_end (args);

  return ret;
}

RMem *
r_mem_mergev (const RMemAllocationParams * params, RMem * a, va_list args)
{
  va_list ac;
  rsize i, count;
  RMem ** mems;

  if (R_UNLIKELY (a == NULL)) return NULL;
  if (params == NULL)
    params = &g__r_mem_defparams;

  count = 1;
  va_copy (ac, args);
  while (va_arg (ac, rpointer) != NULL) count++;
  va_end (ac);

  mems = r_alloca (sizeof (RMem *) * count);
  mems[0] = a;
  for (i = 1; i < count; i++)
    mems[i] = va_arg (args, RMem *);

  return a->allocator->merge (params, mems, count);
}

