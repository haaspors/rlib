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
#include <rlib/rbuffer.h>

#include <rlib/rmem.h>

/* FIXME: Add logging??? */

#define R_BUFFER_MAX_MEM    32

struct _RBuffer {
  RRef ref;

  RMem * mem[R_BUFFER_MAX_MEM];
  ruint mem_count;
};

static void
r_buffer_free (RBuffer * buf)
{
  ruint i, count = buf->mem_count;
  buf->mem_count = 0;

  for (i = 0; i < count; i++)
    r_mem_unref (buf->mem[i]);

  r_free (buf);
}

RBuffer *
r_buffer_new (void)
{
  RBuffer * ret;

  if ((ret = r_mem_new0 (RBuffer)) != NULL)
    r_ref_init (ret, r_buffer_free);

  return ret;
}

RBuffer *
r_buffer_new_alloc (RMemAllocator * allocator, rsize allocsize,
    const RMemAllocationParams * params)
{
  RBuffer * ret;
  RMem * mem;

  if ((mem = r_mem_allocator_alloc_full (allocator, allocsize, params)) != NULL) {
    if ((ret = r_buffer_new ()) != NULL)
      ret->mem[ret->mem_count++] = mem;
    else
      r_mem_unref (mem);
  } else {
    ret = NULL;
  }

  return ret;
}

RBuffer *
r_buffer_new_wrapped (RMemFlags flags, rpointer data,
    rsize allocsize, rsize size, rsize offset, rpointer user, RDestroyNotify usernotify)
{
  RBuffer * ret;
  RMem * mem;

  if ((mem = r_mem_new_wrapped (flags, data, allocsize, size, offset,
          user, usernotify)) != NULL) {
    if ((ret = r_buffer_new ()) != NULL)
      ret->mem[ret->mem_count++] = mem;
    else
      r_mem_unref (mem);
  } else {
    ret = NULL;
  }

  return ret;
}

rboolean
r_buffer_is_all_writable (const RBuffer * buffer)
{
  ruint i;
  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (buffer->mem_count == 0)) return FALSE;

  for (i = 0; i < buffer->mem_count; i++) {
    if (r_mem_is_readonly (buffer->mem[i]))
      return FALSE;
  }

  return TRUE;
}

rboolean
r_buffer_mem_is_writable (const RBuffer * buffer, ruint idx)
{
  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (buffer->mem_count >= idx)) return FALSE;

  return r_mem_is_writable (buffer->mem[idx]);
}

rsize
r_buffer_get_size (const RBuffer * buffer)
{
  rsize ret = 0;
  ruint i;
  if (R_UNLIKELY (buffer == NULL)) return 0;

  for (i = 0; i < buffer->mem_count; i++)
    ret += buffer->mem[i]->size;

  return ret;
}

rsize
r_buffer_get_allocsize (const RBuffer * buffer)
{
  rsize ret = 0;
  ruint i;
  if (R_UNLIKELY (buffer == NULL)) return 0;

  for (i = 0; i < buffer->mem_count; i++)
    ret += buffer->mem[i]->allocsize;

  return ret;
}

rsize
r_buffer_get_offset (const RBuffer * buffer)
{
  rsize ret = 0;
  if (buffer != NULL) {
    ruint i;
    for (i = 0; i < buffer->mem_count; i++) {
      ret += buffer->mem[i]->offset;
      if (buffer->mem[i]->size > 0)
        break;
    }
  }
  return ret;
}

ruint
r_buffer_mem_count (const RBuffer * buffer)
{
  if (R_UNLIKELY (buffer == NULL)) return 0;
  return buffer->mem_count;
}

rboolean
r_buffer_mem_insert (RBuffer * buffer, RMem * mem, ruint idx)
{
  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (mem == NULL)) return FALSE;
  /* FIXME: Compress memory chunks */
  if (R_UNLIKELY (buffer->mem_count >= R_BUFFER_MAX_MEM)) return FALSE;

  if (idx >= buffer->mem_count)
    return r_buffer_mem_append (buffer, mem);

  r_memmove (&buffer->mem[idx+1], &buffer->mem[idx],
      sizeof (RMem *) * (buffer->mem_count++ - idx));
  buffer->mem[idx] = r_mem_ref (mem);
  return TRUE;
}

rboolean
r_buffer_mem_prepend (RBuffer * buffer, RMem * mem)
{
  return r_buffer_mem_insert (buffer, mem, 0);
}

rboolean
r_buffer_mem_append (RBuffer * buffer, RMem * mem)
{
  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (mem == NULL)) return FALSE;
  if (R_UNLIKELY (buffer->mem_count >= R_BUFFER_MAX_MEM)) {
    RMem * newmem;

    if ((newmem = r_mem_merge_array (NULL, buffer->mem, buffer->mem_count)) == NULL)
      return FALSE;

    r_buffer_mem_clear (buffer);
    buffer->mem[buffer->mem_count++] = newmem;
  }

  buffer->mem[buffer->mem_count++] = r_mem_ref (mem);
  return TRUE;
}

rboolean
r_buffer_mem_replace_range (RBuffer * buffer, ruint idx, int mem_count, RMem * mem)
{
  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (mem == NULL)) return FALSE;
  if (R_UNLIKELY (idx >= buffer->mem_count)) return FALSE;

  if (mem_count < 0)
    mem_count = (int)(buffer->mem_count - idx);
  else if (idx + (ruint)mem_count > buffer->mem_count)
    return FALSE;

  r_mem_unref (buffer->mem[idx]);
  buffer->mem[idx] = r_mem_ref (mem);
  if (--mem_count > 0) {
    int i;
    for (idx++, i = 0; i < mem_count; i++)
      r_mem_unref (buffer->mem[idx + i]);
    r_memmove (&buffer->mem[idx], &buffer->mem[idx + mem_count],
        (buffer->mem_count - (idx + mem_count)) * sizeof (RMem *));
    buffer->mem_count -= mem_count;
  }

  return TRUE;
}

RMem *
r_buffer_mem_peek (RBuffer * buffer, ruint idx)
{
  if (R_UNLIKELY (buffer == NULL)) return NULL;
  if (R_UNLIKELY (idx >= buffer->mem_count)) return NULL;

  return r_mem_ref (buffer->mem[idx]);
}

RMem *
r_buffer_mem_remove (RBuffer * buffer, ruint idx)
{
  RMem * ret;
  ruint count;

  if (R_UNLIKELY (buffer == NULL)) return NULL;
  if (R_UNLIKELY (idx >= buffer->mem_count)) return NULL;

  ret = buffer->mem[idx];
  if ((count = --buffer->mem_count - idx) > 0) {
    r_memmove (&buffer->mem[idx], &buffer->mem[idx + 1],
        count * sizeof (RMem *));
  }
  return ret;
}

void
r_buffer_mem_clear (RBuffer * buffer)
{
  if (buffer != NULL) {
    ruint i, count = buffer->mem_count;
    buffer->mem_count = 0;

    for (i = 0; i < count; i++)
      r_mem_unref (buffer->mem[i]);
  }
}

rboolean
r_buffer_mem_find (RBuffer * buffer, rsize offset, rsize size,
    ruint * idx, ruint * mem_count, rsize * mem_offset)
{
  ruint ix, cn;

  if (R_UNLIKELY (buffer == NULL)) return FALSE;

  for (ix = 0; ix < buffer->mem_count; ix++) {
    if (offset < buffer->mem[ix]->size)
      break;
    offset -= buffer->mem[ix]->size;
  }
  if (ix == buffer->mem_count)
    return FALSE;

  cn = ix;
  if (size > buffer->mem[cn]->size - offset) {
    size -= buffer->mem[cn++]->size - offset;
    for (; cn < buffer->mem_count; cn++) {
      if (size <= buffer->mem[cn]->size)
        break;
      size -= buffer->mem[cn]->size;
    }
    if (cn == buffer->mem_count)
      return FALSE;
  }

  if (idx != NULL)
    *idx = ix;
  if (mem_count != NULL)
    *mem_count = cn - ix + 1;
  if (mem_offset != NULL)
    *mem_offset = offset;

  return TRUE;
}

rboolean
r_buffer_append_from (RBuffer * buffer, RBuffer * from)
{
  ruint i;
  RMem * mem;
  rboolean ret;

  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (from == NULL)) return FALSE;

  for (i = 0, ret = TRUE; i < from->mem_count && ret; i++) {
    if ((mem = r_mem_view (from->mem[i], 0, -1)) == NULL)
      if ((mem = r_mem_copy (from->mem[i], 0, -1)) == NULL)
        return FALSE;
    ret = r_buffer_mem_append (buffer, mem);
    r_mem_unref (mem);
  }

  return ret;
}

rboolean
r_buffer_append_region_from (RBuffer * buffer, RBuffer * from,
    rsize offset, rssize size)
{
  ruint i;
  rssize msize;
  RMem * mem;
  rboolean ret;

  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (from == NULL)) return FALSE;
  if (R_UNLIKELY (size == 0)) return TRUE;
  if (R_UNLIKELY (from->mem_count == 0)) return TRUE;

  for (i = 0; i < from->mem_count && offset >= from->mem[i]->size; i++)
    offset -= from->mem[i]->size;
  if (i == from->mem_count)
    return FALSE;

  msize = MIN (size, (rssize)(from->mem[i]->size - offset));
  if ((mem = r_mem_view (from->mem[i], offset, msize)) == NULL)
    if ((mem = r_mem_copy (from->mem[i], offset, msize)) == NULL)
      return FALSE;

  ret = r_buffer_mem_append (buffer, mem);
  r_mem_unref (mem);

  if (size < 0) {
    for (i++; i < from->mem_count && ret; i++) {
      if ((mem = r_mem_view (from->mem[i], 0, -1)) == NULL)
        if ((mem = r_mem_copy (from->mem[i], 0, -1)) == NULL)
          return FALSE;
      ret = r_buffer_mem_append (buffer, mem);
      r_mem_unref (mem);
    }
  } else {
    size -= msize;

    for (i++; i < from->mem_count && size > 0 && ret; i++) {
      msize = MIN (size, (rssize)(from->mem[i]->size - offset));
      if ((mem = r_mem_view (from->mem[i], offset, msize)) == NULL)
        if ((mem = r_mem_copy (from->mem[i], offset, msize)) == NULL)
          return FALSE;

      ret = r_buffer_mem_append (buffer, mem);
      r_mem_unref (mem);
      size -= msize;
    }
  }

  return ret;
}

RBuffer *
r_buffer_merge_take (RBuffer * a, ...)
{
  va_list args;
  RBuffer * ret;

  va_start (args, a);
  ret = r_buffer_merge_takev (a, args);
  va_end (args);

  return ret;
}

RBuffer *
r_buffer_merge_takev (RBuffer * a, va_list args)
{
  if (R_LIKELY (a != NULL)) {
    RBuffer * from;

    while ((from = va_arg (args, RBuffer *)) != NULL) {
      if (a->mem_count + from->mem_count <= R_BUFFER_MAX_MEM) {
        r_memcpy (&a->mem[a->mem_count], from->mem, from->mem_count * sizeof (RMem *));
        a->mem_count += from->mem_count;
        from->mem_count = 0;
      } else {
        ruint count = a->mem_count + from->mem_count;
        RMem ** mems = r_alloca (count * sizeof (RMem *));

        r_memcpy (&mems[           0], a->mem,    a->mem_count * sizeof (RMem *));
        r_memcpy (&mems[a->mem_count], from->mem, from->mem_count * sizeof (RMem *));

        if (!r_buffer_mem_replace_all (a, r_mem_take_array (NULL, mems, count))) {
          /* WARNING ... */
        }
      }

      r_buffer_unref (from);
    }
  }

  return a;
}

RBuffer *
r_buffer_merge_take_array (RBuffer ** arr, ruint count)
{
  RBuffer * ret;

  if ((ret = r_buffer_new ()) != NULL) {
    ruint mem_count, i;
    RMem ** mems, ** ptr;
    for (i = 0, mem_count = 0; i < count; i++)
      mem_count += arr[i]->mem_count;

    mems = r_alloca (mem_count * sizeof (RMem *));
    for (i = 0, ptr = mems; i < count; i++) {
      r_memcpy (ptr, arr[i]->mem, arr[i]->mem_count * sizeof (RMem *));
      ptr += arr[i]->mem_count;
      arr[i]->mem_count = 0;
      r_buffer_unref (arr[i]);
    }

    if (mem_count >= R_BUFFER_MAX_MEM / 2) {
      RMem * mem;
      if ((mem = r_mem_take_array (NULL, mems, mem_count)) != NULL) {
        r_buffer_mem_append (ret, mem);
      } else {
        r_buffer_unref (ret);
        ret = NULL;
      }
    } else {
      r_memcpy (ret->mem, mems, mem_count * sizeof (RMem *));
      ret->mem_count = mem_count;
    }
  }

  return ret;
}

static rboolean
r_buffer_resize_fast (RBuffer * buffer, rsize offset, rsize size)
{
  ruint i;
  RMem * mem;

  if (R_UNLIKELY (!r_buffer_is_all_writable (buffer))) return FALSE;
  if (R_UNLIKELY (r_buffer_get_allocsize (buffer) < offset + size))
    return FALSE;

  for (i = 0; i < buffer->mem_count; i++) {
    mem = buffer->mem[i];

    if (offset < mem->allocsize) {
      i++;
      if (size < mem->allocsize - offset) {
        r_mem_resize (mem, offset, size);
        size = 0;
      } else {
        size -= mem->allocsize - offset;
        r_mem_resize (mem, offset, mem->allocsize - offset);

        for (; i < buffer->mem_count; i++) {
          mem = buffer->mem[i];
          if (size < mem->allocsize) {
            i++;
            r_mem_resize (mem, 0, size);
            size = 0;
            break;
          }

          size -= mem->allocsize;
          r_mem_resize (mem, 0, mem->allocsize);
        }
      }

      offset = 0;
      break;
    }
    r_mem_resize (mem, mem->allocsize, 0);
    offset -= mem->allocsize;
  }

  while (i < buffer->mem_count)
    r_mem_unref (buffer->mem[--buffer->mem_count]);

  return TRUE;
}

/* FIXME: Resize buffer without changing prefix and padding on individual
 *        memory chunks if possible. */
rboolean
r_buffer_resize (RBuffer * buffer, rsize offset, rsize size)
{
#if 0
  ruint i;
  RMem * mem;
  rsize orig_offset, orig_size;

  if (R_UNLIKELY (!r_buffer_is_all_writable (buffer))) return FALSE;
  if (R_UNLIKELY (r_buffer_get_allocsize (buffer) < offset + size))
    return FALSE;

  orig_offset = offset;
  orig_size = size;

  i = 0;
  mem = buffer->mem[i++];
  if (offset < mem->offset + mem->size) {
    r_mem_resize (mem, offset, mem->offset + mem->size - offset);
  } else {
    offset -= mem->offset + mem->size;
    r_mem_resize (mem, mem->offset + mem->size, 0);

    for (i = 1; i < buffer->mem_count; i++) {
      mem = buffer->mem[i];
      if (offset < mem->size) {
        r_mem_resize (mem, mem->offset + offset, mem->size - offset);
        break;
      }

      offset -= mem->size;
      r_mem_resize (mem, mem->offset + mem->size, 0);
    }

    if (offset > 0)
      return r_buffer_resize_fast (buffer, orig_offset, orig_size);
  }

  while (i < buffer->mem_count)
    r_mem_unref (buffer->mem[--buffer->mem_count]);

  return TRUE;
#else
  return r_buffer_resize_fast (buffer, offset, size);
#endif
}

rboolean
r_buffer_shrink (RBuffer * buffer, rsize size)
{
  ruint i;

  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (size == 0)) {
    r_buffer_mem_clear (buffer);
    return TRUE;
  }

  for (i = 0; i < buffer->mem_count; i++) {
    if (buffer->mem[i]->size >= size) {
      if (r_mem_resize (buffer->mem[i], buffer->mem[i]->offset, size)) {
        ruint j;
        for (j = i + 1; j < buffer->mem_count; j++) {
          r_mem_unref (buffer->mem[j]);
          buffer->mem[j] = NULL;
        }
        buffer->mem_count = i + 1;
        size = 0;
      }
      break;
    }

    size -= buffer->mem[i]->size;
  }

  return (size == 0);
}

rboolean
r_buffer_map_mem_range (RBuffer * buffer, ruint idx, int mem_count,
    RMemMapInfo * info, RMemMapFlags flags)
{
  rboolean ret;

  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (idx >= buffer->mem_count)) return FALSE;
  if (R_UNLIKELY (info == NULL)) return FALSE;

  if (mem_count < 0)
    mem_count = (int)(buffer->mem_count - idx);
  else if (idx + (ruint)mem_count > buffer->mem_count)
    return FALSE;

#if 0
  if (R_UNLIKELY (flags & R_MEM_MAP_WRITE && !r_buffer_is_all_writable (buffer)))
    return FALSE;
#endif

  if (mem_count == 1) {
    ret = r_mem_map (buffer->mem[idx], info, flags);
  } else if (mem_count == 0) {
    info->mem = NULL;
    info->data = NULL;
    info->size = info->allocsize = 0;
    info->flags = flags;
    ret = TRUE;
  } else {
    RMem * mem;

    if ((mem = r_mem_merge_array (NULL, &buffer->mem[idx], (ruint)mem_count)) != NULL) {
      if (r_buffer_is_all_writable (buffer))
        ret = r_buffer_mem_replace_range (buffer, idx, mem_count, mem);

      ret = r_mem_map (mem, info, flags);
      r_mem_unref (mem);
    } else {
      ret = FALSE;
    }
  }

  return ret;
}

rboolean
r_buffer_map_byte_range (RBuffer * buffer, rsize offset, rssize size,
    RMemMapInfo * info, RMemMapFlags flags)
{
  rboolean ret;
  ruint idx, count;
  rsize max_size, moff, msize;

  if (R_UNLIKELY (buffer == NULL)) return FALSE;

  max_size = r_buffer_get_size (buffer);
  if (R_UNLIKELY (offset + MAX (size, 0) > max_size)) return FALSE;

  msize = size < 0 ? max_size - offset : (rsize)size;
  if ((ret = r_buffer_mem_find (buffer, offset, msize, &idx, &count, &moff)) &&
      (ret = r_buffer_map_mem_range (buffer, idx, (int)count, info, flags))) {
    info->data += moff;
    info->size = msize;
  }

  return ret;
}

rboolean
r_buffer_unmap (RBuffer * buffer, RMemMapInfo * info)
{
  if (R_UNLIKELY (buffer == NULL)) return FALSE;
  if (R_UNLIKELY (info == NULL)) return FALSE;

  if (info->mem != NULL)
    r_mem_unmap (info->mem, info);

  r_memclear (info, sizeof (RMemMapInfo));
  return TRUE;
}

rsize
r_buffer_fill (RBuffer * buffer, rsize offset, rconstpointer src, rsize size)
{
  ruint i;
  rsize ret, msize;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  const ruint8 * ptr;

  if (R_UNLIKELY (buffer == NULL)) return 0;
  if (R_UNLIKELY (src == NULL)) return 0;
  if (R_UNLIKELY (size == 0)) return 0;

  for (i = 0; i < buffer->mem_count && offset >= buffer->mem[i]->size; i++)
    offset -= buffer->mem[i]->size;
  if (i == buffer->mem_count)
    return 0;

  if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_WRITE))
    return 0;

  ptr = src;
  msize = MIN (size, info.size - offset);
  r_memcpy (info.data + offset, ptr, msize);
  r_mem_unmap (buffer->mem[i], &info);
  size -= msize;
  ret = msize;
  ptr += msize;

  for (i++; i < buffer->mem_count && size > 0; i++) {
    if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_WRITE))
      break;

    msize = MIN (info.size, size);
    r_memcpy (info.data, ptr, msize);
    r_mem_unmap (buffer->mem[i], &info);

    size -= msize;
    ret += msize;
    ptr += msize;
  }

  return ret;
}

rsize
r_buffer_extract (RBuffer * buffer, rsize offset, rpointer dst, rsize size)
{
  ruint i;
  rsize ret, msize;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint8 * ptr;

  if (R_UNLIKELY (buffer == NULL)) return 0;
  if (R_UNLIKELY (dst == NULL)) return 0;
  if (R_UNLIKELY (size == 0)) return 0;

  for (i = 0; i < buffer->mem_count && offset >= buffer->mem[i]->size; i++)
    offset -= buffer->mem[i]->size;
  if (i == buffer->mem_count)
    return 0;

  if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_READ))
    return 0;

  ptr = dst;
  msize = MIN (size, info.size - offset);
  r_memcpy (ptr, info.data + offset, msize);
  r_mem_unmap (buffer->mem[i], &info);
  size -= msize;
  ret = msize;
  ptr += msize;

  for (i++; i < buffer->mem_count && size > 0; i++) {
    if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_READ))
      break;

    msize = MIN (info.size, size);
    r_memcpy (ptr, info.data, msize);
    r_mem_unmap (buffer->mem[i], &info);

    size -= msize;
    ret += msize;
    ptr += msize;
  }

  return ret;
}

rpointer
r_buffer_extract_dup (RBuffer * buffer, rsize offset, rsize size, rsize * dstsize)
{
  rpointer dst;

  if (R_UNLIKELY (buffer == NULL)) return NULL;
  if (R_UNLIKELY (dstsize == NULL)) return NULL;
  if (R_UNLIKELY (size == 0)) {
    *dstsize = 0;
    return NULL;
  }

  dst = r_malloc (size);
  *dstsize = r_buffer_extract (buffer, offset, dst, size);
  return dst;
}

rsize
r_buffer_memset (RBuffer * buffer, rsize offset, ruint8 val, rsize size)
{
  ruint i;
  rsize ret, msize;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  if (R_UNLIKELY (buffer == NULL)) return 0;
  if (R_UNLIKELY (size == 0)) return 0;

  for (i = 0; i < buffer->mem_count && offset >= buffer->mem[i]->size; i++)
    offset -= buffer->mem[i]->size;
  if (i == buffer->mem_count)
    return 0;

  if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_WRITE))
    return 0;

  msize = MIN (size, info.size - offset);
  r_memset (info.data + offset, val, msize);
  r_mem_unmap (buffer->mem[i], &info);
  size -= msize;
  ret = msize;

  for (i++; i < buffer->mem_count && size > 0; i++) {
    if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_WRITE))
      break;

    msize = MIN (info.size, size);
    r_memset (info.data, val, msize);
    r_mem_unmap (buffer->mem[i], &info);

    size -= msize;
    ret += msize;
  }

  return ret;
}

int
r_buffer_memcmp (RBuffer * buffer, rsize offset, rconstpointer mem, rsize size)
{
  ruint i;
  int ret;
  rsize msize;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  const ruint8 * ptr;

  if (R_UNLIKELY (buffer == NULL)) return -1;
  if (R_UNLIKELY (mem == NULL)) return 1;

  for (i = 0; i < buffer->mem_count && offset >= buffer->mem[i]->size; i++)
    offset -= buffer->mem[i]->size;
  if (i == buffer->mem_count)
    return 1;

  if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_READ))
    return -1;

  ptr = mem;
  msize = MIN (size, info.size - offset);
  ret = r_memcmp (info.data + offset, ptr, msize);
  r_mem_unmap (buffer->mem[i], &info);
  size -= msize;
  ptr += msize;

  for (i++; i < buffer->mem_count && size > 0 && ret == 0; i++) {
    if (!r_mem_map (buffer->mem[i], &info, R_MEM_MAP_READ))
      break;
    msize = MIN (info.size, size);
    ret = r_memcmp (info.data, ptr, msize);
    r_mem_unmap (buffer->mem[i], &info);

    ptr += msize;
    size -= msize;
  }

  return size == 0 ? ret : 1;
}

