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

#include "config.h"
#include <rlib/rmem.h>
#include <string.h>

static const RMemVTable r_memsysvtable  = { malloc, calloc, realloc, free };
static RMemVTable r_memvtable           = { malloc, calloc, realloc, free };

void
r_free (rpointer ptr)
{
  r_memvtable.free (ptr);
}

rpointer
r_malloc (rsize size)
{
  rpointer ret;

  ret = r_memvtable.malloc (size);

  return ret;
}

rpointer
r_malloc0 (rsize size)
{
  rpointer ret;

  ret = r_memvtable.calloc (1, size);

  return ret;
}

rpointer
r_calloc (rsize count, rsize size)
{
  rpointer ret;

  ret = r_memvtable.calloc (count, size);

  return ret;
}

rpointer
r_realloc (rpointer ptr, rsize size)
{
  rpointer ret;

  ret = r_memvtable.realloc (ptr, size);

  return ret;
}

void
r_mem_set_vtable (RMemVTable * vtable)
{
  /* TODO: Sanity check incoming vtable? */
  r_memvtable = *vtable;
}

rboolean
r_mem_using_system_default (void)
{
  return memcmp (&r_memvtable, &r_memsysvtable, sizeof (RMemVTable)) == 0;
}

int
r_memcmp (rconstpointer a, rconstpointer b, rsize size)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  return memcmp (a, b, size);
}

rpointer
r_memset (rpointer a, int v, rsize size)
{
  if (a != NULL)
    memset (a, v, size);
  return a;
}

rpointer
r_memcpy (rpointer R_ATTR_RESTRICT dst, rconstpointer
    R_ATTR_RESTRICT src, rsize size)
{
  if (dst != NULL && src != NULL)
    return memcpy (dst, src, size);

  return NULL;
}

rpointer
r_memmove (rpointer dst, rconstpointer src, rsize size)
{
  if (dst != NULL && src != NULL)
    return memmove (dst, src, size);

  return NULL;
}

rpointer
r_memdup (rconstpointer src, rsize size)
{
  rpointer ret;
  if (src != NULL && size > 0) {
    if ((ret = r_malloc (size)) != NULL)
      memcpy (ret, src, size);
  } else {
    ret = NULL;
  }

  return ret;
}

rpointer
r_mem_scan_byte (rconstpointer mem, rsize size, ruint8 byte)
{
  if (R_LIKELY (mem != NULL)) {
    const ruint8 * ptr = mem, * end;
    for (end = ptr + size; ptr < end; ptr++) {
      if (*ptr == byte)
        return (rpointer)ptr;
    }
  }

  return NULL;
}

rpointer
r_mem_scan_byte_any (rconstpointer mem, rsize size,
    const ruint8 * byte, rsize bytes)
{
  if (R_LIKELY (mem != NULL && byte != NULL && bytes > 0)) {
    const ruint8 * ptr = mem, * end;
    for (end = ptr + size; ptr < end; ptr++) {
      if (r_mem_scan_byte (byte, bytes, *ptr) != NULL)
        return (rpointer)ptr;
    }
  }

  return NULL;
}

rpointer
r_mem_scan_data (rconstpointer mem, rsize size,
    rconstpointer data, rsize datasize)
{
  if (R_LIKELY (mem != NULL && data != NULL && datasize > 0)) {
    const ruint8 * ptr = mem, * end = mem + size - datasize;
    ruint8 byte = *(const ruint8 *)data;

    while (ptr < end) {
      if ((ptr = (rpointer)r_mem_scan_byte (ptr, size - datasize, byte)) == NULL)
        break;
      if (r_memcmp (ptr, data, datasize) == 0)
        return (rpointer)ptr;
    }
  }

  return NULL;
}

