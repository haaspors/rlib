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
r_memcpy (void * R_ATTR_RESTRICT dst, const void * R_ATTR_RESTRICT src,
    rsize size)
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

rsize
r_memagg (rpointer dst, rsize size, rsize * out, ...)
{
  rsize ret;
  va_list args;

  va_start (args, out);
  ret = r_memaggv (dst, size, out, args);
  va_end (args);

  return ret;
}

rsize
r_memaggv (rpointer dst, rsize size, rsize * out, va_list args)
{
  rsize ret = 0;
  rconstpointer p;
  ruint8 * ptr = dst;
  rsize c, s = 0;

  while ((p = va_arg (args, rconstpointer)) != NULL &&
      (c = va_arg (args, rsize)) <= size) {
    r_memcpy (&ptr[s], p, c);
    s += c;
    ret++;
  }

  if (out != NULL)
    *out = s;

  return ret;
}

rpointer
r_memdup_agg (rsize * out, ...)
{
  rpointer ret;
  va_list args;

  va_start (args, out);
  ret = r_memdup_aggv (out, args);
  va_end (args);

  return ret;
}

rpointer
r_memdup_aggv (rsize * out, va_list args)
{
  va_list ac;
  rsize size = 0, count = 0;
  rpointer ret;

  va_copy (ac, args);
  while (va_arg (ac, rconstpointer) != NULL) {
    count++;
    size += va_arg (ac, rsize);
  }
  va_end (ac);

  if (R_UNLIKELY (size == 0)) {
    ret = NULL;
  } else if ((ret = r_malloc (size)) != NULL) {
    if (R_UNLIKELY (r_memaggv (ret, size, out, args) != count)) {
      r_free (ret);
      ret = NULL;
    }
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
  if (R_LIKELY (mem != NULL && data != NULL && datasize > 0 && datasize <= size)) {
    const ruint8 * ptr = mem;
    const ruint8 * end = RSIZE_TO_POINTER (RPOINTER_TO_SIZE (mem) + size - datasize);
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

