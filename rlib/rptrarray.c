/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/rptrarray.h>

#include <rlib/rmem.h>

#define R_PTR_ARRAY_MIN_SIZE    8

typedef struct {
  rpointer ptr;
  RDestroyNotify notify;
} RPtrNode;

struct _RPtrArray {
  RRef ref;

  rsize nalloc, nsize;
  RPtrNode * array;
};

static inline void
r_ptr_array_notify_idx (RPtrArray * array, rsize idx)
{
  if (array->array[idx].notify != NULL)
    array->array[idx].notify (array->array[idx].ptr);
}

static inline void
r_ptr_array_notify_range (RPtrArray * array, rsize idx, rsize until)
{
  for (; idx < until; idx++) {
    if (array->array[idx].notify != NULL)
      array->array[idx].notify (array->array[idx].ptr);
  }
}

static inline void
r_ptr_array_notify_range_full (RPtrArray * array, rsize idx, rsize until,
    RFunc func, rpointer user)
{
  for (; idx < until; idx++) {
    func (array->array[idx].ptr, user);
    if (array->array[idx].notify != NULL)
      array->array[idx].notify (array->array[idx].ptr);
  }
}

static void
r_ptr_array_free (RPtrArray * array)
{
  r_ptr_array_notify_range (array, 0, array->nsize);
  r_free (array->array);
  r_free (array);
}

static void
r_ptr_array_ensure_size (RPtrArray * array, rsize size)
{
  if (size < R_PTR_ARRAY_MIN_SIZE)
    size = R_PTR_ARRAY_MIN_SIZE;

  if (size > array->nalloc) {
    if (RSIZE_POPCOUNT (size) != 1)
      size = 1 << ((sizeof (rsize) * 8) - RSIZE_CLZ (size));

    array->array = r_realloc (array->array, size * sizeof (RPtrNode));
    array->nalloc = size;
  }
}

RPtrArray *
r_ptr_array_new_sized (rsize size)
{
  RPtrArray * ret;

  if ((ret = r_mem_new (RPtrArray)) != NULL) {
    r_ref_init (ret, r_ptr_array_free);
    ret->nalloc = ret->nsize = 0;
    ret->array = NULL;
    r_ptr_array_ensure_size (ret, size);
  }

  return ret;
}

rsize
r_ptr_array_size (const RPtrArray * array)
{
  return array->nsize;
}

rsize
r_ptr_array_alloc_size (const RPtrArray * array)
{
  return array->nalloc;
}

rpointer
r_ptr_array_get (RPtrArray * array, rsize idx)
{
  if (R_UNLIKELY (idx >= array->nsize)) return NULL;
  return array->array[idx].ptr;
}

rsize
r_ptr_array_add (RPtrArray * array, rpointer data, RDestroyNotify notify)
{
  r_ptr_array_ensure_size (array, array->nsize + 1);
  array->array[array->nsize].ptr = data;
  array->array[array->nsize].notify = notify;
  return array->nsize++;
}

rsize
r_ptr_array_update_idx (RPtrArray * array, rsize idx, rpointer data, RDestroyNotify notify)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;

  r_ptr_array_notify_idx (array, idx);

  array->array[idx].ptr = data;
  array->array[idx].notify = notify;
  return idx;
}

rsize
r_ptr_array_clear_range (RPtrArray * array, rsize idx, rssize size)
{
  rsize end;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  r_ptr_array_notify_range (array, idx, end);
  r_memclear (&array->array[idx], (end - idx) * sizeof (RPtrNode));

  return end - idx;
}

rsize
r_ptr_array_remove_idx_full (RPtrArray * array, rsize idx, RFunc func, rpointer user)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;

  if (func != NULL) func (array->array[idx].ptr, user);
  r_ptr_array_notify_idx (array, idx);

  if (idx < --array->nsize) {
    r_memmove (&array->array[idx], &array->array[idx + 1],
        (array->nsize - idx) * sizeof (RPtrNode));
  }

  return idx;
}

rsize
r_ptr_array_remove_idx_fast_full (RPtrArray * array, rsize idx, RFunc func, rpointer user)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;
  if (func != NULL) func (array->array[idx].ptr, user);
  r_ptr_array_notify_idx (array, idx);

  if (idx < --array->nsize)
    array->array[idx] = array->array[array->nsize];

  return idx;
}

rsize
r_ptr_array_remove_idx_clear_full (RPtrArray * array, rsize idx, RFunc func, rpointer user)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;

  if (func != NULL) func (array->array[idx].ptr, user);
  r_ptr_array_clear_idx (array, idx);

  if (idx == array->nsize - 1)
    array->nsize--;
  return idx;
}

rsize
r_ptr_array_remove_range_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user)
{
  rsize end;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  if (func != NULL)
    r_ptr_array_notify_range_full (array, idx, end, func, user);
  else
    r_ptr_array_notify_range (array, idx, end);

  if (end < array->nsize) {
    r_memmove (&array->array[idx], &array->array[end],
        (array->nsize - end) * sizeof (RPtrNode));
  }

  array->nsize -= (end - idx);
  return end - idx;
}

rsize
r_ptr_array_remove_range_fast_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user)
{
  rsize end;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  if (func != NULL)
    r_ptr_array_notify_range_full (array, idx, end, func, user);
  else
    r_ptr_array_notify_range (array, idx, end);

  array->nsize -= (end - idx);
  r_memmove (&array->array[idx], &array->array[array->nsize],
      (end - idx) * sizeof (RPtrNode));

  return end - idx;
}

rsize
r_ptr_array_remove_range_clear_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user)
{
  rsize end;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  if (func != NULL)
    r_ptr_array_notify_range_full (array, idx, end, func, user);
  else
    r_ptr_array_notify_range (array, idx, end);

  if (end < array->nsize)
    r_memclear (&array->array[idx], (end - idx) * sizeof (RPtrNode));
  else
    array->nsize -= (end - idx);

  return end - idx;
}

rsize
r_ptr_array_find_range (RPtrArray * array, rpointer data, rsize idx, rssize size)
{
  rsize end;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  for (; idx < end; idx++) {
    if (array->array[idx].ptr == data)
      return idx;
  }

  return R_PTR_ARRAY_INVALID_IDX;
}

rsize
r_ptr_array_foreach_range (RPtrArray * array, rsize idx, rssize size,
    RFunc func, rpointer user)
{
  rsize i, end;

  if (R_UNLIKELY (func == NULL)) return 0;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  for (i = idx; i < end; i++)
    func (array->array[i].ptr, user);

  return end - idx;
}

