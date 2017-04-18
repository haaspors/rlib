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
#define R_PTR_ARRAY_N(array, idx) ((RPtrNode *)(array)->mem)[idx]

typedef struct {
  rpointer ptr;
  RDestroyNotify notify;
} RPtrNode;


static inline void
r_ptr_array_notify_idx (RPtrArray * array, rsize idx)
{
  if (R_PTR_ARRAY_N (array, idx).notify != NULL)
    R_PTR_ARRAY_N (array, idx).notify (R_PTR_ARRAY_N (array, idx).ptr);
}

static inline void
r_ptr_array_notify_range (RPtrArray * array, rsize idx, rsize until)
{
  for (; idx < until; idx++) {
    if (R_PTR_ARRAY_N (array, idx).notify != NULL)
      R_PTR_ARRAY_N (array, idx).notify (R_PTR_ARRAY_N (array, idx).ptr);
  }
}

static inline void
r_ptr_array_notify_range_full (RPtrArray * array, rsize idx, rsize until,
    RFunc func, rpointer user)
{
  for (; idx < until; idx++) {
    func (R_PTR_ARRAY_N (array, idx).ptr, user);
    if (R_PTR_ARRAY_N (array, idx).notify != NULL)
      R_PTR_ARRAY_N (array, idx).notify (R_PTR_ARRAY_N (array, idx).ptr);
  }
}

void
r_ptr_array_init (RPtrArray * array)
{
  r_ref_init (array, r_ptr_array_clear);
  array->nalloc = array->nsize = 0;
  array->mem = NULL;
}

void
r_ptr_array_clear (RPtrArray * array)
{
  r_ptr_array_notify_range (array, 0, array->nsize);
  r_free (array->mem);
  array->nalloc = array->nsize = 0;
  array->mem = NULL;
}

static void
r_ptr_array_free (RPtrArray * array)
{
  r_ptr_array_clear (array);
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

    array->mem = r_realloc (array->mem, size * sizeof (RPtrNode));
    array->nalloc = size;
  }
}

RPtrArray *
r_ptr_array_new_sized (rsize size)
{
  RPtrArray * ret;

  if ((ret = r_mem_new (RPtrArray)) != NULL) {
    r_ptr_array_init (ret);
    r_ref_init (ret, r_ptr_array_free);
    r_ptr_array_ensure_size (ret, size);
  }

  return ret;
}

rpointer
r_ptr_array_get (RPtrArray * array, rsize idx)
{
  if (R_UNLIKELY (idx >= array->nsize)) return NULL;
  return R_PTR_ARRAY_N (array, idx).ptr;
}

rsize
r_ptr_array_add (RPtrArray * array, rpointer data, RDestroyNotify notify)
{
  r_ptr_array_ensure_size (array, array->nsize + 1);
  R_PTR_ARRAY_N (array, array->nsize).ptr = data;
  R_PTR_ARRAY_N (array, array->nsize).notify = notify;
  return array->nsize++;
}

rsize
r_ptr_array_update_idx (RPtrArray * array, rsize idx, rpointer data, RDestroyNotify notify)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;

  r_ptr_array_notify_idx (array, idx);

  R_PTR_ARRAY_N (array, idx).ptr = data;
  R_PTR_ARRAY_N (array, idx).notify = notify;
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
  r_memclear (&R_PTR_ARRAY_N (array, idx), (end - idx) * sizeof (RPtrNode));

  return end - idx;
}

rsize
r_ptr_array_remove_idx_full (RPtrArray * array, rsize idx, RFunc func, rpointer user)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;

  if (func != NULL) func (R_PTR_ARRAY_N (array, idx).ptr, user);
  r_ptr_array_notify_idx (array, idx);

  if (idx < --array->nsize) {
    r_memmove (&R_PTR_ARRAY_N (array, idx), &R_PTR_ARRAY_N (array, idx + 1),
        (array->nsize - idx) * sizeof (RPtrNode));
  }

  return idx;
}

rsize
r_ptr_array_remove_idx_fast_full (RPtrArray * array, rsize idx, RFunc func, rpointer user)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;
  if (func != NULL) func (R_PTR_ARRAY_N (array, idx).ptr, user);
  r_ptr_array_notify_idx (array, idx);

  if (idx < --array->nsize)
    R_PTR_ARRAY_N (array, idx) = R_PTR_ARRAY_N (array, array->nsize);

  return idx;
}

rsize
r_ptr_array_remove_idx_clear_full (RPtrArray * array, rsize idx, RFunc func, rpointer user)
{
  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;

  if (func != NULL) func (R_PTR_ARRAY_N (array, idx).ptr, user);
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
    r_memmove (&R_PTR_ARRAY_N (array, idx), &R_PTR_ARRAY_N (array, end),
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
  r_memmove (&R_PTR_ARRAY_N (array, idx), &R_PTR_ARRAY_N (array, array->nsize),
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
    r_memclear (&R_PTR_ARRAY_N (array, idx), (end - idx) * sizeof (RPtrNode));
  else
    array->nsize -= (end - idx);

  return end - idx;
}

rsize
r_ptr_array_find_range (RPtrArray * array, rpointer data, rsize idx, rssize size)
{
  rsize end;

  if (R_UNLIKELY (idx >= array->nsize)) return R_PTR_ARRAY_INVALID_IDX;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return R_PTR_ARRAY_INVALID_IDX;

  for (; idx < end; idx++) {
    if (R_PTR_ARRAY_N (array, idx).ptr == data)
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
    func (R_PTR_ARRAY_N (array, i).ptr, user);

  return end - idx;
}

