/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/data/rkvptrarray.h>

#include <rlib/rmem.h>

#define R_KV_PTR_ARRAY_MIN_SIZE    8
#define R_KV_PTR_ARRAY_N(array, idx) ((RKVPtrNode *)(array)->mem)[idx]

typedef struct {
  rpointer key, val;
  RDestroyNotify keynotify, valnotify;
} RKVPtrNode;


static inline void
r_kv_ptr_array_notify_idx (RKVPtrArray * array, rsize idx)
{
  if (R_KV_PTR_ARRAY_N (array, idx).keynotify != NULL)
    R_KV_PTR_ARRAY_N (array, idx).keynotify (R_KV_PTR_ARRAY_N (array, idx).key);
  if (R_KV_PTR_ARRAY_N (array, idx).valnotify != NULL)
    R_KV_PTR_ARRAY_N (array, idx).valnotify (R_KV_PTR_ARRAY_N (array, idx).val);
}

static inline void
r_kv_ptr_array_notify_range (RKVPtrArray * array, rsize idx, rsize until)
{
  for (; idx < until; idx++) {
    if (R_KV_PTR_ARRAY_N (array, idx).keynotify != NULL)
      R_KV_PTR_ARRAY_N (array, idx).keynotify (R_KV_PTR_ARRAY_N (array, idx).key);
    if (R_KV_PTR_ARRAY_N (array, idx).valnotify != NULL)
      R_KV_PTR_ARRAY_N (array, idx).valnotify (R_KV_PTR_ARRAY_N (array, idx).val);
  }
}


void
r_kv_ptr_array_init (RKVPtrArray * array, REqualFunc eqfunc)
{
  r_ref_init (array, r_kv_ptr_array_clear);
  array->eqfunc = eqfunc;
  array->nalloc = array->nsize = 0;
  array->mem = NULL;
}

void
r_kv_ptr_array_clear (RKVPtrArray * array)
{
  r_kv_ptr_array_notify_range (array, 0, array->nsize);
  r_free (array->mem);
  array->nalloc = array->nsize = 0;
  array->mem = NULL;
}

static void
r_kv_ptr_array_free (RKVPtrArray * array)
{
  r_kv_ptr_array_clear (array);
  r_free (array);
}

static void
r_kv_ptr_array_ensure_size (RKVPtrArray * array, rsize size)
{
  if (size < R_KV_PTR_ARRAY_MIN_SIZE)
    size = R_KV_PTR_ARRAY_MIN_SIZE;

  if (size > array->nalloc) {
    if (RSIZE_POPCOUNT (size) != 1)
      size = 1 << ((sizeof (rsize) * 8) - RSIZE_CLZ (size));

    array->mem = r_realloc (array->mem, size * sizeof (RKVPtrNode));
    array->nalloc = size;
  }
}

RKVPtrArray *
r_kv_ptr_array_new_sized (rsize size, REqualFunc eqfunc)
{
  RKVPtrArray * ret;

  if ((ret = r_mem_new (RKVPtrArray)) != NULL) {
    r_kv_ptr_array_init (ret, eqfunc);
    r_ref_init (ret, r_kv_ptr_array_free);
    r_kv_ptr_array_ensure_size (ret, size);
  }

  return ret;
}

rpointer
r_kv_ptr_array_get_key (RKVPtrArray * array, rsize idx)
{
  if (R_UNLIKELY (idx >= array->nsize)) return NULL;
  return R_KV_PTR_ARRAY_N (array, idx).key;
}

rpointer
r_kv_ptr_array_get_val (RKVPtrArray * array, rsize idx)
{
  if (R_UNLIKELY (idx >= array->nsize)) return NULL;
  return R_KV_PTR_ARRAY_N (array, idx).val;
}

rpointer
r_kv_ptr_array_get (RKVPtrArray * array, rsize idx, rpointer * key)
{
  if (R_UNLIKELY (idx >= array->nsize)) return NULL;
  if (key != NULL)
    *key = R_KV_PTR_ARRAY_N (array, idx).key;
  return R_KV_PTR_ARRAY_N (array, idx).val;
}

rboolean
r_ptr_equal (rconstpointer a, rconstpointer b)
{
  return a == b;
}

rsize
r_kv_ptr_array_find_range (RKVPtrArray * array, rconstpointer key, rsize idx, rssize size)
{
  rsize end;
  REqualFunc eqfunc;

  if (R_UNLIKELY (idx >= array->nsize)) return R_KV_PTR_ARRAY_INVALID_IDX;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return R_KV_PTR_ARRAY_INVALID_IDX;

  eqfunc = array->eqfunc != NULL ? array->eqfunc : r_ptr_equal;
  for (; idx < end; idx++) {
    if (eqfunc (R_KV_PTR_ARRAY_N (array, idx).key, key))
      return idx;
  }

  return R_KV_PTR_ARRAY_INVALID_IDX;
}

rsize
r_kv_ptr_array_add (RKVPtrArray * array,
    rpointer key, RDestroyNotify keynotify,
    rpointer val, RDestroyNotify valnotify)
{
  r_kv_ptr_array_ensure_size (array, array->nsize + 1);
  R_KV_PTR_ARRAY_N (array, array->nsize).key = key;
  R_KV_PTR_ARRAY_N (array, array->nsize).val = val;
  R_KV_PTR_ARRAY_N (array, array->nsize).keynotify = keynotify;
  R_KV_PTR_ARRAY_N (array, array->nsize).valnotify = valnotify;
  return array->nsize++;
}

rsize
r_kv_ptr_array_remove_range (RKVPtrArray * array, rsize idx, rssize size)
{
  rsize end;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  r_kv_ptr_array_notify_range (array, idx, end);

  if (end < array->nsize) {
    r_memmove (&R_KV_PTR_ARRAY_N (array, idx), &R_KV_PTR_ARRAY_N (array, end),
        (array->nsize - end) * sizeof (RKVPtrNode));
  }

  array->nsize -= (end - idx);
  return end - idx;
}

rsize
r_kv_ptr_array_remove_key_first (RKVPtrArray * array, rpointer key)
{
  rsize idx;

  if ((idx = r_kv_ptr_array_find (array, key)) != R_KV_PTR_ARRAY_INVALID_IDX)
    return r_kv_ptr_array_remove_idx (array, idx);

  return 0;
}

rsize
r_kv_ptr_array_remove_key_all (RKVPtrArray * array, rpointer key)
{
  rsize idx, ret = 0;
  REqualFunc eqfunc;

  eqfunc = array->eqfunc != NULL ? array->eqfunc : r_ptr_equal;
  for (idx = 0; idx < array->nsize; ) {
    if (eqfunc (R_KV_PTR_ARRAY_N (array, idx).key, key)) {
      ret += r_kv_ptr_array_remove_idx (array, idx);
    } else {
      idx += 1;
    }
  }

  return ret;
}

rsize
r_kv_ptr_array_foreach_range (RKVPtrArray * array,
    rsize idx, rssize size, RKeyValueFunc func, rpointer user)
{
  rsize i, end;

  if (R_UNLIKELY (func == NULL)) return 0;

  if (R_UNLIKELY (idx >= array->nsize)) return 0;
  end = (size < 0) ? array->nsize : idx + size;
  if (R_UNLIKELY (end > array->nsize)) return 0;

  for (i = idx; i < end; i++)
    func (R_KV_PTR_ARRAY_N (array, i).key, R_KV_PTR_ARRAY_N (array, i).val, user);

  return end - idx;
}

