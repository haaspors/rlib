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

#include <rlib/rhashset.h>
#include <rlib/rhash-private.h>

#include <rlib/rmem.h>


typedef struct {
  rpointer item;
  rsize hash;
} RHashSetBucket;

struct _RHashSet {
  RRef ref;

  rsize size;
  ruint8 allocidx;
  RHashSetBucket * buckets;

  RHashFunc hashfunc;
  REqualFunc equalfunc;
  RDestroyNotify notify;
};

static void
r_hash_set_free (RHashSet * hs)
{
  if (hs->notify != NULL) {
    rsize i, c = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx);
    for (i = 0; i < c; i++) {
      if (hs->buckets[i].hash != R_HASH_EMPTY)
        hs->notify (hs->buckets[i].item);
    }
  }

  r_free (hs->buckets);
  r_free (hs);
}

static void
r_hash_set_resize (RHashSet * hs, ruint8 allocidx)
{
  RHashSetBucket * buckets = hs->buckets;
  rsize i, size;

  size = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (allocidx);
  hs->buckets = r_mem_new_n (RHashSetBucket, size);
  for (i = 0; i < size; i++)
    hs->buckets[i].hash = R_HASH_EMPTY;

  size = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx);
  hs->allocidx = allocidx;

  for (i = 0; i < size; i++) {
    rsize idx, step = 0;

    if (buckets[i].hash == R_HASH_EMPTY)
      continue;

    idx = buckets[i].hash % r_hash_size_primes[hs->allocidx];
    while (hs->buckets[idx].hash != R_HASH_EMPTY) {
      idx += ++step;
      idx &= (R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx) - 1);
    }

    hs->buckets[idx] = buckets[i];
  }

  r_free (buckets);
}

RHashSet *
r_hash_set_new_full (RHashFunc hash, REqualFunc equal, RDestroyNotify notify)
{
  RHashSet * ret;

  if ((ret = r_mem_new (RHashSet)) != NULL) {
    rsize i, size;
    r_ref_init (ret, r_hash_set_free);

    ret->size = 0;
    ret->allocidx = 0;
    size = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ret->allocidx);
    ret->buckets = r_mem_new_n (RHashSetBucket, size);
    for (i = 0; i < size; i++)
      ret->buckets[i].hash = R_HASH_EMPTY;
    ret->hashfunc = hash != NULL ? hash : r_direct_hash;
    ret->equalfunc = equal;
    ret->notify = notify;
  }

  return ret;
}

rsize
r_hash_set_size (RHashSet * hs)
{
  return hs->size;
}

rsize
r_hash_set_current_alloc_size (RHashSet * hs)
{
  return R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx);
}

static inline rsize
r_hash_set_hash (RHashSet * hs, rconstpointer item)
{
  rsize ret = hs->hashfunc (item);
  if (R_UNLIKELY (ret == R_HASH_EMPTY))
    ret++;
  return ret;
}

static rsize
r_hash_set_lookup_bucket (RHashSet * hs, rconstpointer item, rsize * hash)
{
  rsize idx, step = 0;

  *hash = r_hash_set_hash (hs, item);
  idx = *hash % r_hash_size_primes[hs->allocidx];

  while (hs->buckets[idx].hash != R_HASH_EMPTY) {
    if (hs->buckets[idx].hash == *hash) {
      if ((hs->equalfunc == NULL && item == hs->buckets[idx].item) ||
          hs->equalfunc (item, hs->buckets[idx].item))
        break;
    }

    idx += ++step;
    idx &= (R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx) - 1);
  }

  return idx;
}

rboolean
r_hash_set_insert (RHashSet * hs, rpointer item)
{
  rsize idx, hash;

  if (R_UNLIKELY (hs == NULL)) return FALSE;

  if (hs->size >= R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx))
    r_hash_set_resize (hs, hs->allocidx + 1);

  idx = r_hash_set_lookup_bucket (hs, item, &hash);
  if (hs->buckets[idx].hash == hash) {
    if (hs->notify != NULL)
      hs->notify (hs->buckets[idx].item);
  } else {
    hs->buckets[idx].hash = hash;
    hs->size++;
  }

  hs->buckets[idx].item = item;
  return TRUE;
}

rboolean
r_hash_set_contains (RHashSet * hs, rconstpointer item)
{
  rsize idx, hash;

  if (R_UNLIKELY (hs == NULL)) return FALSE;

  idx = r_hash_set_lookup_bucket (hs, item, &hash);
  return hs->buckets[idx].hash == hash;
}

rboolean
r_hash_set_contains_full (RHashSet * hs, rconstpointer item,
    rpointer * out)
{
  rsize idx, hash;

  if (R_UNLIKELY (hs == NULL)) return FALSE;

  idx = r_hash_set_lookup_bucket (hs, item, &hash);
  if (hs->buckets[idx].hash == hash) {
    if (out != NULL)
      *out = hs->buckets[idx].item;
    return TRUE;
  }

  return FALSE;
}

void
r_hash_set_remove_all (RHashSet * hs)
{
  if (R_UNLIKELY (hs == NULL)) return;
  if (R_UNLIKELY (hs->size == 0)) return;

  if (hs->notify != NULL) {
    rsize i, c = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx);
    for (i = 0; i < c; i++) {
      if (hs->buckets[i].hash == R_HASH_EMPTY) continue;
      hs->notify (hs->buckets[i].item);
      hs->buckets[i].hash = R_HASH_EMPTY;
    }
  }

  hs->size = 0;
}

rboolean
r_hash_set_remove (RHashSet * hs, rconstpointer item)
{
  rsize idx, hash;

  if (R_UNLIKELY (hs == NULL)) return FALSE;

  idx = r_hash_set_lookup_bucket (hs, item, &hash);
  if (R_UNLIKELY (hs->buckets[idx].hash != hash))
    return FALSE;

  if (hs->notify != NULL)
    hs->notify (hs->buckets[idx].item);
  hs->buckets[idx].hash = R_HASH_EMPTY;

  hs->size--;
  return TRUE;
}

rboolean
r_hash_set_steal (RHashSet * hs, rconstpointer item, rpointer * out)
{
  rsize idx, hash;

  if (R_UNLIKELY (hs == NULL)) return FALSE;

  idx = r_hash_set_lookup_bucket (hs, item, &hash);
  if (R_UNLIKELY (hs->buckets[idx].hash != hash)) {
    if (out != NULL)
      *out = NULL;
    return FALSE;
  }

  if (out != NULL)
    *out = hs->buckets[idx].item;
  hs->buckets[idx].hash = R_HASH_EMPTY;

  hs->size--;
  return TRUE;
}

rboolean
r_hash_set_foreach (RHashSet * hs, RFunc func, rpointer user)
{
  rsize i, c;

  if (R_UNLIKELY (hs == NULL)) return FALSE;
  if (R_UNLIKELY (func == NULL)) return FALSE;

  c = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (hs->allocidx);
  for (i = 0; i < c; i++) {
    if (hs->buckets[i].hash != R_HASH_EMPTY)
      func (hs->buckets[i].item, user);
  }

  return TRUE;
}

