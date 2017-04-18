/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rhash-private.h"

#include <rlib/rhashtable.h>

#include <rlib/rmem.h>

typedef struct {
  rpointer key;
  rpointer val;
  rsize hash;
} RHashTableBucket;

struct _RHashTable {
  RRef ref;

  rsize size;
  ruint8 allocidx;
  RHashTableBucket * buckets;

  RHashFunc hashfunc;
  REqualFunc equalfunc;
  RDestroyNotify keynotify;
  RDestroyNotify valuenotify;
};

static void
r_hash_table_free (RHashTable * ht)
{
  rsize i, c = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx);

  if (ht->keynotify != NULL && ht->valuenotify != NULL) {
    for (i = 0; i < c; i++) {
      if (ht->buckets[i].hash != R_HASH_EMPTY) {
        ht->keynotify (ht->buckets[i].key);
        ht->valuenotify (ht->buckets[i].val);
      }
    }
  } else if (ht->valuenotify != NULL) {
    for (i = 0; i < c; i++) {
      if (ht->buckets[i].hash != R_HASH_EMPTY)
        ht->valuenotify (ht->buckets[i].val);
    }
  } else if (ht->keynotify != NULL) {
    for (i = 0; i < c; i++) {
      if (ht->buckets[i].hash != R_HASH_EMPTY)
        ht->keynotify (ht->buckets[i].key);
    }
  }

  r_free (ht->buckets);
  r_free (ht);
}

static void
r_hash_table_resize (RHashTable * ht, ruint8 allocidx)
{
  RHashTableBucket * buckets = ht->buckets;
  rsize i, size;

  size = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (allocidx);
  ht->buckets = r_mem_new_n (RHashTableBucket, size);
  for (i = 0; i < size; i++)
    ht->buckets[i].hash = R_HASH_EMPTY;

  size = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx);
  ht->allocidx = allocidx;

  for (i = 0; i < size; i++) {
    rsize idx, step = 0;

    if (buckets[i].hash == R_HASH_EMPTY)
      continue;

    idx = buckets[i].hash % r_hash_size_primes[ht->allocidx];
    while (ht->buckets[idx].hash != R_HASH_EMPTY) {
      idx += ++step;
      idx &= (R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx) - 1);
    }

    ht->buckets[idx] = buckets[i];
  }

  r_free (buckets);
}

RHashTable *
r_hash_table_new_full (RHashFunc hash, REqualFunc equal,
    RDestroyNotify keynotify, RDestroyNotify valuenotify)
{
  RHashTable * ret;

  if ((ret = r_mem_new (RHashTable)) != NULL) {
    rsize i, size;
    r_ref_init (ret, r_hash_table_free);

    ret->size = 0;
    ret->allocidx = 0;
    size = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ret->allocidx);
    ret->buckets = r_mem_new_n (RHashTableBucket, size);
    for (i = 0; i < size; i++)
      ret->buckets[i].hash = R_HASH_EMPTY;
    ret->hashfunc = hash != NULL ? hash : r_direct_hash;
    ret->equalfunc = equal;
    ret->keynotify = keynotify;
    ret->valuenotify = valuenotify;
  }

  return ret;
}

rsize
r_hash_table_size (RHashTable * ht)
{
  return ht->size;
}

rsize
r_hash_table_current_alloc_size (RHashTable * ht)
{
  return R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx);
}

static inline rsize
r_hash_table_hash (RHashTable * ht, rconstpointer key)
{
  rsize ret = ht->hashfunc (key);
  if (R_UNLIKELY (ret == R_HASH_EMPTY))
    ret++;
  return ret;
}

static rsize
r_hash_table_lookup_bucket (RHashTable * ht, rconstpointer key, rsize * hash)
{
  rsize idx, step = 0;

  *hash = r_hash_table_hash (ht, key);
  idx = *hash % r_hash_size_primes[ht->allocidx];

  while (ht->buckets[idx].hash != R_HASH_EMPTY) {
    if (ht->buckets[idx].hash == *hash) {
      if ((ht->equalfunc == NULL && key == ht->buckets[idx].key) ||
          ht->equalfunc (key, ht->buckets[idx].key))
        break;
    }

    idx += ++step;
    idx &= (R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx) - 1);
  }

  return idx;
}

RHashTableError
r_hash_table_insert (RHashTable * ht, rpointer key, rpointer value)
{
  rsize idx, hash;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;

  if (ht->size >= R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx))
    r_hash_table_resize (ht, ht->allocidx + 1);

  idx = r_hash_table_lookup_bucket (ht, key, &hash);
  if (ht->buckets[idx].hash == hash) {
    if (ht->keynotify != NULL && ht->buckets[idx].key != NULL)
      ht->keynotify (ht->buckets[idx].key);
    if (ht->valuenotify != NULL && ht->buckets[idx].val != NULL)
      ht->valuenotify (ht->buckets[idx].val);
  } else {
    ht->buckets[idx].hash = hash;
    ht->size++;
  }

  ht->buckets[idx].key = key;
  ht->buckets[idx].val = value;
  return R_HASH_TABLE_OK;
}

rpointer
r_hash_table_lookup (RHashTable * ht, rconstpointer key)
{
  rsize idx, hash;
  idx = r_hash_table_lookup_bucket (ht, key, &hash);
  return (ht->buckets[idx].hash == hash) ? ht->buckets[idx].val : NULL;
}

RHashTableError
r_hash_table_lookup_full (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout)
{
  rsize idx, hash;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;

  idx = r_hash_table_lookup_bucket (ht, key, &hash);
  if (ht->buckets[idx].hash == hash) {
    if (keyout != NULL)
      *keyout = ht->buckets[idx].key;
    if (valueout != NULL)
      *valueout = ht->buckets[idx].val;
    return R_HASH_TABLE_OK;
  }

  return R_HASH_TABLE_NOT_FOUND;
}

RHashTableError
r_hash_table_contains (RHashTable * ht, rconstpointer key)
{
  rsize idx, hash;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;

  idx = r_hash_table_lookup_bucket (ht, key, &hash);
  return ht->buckets[idx].hash == hash ? R_HASH_TABLE_OK : R_HASH_TABLE_NOT_FOUND;
}

void
r_hash_table_remove_all (RHashTable * ht)
{
  rsize i, c;

  if (R_UNLIKELY (ht == NULL)) return;
  if (R_UNLIKELY (ht->size == 0)) return;

  c = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx);

  if (ht->keynotify != NULL && ht->valuenotify != NULL) {
    for (i = 0; i < c; i++) {
      if (ht->buckets[i].hash == R_HASH_EMPTY) continue;
      ht->keynotify (ht->buckets[i].key);
      ht->valuenotify (ht->buckets[i].val);
      ht->buckets[i].hash = R_HASH_EMPTY;
    }
  } else if (ht->valuenotify != NULL) {
    for (i = 0; i < c; i++) {
      if (ht->buckets[i].hash == R_HASH_EMPTY) continue;
      ht->valuenotify (ht->buckets[i].val);
      ht->buckets[i].hash = R_HASH_EMPTY;
    }
  } else if (ht->keynotify != NULL) {
    for (i = 0; i < c; i++) {
      if (ht->buckets[i].hash == R_HASH_EMPTY) continue;
      ht->keynotify (ht->buckets[i].key);
      ht->buckets[i].hash = R_HASH_EMPTY;
    }
  }

  ht->size = 0;
}

static void
r_hash_table_internal_remove (RHashTable * ht, rsize idx)
{
  if (ht->keynotify != NULL)
    ht->keynotify (ht->buckets[idx].key);
  if (ht->valuenotify != NULL)
    ht->valuenotify (ht->buckets[idx].val);
  ht->buckets[idx].hash = R_HASH_EMPTY;

  ht->size--;
}

RHashTableError
r_hash_table_remove (RHashTable * ht, rconstpointer key)
{
  rsize idx, hash;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;

  idx = r_hash_table_lookup_bucket (ht, key, &hash);
  if (R_UNLIKELY (ht->buckets[idx].hash != hash))
    return R_HASH_TABLE_NOT_FOUND;

  r_hash_table_internal_remove (ht, idx);
  return R_HASH_TABLE_OK;
}

RHashTableError
r_hash_table_remove_full (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout)
{
  rsize idx, hash;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;

  idx = r_hash_table_lookup_bucket (ht, key, &hash);
  if (R_UNLIKELY (ht->buckets[idx].hash != hash)) {
    if (keyout != NULL)
      *keyout = NULL;
    if (valueout != NULL)
      *valueout = NULL;
    return R_HASH_TABLE_NOT_FOUND;
  }

  if (keyout != NULL)
    *keyout = ht->buckets[idx].key;
  if (valueout != NULL)
    *valueout = ht->buckets[idx].val;

  r_hash_table_internal_remove (ht, idx);
  return R_HASH_TABLE_OK;
}

RHashTableError
r_hash_table_steal (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout)
{
  rsize idx, hash;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;

  idx = r_hash_table_lookup_bucket (ht, key, &hash);
  if (R_UNLIKELY (ht->buckets[idx].hash != hash)) {
    if (keyout != NULL)
      *keyout = NULL;
    if (valueout != NULL)
      *valueout = NULL;
    return R_HASH_TABLE_NOT_FOUND;
  }

  if (keyout != NULL)
    *keyout = ht->buckets[idx].key;
  if (valueout != NULL)
    *valueout = ht->buckets[idx].val;
  ht->buckets[idx].hash = R_HASH_EMPTY;

  ht->size--;
  return R_HASH_TABLE_OK;
}

rboolean
r_hash_table_remove_func_value (rpointer key, rpointer value, rpointer user)
{
  (void) key;
  return value == user;
}

RHashTableError
r_hash_table_remove_with_func (RHashTable * ht,
    RKeyValueFuncReturn func, rpointer user)
{
  rsize i, c;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;
  if (R_UNLIKELY (func == NULL)) return R_HASH_TABLE_INVAL;

  c = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx);
  for (i = 0; i < c; i++) {
    if (ht->buckets[i].hash != R_HASH_EMPTY &&
        func (ht->buckets[i].key, ht->buckets[i].val, user)) {
      r_hash_table_internal_remove (ht, i);
    }
  }

  return R_HASH_TABLE_OK;
}

RHashTableError
r_hash_table_foreach (RHashTable * ht, RKeyValueFunc func, rpointer user)
{
  rsize i, c;

  if (R_UNLIKELY (ht == NULL)) return R_HASH_TABLE_INVAL;
  if (R_UNLIKELY (func == NULL)) return R_HASH_TABLE_INVAL;

  c = R_HASH_CONTAINER_ALLOC_IDX_TO_SIZE (ht->allocidx);
  for (i = 0; i < c; i++) {
    if (ht->buckets[i].hash != R_HASH_EMPTY)
      func (ht->buckets[i].key, ht->buckets[i].val, user);
  }

  return R_HASH_TABLE_OK;
}


const rsize r_hash_size_primes[RLIB_SIZEOF_SIZE_T * 8 - 2] = {
                                        7,
                                       11,
                                       23,
                                       47,
                                       97,
                                      199,
                                      409,
                                      823,
                                     1741,
                                     3469,
                                     6949,
                                    14033,
                                    28411,
                                    57557,
#if RLIB_SIZEOF_SIZE_T >= 4
                                   116731,
                                   236897,
                                   480881,
                                   976369,
                                  1982627,
                                  4026031,
                                  8175383,
                                 16601593,
                                 33712729,
                                 68460391,
                                139022417,
                                282312799,
                                573292817,
                               1164186217,
                               2364114217,
                               4294967291,
#if RLIB_SIZEOF_SIZE_T >= 8
  RUINT64_CONSTANT (          8589934583),
  RUINT64_CONSTANT (         17179869143),
  RUINT64_CONSTANT (         34359738337),
  RUINT64_CONSTANT (         68719476731),
  RUINT64_CONSTANT (        137438953447),
  RUINT64_CONSTANT (        274877906899),
  RUINT64_CONSTANT (        549755813881),
  RUINT64_CONSTANT (       1099511627689),
  RUINT64_CONSTANT (       2199023255531),
  RUINT64_CONSTANT (       4398046511093),
  RUINT64_CONSTANT (       8796093022151),
  RUINT64_CONSTANT (      17592186044399),
  RUINT64_CONSTANT (      35184372088777),
  RUINT64_CONSTANT (      70368744177643),
  RUINT64_CONSTANT (     140737488355213),
  RUINT64_CONSTANT (     281474976710597),
  RUINT64_CONSTANT (     562949953421231),
  RUINT64_CONSTANT (    1125899906842597),
  RUINT64_CONSTANT (    2251799813685119),
  RUINT64_CONSTANT (    4503599627370449),
  RUINT64_CONSTANT (    9007199254740881),
  RUINT64_CONSTANT (   18014398509481951),
  RUINT64_CONSTANT (   36028797018963913),
  RUINT64_CONSTANT (   72057594037927931),
  RUINT64_CONSTANT (  144115188075855859),
  RUINT64_CONSTANT (  288230376151711717),
  RUINT64_CONSTANT (  576460752303423433),
  RUINT64_CONSTANT ( 1152921504606846883),
  RUINT64_CONSTANT ( 2305843009213693951),
  RUINT64_CONSTANT ( 4611686018427387847),
  RUINT64_CONSTANT ( 9223372036854775783),
  RUINT64_CONSTANT (18446744073709551557),
#endif
#endif
};

