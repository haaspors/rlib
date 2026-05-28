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
#ifndef __R_KV_PTR_ARRAY_H__
#define __R_KV_PTR_ARRAY_H__

/**
 * @defgroup r_kvptrarray Key-value pointer array
 * @ingroup r_data
 *
 * @brief Growable, refcounted ordered array of @c (key, value)
 * pointer pairs.
 *
 * Unlike @ref r_hashtable, key order is preserved and lookups
 * walk the array linearly via a caller-supplied @ref REqualFunc.
 * Useful when iteration order matters or the entry count is small
 * enough that the constant-factor wins over hashing.
 *
 * @{
 */

/**
 * @file rlib/data/rkvptrarray.h
 * @brief Growable refcounted array of @c (key, value) pointer pairs.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rhashfuncs.h>

R_BEGIN_DECLS

/** @brief Sentinel returned by lookup helpers when no match is found. */
#define R_KV_PTR_ARRAY_INVALID_IDX  RSIZE_MAX

/** @brief Opaque, refcounted KV pointer array. */
typedef struct RKVPtrArray RKVPtrArray;

/** @name Lifecycle
 *  @{ */

/** @brief Static initialiser with a caller-chosen equality function. */
#define R_KV_PTR_ARRAY_INIT_WITH_FUNC(eqfunc) { R_REF_STATIC_INIT (NULL), eqfunc, 0, 0, NULL }
/** @brief Static initialiser with identity (pointer) equality. */
#define R_KV_PTR_ARRAY_INIT       R_KV_PTR_ARRAY_INIT_WITH_FUNC (NULL)
/** @brief Static initialiser for string-keyed arrays (uses @c r_str_equal). */
#define R_KV_PTR_ARRAY_INIT_STR   R_KV_PTR_ARRAY_INIT_WITH_FUNC (r_str_equal)
/**
 * @brief Initialise an embedded / stack array with the given equality function.
 *
 * @param array   The array.
 * @param eqfunc  Key comparator, or @c NULL for identity equality.
 */
R_API void r_kv_ptr_array_init (RKVPtrArray * array, REqualFunc eqfunc);
/** @brief Convenience: initialise as a string-keyed array. */
#define r_kv_ptr_array_init_str(array) r_kv_ptr_array_init (array, r_str_equal)
/** @brief Drop every pair, run destroy notifiers, release storage. */
R_API void r_kv_ptr_array_clear (RKVPtrArray * array);

/** @brief Heap-allocate an empty identity-keyed array. */
#define r_kv_ptr_array_new()      r_kv_ptr_array_new_sized (0, NULL)
/** @brief Heap-allocate an empty string-keyed array. */
#define r_kv_ptr_array_new_str()  r_kv_ptr_array_new_sized (0, r_str_equal)
/**
 * @brief Heap-allocate an array with @p size initial slots and the
 * caller's equality function.
 */
R_API RKVPtrArray * r_kv_ptr_array_new_sized (rsize size, REqualFunc eqfunc) R_ATTR_MALLOC;
/** @brief Increment the array's refcount. */
#define r_kv_ptr_array_ref   r_ref_ref
/** @brief Decrement the array's refcount; clears when it reaches zero. */
#define r_kv_ptr_array_unref r_ref_unref

/** @brief Number of pairs currently in @p array. */
#define r_kv_ptr_array_size(array) (array)->nsize
/** @brief Allocated capacity (in pair slots). */
#define r_kv_ptr_array_alloc_size(array) (array)->nalloc

/** @} */

/** @name Lookup and access
 *  @{ */

/** @brief Key at @p idx. */
R_API rpointer r_kv_ptr_array_get_key (RKVPtrArray * array, rsize idx);
/** @brief Value at @p idx. */
R_API rpointer r_kv_ptr_array_get_val (RKVPtrArray * array, rsize idx);
/**
 * @brief Return the value at @p idx and write the key into @p key.
 *
 * @param array  The array.
 * @param idx    Slot index.
 * @param key    Out: stored key (pass @c NULL to discard).
 */
R_API rpointer r_kv_ptr_array_get (RKVPtrArray * array, rsize idx, rpointer * key);
/** @brief Const-correct variant of @ref r_kv_ptr_array_get. */
R_API rconstpointer r_kv_ptr_array_get_const (const RKVPtrArray * array, rsize idx, rconstpointer * key);

/** @brief Convenience: find the first slot whose key matches @p key. */
#define r_kv_ptr_array_find(array, key) r_kv_ptr_array_find_range (array, key, 0, -1)
/**
 * @brief Find the first slot whose key matches @p key within
 * @c [idx, idx+size).
 */
R_API rsize r_kv_ptr_array_find_range (RKVPtrArray * array, rconstpointer key, rsize idx, rssize size);

/** @} */

/** @name Insertion and removal
 *  @{ */

/**
 * @brief Append a @c (key, value) pair with per-side destroy notifiers.
 *
 * @param array      The array.
 * @param key        Key pointer.
 * @param keynotify  Destroy notifier for @p key, or @c NULL.
 * @param val        Value pointer.
 * @param valnotify  Destroy notifier for @p val, or @c NULL.
 * @return Index at which the pair was stored.
 */
R_API rsize r_kv_ptr_array_add (RKVPtrArray * array,
    rpointer key, RDestroyNotify keynotify, rpointer val, RDestroyNotify valnotify);
/** @brief Overwrite slot @p idx; previous key/value run through their destroy notifiers. */
R_API rsize r_kv_ptr_array_update_idx (RKVPtrArray * array, rsize idx,
    rpointer key, RDestroyNotify keynotify, rpointer val, RDestroyNotify valnotify);
/** @brief Stable range remove; destroy notifiers run on each entry. */
R_API rsize r_kv_ptr_array_remove_range (RKVPtrArray * array, rsize idx, rssize size);
/** @brief Convenience: stable single-slot remove. */
#define r_kv_ptr_array_remove_idx(array, idx) r_kv_ptr_array_remove_range (array, idx, 1)
/** @brief Convenience: remove every pair. */
#define r_kv_ptr_array_remove_all(array) r_kv_ptr_array_remove_range (array, 0, -1)
/** @brief Remove the first slot whose key matches @p key. */
R_API rsize r_kv_ptr_array_remove_key_first (RKVPtrArray * array, rpointer key);
/** @brief Remove every slot whose key matches @p key. */
R_API rsize r_kv_ptr_array_remove_key_all (RKVPtrArray * array, rpointer key);

/** @} */

/** @name Iteration
 *  @{ */

/** @brief Invoke @p func on each pair in @c [idx, idx+size). */
R_API rsize r_kv_ptr_array_foreach_range (RKVPtrArray * array,
    rsize idx, rssize size, RKeyValueFunc func, rpointer user);
/** @brief Convenience: iterate every pair. */
#define r_kv_ptr_array_foreach(array, func, user) \
  r_kv_ptr_array_foreach_range (array, 0, -1, func, user)

/** @} */


/**
 * @brief Public definition of @ref RKVPtrArray.
 *
 * Exposed so callers can stack-allocate or embed the struct
 * directly. Treat as opaque - access through the
 * @c r_kv_ptr_array_* helpers above.
 */
struct RKVPtrArray {
  RRef ref;             /**< Refcount base. */

  REqualFunc eqfunc;    /**< Key comparator (NULL for identity). */

  rsize nalloc;         /**< Allocated capacity (pairs). */
  rsize nsize;          /**< Number of pairs in use. */
  rpointer mem;         /**< Pair storage. */
};

R_END_DECLS

/** @} */

#endif /* __R_KV_PTR_ARRAY_H__ */

