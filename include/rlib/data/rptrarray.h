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
#ifndef __R_PTR_ARRAY_H__
#define __R_PTR_ARRAY_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_ptrarray Pointer array
 * @ingroup r_data
 *
 * @brief Growable, refcounted array of @c rpointer values with
 * optional per-slot destroy notifiers.
 *
 * Use either as a heap-allocated refcounted object
 * (@ref r_ptr_array_new) or as an embedded / stack value
 * (@ref R_PTR_ARRAY_INIT + @ref r_ptr_array_init). Removals
 * support three semantics: stable in-order (@c remove_idx),
 * swap-last-into-the-gap (@c remove_idx_fast), and zero-the-slot
 * without shrinking (@c remove_idx_clear). Each shape has a
 * @c _full variant that fires a caller-supplied function on the
 * displaced item.
 *
 * @{
 */

/**
 * @file rlib/data/rptrarray.h
 * @brief Growable, refcounted array of @c rpointer values.
 */

#include <rlib/rtypes.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

/** @brief Sentinel returned by lookup helpers when no match is found. */
#define R_PTR_ARRAY_INVALID_IDX               RSIZE_MAX

/** @brief Opaque, refcounted growable pointer array (definition below). */
typedef struct RPtrArray RPtrArray;

/** @name Lifecycle
 *  @{ */

/** @brief Static initialiser for an embedded / stack @ref RPtrArray. */
#define R_PTR_ARRAY_INIT                      { R_REF_STATIC_INIT (NULL), 0, 0, NULL }
/** @brief Initialise an embedded / stack @ref RPtrArray to empty. */
R_API void r_ptr_array_init (RPtrArray * array);
/** @brief Drop every item and release backing storage; destroy notifiers run. */
R_API void r_ptr_array_clear (RPtrArray * array);

/** @brief Heap-allocate an empty array (initial capacity 0). */
#define r_ptr_array_new() r_ptr_array_new_sized (0)
/** @brief Heap-allocate an array with a preset initial capacity. */
R_API RPtrArray * r_ptr_array_new_sized (rsize size) R_ATTR_MALLOC;
/** @brief Increment the array's refcount. */
#define r_ptr_array_ref   r_ref_ref
/** @brief Decrement the array's refcount; clears when it reaches zero. */
#define r_ptr_array_unref r_ref_unref

/** @brief Number of items currently in @p array. */
#define r_ptr_array_size(array) (array)->nsize
/** @brief Allocated capacity (in slots). */
#define r_ptr_array_alloc_size(array) (array)->nalloc

/** @} */

/** @name Item access and search
 *  @{ */

/** @brief Return the pointer stored at @p idx. */
R_API rpointer r_ptr_array_get (RPtrArray * array, rsize idx);
/** @brief Const-correct variant of @ref r_ptr_array_get. */
R_API rconstpointer r_ptr_array_get_const (const RPtrArray * array, rsize idx);

/** @brief Convenience: find first occurrence of @p data over the whole array. */
#define r_ptr_array_find(array, data) r_ptr_array_find_range (array, data, 0, -1)
/**
 * @brief Find first occurrence of @p data within the range starting
 * at @p idx for @p size items.
 *
 * @param array  The array.
 * @param data   Value to match (identity comparison).
 * @param idx    First index to search.
 * @param size   Range length, or @c -1 for "to end".
 * @return Index of the first match, or @ref R_PTR_ARRAY_INVALID_IDX.
 */
R_API rsize r_ptr_array_find_range (RPtrArray * array, rpointer data, rsize idx, rssize size);

/** @} */

/** @name Inserting and updating
 *  @{ */

/**
 * @brief Append @p data to the array.
 *
 * @param array   The array.
 * @param data    Pointer to store.
 * @param notify  Destroy notifier invoked when the slot is later
 *                cleared / removed, or @c NULL.
 * @return Index at which @p data was stored.
 */
R_API rsize r_ptr_array_add (RPtrArray * array,
    rpointer data, RDestroyNotify notify);
/**
 * @brief Insert @p data at @p idx, shifting later items up by one.
 */
R_API rsize r_ptr_array_insert (RPtrArray * array, rsize idx,
    rpointer data, RDestroyNotify notify);
/**
 * @brief Overwrite the slot at @p idx.
 *
 * The previous slot's destroy notifier runs (if any) before
 * @p data takes its place.
 */
R_API rsize r_ptr_array_update_idx (RPtrArray * array, rsize idx,
    rpointer data, RDestroyNotify notify);
/** @brief Convenience: write @c NULL into slot @p idx, freeing the previous value. */
#define r_ptr_array_clear_idx(array, idx) r_ptr_array_update_idx (array, idx, NULL, NULL)
/**
 * @brief Write @c NULL into every slot in the range; previous values
 * run through their destroy notifiers.
 */
R_API rsize r_ptr_array_clear_range (RPtrArray * array, rsize idx, rssize size);

/** @} */

/** @name Removal — three semantics
 *
 * @c _full variants accept a @c (func, user) pair that's invoked on
 * each removed item; the macro shortcuts pass @c (NULL, NULL).
 *
 *   - **idx** family — stable: removes the slot and shifts later
 *     items down. O(n).
 *   - **idx_fast** family — swap-with-last into the gap. O(1) but
 *     reorders items.
 *   - **idx_clear** family — overwrite the slot with @c NULL
 *     without shrinking @c nsize. O(1).
 *  @{ */

/** @brief Convenience: remove all items, no per-item function. */
#define r_ptr_array_remove_all(array) r_ptr_array_remove_range_clear_full (array, 0, -1, NULL, NULL)
/** @brief Convenience: remove all items, calling @p func on each. */
#define r_ptr_array_remove_all_full(array, func, user) r_ptr_array_remove_range_clear_full (array, 0, -1, func, user)

/** @brief Convenience: stable remove of slot @p idx, no per-item function. */
#define r_ptr_array_remove_idx(array, idx) r_ptr_array_remove_idx_full (array, idx, NULL, NULL)
/** @brief Convenience: swap-with-last remove of slot @p idx, no per-item function. */
#define r_ptr_array_remove_idx_fast(array, idx) r_ptr_array_remove_idx_fast_full (array, idx, NULL, NULL)
/** @brief Convenience: clear-in-place at slot @p idx, no per-item function. */
#define r_ptr_array_remove_idx_clear(array, idx) r_ptr_array_remove_idx_clear_full (array, idx, NULL, NULL)
/** @brief Stable remove of slot @p idx; @p func runs on the displaced item. */
R_API rsize r_ptr_array_remove_idx_full (RPtrArray * array, rsize idx,
    RFunc func, rpointer user);
/** @brief Swap-with-last remove of slot @p idx; @p func runs on the displaced item. */
R_API rsize r_ptr_array_remove_idx_fast_full (RPtrArray * array, rsize idx,
    RFunc func, rpointer user);
/** @brief Clear-in-place at slot @p idx; @p func runs on the displaced item. */
R_API rsize r_ptr_array_remove_idx_clear_full (RPtrArray * array, rsize idx,
    RFunc func, rpointer user);

/** @brief Convenience: stable remove of first occurrence of @p data. */
#define r_ptr_array_remove_first_full(array, data, func, user) r_ptr_array_remove_idx_full (array, r_ptr_array_find (array, data), func, user)
/** @brief Convenience: swap-with-last remove of first occurrence of @p data. */
#define r_ptr_array_remove_first_fast_full(array, data, func, user) r_ptr_array_remove_idx_fast_full (array, r_ptr_array_find (array, data), func, user)
/** @brief Convenience: clear-in-place at first occurrence of @p data. */
#define r_ptr_array_remove_first_clear_full(array, data, func, user) r_ptr_array_remove_idx_clear_full (array, r_ptr_array_find (array, data), func, user)
/** @brief Convenience: stable remove of @p data, no per-item function. */
#define r_ptr_array_remove_first(array, data) r_ptr_array_remove_first_full (array, data, NULL, NULL)
/** @brief Convenience: swap-with-last remove of @p data, no per-item function. */
#define r_ptr_array_remove_first_fast(array, data) r_ptr_array_remove_first_fast_full (array, data, NULL, NULL)
/** @brief Convenience: clear-in-place at @p data, no per-item function. */
#define r_ptr_array_remove_first_clear(array, data) r_ptr_array_remove_first_clear_full (array, data, NULL, NULL)

/** @brief Convenience: stable range remove, no per-item function. */
#define r_ptr_array_remove_range(array, idx, inc) r_ptr_array_remove_range_full (array, idx, inc, NULL, NULL)
/** @brief Convenience: swap-with-last range remove. */
#define r_ptr_array_remove_range_fast(array, idx, inc) r_ptr_array_remove_range_fast_full (array, idx, inc, NULL, NULL)
/** @brief Convenience: clear-in-place over the range. */
#define r_ptr_array_remove_range_clear(array, idx, inc) r_ptr_array_remove_range_clear_full (array, idx, inc, NULL, NULL)
/** @brief Stable range remove with per-item function. */
R_API rsize r_ptr_array_remove_range_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user);
/** @brief Swap-with-last range remove with per-item function. */
R_API rsize r_ptr_array_remove_range_fast_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user);
/** @brief Clear-in-place over the range with per-item function. */
R_API rsize r_ptr_array_remove_range_clear_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user);

/** @} */

/** @name Iteration and ordering
 *  @{ */

/** @brief Convenience: invoke @p func on every item. */
#define r_ptr_array_foreach(array, func, user) r_ptr_array_foreach_range (array, 0, -1, func, user)
/** @brief Invoke @p func on each item in the range @c [idx, idx+size). */
R_API rsize r_ptr_array_foreach_range (RPtrArray * array, rsize idx, rssize size,
    RFunc func, rpointer user);

/** @brief In-place sort using comparator @p cmp. */
R_API void r_ptr_array_sort (RPtrArray * array, RCmpFunc cmp);

/** @} */

/**
 * @brief Public definition of @ref RPtrArray.
 *
 * Exposed so callers can stack-allocate or embed the struct
 * directly. Treat as opaque - access through the @c r_ptr_array_*
 * helpers above.
 */
struct RPtrArray {
  RRef ref;             /**< Refcount base. */

  rsize nalloc;         /**< Allocated capacity (in slots). */
  rsize nsize;          /**< Number of slots in use. */
  rpointer mem;         /**< Slot storage. */
};

R_END_DECLS

/** @} */

#endif /* __R_PTR_ARRAY_H__ */


