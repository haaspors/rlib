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
#ifndef __R_HASH_SET_H__
#define __R_HASH_SET_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_hashset Hash set
 * @ingroup r_data
 *
 * @brief Refcounted hash set: the keys-only sibling of
 * @ref r_hashtable.
 *
 * Same shape as @ref RHashTable - caller-supplied hash and
 * equality functions, optional destroy notifier - but each entry
 * is a single @c rpointer instead of a @c (key, value) pair.
 *
 * @{
 */

/**
 * @file rlib/data/rhashset.h
 * @brief Refcounted hash-set container.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rhashfuncs.h>

R_BEGIN_DECLS

/** @brief Opaque refcounted hash set. */
typedef struct RHashSet RHashSet;

/** @brief Convenience: construct a hash set with no destroy notifier. */
#define r_hash_set_new(hash, equal) r_hash_set_new_full (hash, equal, NULL)
/**
 * @brief Construct a hash set with custom hash / equality and an
 * optional destroy notifier.
 *
 * @param hash    Hash function applied to each item.
 * @param equal   Equality comparator paired with @p hash.
 * @param notify  Destroy notifier for items, or @c NULL.
 */
R_API RHashSet * r_hash_set_new_full (RHashFunc hash, REqualFunc equal,
    RDestroyNotify notify) R_ATTR_MALLOC;
/** @brief Increment the set's refcount. */
#define r_hash_set_ref    r_ref_ref
/** @brief Decrement the set's refcount; clears all entries when it reaches zero. */
#define r_hash_set_unref  r_ref_unref

/** @brief Number of items currently in the set. */
R_API rsize r_hash_set_size (RHashSet * ht);
/** @brief Allocated bucket count. */
R_API rsize r_hash_set_current_alloc_size (RHashSet * ht);

/**
 * @brief Add @p item to the set.
 *
 * @return @c TRUE if @p item was newly added, @c FALSE if it was
 * already present.
 */
R_API rboolean r_hash_set_insert (RHashSet * ht, rpointer item);

/** @brief @c TRUE iff @p item is present. */
R_API rboolean r_hash_set_contains (RHashSet * ht, rconstpointer item);
/**
 * @brief Look up @p item and return the set-owned pointer.
 *
 * Useful when @p item is a search key that's equal to but not
 * pointer-identical with the stored item.
 *
 * @param ht    The set.
 * @param item  The search key.
 * @param out   Out: stored item, or @c NULL.
 */
R_API rboolean r_hash_set_contains_full (RHashSet * ht, rconstpointer item,
    rpointer * out);

/** @brief Remove every item; destroy notifier runs. */
R_API void r_hash_set_remove_all (RHashSet * ht);
/** @brief Remove @p item; destroy notifier runs. */
R_API rboolean r_hash_set_remove (RHashSet * ht, rconstpointer item);
/**
 * @brief Remove @p item without running the destroy notifier; hand
 * the stored pointer back via @p out.
 */
R_API rboolean r_hash_set_steal (RHashSet * ht, rconstpointer item,
    rpointer * out);

/** @brief Iterate every item in the set. */
R_API rboolean r_hash_set_foreach (RHashSet * ht, RFunc func, rpointer user);

R_END_DECLS

/** @} */

#endif /* __R_HASH_SET_H__ */


