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
#ifndef __R_HASH_TABLE_H__
#define __R_HASH_TABLE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_hashtable Hash table
 * @ingroup r_data
 *
 * @brief Refcounted hash map with caller-supplied hash and equality
 * functions and optional per-key / per-value destroy notifiers.
 *
 * Keys and values are stored as @c rpointer, leaving the ownership
 * model to the caller. Pass @c RDestroyNotify callbacks at
 * construction time and the table will invoke them on @c remove /
 * @c remove_all / unref; pass @c NULL for caller-owned keys or
 * values.
 *
 * Pre-built hash / equality pairs for the common key types live in
 * @ref r_hashfuncs (@c r_direct_hash / @c r_direct_equal for
 * pointer-identity keys, @c r_str_hash / @c r_str_equal for
 * NUL-terminated strings). See @ref r_dictionary for the string-keyed
 * convenience wrapper.
 *
 * @{
 */

/**
 * @file rlib/data/rhashtable.h
 * @brief Refcounted hash-map container.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rhashfuncs.h>

R_BEGIN_DECLS

/** @brief Opaque refcounted hash table. */
typedef struct RHashTable RHashTable;

/**
 * @brief Result code for hash-table operations.
 *
 * Non-positive values (@c REPLACE / @c OK) are successes;
 * @c REPLACE flags that an existing entry was overwritten by
 * @ref r_hash_table_insert.
 */
typedef enum {
  R_HASH_TABLE_REPLACE = -1,    /**< Insert overwrote an existing entry. */
  R_HASH_TABLE_OK = 0,          /**< Operation completed successfully. */
  R_HASH_TABLE_INVAL,           /**< Invalid argument. */
  R_HASH_TABLE_NOT_FOUND,       /**< Key not present. */
  R_HASH_TABLE_ERROR,           /**< Internal failure. */
} RHashTableError;
/** @brief Convenience predicate: @c TRUE iff @p err is a success code. */
#define R_HASH_TABLE_IS_SUCCESS(err)  (err <= R_HASH_TABLE_OK)
/** @brief Convenience predicate: @c TRUE iff @p err is an error code. */
#define R_HASH_TABLE_IS_ERROR(err)    (err  > R_HASH_TABLE_OK)

/**
 * @brief Convenience: construct a hash table with no destroy
 * notifiers (caller owns both keys and values).
 */
#define r_hash_table_new(hash, equal) r_hash_table_new_full (hash, equal, NULL, NULL)
/**
 * @brief Construct a hash table with custom hash / equality and
 * optional per-side destroy notifiers.
 *
 * @param hash         Hash function applied to each key.
 * @param equal        Equality comparator paired with @p hash.
 * @param keynotify    Destroy notifier for keys, or @c NULL.
 * @param valuenotify  Destroy notifier for values, or @c NULL.
 */
R_API RHashTable * r_hash_table_new_full (RHashFunc hash, REqualFunc equal,
    RDestroyNotify keynotify, RDestroyNotify valuenotify) R_ATTR_MALLOC;
/** @brief Increment the table's refcount. */
#define r_hash_table_ref    r_ref_ref
/** @brief Decrement the table's refcount; clears all entries when it reaches zero. */
#define r_hash_table_unref  r_ref_unref

/** @brief Number of entries currently in the table. */
R_API rsize r_hash_table_size (RHashTable * ht);
/** @brief Allocated bucket count; useful for sizing diagnostics. */
R_API rsize r_hash_table_current_alloc_size (RHashTable * ht);

/**
 * @brief Insert or replace @c (key, value).
 *
 * Returns @c R_HASH_TABLE_REPLACE if an existing entry was
 * overwritten (existing key + value run through their destroy
 * notifiers), @c R_HASH_TABLE_OK on fresh insert.
 */
R_API RHashTableError r_hash_table_insert (RHashTable * ht,
    rpointer key, rpointer value);

/** @brief Return the value associated with @p key, or @c NULL. */
R_API rpointer r_hash_table_lookup (RHashTable * ht, rconstpointer key);
/**
 * @brief Look up @p key, returning both the stored key and value.
 *
 * Useful when the caller needs the table-owned key (e.g. to know
 * which of several equivalent keys is present).
 */
R_API RHashTableError r_hash_table_lookup_full (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout);
/** @brief @c R_HASH_TABLE_OK iff @p key is present, @c R_HASH_TABLE_NOT_FOUND otherwise. */
R_API RHashTableError r_hash_table_contains (RHashTable * ht, rconstpointer key);

/** @brief Remove every entry, invoking destroy notifiers. */
R_API void r_hash_table_remove_all (RHashTable * ht);
/** @brief Remove the entry for @p key; destroy notifiers run. */
R_API RHashTableError r_hash_table_remove (RHashTable * ht, rconstpointer key);
/**
 * @brief Remove an entry and hand the destroy responsibility back
 * to the caller.
 *
 * Same as @ref r_hash_table_remove but returns the stored key /
 * value rather than running them through the destroy notifiers.
 */
R_API RHashTableError r_hash_table_remove_full (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout);
/** @brief Alias for @ref r_hash_table_remove_full reflecting the "take ownership" semantics. */
R_API RHashTableError r_hash_table_steal (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout);

/**
 * @brief Filter callback that matches by value identity.
 *
 * Internal helper used by @ref r_hash_table_remove_all_values;
 * exported so callers can pass it directly to
 * @ref r_hash_table_remove_with_func without naming a private
 * lambda.
 */
R_API rboolean r_hash_table_remove_func_value (rpointer key, rpointer value,
    rpointer user);
/**
 * @brief Remove all entries for which @p func returns @c TRUE.
 *
 * @c func is invoked for each entry with the supplied @p user
 * cookie; on @c TRUE the entry is removed (destroy notifiers run).
 */
R_API RHashTableError r_hash_table_remove_with_func (RHashTable * ht,
    RKeyValueFuncReturn func, rpointer user);
/**
 * @brief Convenience: remove every entry whose value pointer
 * matches @p val.
 */
#define r_hash_table_remove_all_values(ht, val) \
  r_hash_table_remove_with_func (ht, r_hash_table_remove_func_value, val)

/**
 * @brief Iterate every @c (key, value) pair in the table.
 *
 * @p func may not insert into or remove from @p ht; use
 * @ref r_hash_table_remove_with_func for filtered removal.
 */
R_API RHashTableError r_hash_table_foreach (RHashTable * ht, RKeyValueFunc func, rpointer user);

R_END_DECLS

/** @} */

#endif /* __R_HASH_TABLE_H__ */

