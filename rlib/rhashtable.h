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

#include <rlib/rtypes.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

typedef struct _RHashTable RHashTable;

typedef enum {
  R_HASH_TABLE_REPLACE = -1,
  R_HASH_TABLE_OK = 0,
  R_HASH_TABLE_INVAL,
  R_HASH_TABLE_NOT_FOUND,
  R_HASH_TABLE_ERROR,
} RHashTableError;
#define R_HASH_TABLE_IS_SUCCESS(err)  (err <= R_HASH_TABLE_OK)
#define R_HASH_TABLE_IS_ERROR(err)    (err  > R_HASH_TABLE_OK)

#define r_hash_table_new(hash, equal) r_hash_table_new_full (hash, equal, NULL, NULL)
R_API RHashTable * r_hash_table_new_full (RHashFunc hash, REqualFunc equal,
    RDestroyNotify keynotify, RDestroyNotify valuenotify) R_ATTR_MALLOC;
#define r_hash_table_ref    r_ref_ref
#define r_hash_table_unref  r_ref_unref

R_API rsize r_hash_table_size (RHashTable * ht);
R_API rsize r_hash_table_current_alloc_size (RHashTable * ht);

R_API RHashTableError r_hash_table_insert (RHashTable * ht,
    rpointer key, rpointer value);

R_API rpointer r_hash_table_lookup (RHashTable * ht, rconstpointer key);
R_API RHashTableError r_hash_table_lookup_full (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout);
R_API RHashTableError r_hash_table_contains (RHashTable * ht, rconstpointer key);

R_API void r_hash_table_remove_all (RHashTable * ht);
R_API RHashTableError r_hash_table_remove (RHashTable * ht, rconstpointer key);
R_API RHashTableError r_hash_table_remove_full (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout);
R_API RHashTableError r_hash_table_steal (RHashTable * ht, rconstpointer key,
    rpointer * keyout, rpointer * valueout);

R_API RHashTableError r_hash_table_foreach (RHashTable * ht, RKeyValueFunc func, rpointer user);


/* hash and equal functions */
R_API rsize r_direct_hash (rconstpointer data);
R_API rboolean r_direct_equal (rconstpointer a, rconstpointer b);
R_API rsize r_str_hash (rconstpointer data);
R_API rboolean r_str_equal (rconstpointer a, rconstpointer b);

R_END_DECLS

#endif /* __R_HASH_TABLE_H__ */

