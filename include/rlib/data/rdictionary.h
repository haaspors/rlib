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
#ifndef __R_DICTIONARY_H__
#define __R_DICTIONARY_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/data/rhashtable.h>

R_BEGIN_DECLS

#define RDictionary RHashTable

static inline RDictionary * r_dictionary_new (void) R_ATTR_MALLOC;
static inline RDictionary * r_dictionary_new_full (RDestroyNotify notify) R_ATTR_MALLOC;
#define r_dictionary_ref    r_ref_ref
#define r_dictionary_unref  r_ref_unref

static inline rsize r_dictionary_size (RDictionary * dict);
static inline rsize r_dictionary_current_alloc_size (RDictionary * dict);

static inline rboolean r_dictionary_insert (RDictionary * dict, const rchar * key, rpointer value);
static inline rpointer r_dictionary_lookup (RDictionary * dict, const rchar * key);
static inline rboolean r_dictionary_lookup_full (RDictionary * dict, const rchar * key, rpointer * value);
static inline rboolean r_dictionary_contains (RDictionary * dict, const rchar * key);
static inline rboolean r_dictionary_steal (RDictionary * dict, const rchar * key, rpointer * value);
static inline rboolean r_dictionary_remove (RDictionary * dict, const rchar * key);

static inline rboolean r_dictionary_foreach (RDictionary * dict, RStrKeyValueFunc func, rpointer user);

R_END_DECLS


static inline RDictionary * r_dictionary_new (void)
{
  return r_hash_table_new_full (r_str_hash, r_str_equal, NULL, NULL);
}

static inline RDictionary * r_dictionary_new_full (RDestroyNotify notify)
{
  return r_hash_table_new_full (r_str_hash, r_str_equal, NULL, notify);
}

static inline rsize r_dictionary_size (RDictionary * dict)
{
  return r_hash_table_size (dict);
}

static inline rsize r_dictionary_current_alloc_size (RDictionary * dict)
{
  return r_hash_table_current_alloc_size (dict);
}

static inline rboolean r_dictionary_insert (RDictionary * dict, const rchar * key, rpointer value)
{
  return r_hash_table_insert (dict, (rpointer)key, value) == R_HASH_TABLE_OK;
}

static inline rpointer r_dictionary_lookup (RDictionary * dict, const rchar * key)
{
  return r_hash_table_lookup (dict, key);
}

static inline rboolean r_dictionary_lookup_full (RDictionary * dict, const rchar * key, rpointer * value)
{
  return r_hash_table_lookup_full (dict, key, NULL, value) == R_HASH_TABLE_OK;
}

static inline rboolean r_dictionary_contains (RDictionary * dict, const rchar * key)
{
  return r_hash_table_contains (dict, key) == R_HASH_TABLE_OK;
}

static inline rboolean r_dictionary_steal (RDictionary * dict, const rchar * key, rpointer * value)
{
  return r_hash_table_steal (dict, key, NULL, value) == R_HASH_TABLE_OK;
}

static inline rboolean r_dictionary_remove (RDictionary * dict, const rchar * key)
{
  return r_hash_table_remove (dict, key) == R_HASH_TABLE_OK;
}

static inline rboolean r_dictionary_foreach (RDictionary * dict, RStrKeyValueFunc func, rpointer user)
{
  return r_hash_table_foreach (dict, (RKeyValueFunc)func, user) == R_HASH_TABLE_OK;
}

#endif /* __R_DICTIONARY_H__ */

