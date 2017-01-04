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

#include <rlib/rtypes.h>

#include <rlib/rhashfuncs.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

typedef struct _RHashSet RHashSet;

#define r_hash_set_new(hash, equal) r_hash_set_new_full (hash, equal, NULL)
R_API RHashSet * r_hash_set_new_full (RHashFunc hash, REqualFunc equal,
    RDestroyNotify notify) R_ATTR_MALLOC;
#define r_hash_set_ref    r_ref_ref
#define r_hash_set_unref  r_ref_unref

R_API rsize r_hash_set_size (RHashSet * ht);
R_API rsize r_hash_set_current_alloc_size (RHashSet * ht);

R_API rboolean r_hash_set_insert (RHashSet * ht, rpointer item);

R_API rboolean r_hash_set_contains (RHashSet * ht, rconstpointer item);
R_API rboolean r_hash_set_contains_full (RHashSet * ht, rconstpointer item,
    rpointer * out);

R_API void r_hash_set_remove_all (RHashSet * ht);
R_API rboolean r_hash_set_remove (RHashSet * ht, rconstpointer item);
R_API rboolean r_hash_set_steal (RHashSet * ht, rconstpointer item,
    rpointer * out);

R_API rboolean r_hash_set_foreach (RHashSet * ht, RFunc func, rpointer user);

R_END_DECLS

#endif /* __R_HASH_SET_H__ */


