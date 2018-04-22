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

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/data/rhashfuncs.h>

R_BEGIN_DECLS

#define R_KV_PTR_ARRAY_INVALID_IDX  RSIZE_MAX

typedef struct _RKVPtrArray RKVPtrArray;

/* Create using stack/static/embedded initialization */
#define R_KV_PTR_ARRAY_INIT_WITH_FUNC(eqfunc) { R_REF_STATIC_INIT (NULL), eqfunc, 0, 0, NULL }
#define R_KV_PTR_ARRAY_INIT       R_KV_PTR_ARRAY_INIT_WITH_FUNC (NULL)
#define R_KV_PTR_ARRAY_INIT_STR   R_KV_PTR_ARRAY_INIT_WITH_FUNC (r_str_equal)
R_API void r_kv_ptr_array_init (RKVPtrArray * array, REqualFunc eqfunc);
#define r_kv_ptr_array_init_str(array) r_kv_ptr_array_init (array, r_str_equal)
R_API void r_kv_ptr_array_clear (RKVPtrArray * array);

/* Create using ref counting */
#define r_kv_ptr_array_new()      r_kv_ptr_array_new_sized (0, NULL)
#define r_kv_ptr_array_new_str()  r_kv_ptr_array_new_sized (0, r_str_equal)
R_API RKVPtrArray * r_kv_ptr_array_new_sized (rsize size, REqualFunc eqfunc) R_ATTR_MALLOC;
#define r_kv_ptr_array_ref   r_ref_ref
#define r_kv_ptr_array_unref r_ref_unref

#define r_kv_ptr_array_size(array) (array)->nsize
#define r_kv_ptr_array_alloc_size(array) (array)->nalloc
R_API rpointer r_kv_ptr_array_get_key (RKVPtrArray * array, rsize idx);
R_API rpointer r_kv_ptr_array_get_val (RKVPtrArray * array, rsize idx);
R_API rpointer r_kv_ptr_array_get (RKVPtrArray * array, rsize idx, rpointer * key);
R_API rconstpointer r_kv_ptr_array_get_const (const RKVPtrArray * array, rsize idx, rconstpointer * key);

#define r_kv_ptr_array_find(array, key) r_kv_ptr_array_find_range (array, key, 0, -1)
R_API rsize r_kv_ptr_array_find_range (RKVPtrArray * array, rconstpointer key, rsize idx, rssize size);

R_API rsize r_kv_ptr_array_add (RKVPtrArray * array,
    rpointer key, RDestroyNotify keynotify, rpointer val, RDestroyNotify valnotify);
/*R_API rsize r_kv_ptr_array_update_idx (RKVPtrArray * array, rsize idx,*/
    /*rpointer key, RDestroyNotify keynotify, rpointer val, RDestroyNotify valnotify);*/
R_API rsize r_kv_ptr_array_remove_range (RKVPtrArray * array, rsize idx, rssize size);
#define r_kv_ptr_array_remove_idx(array, idx) r_kv_ptr_array_remove_range (array, idx, 1)
#define r_kv_ptr_array_remove_all(array) r_kv_ptr_array_remove_range (array, 0, -1)
R_API rsize r_kv_ptr_array_remove_key_first (RKVPtrArray * array, rpointer key);
R_API rsize r_kv_ptr_array_remove_key_all (RKVPtrArray * array, rpointer key);

R_API rsize r_kv_ptr_array_foreach_range (RKVPtrArray * array,
    rsize idx, rssize size, RKeyValueFunc func, rpointer user);
#define r_kv_ptr_array_foreach(array, func, user) \
  r_kv_ptr_array_foreach_range (array, 0, -1, func, user)


struct _RKVPtrArray {
  RRef ref;

  REqualFunc eqfunc;

  rsize nalloc, nsize;
  rpointer mem;
};

R_END_DECLS

#endif /* __R_KV_PTR_ARRAY_H__ */

