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

#include <rlib/rtypes.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

#define R_PTR_ARRAY_INVALID_IDX               RSIZE_MAX

typedef struct _RPtrArray RPtrArray;

/* Create using stack/static/embedded initialization */
#define R_PTR_ARRAY_INIT                      { R_REF_STATIC_INIT (NULL), 0, 0, NULL }
R_API void r_ptr_array_init (RPtrArray * array);
R_API void r_ptr_array_clear (RPtrArray * array);

/* Create using ref counting */
#define r_ptr_array_new() r_ptr_array_new_sized (0)
R_API RPtrArray * r_ptr_array_new_sized (rsize size) R_ATTR_MALLOC;
#define r_ptr_array_ref   r_ref_ref
#define r_ptr_array_unref r_ref_unref

#define r_ptr_array_size(array) (array)->nsize
#define r_ptr_array_alloc_size(array) (array)->nalloc
R_API rpointer r_ptr_array_get (RPtrArray * array, rsize idx);
R_API rconstpointer r_ptr_array_get_const (const RPtrArray * array, rsize idx);

#define r_ptr_array_find(array, data) r_ptr_array_find_range (array, data, 0, -1)
R_API rsize r_ptr_array_find_range (RPtrArray * array, rpointer data, rsize idx, rssize size);

R_API rsize r_ptr_array_add (RPtrArray * array,
    rpointer data, RDestroyNotify notify);
/* FIXME */
/*R_API rsize r_ptr_array_insert (RPtrArray * array, rsize idx,*/
    /*rpointer data, RDestroyNotify notify);*/
R_API rsize r_ptr_array_update_idx (RPtrArray * array, rsize idx,
    rpointer data, RDestroyNotify notify);
#define r_ptr_array_clear_idx(array, idx) r_ptr_array_update_idx (array, idx, NULL, NULL)
R_API rsize r_ptr_array_clear_range (RPtrArray * array, rsize idx, rssize size);

#define r_ptr_array_remove_all(array) r_ptr_array_remove_range_clear_full (array, 0, -1, NULL, NULL)
#define r_ptr_array_remove_all_full(array, func, user) r_ptr_array_remove_range_clear_full (array, 0, -1, func, user)

#define r_ptr_array_remove_idx(array, idx) r_ptr_array_remove_idx_full (array, idx, NULL, NULL)
#define r_ptr_array_remove_idx_fast(array, idx) r_ptr_array_remove_idx_fast_full (array, idx, NULL, NULL)
#define r_ptr_array_remove_idx_clear(array, idx) r_ptr_array_remove_idx_clear_full (array, idx, NULL, NULL)
R_API rsize r_ptr_array_remove_idx_full (RPtrArray * array, rsize idx,
    RFunc func, rpointer user);
R_API rsize r_ptr_array_remove_idx_fast_full (RPtrArray * array, rsize idx,
    RFunc func, rpointer user);
R_API rsize r_ptr_array_remove_idx_clear_full (RPtrArray * array, rsize idx,
    RFunc func, rpointer user);

#define r_ptr_array_remove_first_full(array, data, func, user) r_ptr_array_remove_idx_full (array, r_ptr_array_find (array, data), func, user)
#define r_ptr_array_remove_first_fast_full(array, data, func, user) r_ptr_array_remove_idx_fast_full (array, r_ptr_array_find (array, data), func, user)
#define r_ptr_array_remove_first_clear_full(array, data, func, user) r_ptr_array_remove_idx_clear_full (array, r_ptr_array_find (array, data), func, user)
#define r_ptr_array_remove_first(array, data) r_ptr_array_remove_first_full (array, data, NULL, NULL)
#define r_ptr_array_remove_first_fast(array, data) r_ptr_array_remove_first_fast_full (array, data, NULL, NULL)
#define r_ptr_array_remove_first_clear(array, data) r_ptr_array_remove_first_clear_full (array, data, NULL, NULL)

#define r_ptr_array_remove_range(array, idx, inc) r_ptr_array_remove_range_full (array, idx, inc, NULL, NULL)
#define r_ptr_array_remove_range_fast(array, idx, inc) r_ptr_array_remove_range_fast_full (array, idx, inc, NULL, NULL)
#define r_ptr_array_remove_range_clear(array, idx, inc) r_ptr_array_remove_range_clear_full (array, idx, inc, NULL, NULL)
R_API rsize r_ptr_array_remove_range_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user);
R_API rsize r_ptr_array_remove_range_fast_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user);
R_API rsize r_ptr_array_remove_range_clear_full (RPtrArray * array,
    rsize idx, rssize size, RFunc func, rpointer user);

#define r_ptr_array_foreach(array, func, user) r_ptr_array_foreach_range (array, 0, -1, func, user)
R_API rsize r_ptr_array_foreach_range (RPtrArray * array, rsize idx, rssize size,
    RFunc func, rpointer user);

/* FIXME: Sorting? */
/*R_API void r_ptr_array_sort (RPtrArray * array, RCmpFunc cmp);*/

struct _RPtrArray {
  RRef ref;

  rsize nalloc, nsize;
  rpointer mem;
};

R_END_DECLS

#endif /* __R_PTR_ARRAY_H__ */


