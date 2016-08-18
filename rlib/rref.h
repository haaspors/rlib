/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_REF_H__
#define __R_REF_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/ratomic.h>

R_BEGIN_DECLS

typedef struct _RRef {
  rauint refcount;
  RDestroyNotify notify;
} RRef;

#define r_ref_refcount(ref) r_atomic_uint_load (&((RRef *)ref)->refcount)
#define r_ref_init(self, destroy)         R_STMT_START {                      \
  r_atomic_uint_store (&((RRef *)self)->refcount, 1);                         \
  ((RRef *)self)->notify = (RDestroyNotify)destroy;                           \
} R_STMT_END

R_API rpointer r_ref_ref (rpointer ref);
R_API void r_ref_unref (rpointer ref);

R_END_DECLS

#endif /* __R_REF_H__ */

