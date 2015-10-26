/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_ALLOC_H__
#define __R_ALLOC_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <stdlib.h>

#if defined(__BIONIC__) && defined (RLIB_HAVE_ALLOCA_H)
#include <alloca.h>
#elif defined(__GNUC__)
#undef alloca
#define alloca(size)   __builtin_alloca (size)
#elif defined(RLIB_HAVE_ALLOCA_H)
#include <alloca.h>
#elif defined(_MSC_VER) || defined(__DMC__)
#include <malloc.h>
#define alloca _alloca
#elif defined(_AIX)
#pragma alloca
#elif !defined(alloca)
R_BEGIN_DECLS
char *alloca ();
R_END_DECLS
#endif


R_BEGIN_DECLS

#define r_alloca(size)    alloca (size)
#define r_newa(type, n)   ((type*) r_alloca (sizeof (type) * (rsize) (n)))

R_API void     r_free     (rpointer ptr);
R_API rpointer r_malloc   (rsize size) R_ATTR_MALLOC R_ATTR_ALLOC_SIZE_ARG(1);
R_API rpointer r_malloc0  (rsize size) R_ATTR_MALLOC R_ATTR_ALLOC_SIZE_ARG(1);
R_API rpointer r_calloc   (rsize count, rsize size) R_ATTR_ALLOC_SIZE_ARGS(1, 2);
R_API rpointer r_realloc  (rpointer ptr, rsize size) R_ATTR_WARN_UNUSED_RESULT;

typedef struct {
  rpointer (*malloc)  (rsize size);
  rpointer (*calloc)  (rsize count, rsize size);
  rpointer (*realloc) (rpointer ptr, rsize size);
  void     (*free)    (rpointer ptr);
} RMemVTable;

R_API void r_mem_set_vtable (RMemVTable * vtable);
R_API rboolean r_mem_using_system_default (void);

R_END_DECLS

#endif /* __R_ALLOC_H__ */

