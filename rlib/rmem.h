/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MEM_H__
#define __R_MEM_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <stdlib.h>
#include <stdarg.h>

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

/* Stack allocations */
#define r_alloca(size)        alloca (size)
#define r_alloca0(size)       r_memclear (r_alloca (size), size)
#define r_mem_newa_n(type, n) ((type*) r_alloca (sizeof (type) * (rsize) (n)))
#define r_mem_newa0_n(type, n)((type*) (r_alloca0 (sizeof (type) * (rsize) (n)))
#define r_mem_newa(type)      r_mem_newa_n (type, 1)
#define r_mem_newa0(type)     r_mem_newa_n0 (type, 1)

/* Heap allocations */
R_API void     r_free     (rpointer ptr);
R_API rpointer r_malloc   (rsize size) R_ATTR_MALLOC R_ATTR_ALLOC_SIZE_ARG(1);
R_API rpointer r_malloc0  (rsize size) R_ATTR_MALLOC R_ATTR_ALLOC_SIZE_ARG(1);
R_API rpointer r_calloc   (rsize count, rsize size) R_ATTR_ALLOC_SIZE_ARGS(1, 2);
R_API rpointer r_realloc  (rpointer ptr, rsize size) R_ATTR_WARN_UNUSED_RESULT;
#define r_mem_new_n(type, n)  ((type*) r_malloc (sizeof (type) * (rsize) (n)))
#define r_mem_new0_n(type, n) ((type*) r_malloc0 (sizeof (type) * (rsize) (n)))
#define r_mem_new(type)       r_mem_new_n (type, 1)
#define r_mem_new0(type)      r_mem_new0_n (type, 1)

typedef struct {
  rpointer (*malloc)  (rsize size);
  rpointer (*calloc)  (rsize count, rsize size);
  rpointer (*realloc) (rpointer ptr, rsize size);
  void     (*free)    (rpointer ptr);
} RMemVTable;

R_API void r_mem_set_vtable (RMemVTable * vtable);
R_API rboolean r_mem_using_system_default (void);


/* Common memory operations */
R_API int       r_memcmp (rconstpointer a, rconstpointer b, rsize size);
R_API rpointer  r_memset (rpointer a, int v, rsize size);
#define r_memclear(ptr, size)   r_memset (ptr, 0, size)
R_API rpointer  r_memcpy (void * R_ATTR_RESTRICT dst,
    const void * R_ATTR_RESTRICT src, rsize size);
R_API rpointer  r_memmove (rpointer dst, rconstpointer src, rsize size);
R_API rpointer  r_memdup (rconstpointer src, rsize size) R_ATTR_MALLOC;
R_API rsize     r_memagg (rpointer dst, rsize size, rsize * out, ...) R_ATTR_NULL_TERMINATED;
R_API rsize     r_memaggv (rpointer dst, rsize size, rsize * out, va_list args);
R_API rpointer  r_memdup_agg (rsize * out, ...) R_ATTR_NULL_TERMINATED R_ATTR_MALLOC;
R_API rpointer  r_memdup_aggv (rsize * out, va_list args) R_ATTR_MALLOC;

/* memory scan operations */
R_API rpointer r_mem_scan_byte (rconstpointer mem, rsize size, ruint8 byte);
R_API rpointer r_mem_scan_byte_any (rconstpointer mem, rsize size,
    const ruint8 * byte, rsize bytes);
R_API rpointer r_mem_scan_data (rconstpointer mem, rsize size,
    rconstpointer data, rsize datasize);

/* memory scan for pattern */
typedef enum {
  R_MEM_TOKEN_NONE = -1,
  R_MEM_TOKEN_BYTES,
  R_MEM_TOKEN_WILDCARD,
  R_MEM_TOKEN_WILDCARD_SIZED,
  R_MEM_TOKEN_COUNT
} RMemTokenType;

typedef enum {
  R_MEM_SCAN_RESULT_INVAL             = -4,
  R_MEM_SCAN_RESULT_OOM               = -3,
  R_MEM_SCAN_RESULT_INVALID_PATTERN   = -2,
  R_MEM_SCAN_RESULT_PATTERN_NOT_IMPL  = -1,
  R_MEM_SCAN_RESULT_OK                =  0,
  R_MEM_SCAN_RESULT_NOT_FOUND
} RMemScanResultType;

typedef struct _RMemScanToken {
  const rchar * ptr_pattern;
  rpointer ptr_data;
  rsize size;
  RMemTokenType type;
} RMemScanToken;

typedef struct _RMemScanResult {
  rpointer ptr;
  rpointer end;
  rsize tokens;
  RMemScanToken token[0];
} RMemScanResult;

R_API rpointer r_mem_scan_simple_pattern (rconstpointer mem, rsize size,
    const rchar * pattern, rpointer * end);
R_API RMemScanResultType r_mem_scan_pattern (rconstpointer mem, rsize size,
    const rchar * pattern, RMemScanResult ** result);

R_END_DECLS

#endif /* __R_MEM_H__ */

