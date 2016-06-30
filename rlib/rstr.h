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
#ifndef __R_STR_H__
#define __R_STR_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rlist.h>
#include <stdarg.h>
#include <stdio.h>

R_BEGIN_DECLS

R_API rsize r_strlen (const rchar * str);

/* Compare strings */
R_API int r_strcmp (const rchar * a, const rchar * b);
R_API int r_strncmp (const rchar * a, const rchar * b, rsize len);
#define r_str_equals(a,b) (r_strcmp (a, b) == 0)

R_API rboolean r_str_has_prefix (const rchar * str, const rchar * prefix);
R_API rboolean r_str_has_suffix (const rchar * str, const rchar * suffix);
#define r_str_has_substring(str, sub) (r_str_idx_of_str (str, -1, sub, -1) >= 0)

/* Search/scan for characters/strings */
R_API rsize r_strspn (const rchar * str, const rchar * set);
R_API rsize r_strcspn (const rchar * str, const rchar * cset);
R_API rchar * r_strchr (const rchar * str, int c);
R_API rchar * r_strstr (const rchar * str, const rchar * sub);
R_API rchar * r_strpbrk (const rchar * str, const rchar * set);
R_API rchar * r_str_ptr_of_c (const rchar * str, rssize strsize, rchar c);
R_API rchar * r_str_ptr_of_c_any (const rchar * str, rssize strsize,
    const rchar * c, rssize chars);
R_API rchar * r_str_ptr_of_str (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize);
R_API rssize r_str_idx_of_c (const rchar * str, rssize strsize, rchar c);
R_API rssize r_str_idx_of_c_any (const rchar * str, rssize strsize,
    const rchar * c, rssize chars);
R_API rssize r_str_idx_of_str (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize);

/* Copy and concatenate */
R_API rchar * r_strcpy (rchar * dst, const rchar * src);
R_API rchar * r_strncpy (rchar * dst, const rchar * src, rsize len);
R_API rchar * r_strcat (rchar * dst, const rchar * src);
R_API rchar * r_strncat (rchar * dst, const rchar * src, rsize len);
R_API rchar * r_stpcpy (rchar * dst, const rchar * src);
R_API rchar * r_stpncpy (rchar * dst, const rchar * src, rsize len);

R_API rchar * r_strdup (const rchar * str);
R_API rchar * r_strndup (const rchar * str, rsize n);
R_API rchar * r_strdup_wstrip (const rchar * str);
R_API rchar * r_strdup_strip (const rchar * str, const rchar * chars);

/* Strip for whitespace or specific characters */
R_API rchar * r_str_wstrip (rchar * str);
R_API const rchar * r_str_lwstrip (const rchar * str);
R_API rchar * r_str_twstrip (rchar * str);

R_API rchar * r_str_strip (rchar * str, const rchar * chars);
R_API const rchar * r_str_lstrip (const rchar * str, const rchar * chars);
R_API rchar * r_str_tstrip (rchar * str, const rchar * chars);

/* Join and split */
R_API rchar * r_strjoin (const rchar * delim, ...);
R_API rchar * r_strjoinv (const rchar * delim, va_list args);
R_API rchar ** r_strsplit (const rchar * str, const rchar * delim, rsize max);

/* Parsing from string to numbers (integers and floats) */
typedef enum {
  R_STR_PARSE_OK,
  R_STR_PARSE_RANGE,
  R_STR_PARSE_INVAL,
} RStrParse;
R_API rint8   r_str_to_int8   (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
R_API ruint8  r_str_to_uint8  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
R_API rint16  r_str_to_int16  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
R_API ruint16 r_str_to_uint16 (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
R_API rint32  r_str_to_int32  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
R_API ruint32 r_str_to_uint32 (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
R_API rint64  r_str_to_int64  (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
R_API ruint64 r_str_to_uint64 (const rchar * str, const rchar ** endptr,
    ruint base, RStrParse * res);
#if RLIB_SIZEOF_INT == 8
#define r_str_to_int   r_str_to_int64
#define r_str_to_uint  r_str_to_uint64
#elif RLIB_SIZEOF_INT == 4
#define r_str_to_int   r_str_to_int32
#define r_str_to_uint  r_str_to_uint32
#elif RLIB_SIZEOF_INT == 2
#define r_str_to_int   r_str_to_int16
#define r_str_to_uint  r_str_to_uint16
#elif RLIB_SIZEOF_INT == 1
#define r_str_to_int   r_str_to_int8
#define r_str_to_uint  r_str_to_uint8
#endif
#if RLIB_SIZEOF_LONG == 8
#define r_strtol(str, endptr, base)   r_str_to_int64 (str, endptr, base, NULL)
#define r_strtoul(str, endptr, base)  r_str_to_uint64 (str, endptr, base, NULL)
#elif RLIB_SIZEOF_LONG == 4
#define r_strtol(str, endptr, base)   r_str_to_int32 (str, endptr, base, NULL)
#define r_strtoul(str, endptr, base)  r_str_to_uint32 (str, endptr, base, NULL)
#elif RLIB_SIZEOF_LONG == 2
#define r_strtol(str, endptr, base)   r_str_to_int16 (str, endptr, base, NULL)
#define r_strtoul(str, endptr, base)  r_str_to_uint16 (str, endptr, base, NULL)
#elif RLIB_SIZEOF_LONG == 1
#define r_strtol(str, endptr, base)   r_str_to_int8 (str, endptr, base, NULL)
#define r_strtoul(str, endptr, base)  r_str_to_uint8 (str, endptr, base, NULL)
#endif
#define r_strtoll(str, endptr, base)  r_str_to_int64 (str, endptr, base, NULL)
#define r_strtoull(str, endptr, base) r_str_to_uint64 (str, endptr, base, NULL)

R_API rfloat r_str_to_float (const rchar * str, const rchar ** endptr, RStrParse * res);
R_API rdouble r_str_to_double (const rchar * str, const rchar ** endptr, RStrParse * res);
#define r_strtof(str, endptr) r_str_to_float  (str, endptr, NULL)
#define r_strtod(str, endptr) r_str_to_double (str, endptr, NULL)

/* Formatting strings */
#define r_sprintf       sprintf
#define r_vsprintf      vsprintf
#define r_snprintf      snprintf
#define r_vsnprintf     vsnprintf
R_API int     r_asprintf (rchar ** str, const rchar * fmt, ...) R_ATTR_PRINTF (2, 3);
R_API int     r_vasprintf (rchar ** str, const rchar * fmt, va_list args) R_ATTR_PRINTF (2, 0);
R_API rchar * r_strprintf (const rchar * fmt, ...) R_ATTR_PRINTF (1, 2);
R_API rchar * r_strvprintf (const rchar * fmt, va_list args) R_ATTR_PRINTF (1, 0);

/* Dump/format memory to string */
#define R_STR_MEM_DUMP_SIZE(align) \
  ((align * 4) + (align / 4) + (RLIB_SIZEOF_VOID_P * 2) + 8)
R_API rboolean r_str_mem_dump (rchar * str, const ruint8 * ptr,
    rsize size, rsize align);
R_API rchar * r_str_mem_dump_dup (const ruint8 * ptr,
    rsize size, rsize align);
R_API rchar * r_str_mem_hex (const ruint8 * ptr, rsize size);

/* Scanning */
R_API int     r_strscanf (const rchar * str, const rchar * fmt, ...) R_ATTR_SCANF (2, 3);
R_API int     r_strvscanf (const rchar * str, const rchar * fmt, va_list args) R_ATTR_SCANF (2, 0);

/* String list */
R_API RSList * r_str_list_new (const rchar * str0, ...);
R_API RSList * r_str_list_newv (const rchar * str0, va_list args);

R_API rchar ** r_strv_new (const rchar * str0, ...);
R_API rchar ** r_strv_newv (const rchar * str0, va_list args);
R_API rchar ** r_strv_copy (rchar * const * strv);
R_API void r_strv_free (rchar ** strv);
R_API rsize r_strv_len (rchar * const * strv);
R_API void r_strv_foreach (rchar ** strv, RFunc func, rpointer user);
R_API rboolean r_strv_contains (rchar * const * strv, const rchar * str);
R_API rchar * r_strv_join (rchar * const * strv, const rchar * delim);

R_END_DECLS

#endif /* __R_STR_H__ */

