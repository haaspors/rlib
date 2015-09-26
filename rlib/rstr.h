/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
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

R_API int r_strcmp (const rchar * a, const rchar * b);
#define r_str_equals(a,b) (r_strcmp (a, b) == 0)
R_API rchar * r_stpcpy (rchar * dst, const rchar * src);

R_API const rchar * r_strlwstrip (const rchar * str);
R_API rchar * r_strtwstrip (rchar * str);
#define r_strstrip(str) r_strtstrip (r_strlstrip (str))

#define r_sprintf       sprintf
#define r_vsprintf      vsprintf
#define r_snprintf      snprintf
#define r_vsnprintf     vsnprintf
R_API int     r_asprintf (rchar ** str, const rchar * fmt, ...) R_ATTR_PRINTF (2, 3);
R_API int     r_vasprintf (rchar ** str, const rchar * fmt, va_list args) R_ATTR_PRINTF (2, 0);
R_API rchar * r_strprintf (const rchar * fmt, ...) R_ATTR_PRINTF (1, 2);
R_API rchar * r_strvprintf (const rchar * fmt, va_list args) R_ATTR_PRINTF (1, 0);

R_API rchar * r_strdup (const rchar * str);
R_API rchar * r_strndup (const rchar * str, rsize n);
R_API rchar * r_strdup_strip (const rchar * str);

R_API RSList * r_str_list_new (const rchar * str0, ...);
R_API RSList * r_str_list_newv (const rchar * str0, va_list args);
R_API RSList * r_str_list_new_from_strv (rchar ** strv, rboolean take);
R_API rchar ** r_strv_new (const rchar * str0, ...);
R_API rchar ** r_strv_newv (const rchar * str0, va_list args);
R_API void r_strv_free (rchar ** strv);
R_API rsize r_strv_len (rchar * const * strv);
R_API rboolean r_strv_contains (rchar * const * strv, const rchar * str);
R_API rchar * r_strv_join (rchar * const * strv, const rchar * delim);

R_API rchar ** r_strsplit (const rchar * str, const rchar * delim, rsize max);
R_API rchar * r_strjoin (const rchar * delim, ...);
R_API rchar * r_strjoinv (const rchar * delim, va_list args);

R_END_DECLS

#endif /* __R_STR_H__ */

