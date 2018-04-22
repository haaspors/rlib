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
#ifndef __R_STRING_H__
#define __R_STRING_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <stdarg.h>

R_BEGIN_DECLS

typedef struct RString RString;

R_ATTR_WARN_UNUSED_RESULT
R_API RString * r_string_new (const rchar * cstr) R_ATTR_MALLOC;
R_ATTR_WARN_UNUSED_RESULT
R_API RString * r_string_new_sized (rsize size) R_ATTR_MALLOC;

R_API void r_string_free (RString * str);
R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_string_free_keep (RString * str);

R_API rsize r_string_length (RString * str);
R_API rsize r_string_alloc_size (RString * str);

R_API int r_string_cmp (RString * str1, RString * str2);
R_API int r_string_cmp_cstr (RString * str, const rchar * cstr);

R_API rsize r_string_reset (RString * str, const rchar * cstr);

R_API rsize r_string_append_c (RString * str, rchar c);
R_API rsize r_string_append (RString * str, const rchar * cstr);
R_API rsize r_string_append_len (RString * str, const rchar * cstr, rsize len);
R_API rsize r_string_append_printf (RString * str, const rchar * fmt, ...) R_ATTR_PRINTF (2, 3);
R_API rsize r_string_append_vprintf (RString * str, const rchar * fmt, va_list ap) R_ATTR_PRINTF (2, 0);

R_API rsize r_string_prepend (RString * str, const rchar * cstr);
R_API rsize r_string_prepend_len (RString * str, const rchar * cstr, rsize len);
R_API rsize r_string_prepend_printf (RString * str, const rchar * fmt, ...) R_ATTR_PRINTF (2, 3);
R_API rsize r_string_prepend_vprintf (RString * str, const rchar * fmt, va_list ap) R_ATTR_PRINTF (2, 0);

R_API rsize r_string_insert (RString * str, rsize pos, const rchar * cstr);
R_API rsize r_string_insert_len (RString * str, rsize pos, const rchar * cstr, rsize len);
R_API rsize r_string_overwrite (RString * str, rsize pos, const rchar * cstr);
R_API rsize r_string_overwrite_len (RString * str, rsize pos, const rchar * cstr, rsize len);

R_API rsize r_string_truncate (RString * str, rsize len);
R_API rsize r_string_erase (RString * str, rsize pos, rsize len);

R_END_DECLS

#endif /* __R_STRING_H__ */

