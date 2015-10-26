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
#ifndef __R_UNICODE_H__
#define __R_UNICODE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

typedef ruint32   runichar;
typedef ruint32   runichar4;
typedef ruint16   runichar2;

R_API runichar2 * r_utf8_to_utf16 (const rchar * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;
R_API rchar * r_utf16_to_utf8 (const runichar2 * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;

#if 0
R_API runichar * r_utf8_to_uft32 (const rchar * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;
R_API rchar * r_utf32_to_uft8 (const runichar *, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;

R_API runichar * r_utf16_to_uft32 (const runichar2 * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;
R_API runichar2 * r_utf32_to_uft16 (const runichar *, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen) R_ATTR_MALLOC;
#endif

R_END_DECLS

#endif /* __R_UNICODE_H__ */
