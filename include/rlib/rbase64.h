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
#ifndef __R_BASE64_H__
#define __R_BASE64_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

R_API rboolean r_base64_is_valid_char (rchar ch);

R_API rsize r_base64_encode (rchar * dst, rsize dsize, rconstpointer src, rsize size);
R_API rsize r_base64_decode (ruint8 * dst, rsize dsize, const rchar * src, rssize size);

R_API rchar * r_base64_encode_dup (rconstpointer data, rsize size, rsize * outsize) R_ATTR_MALLOC;
R_API rchar * r_base64_encode_dup_full (rconstpointer data, rsize size, rsize linesize, rsize * outsize) R_ATTR_MALLOC;
R_API ruint8 * r_base64_decode_dup (const rchar * data, rssize size, rsize * outsize) R_ATTR_MALLOC;

R_END_DECLS

#endif /* __R_BASE64_H__ */

