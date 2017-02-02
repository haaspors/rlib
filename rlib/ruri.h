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
#ifndef __R_URI_H__
#define __R_URI_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rref.h>

#define R_URI_GENERIC_DELIMITERS        ":/?#[]@"
#define R_URI_SUBCOMPONENT_DELIMITERS   "!$&'()*+,;="

R_BEGIN_DECLS

R_API rchar * r_uri_escape_str (const rchar * str, rssize size, rsize * out) R_ATTR_MALLOC;
R_API rchar * r_uri_unescape_str (const rchar * str, rssize size, rsize * out) R_ATTR_MALLOC;

typedef struct _RUri RUri;
#define r_uri_ref r_ref_ref
#define r_uri_unref r_ref_unref

#define r_uri_new r_uri_new_unescaped
R_API RUri * r_uri_new_unescaped (const rchar * uri, rssize size) R_ATTR_MALLOC;
R_API RUri * r_uri_new_escaped (const rchar * uri, rssize size) R_ATTR_MALLOC;
R_API RUri * r_uri_new_simple (const rchar * scheme, const rchar * authority,
    const rchar * path);
R_API RUri * r_uri_new_full (const rchar * scheme,
    const rchar * userinfo, const rchar * hostname, ruint16 port,
    const rchar * path, const rchar * query, const rchar * fragment);
#define r_uri_new_http(host, req) r_uri_new_http_sized (host, -1, req, -1)
R_API RUri * r_uri_new_http_sized (const rchar * host, rssize hostsize,
    const rchar * request, rssize reqsize);

/* All will be unescaped */
R_API rchar * r_uri_get_unescaped (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_scheme (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_authority (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_userinfo (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_hostname_port (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_hostname (const RUri * uri) R_ATTR_MALLOC;
R_API ruint16 r_uri_get_port (const RUri * uri);
R_API rchar * r_uri_get_path (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_query (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_fragment (const RUri * uri) R_ATTR_MALLOC;
R_API rchar * r_uri_get_pqf (const RUri * uri) R_ATTR_MALLOC;

/* All will be escaped */
R_API rchar * r_uri_get_escaped (const RUri * uri) R_ATTR_MALLOC;
R_API const rchar * r_uri_get_escaped_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_scheme_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_authority_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_userinfo_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_hostname_port_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_hostname_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_port_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_pqf_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_path_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_query_ptr (const RUri * uri, rsize * size);
R_API const rchar * r_uri_get_fragment_ptr (const RUri * uri, rsize * size);

R_END_DECLS

#endif /* __R_URI_H__ */

