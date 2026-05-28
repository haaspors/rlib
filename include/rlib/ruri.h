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

/**
 * @file rlib/ruri.h
 * @brief Percent-encoding helpers and a parsed-URI type with
 * component accessors.
 */

#include <rlib/rtypes.h>

#include <rlib/rref.h>

/**
 * @defgroup r_uri URIs
 *
 * @brief RFC 3986 percent-encoding helpers plus a refcounted parsed
 * @ref RUri with accessors for every component.
 *
 * The standalone @ref r_uri_escape_str / @ref r_uri_unescape_str
 * percent-encode and decode strings. @ref RUri parses a full URI and
 * exposes each component (scheme, authority, userinfo, host, port,
 * path, query, fragment) two ways:
 *
 *   - @c r_uri_get_* — return a freshly-allocated, unescaped copy the
 *     caller frees.
 *   - @c r_uri_get_*_ptr — return a borrowed pointer into the URI's
 *     still-escaped backing store plus its length; no allocation.
 *
 * @{
 */

/** @brief RFC 3986 generic (gen-delims) delimiter set. */
#define R_URI_GENERIC_DELIMITERS        ":/?#[]@"
/** @brief RFC 3986 sub-delims delimiter set. */
#define R_URI_SUBCOMPONENT_DELIMITERS   "!$&'()*+,;="

R_BEGIN_DECLS

/**
 * @brief Percent-encode @p str, escaping everything outside the
 * unreserved set.
 * @param str  Input string.
 * @param size Length, or @c -1 for @c strlen.
 * @param out  Optional out-pointer for the result length.
 * @return Newly-allocated escaped string.
 */
R_API rchar * r_uri_escape_str (const rchar * str, rssize size, rsize * out) R_ATTR_MALLOC;
/**
 * @brief Decode percent-escapes in @p str.
 * @param str  Input string.
 * @param size Length, or @c -1 for @c strlen.
 * @param out  Optional out-pointer for the result length.
 * @return Newly-allocated unescaped string.
 */
R_API rchar * r_uri_unescape_str (const rchar * str, rssize size, rsize * out) R_ATTR_MALLOC;

/** @brief Opaque, refcounted parsed-URI handle. */
typedef struct RUri RUri;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_uri_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_uri_unref r_ref_unref

/** @brief Parse a URI given as an already-unescaped string (alias @c r_uri_new). */
#define r_uri_new r_uri_new_unescaped
/** @brief Parse a URI from an unescaped string; @p size may be @c -1 for @c strlen. */
R_API RUri * r_uri_new_unescaped (const rchar * uri, rssize size) R_ATTR_MALLOC;
/** @brief Parse a URI from an already percent-escaped string. */
R_API RUri * r_uri_new_escaped (const rchar * uri, rssize size) R_ATTR_MALLOC;
/** @brief Build a URI from scheme, authority and path components. */
R_API RUri * r_uri_new_simple (const rchar * scheme, const rchar * authority,
    const rchar * path);
/** @brief Build a URI from all components individually. */
R_API RUri * r_uri_new_full (const rchar * scheme,
    const rchar * userinfo, const rchar * hostname, ruint16 port,
    const rchar * path, const rchar * query, const rchar * fragment);
/** @brief Build an @c http URI from a host and request target. */
#define r_uri_new_http(host, req) r_uri_new_http_sized (host, -1, req, -1)
/** @brief Sized variant of @ref r_uri_new_http. */
R_API RUri * r_uri_new_http_sized (const rchar * host, rssize hostsize,
    const rchar * request, rssize reqsize);

/** @name Unescaped component accessors (allocating)
 *  Each returns a freshly-allocated, percent-decoded copy.
 *  @{ */
/** @brief Whole URI, unescaped. */
R_API rchar * r_uri_get_unescaped (const RUri * uri) R_ATTR_MALLOC;
/** @brief Scheme component (e.g. @c "https"). */
R_API rchar * r_uri_get_scheme (const RUri * uri) R_ATTR_MALLOC;
/** @brief Authority component (userinfo + host + port). */
R_API rchar * r_uri_get_authority (const RUri * uri) R_ATTR_MALLOC;
/** @brief Userinfo component. */
R_API rchar * r_uri_get_userinfo (const RUri * uri) R_ATTR_MALLOC;
/** @brief Host and port together (e.g. @c "host:443"). */
R_API rchar * r_uri_get_hostname_port (const RUri * uri) R_ATTR_MALLOC;
/** @brief Host component only. */
R_API rchar * r_uri_get_hostname (const RUri * uri) R_ATTR_MALLOC;
/** @brief Port number, or 0 if absent. */
R_API ruint16 r_uri_get_port (const RUri * uri);
/** @brief Path component. */
R_API rchar * r_uri_get_path (const RUri * uri) R_ATTR_MALLOC;
/** @brief Query component (without the leading @c '?'). */
R_API rchar * r_uri_get_query (const RUri * uri) R_ATTR_MALLOC;
/** @brief Fragment component (without the leading @c '#'). */
R_API rchar * r_uri_get_fragment (const RUri * uri) R_ATTR_MALLOC;
/** @brief Path + query + fragment together (the HTTP request target). */
R_API rchar * r_uri_get_pqf (const RUri * uri) R_ATTR_MALLOC;
/** @} */

/** @name Escaped component accessors (borrowed)
 *  Each returns a borrowed pointer into the URI's escaped backing
 *  store plus its length via @p size; do not free.
 *  @{ */
/** @brief Whole URI, escaped (allocating). */
R_API rchar * r_uri_get_escaped (const RUri * uri) R_ATTR_MALLOC;
/** @brief Borrowed pointer to the whole escaped URI. */
R_API const rchar * r_uri_get_escaped_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped scheme. */
R_API const rchar * r_uri_get_scheme_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped authority. */
R_API const rchar * r_uri_get_authority_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped userinfo. */
R_API const rchar * r_uri_get_userinfo_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped host:port. */
R_API const rchar * r_uri_get_hostname_port_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped host. */
R_API const rchar * r_uri_get_hostname_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped port. */
R_API const rchar * r_uri_get_port_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped path + query + fragment. */
R_API const rchar * r_uri_get_pqf_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped path. */
R_API const rchar * r_uri_get_path_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped query. */
R_API const rchar * r_uri_get_query_ptr (const RUri * uri, rsize * size);
/** @brief Borrowed pointer to the escaped fragment. */
R_API const rchar * r_uri_get_fragment_ptr (const RUri * uri, rsize * size);
/** @} */

R_END_DECLS

/** @} */ /* r_uri */

#endif /* __R_URI_H__ */

