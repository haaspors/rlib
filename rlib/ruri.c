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

#include "config.h"
#include <rlib/ruri.h>

#include <rlib/charset/rascii.h>
#include <rlib/data/rstring.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

rchar *
r_uri_escape_str (const rchar * str, rssize size, rsize * out)
{
  if (R_UNLIKELY (str == NULL)) return NULL;
  if (size < 0) size = r_strlen (str);

  /* TODO: implement */

  if (out != NULL)
    *out = size;
  return r_strndup (str, size);
}

rchar *
r_uri_unescape_str (const rchar * str, rssize size, rsize * out)
{
  if (R_UNLIKELY (str == NULL)) return NULL;
  if (size < 0) size = r_strlen (str);

  /* TODO: implement */

  if (out != NULL)
    *out = size;
  return r_strndup (str, size);
}

typedef struct {
  rchar * ptr;
  rsize size;
} RUriComponent;
#define r_uri_component_clear(seg, start) (seg)->ptr = (start), (seg)->size = 0

struct _RUri {
  RRef ref;

  RUriComponent scheme;
  RUriComponent userinfo;
  RUriComponent hostname;
  RUriComponent port;
  RUriComponent path;
  RUriComponent query;
  RUriComponent fragment;

  rsize size;
  rchar escaped[0];
};


//  while (*p != 0 && r_ascii_isspace (*p)) p++;
//  next = r_str_ptr_of_c_any (p, RPOINTER_TO_SIZE (pend - p), R_URI_GENERIC_DELIMITERS, sizeof (R_URI_GENERIC_DELIMITERS));
static rboolean
r_uri_parse (RUri * uri)
{
  rchar * p, * pend, * next;

  r_uri_component_clear (&uri->scheme, uri->escaped);
  r_uri_component_clear (&uri->userinfo, uri->escaped);
  r_uri_component_clear (&uri->hostname, uri->escaped);
  r_uri_component_clear (&uri->port, uri->escaped);
  r_uri_component_clear (&uri->path, uri->escaped);
  r_uri_component_clear (&uri->query, uri->escaped);
  r_uri_component_clear (&uri->fragment, uri->escaped);

  p = uri->escaped;
  pend = uri->escaped + uri->size;

  /* scheme */
  if ((next = r_str_ptr_of_c (p, RPOINTER_TO_SIZE (pend - p), ':')) != NULL) {
    uri->scheme.size = RPOINTER_TO_SIZE (next - p);
    p = next + 1;
  } else {
    return FALSE;
  }

  /* authority */
  if (RPOINTER_TO_SIZE (next - p) >= 2 && p[0] == '/' && p[1] == '/') {
    rchar * authend;
    p += 2;

    if ((authend = r_str_ptr_of_c_any (p, RPOINTER_TO_SIZE (pend - p), "/?#", 3)) == NULL)
      authend = pend;

    /* userinfo */
    uri->userinfo.ptr = p;
    if ((next = r_str_ptr_of_c (p, RPOINTER_TO_SIZE (authend - p), '@')) != NULL) {
      uri->userinfo.size = RPOINTER_TO_SIZE (next - p);
      p = next + 1;
    }

    /* hostname */
    if (*p == '[') {
      if ((next = r_str_ptr_of_c (p, RPOINTER_TO_SIZE (authend - p), ']')) == NULL)
        return FALSE;

      uri->hostname.ptr = ++p;
      uri->hostname.size = RPOINTER_TO_SIZE (next - p);
      p = next + 1;
      if (*p == ':')
        p++;
      else if (p != authend)
        return FALSE;
    } else {
      uri->hostname.ptr = p;
      if ((next = r_str_ptr_of_c (p, RPOINTER_TO_SIZE (authend - p), ':')) != NULL) {
        uri->hostname.size = RPOINTER_TO_SIZE (next - p);
        p = next + 1;
      } else {
        uri->hostname.size = RPOINTER_TO_SIZE (authend - p);
        p = authend;
      }
    }

    /* port */
    uri->port.ptr = p;
    uri->port.size = RPOINTER_TO_SIZE (authend - p);

    p = authend;
  }

  /* path, query and fragment */
  uri->path.ptr = p;
  if ((next = r_str_ptr_of_c_any (p, RPOINTER_TO_SIZE (pend - p), "?#", 2)) != NULL) {
    uri->path.size = RPOINTER_TO_SIZE (next - p);

    /* query */
    p = next;
    if (*p == '?') {
      uri->query.ptr = ++p;
      if ((next = r_str_ptr_of_c (p, RPOINTER_TO_SIZE (pend - p), '#')) == NULL)
        next = pend;

      uri->query.size = RPOINTER_TO_SIZE (next - p);
      p = next;
    } else {
      uri->query.ptr = p;
    }

    /* fragment */
    uri->fragment.ptr = p;
    uri->fragment.size = RPOINTER_TO_SIZE (pend - p);
  } else {
    uri->path.size = RPOINTER_TO_SIZE (pend - p);
    uri->query.ptr = uri->fragment.ptr = pend;
  }

  return TRUE;
}

RUri *
r_uri_new_unescaped (const rchar * uri, rssize size)
{
  RUri * ret;
  rchar * escaped;
  rsize esize;

  if ((escaped = r_uri_escape_str (uri, size, &esize)) != NULL) {
    ret = r_uri_new_escaped (escaped, (rssize)esize);
    r_free (escaped);
  } else {
    ret = NULL;
  }

  return ret;
}

RUri *
r_uri_new_escaped (const rchar * uri, rssize size)
{
  RUri * ret;

  if (R_UNLIKELY (uri == NULL)) return NULL;
  if (size < 0) size = (rssize)r_strlen (uri);
  if (R_UNLIKELY (size == 0)) return NULL;

  while (size > 0 && r_ascii_isspace (*uri)) {
    size--;
    uri++;
  }

  if ((ret = r_malloc (sizeof (RUri) + size + 1)) != NULL) {
    r_ref_init (ret, r_free);
    ret->size = (rsize)size;
    r_memcpy (ret->escaped, uri, size);
    ret->escaped[size] = 0;

    if (R_UNLIKELY (!r_uri_parse (ret))) {
      r_uri_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

RUri *
r_uri_new_simple (const rchar * scheme, const rchar * authority, const rchar * path)
{
  RUri * ret;
  RString * str;
  rchar * unescaped;

  if (R_UNLIKELY (scheme == NULL)) return NULL;
  if (R_UNLIKELY ((str = r_string_new_sized (256)) == NULL)) return NULL;

  r_string_append_printf (str, "%s:", scheme);
  if (authority != NULL)
    r_string_append_printf (str, "//%s", authority);
  if (path != NULL)
    r_string_append (str, path);

  unescaped = r_string_free_keep (str);
  ret = r_uri_new_unescaped (unescaped, -1);
  r_free (unescaped);
  return ret;
}

RUri *
r_uri_new_full (const rchar * scheme,
    const rchar * userinfo, const rchar * hostname, ruint16 port,
    const rchar * path, const rchar * query, const rchar * fragment)
{
  RUri * ret;
  RString * str;
  rchar * unescaped;

  if (R_UNLIKELY (scheme == NULL)) return NULL;
  if (R_UNLIKELY (userinfo != NULL && hostname == NULL)) return NULL;
  if (R_UNLIKELY (port > 0 && hostname == NULL)) return NULL;
  if (R_UNLIKELY ((str = r_string_new_sized (256)) == NULL)) return NULL;

  r_string_append_printf (str, "%s:", scheme);

  if (hostname != NULL) {
    if (userinfo == NULL)
      r_string_append_printf (str, "//%s", hostname);
    else
      r_string_append_printf (str, "//%s@%s", userinfo, hostname);
    if (port > 0)
      r_string_append_printf (str, ":%"RUINT16_FMT, port);
  }

  if (path != NULL)
    r_string_append (str, path);
  if (query != NULL)
    r_string_append_printf (str, "?%s", query);
  if (fragment != NULL)
    r_string_append_printf (str, "#%s", fragment);

  unescaped = r_string_free_keep (str);
  ret = r_uri_new_unescaped (unescaped, -1);
  r_free (unescaped);
  return ret;
}

RUri *
r_uri_new_http_sized (const rchar * host, rssize hostsize,
    const rchar * request, rssize reqsize)
{
  RUri * ret;

  if (R_UNLIKELY (hostsize == 0)) return NULL;
  if (R_UNLIKELY (request == NULL || *request == 0)) return NULL;

  if (host != NULL && *host != 0) {
    rchar * hostname, * pqf;

    if (hostsize < 0) hostsize = r_strlen (host);
    if (reqsize < 0) reqsize = r_strlen (request);

    hostname = r_strndup (host, hostsize);
    pqf = r_strndup (request, reqsize);
    ret = r_uri_new_simple ("http", hostname, pqf);
    r_free (hostname);
    r_free (pqf);
  } else {
    ret = r_uri_new_unescaped (request, reqsize);
  }

  return ret;
}

rchar *
r_uri_get_unescaped (const RUri * uri)
{
  return r_uri_unescape_str (uri->escaped, (rssize)uri->size, NULL);
}

rchar *
r_uri_get_scheme (const RUri * uri)
{
  return r_strndup (uri->scheme.ptr, uri->scheme.size);
}

rchar *
r_uri_get_authority (const RUri * uri)
{
  rsize size = RPOINTER_TO_SIZE (uri->port.ptr) -
      RPOINTER_TO_SIZE (uri->userinfo.ptr) + uri->port.size;
  return r_uri_unescape_str (uri->userinfo.ptr, (rssize)size, NULL);
}

rchar *
r_uri_get_hostname_port (const RUri * uri)
{
  rsize size = RPOINTER_TO_SIZE (uri->port.ptr) -
      RPOINTER_TO_SIZE (uri->hostname.ptr) + uri->port.size;
  return r_uri_unescape_str (uri->hostname.ptr, (rssize)size, NULL);
}

rchar *
r_uri_get_userinfo (const RUri * uri)
{
  return r_uri_unescape_str (uri->userinfo.ptr, (rssize)uri->userinfo.size, NULL);
}

rchar *
r_uri_get_hostname (const RUri * uri)
{
  return r_uri_unescape_str (uri->hostname.ptr, (rssize)uri->hostname.size, NULL);
}

ruint16
r_uri_get_port (const RUri * uri)
{
  if (uri->port.size == 0)
    return 0;

  return r_str_to_uint16 (uri->port.ptr, NULL, 10, NULL);
}

rchar *
r_uri_get_pqf (const RUri * uri)
{
  rsize size = RPOINTER_TO_SIZE (uri->escaped) + uri->port.size -
      RPOINTER_TO_SIZE (uri->path.ptr);
  return r_uri_unescape_str (uri->path.ptr, (rssize)size, NULL);
}

rchar *
r_uri_get_path (const RUri * uri)
{
  return r_uri_unescape_str (uri->path.ptr, (rssize)uri->path.size, NULL);
}

rchar *
r_uri_get_query (const RUri * uri)
{
  return r_uri_unescape_str (uri->query.ptr, (rssize)uri->query.size, NULL);
}

rchar *
r_uri_get_fragment (const RUri * uri)
{
  return r_uri_unescape_str (uri->fragment.ptr, (rssize)uri->fragment.size, NULL);
}

rchar *
r_uri_get_escaped (const RUri * uri)
{
  return r_memdup (uri->escaped, uri->size + 1);
}

const rchar *
r_uri_get_escaped_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->size;
  return uri->escaped;
}

const rchar *
r_uri_get_scheme_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->scheme.size;
  return uri->scheme.ptr;
}

const rchar *
r_uri_get_authority_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) {
    *size = RPOINTER_TO_SIZE (uri->port.ptr) -
      RPOINTER_TO_SIZE (uri->userinfo.ptr) + uri->port.size;
  }

  return uri->userinfo.ptr;
}

const rchar *
r_uri_get_userinfo_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->userinfo.size;
  return uri->userinfo.ptr;
}

const rchar *
r_uri_get_hostname_port_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) {
    *size = RPOINTER_TO_SIZE (uri->port.ptr) -
      RPOINTER_TO_SIZE (uri->hostname.ptr) + uri->port.size;
  }

  return uri->hostname.ptr;
}

const rchar *
r_uri_get_hostname_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->hostname.size;
  return uri->hostname.ptr;
}

const rchar *
r_uri_get_port_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->port.size;
  return uri->port.ptr;
}

const rchar *
r_uri_get_pqf_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) {
    *size = RPOINTER_TO_SIZE (uri->escaped) + uri->port.size -
      RPOINTER_TO_SIZE (uri->path.ptr);
  }

  return uri->path.ptr;
}

const rchar *
r_uri_get_path_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->path.size;
  return uri->path.ptr;
}

const rchar *
r_uri_get_query_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->query.size;
  return uri->query.ptr;
}

const rchar *
r_uri_get_fragment_ptr (const RUri * uri, rsize * size)
{
  if (size != NULL) *size = uri->fragment.size;
  return uri->fragment.ptr;
}

