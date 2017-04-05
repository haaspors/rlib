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
#include <rlib/net/proto/rhttp.h>

#include <rlib/rascii.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

static const rchar * r_http_method_supported[] = {
  "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE",
};

static const rchar * r_http_status_phrase[][99] = {
  { "" },
  { /* 1xx */
    "Continue",
    "Switching Protocols",
    "Processing",
  },
  { /* 2xx */
    "OK",
    "Created",
    "Accepted",
    "Non-Authoritative Information",
    "No Content",
    "Reset Content",
    "Partial Content",
    "Multi Status",
    "Already Reported",
    NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    "IM Used", /* 226 */
  },
  { /* 3xx */
    "Multiple Choices",
    "Moved Permanently",
    "Found",
    "See Other",
    "Not Modified",
    "Use Proxy",
    NULL,
    "Temporary Redirect",
    "Permanent Redirect",
  },
  { /* 4xx */
    "Bad Request",
    "Unauthorized",
    "Payment Required",
    "Forbidden",
    "Not Found",
    "Method Not Allowed",
    "Not Acceptable",
    "Proxy Authentication Required",
    "Request Timeout",
    "Conflict",
    "Gone",
    "Length Required",
    "Precondition Failed",
    "Payload Too Large",
    "URI Too Long",
    "Unsupported Media Type",
    "Range Not Satisfiable",
    "Expectation Failed",
    "Teapot",
    NULL, NULL, NULL,
    "Unprocessable Entity",
    "Locked",
    "Failed Dependency",
    NULL,
    "Upgrade Required", /* 426 */
    NULL,
    "Precondition Required",
    "Too Many Requests",
    NULL,
    "Request Header Fields Too Large",
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NULL, NULL, NULL,
    "Unavailable For Legal Reasons",
  },
  { /* 5xx */
    "Internal Server Error",
    "Not Implemented",
    "Bad Gateway",
    "Service Unavailable",
    "Gateway Timeout",
    "HTTP Version Not Supported",
    "Variant Also Negotiates",
    "Insufficient Storage",
    "Loop Detected",
    NULL,
    "Not Extended",
    "Network Authentication Required",
  },
};

struct _RHttpMsg {
  RRef ref;

  RBuffer * start;
  RBuffer * hdr;
  RBuffer * body;
};


struct _RHttpRequest {
  RHttpMsg msg;

  RHttpMethod method;
  RUri * uri;
};

struct _RHttpResponse {
  RHttpMsg msg;

  RHttpStatus status;
  RHttpRequest * request;
};


static inline RBuffer *
r_http_create_empty_header_buffer (void)
{
  return r_buffer_new_wrapped (R_MEM_FLAG_NONE, "\r\n", 3, 2, 0, NULL, NULL);
}

static RStrMatchResult *
r_http_parse_start_line (rconstpointer data, rsize size)
{
  RStrMatchResult * ret;

  if (r_str_match_pattern (data, size, "* * *\n*", &ret) == R_STR_MATCH_RESULT_OK) {
    /* Old HTTP/1.0 implementations may inject CRLF */
    if (ret->token[0].chunk.str[0] == '\r' && ret->token[0].chunk.str[1] == '\n') {
      ret->token[0].chunk.str += 2;
      ret->token[0].chunk.size -= 2;
    }
    /* Support start line with either CRLF or only LF */
    while (ret->token[4].chunk.str[ret->token[4].chunk.size - 1] == '\r')
      ret->token[4].chunk.size--;
  } else {
    ret = NULL;
  }

  return ret;
}


static void
r_http_msg_init (RHttpMsg * msg, RDestroyNotify notify,
    RBuffer * start, RBuffer * hdr, RBuffer * body)
{
  r_ref_init (msg, notify);
  msg->start = start;
  msg->hdr = hdr;
  msg->body = body;
}

static void
r_http_msg_clear (RHttpMsg * msg)
{
  r_buffer_unref (msg->start);
  r_buffer_unref (msg->hdr);
  if (msg->body != NULL)
    r_buffer_unref (msg->body);
}

RBuffer *
r_http_msg_get_buffer (RHttpMsg * msg)
{
  RBuffer * ret;

  if ((ret = r_buffer_new ()) != NULL) {
    r_buffer_append_mem_from_buffer (ret, msg->start);
    r_buffer_append_mem_from_buffer (ret, msg->hdr);
    if (msg->body != NULL)
      r_buffer_append_mem_from_buffer (ret, msg->body);
  }

  return ret;
}

rchar *
r_http_msg_get_body (RHttpMsg * msg, rsize * size)
{
  rsize real;
  rchar * ret;

  if (msg->body != NULL) {
    if ((real = r_buffer_get_size (msg->body)) > 0) {
      ret = r_malloc (real + 1);
    } else {
      ret = NULL;
    }

    r_buffer_extract (msg->body, 0, ret, real);
    ret[real] = 0;
  } else {
    real = 0;
    ret = NULL;
  }

  if (size != NULL) *size = real;
  return ret;
}

RBuffer *
r_http_msg_get_body_buffer (RHttpMsg * msg)
{
  return msg->body != NULL ? r_buffer_ref (msg->body) : NULL;
}

RHttpError
r_http_msg_set_body_buffer (RHttpMsg * msg, RBuffer * buf)
{
  if (R_UNLIKELY (msg == NULL)) return R_HTTP_INVAL;

  if (msg->body != NULL)
    r_buffer_unref (msg->body);
  if (buf != NULL)
    r_buffer_ref (buf);
  msg->body = buf;

  return R_HTTP_OK;
}

rboolean
r_http_msg_has_header (RHttpMsg * msg, const rchar * field, rssize size)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rboolean ret = FALSE;

  if (R_UNLIKELY (msg == NULL)) return FALSE;
  if (R_UNLIKELY (field == NULL)) return FALSE;
  if (size < 0) size = r_strlen (field);
  if (R_UNLIKELY (size == 0)) return FALSE;

  if (r_buffer_map (msg->hdr, &info, R_MEM_MAP_READ)) {
    rssize idx;
    if ((idx = r_str_idx_of_str_case ((rchar *)info.data, info.size, field, size)) >= 0)
      ret = info.data[idx + (rsize)size] == ':';
    r_buffer_unmap (msg->hdr, &info);
  }

  return ret;
}

rboolean
r_http_msg_has_header_of_value (RHttpMsg * msg,
    const rchar * key, rssize ksize, const rchar * val, rssize vsize)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rboolean ret = FALSE;

  if (R_UNLIKELY (msg == NULL)) return FALSE;
  if (R_UNLIKELY (key == NULL)) return FALSE;
  if (ksize < 0) ksize = r_strlen (key);
  if (R_UNLIKELY (ksize == 0)) return FALSE;
  if (R_UNLIKELY (val == NULL)) return FALSE;
  if (vsize < 0) vsize = r_strlen (val);
  if (R_UNLIKELY (vsize == 0)) return FALSE;

  if (r_buffer_map (msg->hdr, &info, R_MEM_MAP_READ)) {
    rsize off = 0;
    rssize idx;
    while (off < info.size &&
        (idx = r_str_idx_of_str_case ((rchar *)info.data + off, info.size - off, key, ksize)) >= 0) {
      off += idx + ksize + 1;
      while (off < info.size && r_ascii_isspace (((rchar *)info.data)[off]))
        off++;

      if (off + vsize < info.size && r_strncasecmp ((rchar *)info.data + off, val, vsize) == 0) {
        ret = TRUE;
        break;
      }

      off += vsize;
    }
    r_buffer_unmap (msg->hdr, &info);
  }

  return ret;
}

static const rchar *
r_http_get_header (rconstpointer data, rsize size, const rchar * field, rssize fsize,
    rsize * out)
{
  const rchar * beg = data, * end = beg + size, * ret = NULL;
  rssize idx;

  if (fsize < 0) fsize = r_strlen (field);
  if ((idx = r_str_idx_of_str_case (beg, size, field, fsize)) >= 0 &&
      beg[idx + (rsize)fsize] == ':') {
    const rchar * valbeg;

    valbeg = r_str_lwstrip (beg + idx + 1 + (rsize)fsize);
    if ((idx = r_str_idx_of_str (valbeg, RPOINTER_TO_SIZE (end - valbeg), "\r\n", 2)) >= 0) {
      while (idx > 0 && r_ascii_isspace (valbeg[idx - 1]))
        idx--;
      if (out != NULL)
        *out = (rsize)idx;
      ret = valbeg;
    }
  }

  return ret;
}

rchar *
r_http_msg_get_header (RHttpMsg * msg, const rchar * field, rssize fsize)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rchar * ret = NULL;

  if (R_UNLIKELY (msg == NULL)) return NULL;
  if (R_UNLIKELY (field == NULL)) return NULL;
  if (R_UNLIKELY (fsize == 0)) return NULL;

  if (r_buffer_map (msg->hdr, &info, R_MEM_MAP_READ)) {
    const rchar * val;
    rsize valsize = 0;
    if ((val = r_http_get_header (info.data, info.size, field, fsize, &valsize)) != NULL)
      ret = r_strndup (val, valsize);
    r_buffer_unmap (msg->hdr, &info);
  }

  return ret;
}

rboolean
r_http_msg_add_header (RHttpMsg * msg, const rchar * field, rssize fsize,
    const rchar * value, rssize vsize)
{
  rchar * line;
  RBuffer * hdr;

  if (R_UNLIKELY (field == NULL)) return FALSE;
  if (R_UNLIKELY (value == NULL)) return FALSE;
  if (fsize < 0) fsize = r_strlen (field);
  if (vsize < 0) vsize = r_strlen (value);
  if (R_UNLIKELY (fsize == 0)) return FALSE;
  if (R_UNLIKELY (vsize == 0)) return FALSE;

  if ((line = r_strprintf ("%.*s: %.*s\r\n\r\n", (int)fsize, field, (int)vsize, value)) == NULL ||
      (hdr = r_buffer_new_take (line, fsize + 2 + vsize + 4)) == NULL) {
    r_free (line);
    return FALSE;
  }

  if (msg->hdr != NULL) {
    RBuffer * buf;
    rsize off = r_buffer_get_size (msg->hdr);
    off = off > 2 ? off - 2 : 0;

    buf = r_buffer_replace_byte_range (msg->hdr, off, -1, hdr);
    r_buffer_unref (hdr);

    if (R_UNLIKELY (buf == NULL))
      return FALSE;

    r_buffer_unref (msg->hdr);
    hdr = buf;
  }

  msg->hdr = hdr;
  return TRUE;
}



static RBuffer *
r_http_create_request_line (RHttpMethod method, RUri * uri,
    const rchar * ver)
{
  rchar * line;
  const rchar * pqf;
  rsize pqfsize;

  switch (method) {
    case R_HTTP_METHOD_OPTIONS:
      line = r_strprintf ("%s * HTTP/%s\r\n",
          r_http_method_supported[method], ver);
      break;
    case R_HTTP_METHOD_GET:
    case R_HTTP_METHOD_HEAD:
    case R_HTTP_METHOD_POST:
    case R_HTTP_METHOD_PUT:
    case R_HTTP_METHOD_DELETE:
    case R_HTTP_METHOD_CONNECT:
    case R_HTTP_METHOD_TRACE:
      pqf = r_uri_get_pqf_ptr (uri, &pqfsize);
      line = r_strprintf ("%s %.*s HTTP/%s\r\n",
          r_http_method_supported[method], (int)pqfsize, pqf, ver);
      break;
    default:
      return NULL;
  }

  return r_buffer_new_take (line, r_strlen (line));
}



static void
r_http_request_free (RHttpRequest * r)
{
  r_http_msg_clear ((RHttpMsg *)r);

  r_uri_unref (r->uri);
  r_free (r);
}

RHttpRequest *
r_http_request_new (RHttpMethod method,
    const rchar * uri, const rchar * ver, RHttpError * err)
{
  RUri * u;
  RHttpRequest * ret;

  if ((u = r_uri_new (uri, -1)) != NULL) {
    ret = r_http_request_new_with_uri (method, u, ver, err);
    r_uri_unref (u);
  } else {
    if (err != NULL) *err = R_HTTP_INVALID_URI;
    ret = NULL;
  }

  return ret;
}

RHttpRequest *
r_http_request_new_with_uri (RHttpMethod method,
    RUri * uri, const rchar * ver, RHttpError * err)
{
  RHttpRequest * ret;

  if (R_UNLIKELY (uri == NULL)) {
    if (err != NULL) *err = R_HTTP_INVAL;
    return NULL;
  }

  if (ver == NULL)
    ver = "1.1";

  if ((ret = r_mem_new (RHttpRequest)) != NULL) {
    const rchar * hp;
    rsize hpsize;

    r_http_msg_init ((RHttpMsg *)ret, (RDestroyNotify)r_http_request_free,
        r_http_create_request_line (method, uri, ver), NULL, NULL);
    ret->method = method;
    ret->uri = r_uri_ref (uri);
    if ((hp = r_uri_get_hostname_port_ptr (uri, &hpsize)) != NULL)
      r_http_msg_add_header ((RHttpMsg *)ret, "Host", 4, hp, hpsize);
    else
      ret->msg.hdr = r_http_create_empty_header_buffer ();
  } else {
    if (err != NULL) *err = R_HTTP_OOM;
  }

  return ret;
}

static RHttpMethod
r_http_method_parse (rpointer data, rsize size)
{
  rsize i;
  for (i = 0; i < R_N_ELEMENTS (r_http_method_supported); i++) {
    if (r_strncmp (r_http_method_supported[i], data, size) == 0)
      return (RHttpMethod)i;
  }

  return R_HTTP_METHOD_UNKNOWN;
}

static RHttpError
r_http_request_parse (rconstpointer data, rsize size,
    RHttpMethod * method, RStrChunk * target, RStrChunk * ver,
    rsize * hdroff, rsize * hdrsize)
{
  RStrMatchResult * sres;
  rssize idx;

  if ((idx = r_str_idx_of_str ((const rchar *)data, size, "\r\n\r\n", 4)) >= 0) {
    *hdrsize = (rsize)idx + 4;
  } else {
    return R_HTTP_BUF_TOO_SMALL;
  }

  /* Request line */
  if ((sres = r_http_parse_start_line (data, size)) != NULL) {
    *method = r_http_method_parse (sres->token[0].chunk.str,
        sres->token[0].chunk.size);
    *target = sres->token[2].chunk;
    *ver = sres->token[4].chunk;
    *hdroff = RPOINTER_TO_SIZE (sres->token[6].chunk.str) - RPOINTER_TO_SIZE (data);
    r_free (sres);
  } else {
    return R_HTTP_DECODE_ERROR;
  }

  *hdrsize -= *hdroff;

  return R_HTTP_OK;
}

RHttpRequest *
r_http_request_new_from_buffer (RBuffer * buf, RHttpError * err,
    RBuffer ** remainder)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RHttpRequest * ret = NULL;
  RHttpError res;

  if (remainder != NULL)
    *remainder = NULL;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    RHttpMethod method;
    RStrChunk strrequest, strver;
    rsize hdroff, hdrsize, hostsize;
    const rchar * host;

    if ((res = r_http_request_parse (info.data, info.size,
          &method, &strrequest, &strver, &hdroff, &hdrsize)) == R_HTTP_OK) {
      if ((host = r_http_get_header (info.data + hdroff, hdrsize,
              R_STR_WITH_SIZE_ARGS ("Host"), &hostsize)) != NULL) {
        if ((ret = r_mem_new (RHttpRequest)) != NULL) {
          r_http_msg_init ((RHttpMsg *)ret, (RDestroyNotify)r_http_request_free,
              r_buffer_view (buf, 0, hdroff),
              r_buffer_view (buf, hdroff, hdrsize),
              NULL);
          ret->method = method;
          ret->uri = r_uri_new_http_sized (host, hostsize,
              strrequest.str, strrequest.size);
          if (remainder != NULL)
            *remainder = r_buffer_view (buf, hdroff + hdrsize, -1);
        } else {
          res = R_HTTP_OOM;
        }
      } else {
        res = R_HTTP_MISSING_HOST;
      }
    } else if (res == R_HTTP_BUF_TOO_SMALL) {
      if (remainder != NULL)
        *remainder = r_buffer_ref (buf);
    }

    r_buffer_unmap (buf, &info);
  } else {
    res = R_HTTP_INVAL;
  }

  if (err != NULL)
    *err = res;
  return ret;
}

RHttpMethod
r_http_request_get_method (const RHttpRequest * req)
{
  return req->method;
}

RUri *
r_http_request_get_uri (RHttpRequest * req)
{
  return r_uri_ref (req->uri);
}

RHttpBodyParseType
r_http_request_get_body_parse_type (RHttpRequest * req)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RHttpBodyParseType ret = R_HTTP_BODY_PARSE_SIZED;

  if (r_buffer_map (req->msg.hdr, &info, R_MEM_MAP_READ)) {
    const rchar * val;
    rsize size;

    if ((val = r_http_get_header ((const rchar *)info.data, info.size,
            R_STR_WITH_SIZE_ARGS ("Transfer-Encoding"), &size)) != NULL) {
      if (r_str_idx_of_str (val, size, R_STR_WITH_SIZE_ARGS ("chunked")) >= 0)
        ret = R_HTTP_BODY_PARSE_CHUNKED;
    }

    r_buffer_unmap (req->msg.hdr, &info);
  }

  return ret;
}

rssize
r_http_request_calc_body_size (RHttpRequest * req, RHttpBodyParseType * type)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rssize ret = 0;

  if (type != NULL)
    *type = R_HTTP_BODY_PARSE_SIZED;

  if (r_buffer_map (req->msg.hdr, &info, R_MEM_MAP_READ)) {
    const rchar * val;
    rsize size;

    if ((val = r_http_get_header ((const rchar *)info.data, info.size,
            R_STR_WITH_SIZE_ARGS ("Transfer-Encoding"), &size)) != NULL) {
      if (r_str_idx_of_str (val, size, R_STR_WITH_SIZE_ARGS ("chunked")) >= 0) {
        if (type != NULL)
          *type = R_HTTP_BODY_PARSE_CHUNKED;
        ret = -1;
      }
    } else if ((val = r_http_get_header ((const rchar *)info.data, info.size,
            R_STR_WITH_SIZE_ARGS ("Content-Length"), &size)) != NULL) {
      RStrParse p;
      int s = r_str_to_int (val, NULL, 10, &p);
      if (p == R_STR_PARSE_OK)
        ret = (rssize)s;
    }

    r_buffer_unmap (req->msg.hdr, &info);
  }

  return ret;
}


static const rchar *
r_http_status_get_phrase (RHttpStatus status)
{
  ruint i = (ruint)status / 100;
  ruint j = (ruint)status % 100;

  if (R_UNLIKELY (i >= R_N_ELEMENTS (r_http_status_phrase) ||
        r_http_status_phrase[i][j] == NULL))
    i = j = 0;

  return r_http_status_phrase[i][j];
}

static RBuffer *
r_http_create_status_line (RHttpStatus status, const rchar * phrase,
    const rchar * ver)
{
  rchar * line;

  line = r_strprintf ("HTTP/%s %.3d %s\r\n",
      ver != NULL ? ver : "1.1",
      (int)status,
      phrase != NULL ? phrase : r_http_status_get_phrase (status));

  return r_buffer_new_take (line, r_strlen (line));
}

static void
r_http_response_free (RHttpResponse * r)
{
  r_http_msg_clear ((RHttpMsg *)r);

  if (r->request != NULL)
    r_http_request_unref (r->request);
  r_free (r);
}

RHttpResponse *
r_http_response_new (RHttpRequest * req,
    RHttpStatus status, const rchar * phrase, const rchar * ver,
    RHttpError * err)
{
  RHttpResponse * ret;

  if ((ret = r_mem_new (RHttpResponse)) != NULL) {
    r_http_msg_init ((RHttpMsg *)ret, (RDestroyNotify)r_http_response_free,
        r_http_create_status_line (status, phrase, ver),
        r_http_create_empty_header_buffer (),
        NULL);
    ret->status = status;
    ret->request = req != NULL ? r_http_request_ref (req) : NULL;
  } else {
    if (err != NULL) *err = R_HTTP_OOM;
  }

  return ret;
}

static RHttpError
r_http_response_parse (rconstpointer data, rsize size,
    RStrChunk * ver, RHttpStatus * status, RStrChunk * phrase,
    rsize * hdroff, rsize * hdrsize)
{
  RStrMatchResult * sres;
  rssize idx;
  int s;

  if ((idx = r_str_idx_of_str ((const rchar *)data, size, "\r\n\r\n", 4)) >= 0) {
    *hdrsize = (rsize)idx + 4;
  } else {
    return R_HTTP_BUF_TOO_SMALL;
  }

  /* Status line */
  if ((sres = r_http_parse_start_line (data, size)) != NULL &&
      (s = r_str_to_int (sres->token[2].chunk.str, NULL, 10, NULL)) > (int)R_HTTP_STATUS_MIN &&
      (s <= (int)R_HTTP_STATUS_MAX)) {
    *ver = sres->token[0].chunk;
    *status = (RHttpStatus)s;
    *phrase = sres->token[4].chunk;
    *hdroff = RPOINTER_TO_SIZE (sres->token[6].chunk.str) - RPOINTER_TO_SIZE (data);
    r_free (sres);
  } else {
    r_free (sres);
    return R_HTTP_DECODE_ERROR;
  }

  *hdrsize -= *hdroff;

  return R_HTTP_OK;
}

RHttpResponse *
r_http_response_new_from_buffer (RHttpRequest * req,
    RBuffer * buf, RHttpError * err, RBuffer ** remainder)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RHttpResponse * ret = NULL;
  RHttpError res;

  if (remainder != NULL)
    *remainder = NULL;

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    rsize hdroff, hdrsize;
    RStrChunk strphrase, strver;
    RHttpStatus status;

    if ((res = r_http_response_parse (info.data, info.size,
            &strver, &status, &strphrase, &hdroff, &hdrsize)) == R_HTTP_OK) {
      if ((ret = r_mem_new (RHttpResponse)) != NULL) {
        r_http_msg_init ((RHttpMsg *)ret, (RDestroyNotify)r_http_response_free,
            r_buffer_view (buf, 0, hdroff),
            r_buffer_view (buf, hdroff, hdrsize),
            NULL);
        ret->status = status;
        ret->request = req != NULL ? r_http_request_ref (req) : NULL;
        if (remainder != NULL)
          *remainder = r_buffer_view (buf, hdroff + hdrsize, -1);
      } else {
        res = R_HTTP_OOM;
      }
    }

    r_buffer_unmap (buf, &info);
  } else {
    res = R_HTTP_INVAL;
  }

  if (err != NULL)
    *err = res;
  return ret;
}

RHttpStatus
r_http_response_get_status (const RHttpResponse * res)
{
  return res->status;
}

rchar *
r_http_response_get_phrase (const RHttpResponse * res)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rchar * ret = NULL;

  if (r_buffer_map (res->msg.start, &info, R_MEM_MAP_READ)) {
    RStrMatchResult * sres;

    if ((sres = r_http_parse_start_line (info.data, info.size)) != NULL) {
      ret = r_strndup (sres->token[4].chunk.str, sres->token[4].chunk.size);
      r_free (sres);
    }

    r_buffer_unmap (res->msg.start, &info);
  }

  return ret;
}

RHttpRequest *
r_http_response_get_request (RHttpResponse * res)
{
  if (res->request != NULL)
    return r_http_request_ref (res->request);

  return NULL;
}

RHttpError
r_http_response_set_body_buffer_full (RHttpResponse * res, RBuffer * buf,
    const rchar * contenttype, rssize size, rboolean contentlen)
{
  RHttpError ret;

  if ((ret = r_http_response_set_body_buffer (res, buf)) == R_HTTP_OK) {
    if (contenttype != NULL)
      r_http_response_add_header (res, "Content-Type", -1, contenttype, size);
    if (contentlen) {
      rchar len[16];
      r_sprintf (len, "%"RSIZE_FMT, r_buffer_get_size (buf));
      r_http_response_add_header (res, "Content-Length", -1, len, -1);
    }
  }

  return ret;
}

RHttpBodyParseType
r_http_response_get_body_parse_type (RHttpResponse * res)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RHttpBodyParseType ret = R_HTTP_BODY_PARSE_CLOSE; /* Assume close */

  if (r_buffer_map (res->msg.hdr, &info, R_MEM_MAP_READ)) {
    const rchar * val;
    rsize size;
    RHttpMethod reqmethod = (res->request != NULL) ?
      r_http_request_get_method (res->request) : R_HTTP_METHOD_UNKNOWN;
    RHttpStatus resstatus = r_http_response_get_status (res);

    if (reqmethod == R_HTTP_METHOD_HEAD || (resstatus >= 100 && resstatus < 200) ||
        resstatus == R_HTTP_STATUS_NO_CONTENT || resstatus == R_HTTP_STATUS_NOT_MODIFIED) {
      ret = R_HTTP_BODY_PARSE_SIZED;
    } else if (reqmethod == R_HTTP_METHOD_CONNECT && resstatus >= 200 && resstatus < 300) {
      ret = R_HTTP_BODY_PARSE_TUNNEL;
    } else if ((val = r_http_get_header ((const rchar *)info.data, info.size,
            R_STR_WITH_SIZE_ARGS ("Transfer-Encoding"), &size)) != NULL) {
      if (r_str_idx_of_str (val, size, R_STR_WITH_SIZE_ARGS ("chunked")) >= 0)
        ret = R_HTTP_BODY_PARSE_CHUNKED;
    } else if ((val = r_http_get_header ((const rchar *)info.data, info.size,
            R_STR_WITH_SIZE_ARGS ("Content-Length"), &size)) != NULL) {
      ret = R_HTTP_BODY_PARSE_SIZED;
    }

    r_buffer_unmap (res->msg.hdr, &info);
  }

  return ret;
}

rssize
r_http_response_calc_body_size (RHttpResponse * res, RHttpBodyParseType * type)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RHttpBodyParseType pt = R_HTTP_BODY_PARSE_CLOSE; /* Assume close */
  rssize ret = -1;

  if (r_buffer_map (res->msg.hdr, &info, R_MEM_MAP_READ)) {
    const rchar * val;
    rsize size;
    RHttpMethod reqmethod = (res->request != NULL) ?
      r_http_request_get_method (res->request) : R_HTTP_METHOD_UNKNOWN;
    RHttpStatus resstatus = r_http_response_get_status (res);

    if (reqmethod == R_HTTP_METHOD_HEAD || (resstatus >= 100 && resstatus < 200) ||
        resstatus == R_HTTP_STATUS_NO_CONTENT || resstatus == R_HTTP_STATUS_NOT_MODIFIED) {
      pt = R_HTTP_BODY_PARSE_SIZED;
      ret = 0;
    } else if (reqmethod == R_HTTP_METHOD_CONNECT && resstatus >= 200 && resstatus < 300) {
      pt = R_HTTP_BODY_PARSE_TUNNEL;
    } else if ((val = r_http_get_header ((const rchar *)info.data, info.size,
            R_STR_WITH_SIZE_ARGS ("Transfer-Encoding"), &size)) != NULL) {
      if (r_str_idx_of_str (val, size, R_STR_WITH_SIZE_ARGS ("chunked")) >= 0)
        pt = R_HTTP_BODY_PARSE_CHUNKED;
    } else if ((val = r_http_get_header ((const rchar *)info.data, info.size,
            R_STR_WITH_SIZE_ARGS ("Content-Length"), &size)) != NULL) {
      RStrParse p;
      int s = r_str_to_int (val, NULL, 10, &p);
      if (p == R_STR_PARSE_OK)
        ret = (rssize)s;
      pt = R_HTTP_BODY_PARSE_SIZED;
    }

    r_buffer_unmap (res->msg.hdr, &info);
  }

  if (type != NULL)
    *type = pt;

  return ret;
}

