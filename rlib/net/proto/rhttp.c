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

static RMemScanResult *
r_http_parse_start_line (rconstpointer data, rsize size, RMemScanResultType * res)
{
  RMemScanResult * ret;
  RMemScanResultType err;

  if ((err = r_mem_scan_pattern (data, size, "*20*20*0A", &ret)) == R_MEM_SCAN_RESULT_OK) {
    /* Old HTTP/1.0 implementations may inject CRLF */
    if (((const rchar *)ret->token[0].ptr_data)[0] == '\r' &&
        ((const rchar *)ret->token[0].ptr_data)[1] == '\n') {
      ret->token[0].ptr_data = RSIZE_TO_POINTER (RPOINTER_TO_SIZE (ret->token[0].ptr_data) + 2);
      ret->token[0].size -= 2;
    }
    /* Support start line with either CRLF or only LF */
    while (((const rchar *)ret->token[4].ptr_data)[ret->token[4].size - 1] == '\r')
      ret->token[4].size--;
  } else {
    ret = NULL;
  }

  if (res != NULL) *res = err;
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
  if (msg->body != NULL)
    return r_buffer_extract_dup_all (msg->body, size);

  if (size != NULL) *size = 0;
  return NULL;
}

RBuffer *
r_http_msg_get_body_buffer (RHttpMsg * msg)
{
  return msg->body != NULL ? r_buffer_ref (msg->body) : NULL;
}

RHttpError
r_http_msg_set_body (RHttpMsg * msg, RBuffer * buf)
{
  if (R_UNLIKELY (msg == NULL)) return R_HTTP_INVAL;

  if (msg->body != NULL)
    r_buffer_unref (msg->body);
  msg->body = r_buffer_ref (buf);

  return R_HTTP_OK;
}

rboolean
r_http_msg_has_header (RHttpMsg * msg, const rchar * field, rssize size)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rboolean ret = FALSE;

  if (R_UNLIKELY (msg == NULL)) return FALSE;
  if (R_UNLIKELY (field == NULL)) return FALSE;
  if (R_UNLIKELY (size == 0)) return FALSE;

  if (r_buffer_map (msg->hdr, &info, R_MEM_MAP_READ)) {
    rssize idx;
    if ((idx = r_str_idx_of_str_case ((rchar *)info.data, info.size, field, size)) >= 0)
      ret = info.data[idx + (rsize)size] == ':';
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
    rsize * hdroff, rsize * hdrsize, rsize * bodyoff, rsize * bodysize)
{
  RMemScanResult * scanres;
  rssize idx;
  const rchar * tenc, * clen;
  rsize tencsize, clensize;

  /* Request line */
  if ((scanres = r_http_parse_start_line (data, size, NULL)) != NULL) {
    *method = r_http_method_parse (scanres->token[0].ptr_data,
        scanres->token[0].size);
    target->str = scanres->token[2].ptr_data;
    target->size = scanres->token[2].size;
    ver->str = scanres->token[4].ptr_data;
    ver->size = scanres->token[4].size;
    *hdroff = RPOINTER_TO_SIZE (scanres->end) - RPOINTER_TO_SIZE (scanres->ptr);
    r_free (scanres);
  } else {
    return R_HTTP_DECODE_ERROR;
  }

  /* Headers */
  if ((idx = r_str_idx_of_str (((const rchar *)data) + *hdroff, size - *hdroff,
          "\r\n\r\n", 4)) >= 0) {
    *hdrsize = (rsize)idx + 4;
  } else {
    return R_HTTP_BUF_TOO_SMALL;
  }

  /* Body */
  *bodyoff = *hdroff + *hdrsize;

  if ((tenc = r_http_get_header (((const rchar *)data) + *hdroff, *hdrsize,
          R_STR_WITH_SIZE_ARGS ("Transfer-Encoding"), &tencsize)) != NULL) {
    if (tencsize < R_STR_SIZEOF ("chunked") || !r_str_equals (tenc, "chunked"))
      return R_HTTP_BAD_DATA;

    /* FIXME: Support chunked Transfer-Encoding */
    return R_HTTP_NOT_SUPPORTED;
  }

  if ((clen = r_http_get_header (((const rchar *)data) + *hdroff, *hdrsize,
          R_STR_WITH_SIZE_ARGS ("Content-Length"), &clensize)) != NULL) {
    RStrParse p;
    int bsize = r_str_to_int (clen, NULL, 10, &p);
    if (p == R_STR_PARSE_OK) {
      if ((*bodysize = (rsize)bsize) > size - *bodyoff)
        return R_HTTP_BUF_TOO_SMALL;
    } else {
      return R_HTTP_BAD_DATA;
    }
  } else {
    *bodysize = 0;
  }

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
    rsize hdroff, hdrsize, bodyoff, bodysize, hostsize;
    const rchar * host;

    if ((res = r_http_request_parse (info.data, info.size,
          &method, &strrequest, &strver,
          &hdroff, &hdrsize, &bodyoff, &bodysize)) == R_HTTP_OK) {
      if ((host = r_http_get_header (info.data + hdroff, hdrsize,
              R_STR_WITH_SIZE_ARGS ("Host"), &hostsize)) != NULL) {
        if ((ret = r_mem_new (RHttpRequest)) != NULL) {
          r_http_msg_init ((RHttpMsg *)ret, (RDestroyNotify)r_http_request_free,
              r_buffer_view (buf, 0, hdroff),
              r_buffer_view (buf, hdroff, hdrsize),
              r_buffer_view (buf, bodyoff, bodysize));
          ret->method = method;
          ret->uri = r_uri_new_http_sized (host, hostsize,
              strrequest.str, strrequest.size);
          if (remainder != NULL)
            *remainder = r_buffer_view (buf, bodyoff + bodysize, -1);
        } else {
          res = R_HTTP_OOM;
        }
      } else {
        res = R_HTTP_MISSING_HOST;
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



static RBuffer *
r_http_create_status_line (RHttpStatus status, const rchar * phrase,
    const rchar * ver)
{
  rchar * line;

  line = r_strprintf ("HTTP/%s %.3d %s\r\n",
      ver, (int)status, phrase != NULL ? phrase : "");

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
r_http_response_parse (rconstpointer data, rsize size, RHttpMethod reqmethod,
    RStrChunk * ver, RHttpStatus * status, RStrChunk * phrase,
    rsize * hdroff, rsize * hdrsize, rsize * bodyoff, rsize * bodysize)
{
  RMemScanResult * scanres;
  rssize idx;
  const rchar * tenc, * clen;
  rsize tencsize, clensize;
  int s;

  /* Status line */
  if ((scanres = r_http_parse_start_line (data, size, NULL)) != NULL &&
      (s = r_str_to_int (scanres->token[2].ptr_data, NULL, 10, NULL)) > (int)R_HTTP_STATUS_MIN &&
      (s <= (int)R_HTTP_STATUS_MAX)) {
    ver->str = scanres->token[0].ptr_data;
    ver->size = scanres->token[0].size;
    *status = (RHttpStatus)s;
    phrase->str = scanres->token[4].ptr_data;
    phrase->size = scanres->token[4].size;
    *hdroff = RPOINTER_TO_SIZE (scanres->end) - RPOINTER_TO_SIZE (scanres->ptr);
    r_free (scanres);
  } else {
    r_free (scanres);
    return R_HTTP_DECODE_ERROR;
  }

  /* Headers */
  if ((idx = r_str_idx_of_str (((const rchar *)data) + *hdroff, size - *hdroff,
          "\r\n\r\n", 4)) >= 0) {
    *hdrsize = (rsize)idx + 4;
  } else {
    return R_HTTP_BUF_TOO_SMALL;
  }

  /* Body */
  *bodyoff = *hdroff + *hdrsize;

  if (reqmethod == R_HTTP_METHOD_HEAD ||
      (s >= 100 && s < 200) ||
      *status == R_HTTP_STATUS_NO_CONTENT ||
      *status == R_HTTP_STATUS_NOT_MODIFIED) {
    *bodysize = 0;
    return R_HTTP_OK;
  } else if (reqmethod == R_HTTP_METHOD_CONNECT && s >= 200 && s < 300) {
    *bodysize = size - *bodyoff;
    return R_HTTP_OK_BODY_UNTIL_CLOSE;
  }

  if ((tenc = r_http_get_header (((const rchar *)data) + *hdroff, *hdrsize,
          R_STR_WITH_SIZE_ARGS ("Transfer-Encoding"), &tencsize)) != NULL) {
    if (tencsize < R_STR_SIZEOF ("chunked") || !r_str_equals (tenc, "chunked")) {
      *bodysize = size - *bodyoff;
      return R_HTTP_OK_BODY_UNTIL_CLOSE;
    }

    /* FIXME: Support chunked Transfer-Encoding */
    return R_HTTP_NOT_SUPPORTED;
  }

  if ((clen = r_http_get_header (((const rchar *)data) + *hdroff, *hdrsize,
          R_STR_WITH_SIZE_ARGS ("Content-Length"), &clensize)) != NULL) {
    RStrParse p;
    int bsize = r_str_to_int (clen, NULL, 10, &p);
    if (p == R_STR_PARSE_OK) {
      if ((*bodysize = (rsize)bsize) > size - *bodyoff)
        return R_HTTP_BUF_TOO_SMALL;
    } else {
      return R_HTTP_BAD_DATA;
    }
  } else {
    *bodysize = size - *bodyoff;
    return R_HTTP_OK_BODY_UNTIL_CLOSE;
  }

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
    rsize hdroff, hdrsize, bodyoff, bodysize;
    RStrChunk strphrase, strver;
    RHttpStatus status;

    if ((res = r_http_response_parse (info.data, info.size,
            (req != NULL) ? req->method : R_HTTP_METHOD_UNKNOWN,
            &strver, &status, &strphrase,
            &hdroff, &hdrsize, &bodyoff, &bodysize)) <= R_HTTP_OK) {
      if ((ret = r_mem_new (RHttpResponse)) != NULL) {
        r_http_msg_init ((RHttpMsg *)ret, (RDestroyNotify)r_http_response_free,
            r_buffer_view (buf, 0, hdroff),
            r_buffer_view (buf, hdroff, hdrsize),
            r_buffer_view (buf, (rsize)bodyoff, bodysize));
        ret->status = status;
        ret->request = req != NULL ? r_http_request_ref (req) : NULL;
        if (remainder != NULL)
          *remainder = r_buffer_view (buf, bodyoff + bodysize, -1);
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
    RMemScanResult * sres;

    if ((sres = r_http_parse_start_line (info.data, info.size, NULL)) != NULL) {
      ret = r_strndup (sres->token[4].ptr_data, sres->token[4].size);
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

