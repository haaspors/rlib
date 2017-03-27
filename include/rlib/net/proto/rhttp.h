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
#ifndef __R_NET_PROTO_HTTP_H__
#define __R_NET_PROTO_HTTP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>
#include <rlib/ruri.h>

R_BEGIN_DECLS

typedef enum {
  R_HTTP_OK = 0,
  R_HTTP_INVAL,
  R_HTTP_OOM,
  R_HTTP_BUF_TOO_SMALL,
  R_HTTP_INVALID_URI,
  R_HTTP_DECODE_ERROR,
  R_HTTP_ENCODE_ERROR,
  R_HTTP_MISSING_HOST,
  R_HTTP_BAD_DATA,
  R_HTTP_NOT_SUPPORTED,
  R_HTTP_COMPLETE,
} RHttpError;

typedef enum {
  R_HTTP_BODY_PARSE_CHUNKED,
  R_HTTP_BODY_PARSE_SIZED,
  R_HTTP_BODY_PARSE_CLOSE,
  R_HTTP_BODY_PARSE_TUNNEL,
} RHttpBodyParseType;

typedef enum {
  R_HTTP_METHOD_UNKNOWN = -1,
  R_HTTP_METHOD_GET = 0,
  R_HTTP_METHOD_HEAD,
  R_HTTP_METHOD_POST,
  R_HTTP_METHOD_PUT,
  R_HTTP_METHOD_DELETE,
  R_HTTP_METHOD_CONNECT,
  R_HTTP_METHOD_OPTIONS,
  R_HTTP_METHOD_TRACE,
} RHttpMethod;

typedef enum {
  R_HTTP_STATUS_CONTINUE                              = 100,
  R_HTTP_STATUS_SWITCHING_PROTOCOLS                   = 101,
  R_HTTP_STATUS_PROCESSING                            = 102,

  R_HTTP_STATUS_OK                                    = 200,
  R_HTTP_STATUS_CREATED                               = 201,
  R_HTTP_STATUS_ACCEPTED                              = 202,
  R_HTTP_STATUS_NON_AUTHORITATIVE_INFORMATION         = 203,
  R_HTTP_STATUS_NO_CONTENT                            = 204,
  R_HTTP_STATUS_RESET_CONTENT                         = 205,
  R_HTTP_STATUS_PARTIAL_CONTENT                       = 206,
  R_HTTP_STATUS_MULTI_STATUS                          = 207,
  R_HTTP_STATUS_ALREADY_REPORTED                      = 208,
  R_HTTP_STATUS_IM_USED                               = 226,

  R_HTTP_STATUS_MULTIPLE_CHOICES                      = 300,
  R_HTTP_STATUS_MOVED_PERMANENTLY                     = 301,
  R_HTTP_STATUS_FOUND                                 = 302,
  R_HTTP_STATUS_SEE_OTHER                             = 303,
  R_HTTP_STATUS_NOT_MODIFIED                          = 304,
  R_HTTP_STATUS_USE_PROXY                             = 305,
  R_HTTP_STATUS_TEMPORARY_REDIRECT                    = 307,
  R_HTTP_STATUS_PERMANENT_REDIRECT                    = 308,

  R_HTTP_STATUS_BAD_REQUEST                           = 400,
  R_HTTP_STATUS_UNAUTHORIZED                          = 401,
  R_HTTP_STATUS_PAYMENT_REQUIRED                      = 402,
  R_HTTP_STATUS_FORBIDDEN                             = 403,
  R_HTTP_STATUS_NOT_FOUND                             = 404,
  R_HTTP_STATUS_METHOD_NOT_ALLOWED                    = 405,
  R_HTTP_STATUS_NOT_ACCEPTABLE                        = 406,
  R_HTTP_STATUS_PROXY_AUTHENTICATION_REQUIRED         = 407,
  R_HTTP_STATUS_REQUEST_TIMEOUT                       = 408,
  R_HTTP_STATUS_CONFLICT                              = 409,
  R_HTTP_STATUS_GONE                                  = 410,
  R_HTTP_STATUS_LENGTH_REQUIRED                       = 411,
  R_HTTP_STATUS_PRECONDITION_FAILED                   = 412,
  R_HTTP_STATUS_PAYLOAD_TOO_LARGE                     = 413,
  R_HTTP_STATUS_URI_TOO_LONG                          = 414,
  R_HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE                = 415,
  R_HTTP_STATUS_RANGE_NOT_SATISFIABLE                 = 416,
  R_HTTP_STATUS_EXPECTATION_FAILED                    = 417,
  R_HTTP_STATUS_TEAPOT                                = 418,
  R_HTTP_STATUS_UNPROCESSABLE_ENTITY                  = 422,
  R_HTTP_STATUS_LOCKED                                = 423,
  R_HTTP_STATUS_FAILED_DEPENDENCY                     = 424,
  R_HTTP_STATUS_UPGRADE_REQUIRED                      = 426,
  R_HTTP_STATUS_PRECONDITION_REQUIRED                 = 428,
  R_HTTP_STATUS_TOO_MANY_REQUESTS                     = 429,
  R_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE       = 431,
  R_HTTP_STATUS_UNAVAILABLE_FOR_LEGAL_REASONS         = 451,

  R_HTTP_STATUS_INTERNAL_SERVER_ERROR                 = 500,
  R_HTTP_STATUS_NOT_IMPLEMENTED                       = 501,
  R_HTTP_STATUS_BAD_GATEWAY                           = 502,
  R_HTTP_STATUS_SERVICE_UNAVAILABLE                   = 503,
  R_HTTP_STATUS_GATEWAY_TIMEOUT                       = 504,
  R_HTTP_STATUS_VERSION_NOT_SUPPORTED                 = 505,
  R_HTTP_STATUS_VARIANT_ALSO_NEGOTIATES               = 506,
  R_HTTP_STATUS_INSUFFICIENT_STORAGE                  = 507,
  R_HTTP_STATUS_LOOP_DETECTED                         = 508,
  R_HTTP_STATUS_NOT_EXTENDED                          = 510,
  R_HTTP_STATUS_NETWORK_AUTHENTICATION_REQUIRED       = 511,

  R_HTTP_STATUS_MIN                                   = R_HTTP_STATUS_CONTINUE,
  R_HTTP_STATUS_MAX                                   = 999,
} RHttpStatus;

typedef struct _RHttpMsg RHttpMsg;
R_API RBuffer * r_http_msg_get_buffer (RHttpMsg * msg) R_ATTR_WARN_UNUSED_RESULT;
R_API rchar * r_http_msg_get_body (RHttpMsg * msg, rsize * size) R_ATTR_MALLOC;
R_API RBuffer * r_http_msg_get_body_buffer (RHttpMsg * msg) R_ATTR_WARN_UNUSED_RESULT;
R_API RHttpError r_http_msg_set_body_buffer (RHttpMsg * msg, RBuffer * buf);
R_API rboolean r_http_msg_has_header (RHttpMsg * msg, const rchar * field, rssize size);
R_API rboolean r_http_msg_has_header_of_value (RHttpMsg * msg,
    const rchar * key, rssize ksize, const rchar * val, rssize vsize);
R_API rchar * r_http_msg_get_header (RHttpMsg * msg, const rchar * field, rssize size);
rboolean r_http_msg_add_header (RHttpMsg * msg,
    const rchar * field, rssize fsize, const rchar * value, rssize vsize);

typedef struct _RHttpRequest RHttpRequest;
#define r_http_request_ref    r_ref_ref
#define r_http_request_unref  r_ref_unref

R_API RHttpRequest * r_http_request_new (RHttpMethod method,
    const rchar * uri, const rchar * ver, RHttpError * err) R_ATTR_MALLOC;
R_API RHttpRequest * r_http_request_new_with_uri (RHttpMethod method,
    RUri * uri, const rchar * ver, RHttpError * err) R_ATTR_MALLOC;
R_API RHttpRequest * r_http_request_new_from_buffer (RBuffer * buf,
    RHttpError * err, RBuffer ** remainder) R_ATTR_MALLOC;
#define r_http_request_get_buffer(req) r_http_msg_get_buffer ((RHttpMsg *)req)
R_API RHttpMethod r_http_request_get_method (const RHttpRequest * req);
R_API RUri * r_http_request_get_uri (RHttpRequest * req);
#define r_http_request_has_header(req, field, size) r_http_msg_has_header ((RHttpMsg *)req, field, size)
#define r_http_request_has_header_of_value(req, key, ksize, val, vsize)       \
  r_http_msg_has_header_of_value ((RHttpMsg *)req, key, ksize, val, vsize)
#define r_http_request_get_header(req, field, size) r_http_msg_get_header ((RHttpMsg *)req, field, size)
#define r_http_request_add_header(req, field, fsize, value, vsize) r_http_msg_add_header ((RHttpMsg *)req, field, fsize, value, vsize)
#define r_http_request_get_body(req, size) r_http_msg_get_body ((RHttpMsg *)req, size)
#define r_http_request_get_body_buffer(req) r_http_msg_get_body_buffer ((RHttpMsg *)req)
#define r_http_request_set_body_buffer(req, buf) r_http_msg_set_body_buffer ((RHttpMsg *)req, buf)
R_API RHttpBodyParseType r_http_request_get_body_parse_type (RHttpRequest * req);
R_API rssize r_http_request_calc_body_size (RHttpRequest * req, RHttpBodyParseType * type);


typedef struct _RHttpResponse RHttpResponse;
#define r_http_response_ref   r_ref_ref
#define r_http_response_unref r_ref_unref

R_API RHttpResponse * r_http_response_new (RHttpRequest * req,
    RHttpStatus status, const rchar * phrase, const rchar * ver,
    RHttpError * err) R_ATTR_MALLOC;
R_API RHttpResponse * r_http_response_new_from_buffer (RHttpRequest * req,
    RBuffer * buf, RHttpError * err, RBuffer ** remainder) R_ATTR_MALLOC;
R_API RHttpStatus r_http_response_get_status (const RHttpResponse * res);
#define r_http_response_get_buffer(res) r_http_msg_get_buffer ((RHttpMsg *)res)
R_API rchar * r_http_response_get_phrase (const RHttpResponse * res) R_ATTR_MALLOC;
R_API RHttpRequest * r_http_response_get_request (RHttpResponse * res);
#define r_http_response_has_header(res, field, size) r_http_msg_has_header ((RHttpMsg *)res, field, size)
#define r_http_response_has_header_of_value(res, key, ksize, val, vsize)       \
  r_http_msg_has_header_of_value ((RHttpMsg *)res, key, ksize, val, vsize)
#define r_http_response_get_header(res, field, size) r_http_msg_get_header ((RHttpMsg *)res, field, size)
#define r_http_response_add_header(res, field, fsize, value, vsize) r_http_msg_add_header ((RHttpMsg *)res, field, fsize, value, vsize)
#define r_http_response_get_body(res, size) r_http_msg_get_body ((RHttpMsg *)res, size)
#define r_http_response_get_body_buffer(res) r_http_msg_get_body_buffer ((RHttpMsg *)res)
#define r_http_response_set_body_buffer(res, buf) r_http_msg_set_body_buffer ((RHttpMsg *)res, buf)
R_API RHttpBodyParseType r_http_response_get_body_parse_type (RHttpResponse * res);
R_API rssize r_http_response_calc_body_size (RHttpResponse * res, RHttpBodyParseType * type);

R_END_DECLS

#endif /* __R_NET_PROTO_HTTP_H__ */

