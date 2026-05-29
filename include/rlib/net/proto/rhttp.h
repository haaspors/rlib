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

/**
 * @file rlib/net/proto/rhttp.h
 * @brief HTTP/1.x message model: requests, responses, headers and
 * bodies, with buffer encode / decode.
 */

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rref.h>
#include <rlib/ruri.h>

/**
 * @defgroup r_http_proto HTTP protocol
 * @ingroup r_net
 *
 * @brief HTTP/1.x wire model — parse and build requests and
 * responses, manipulate headers, and read / set message bodies.
 *
 * @ref RHttpMsg is the shared base for @ref RHttpRequest and
 * @ref RHttpResponse; the @c r_http_request_* / @c r_http_response_*
 * header and body accessors are convenience macros that forward to
 * the @c r_http_msg_* base operations. Construct messages from
 * components or decode them from an @ref RBuffer (the @c _from_buffer
 * constructors return any unconsumed bytes via a @c remainder
 * out-parameter for streaming).
 *
 * This is the wire codec; the event-loop-driven server lives in
 * @ref r_http_server.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Result code from the HTTP encode / decode and accessor APIs. */
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

/** @brief How a message body's length is determined when parsing. */
typedef enum {
  R_HTTP_BODY_PARSE_CHUNKED, /**< Chunked transfer-encoding. */
  R_HTTP_BODY_PARSE_SIZED,   /**< Fixed length from @c Content-Length. */
  R_HTTP_BODY_PARSE_CLOSE,   /**< Body runs until the connection closes. */
  R_HTTP_BODY_PARSE_TUNNEL,  /**< Tunnelled (e.g. after @c CONNECT). */
} RHttpBodyParseType;

/** @brief HTTP request method. */
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

/** @brief HTTP status code (standard RFC values; names are self-describing). */
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

/** @brief Opaque base message shared by @ref RHttpRequest and @ref RHttpResponse. */
typedef struct RHttpMsg RHttpMsg;
/** @brief Serialise the full message (start line + headers + body) to a buffer. */
R_API RBuffer * r_http_msg_get_buffer (RHttpMsg * msg) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Copy the message body into a freshly-allocated buffer; @p size receives its length. */
R_API rchar * r_http_msg_get_body (RHttpMsg * msg, rsize * size) R_ATTR_MALLOC;
/** @brief Return the message body as an @ref RBuffer. */
R_API RBuffer * r_http_msg_get_body_buffer (RHttpMsg * msg) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Set the message body from an @ref RBuffer. */
R_API RHttpError r_http_msg_set_body_buffer (RHttpMsg * msg, RBuffer * buf);
/** @brief @c TRUE if a header named @p field is present (@p size or @c -1). */
R_API rboolean r_http_msg_has_header (RHttpMsg * msg, const rchar * field, rssize size);
/** @brief @c TRUE if header @p key is present with value @p val. */
R_API rboolean r_http_msg_has_header_of_value (RHttpMsg * msg,
    const rchar * key, rssize ksize, const rchar * val, rssize vsize);
/** @brief Return the value of header @p field (newly allocated), or @c NULL. */
R_API rchar * r_http_msg_get_header (RHttpMsg * msg, const rchar * field, rssize size);
/** @brief Append a header @p field : @p value to the message. */
R_API rboolean r_http_msg_add_header (RHttpMsg * msg,
    const rchar * field, rssize fsize, const rchar * value, rssize vsize);

/** @brief Opaque, refcounted HTTP request (an @ref RHttpMsg). */
typedef struct RHttpRequest RHttpRequest;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_http_request_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_http_request_unref  r_ref_unref

/** @brief Build a request from a method, target URI string and version. */
R_API RHttpRequest * r_http_request_new (RHttpMethod method,
    const rchar * uri, const rchar * ver, RHttpError * err) R_ATTR_MALLOC;
/** @brief Build a request from a method, parsed @ref RUri and version. */
R_API RHttpRequest * r_http_request_new_with_uri (RHttpMethod method,
    RUri * uri, const rchar * ver, RHttpError * err) R_ATTR_MALLOC;
/**
 * @brief Decode a request from @p buf.
 * @param buf       Input bytes to parse.
 * @param err       Optional out-pointer for the @ref RHttpError.
 * @param remainder Out-pointer receiving any bytes past this message.
 */
R_API RHttpRequest * r_http_request_new_from_buffer (RBuffer * buf,
    RHttpError * err, RBuffer ** remainder) R_ATTR_MALLOC;
/** @brief Serialise the request to a buffer (forwards to @ref r_http_msg_get_buffer). */
#define r_http_request_get_buffer(req) r_http_msg_get_buffer ((RHttpMsg *)req)
/** @brief Return the request method. */
R_API RHttpMethod r_http_request_get_method (const RHttpRequest * req);
/** @brief Return the request target as a parsed @ref RUri. */
R_API RUri * r_http_request_get_uri (RHttpRequest * req);
/** @brief @ref r_http_msg_has_header on a request. */
#define r_http_request_has_header(req, field, size) r_http_msg_has_header ((RHttpMsg *)req, field, size)
/** @brief @ref r_http_msg_has_header_of_value on a request. */
#define r_http_request_has_header_of_value(req, key, ksize, val, vsize)       \
  r_http_msg_has_header_of_value ((RHttpMsg *)req, key, ksize, val, vsize)
/** @brief @ref r_http_msg_get_header on a request. */
#define r_http_request_get_header(req, field, size) r_http_msg_get_header ((RHttpMsg *)req, field, size)
/** @brief @ref r_http_msg_add_header on a request. */
#define r_http_request_add_header(req, field, fsize, value, vsize) r_http_msg_add_header ((RHttpMsg *)req, field, fsize, value, vsize)
/** @brief @ref r_http_msg_get_body on a request. */
#define r_http_request_get_body(req, size) r_http_msg_get_body ((RHttpMsg *)req, size)
/** @brief @ref r_http_msg_get_body_buffer on a request. */
#define r_http_request_get_body_buffer(req) r_http_msg_get_body_buffer ((RHttpMsg *)req)
/** @brief @ref r_http_msg_set_body_buffer on a request. */
#define r_http_request_set_body_buffer(req, buf) r_http_msg_set_body_buffer ((RHttpMsg *)req, buf)
/** @brief How the request body length is determined (chunked / sized / ...). */
R_API RHttpBodyParseType r_http_request_get_body_parse_type (RHttpRequest * req);
/** @brief Compute the request body size; @p type receives the parse type. */
R_API rssize r_http_request_calc_body_size (RHttpRequest * req, RHttpBodyParseType * type);


/** @brief Opaque, refcounted HTTP response (an @ref RHttpMsg). */
typedef struct RHttpResponse RHttpResponse;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_http_response_ref   r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_http_response_unref r_ref_unref

/**
 * @brief Build a response to @p req with the given status, reason
 * phrase and version. @p phrase may be @c NULL for the default text.
 */
R_API RHttpResponse * r_http_response_new (RHttpRequest * req,
    RHttpStatus status, const rchar * phrase, const rchar * ver,
    RHttpError * err) R_ATTR_MALLOC;
/** @brief Decode a response from @p buf; @p remainder receives trailing bytes. */
R_API RHttpResponse * r_http_response_new_from_buffer (RHttpRequest * req,
    RBuffer * buf, RHttpError * err, RBuffer ** remainder) R_ATTR_MALLOC;
/** @brief Return the response status code. */
R_API RHttpStatus r_http_response_get_status (const RHttpResponse * res);
/** @brief Serialise the response to a buffer (forwards to @ref r_http_msg_get_buffer). */
#define r_http_response_get_buffer(res) r_http_msg_get_buffer ((RHttpMsg *)res)
/** @brief Return the response reason phrase (newly allocated). */
R_API rchar * r_http_response_get_phrase (const RHttpResponse * res) R_ATTR_MALLOC;
/** @brief Return the request this response was built for. */
R_API RHttpRequest * r_http_response_get_request (RHttpResponse * res);
/** @brief @ref r_http_msg_has_header on a response. */
#define r_http_response_has_header(res, field, size) r_http_msg_has_header ((RHttpMsg *)res, field, size)
/** @brief @ref r_http_msg_has_header_of_value on a response. */
#define r_http_response_has_header_of_value(res, key, ksize, val, vsize)       \
  r_http_msg_has_header_of_value ((RHttpMsg *)res, key, ksize, val, vsize)
/** @brief @ref r_http_msg_get_header on a response. */
#define r_http_response_get_header(res, field, size) r_http_msg_get_header ((RHttpMsg *)res, field, size)
/** @brief @ref r_http_msg_add_header on a response. */
#define r_http_response_add_header(res, field, fsize, value, vsize) r_http_msg_add_header ((RHttpMsg *)res, field, fsize, value, vsize)
/** @brief @ref r_http_msg_get_body on a response. */
#define r_http_response_get_body(res, size) r_http_msg_get_body ((RHttpMsg *)res, size)
/** @brief @ref r_http_msg_get_body_buffer on a response. */
#define r_http_response_get_body_buffer(res) r_http_msg_get_body_buffer ((RHttpMsg *)res)
/** @brief @ref r_http_msg_set_body_buffer on a response. */
#define r_http_response_set_body_buffer(res, buf) r_http_msg_set_body_buffer ((RHttpMsg *)res, buf)
/**
 * @brief Set the response body and its @c Content-Type in one call.
 * @param res         Target response.
 * @param buf         Body bytes.
 * @param contenttype @c Content-Type value to set.
 * @param size        Length of @p contenttype, or @c -1 for @c strlen.
 * @param contentlen  @c TRUE to emit a @c Content-Length header.
 */
R_API RHttpError r_http_response_set_body_buffer_full (RHttpResponse * res,
    RBuffer * buf, const rchar * contenttype, rssize size, rboolean contentlen);
/** @brief How the response body length is determined (chunked / sized / ...). */
R_API RHttpBodyParseType r_http_response_get_body_parse_type (RHttpResponse * res);
/** @brief Compute the response body size; @p type receives the parse type. */
R_API rssize r_http_response_calc_body_size (RHttpResponse * res, RHttpBodyParseType * type);

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_HTTP_H__ */

