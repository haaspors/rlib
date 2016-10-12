/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/net/proto/rtls.h>

#include <rlib/crypto/rx509.h>

static inline ruint32
_r_parse_u24 (const ruint8 * ptr)
{
  return ((ruint32)ptr[0] << 16) | ((ruint32)ptr[1] <<  8) | ((ruint32)ptr[2]);
}

static inline ruint64
_r_parse_u48 (const ruint8 * ptr)
{
  return ((ruint64)ptr[0] << 40) | ((ruint64)ptr[1] << 32) | ((ruint64)ptr[2] << 24) |
         ((ruint64)ptr[3] << 16) | ((ruint64)ptr[4] <<  8) | ((ruint64)ptr[5]);
}

RTLSError
r_tls_parser_init (RTLSParser * parser, rconstpointer buf, rsize size)
{
  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 5)) return R_TLS_ERROR_BUF_TOO_SMALL;

  parser->buffer = buf;
  parser->bufsize = size;
  parser->content = (RTLSContentType)parser->buffer[0];
  if (parser->content < R_TLS_CONTENT_TYPE_FIRST || parser->content > R_TLS_CONTENT_TYPE_LAST)
    return R_TLS_ERROR_INVALID_RECORD;

  parser->version = (RTLSVersion)RUINT16_FROM_BE (*(const ruint16 *)&parser->buffer[1]);

  if (!r_tls_parser_is_dtls (parser)) {
    if (R_UNLIKELY (parser->version < R_TLS_VERSION_TLS_1_0)) return R_TLS_ERROR_VERSION;
    if (R_UNLIKELY (parser->version > R_TLS_VERSION_TLS_1_3)) return R_TLS_ERROR_VERSION;

    parser->epoch = 0;
    parser->seqno = 0;
    parser->fraglen = RUINT16_FROM_BE (*(const ruint16 *)&parser->buffer[3]);
    parser->fragment = &parser->buffer[5];
  } else {
    if (R_UNLIKELY (size < 13)) return R_TLS_ERROR_BUF_TOO_SMALL;
    if (R_UNLIKELY (parser->version > R_TLS_VERSION_DTLS_1_0)) return R_TLS_ERROR_VERSION;
    if (R_UNLIKELY (parser->version < R_TLS_VERSION_DTLS_1_3)) return R_TLS_ERROR_VERSION;

    parser->epoch = RUINT16_FROM_BE (*(const ruint16 *)&parser->buffer[3]);
    parser->seqno = _r_parse_u48 (&parser->buffer[5]);
    parser->fraglen = RUINT16_FROM_BE (*(const ruint16 *)&parser->buffer[11]);
    parser->fragment = &parser->buffer[13];
  }

  if ((parser->fraglen & 0xc000) > 0) return R_TLS_ERROR_CORRUPT_RECORD;
  if (parser->fragment + parser->fraglen > parser->buffer + size) return R_TLS_ERROR_BUF_TOO_SMALL;

  return R_TLS_ERROR_OK;
}

static RTLSError
r_tls_parser_parse_handshake_internal (const RTLSParser * parser,
    RTLSHandshakeType * type, const ruint8 ** body, const ruint8 ** end)
{
  if (R_UNLIKELY (parser->content != R_TLS_CONTENT_TYPE_HANDSHAKE))
    return R_TLS_ERROR_WRONG_TYPE;
  *type = (RTLSHandshakeType)parser->fragment[0];

  *end = parser->fragment + parser->fraglen;
  *body = parser->fragment + (8 + 24) / 8;
  if (r_tls_parser_is_dtls (parser))
    *body += (16 + 24 + 24) / 8;

  if (R_UNLIKELY (*body > *end)) return R_TLS_ERROR_CORRUPT_RECORD;
  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_handshake_full (const RTLSParser * parser,
    RTLSHandshakeType * type, ruint32 * length, ruint16 * msgseq,
    ruint32 * fragoff, ruint32 * fraglen)
{
  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (parser->content != R_TLS_CONTENT_TYPE_HANDSHAKE))
    return R_TLS_ERROR_WRONG_TYPE;
  if (R_UNLIKELY (parser->fraglen < 4)) return R_TLS_ERROR_BUF_TOO_SMALL;

  if (type != NULL)
    *type = (RTLSHandshakeType)parser->fragment[0];
  if (length != NULL)
    *length = _r_parse_u24 (&parser->fragment[1]);
  if (r_tls_parser_is_dtls (parser)) {
    if (R_UNLIKELY (parser->fraglen < 12)) return R_TLS_ERROR_BUF_TOO_SMALL;
    if (msgseq != NULL)
      *msgseq = RUINT16_FROM_BE (*(const ruint16 *)&parser->fragment[4]);
    if (fragoff != NULL)
      *fragoff = _r_parse_u24 (&parser->fragment[6]);
    if (fraglen != NULL)
      *fraglen = _r_parse_u24 (&parser->fragment[9]);
  } else {
    if (msgseq != NULL)   *msgseq = 0;
    if (fragoff != NULL)  *fragoff = 0;
    if (fraglen != NULL)  *fraglen = 0;
  }

  return R_TLS_ERROR_OK;
}

rboolean
r_tls_parser_dtls_is_complete_handshake_fragment (const RTLSParser * parser)
{
  ruint32 len, foff, flen;
  if (r_tls_parser_parse_handshake_full (parser, NULL, &len, NULL, &foff, &flen) == R_TLS_ERROR_OK)
    return foff == 0 && len == flen;

  return FALSE;
}

RTLSError
r_tls_parser_parse_hello (const RTLSParser * parser, RTLSHelloMsg * msg)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO &&
        type != R_TLS_HANDSHAKE_TYPE_SERVER_HELLO))
    return R_TLS_ERROR_WRONG_TYPE;

  msg->version = (RTLSVersion)RUINT16_FROM_BE (*(const ruint16 *)ptr);
  ptr += sizeof (ruint16);

  /* Random */
  if (ptr + R_TLS_HELLO_RANDOM_BYTES + 1 > end) return R_TLS_ERROR_CORRUPT_RECORD;
  msg->random = ptr;
  ptr += R_TLS_HELLO_RANDOM_BYTES;
  /* Session ID */
  msg->sidlen = *ptr++;
  if (ptr + msg->sidlen + 2 > end) return R_TLS_ERROR_CORRUPT_RECORD;
  msg->sid = ptr;
  ptr += msg->sidlen;

  if (type == R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
    /* Cookie */
    if (r_tls_parser_is_dtls (parser)) {
      msg->cookielen = *ptr++;
      if (ptr + msg->cookielen + 2 > end) return R_TLS_ERROR_CORRUPT_RECORD;
      msg->cookie = ptr;
      ptr += msg->cookielen;
    } else {
      msg->cookielen = 0;
      msg->cookie = NULL;
    }
    /* Cipher suites */
    msg->cslen = RUINT16_FROM_BE (*(const ruint16 *)ptr);
    if (ptr + msg->cslen + 1 > end) return R_TLS_ERROR_CORRUPT_RECORD;
    msg->cs = &ptr[sizeof (ruint16)];
    ptr += msg->cslen + sizeof (ruint16);
    /* Compression methods */
    msg->complen = *ptr++;
    if (ptr + msg->complen + 2 > end) return R_TLS_ERROR_CORRUPT_RECORD;
    msg->compression = ptr;
    ptr += msg->complen;
  } else {
    msg->cookielen = 0;
    msg->cookie = NULL;
    if (ptr + sizeof (ruint16) + sizeof (ruint8) + sizeof (ruint16) > end)
      return R_TLS_ERROR_CORRUPT_RECORD;
    /* Cipher suite */
    msg->cslen = sizeof (ruint16);
    msg->cs = ptr;
    ptr += sizeof (ruint16);
    /* Compression methods */
    msg->complen = 1;
    msg->compression = ptr++;
  }

  /* Extensions */
  msg->extlen = RUINT16_FROM_BE (*(const ruint16 *)ptr);
  if (ptr + msg->extlen > end) return R_TLS_ERROR_CORRUPT_RECORD;
  msg->ext = &ptr[sizeof (ruint16)];

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_certificate_next (const RTLSParser * parser,
    RTLSCertificate * cert)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  ruint32 totallen;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + (24 / 8)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if ((totallen = _r_parse_u24 (ptr)) > 0) {
    ptr = (cert->start != NULL) ? cert->cert + cert->len : ptr + (24 / 8);
    if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + (24 / 8)) < RPOINTER_TO_SIZE (end))) {
      cert->start = ptr;
      cert->len = _r_parse_u24 (cert->start);
      cert->cert = cert->start + (24 / 8);

      if (R_UNLIKELY (RPOINTER_TO_SIZE (cert->cert + cert->len) > RPOINTER_TO_SIZE (end)))
        return R_TLS_ERROR_CORRUPT_RECORD;
      else
        return R_TLS_ERROR_OK;
    }
  }

  return R_TLS_ERROR_EOB;
}

RTLSError
r_tls_parser_parse_certificate_request (const RTLSParser * parser,
    RTLSCertReq * req)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  ruint16 len;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint8)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  req->certtypecount = *ptr++;
  req->certtype = ptr;
  ptr += req->certtypecount;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  len = RUINT16_FROM_BE (*(const ruint16 *)ptr);
  req->signschemecount = len / sizeof (ruint16);
  req->signscheme = ptr + sizeof (ruint16);
  ptr += sizeof (ruint16) + len;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16)) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  len = RUINT16_FROM_BE (*(const ruint16 *)ptr);
  req->cacount = len / sizeof (ruint16);
  req->ca = ptr + sizeof (ruint16);
  ptr += sizeof (ruint16) + len;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr) > RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;
  else
    return R_TLS_ERROR_OK;
}

rboolean
r_tls_hello_msg_has_cipher_suite (const RTLSHelloMsg * msg, RCipherSuite cs)
{
  ruint16 i, count;
  count = r_tls_hello_msg_cipher_suite_count (msg);
  for (i = 0; i < count; i++) {
    if (r_tls_hello_msg_cipher_suite (msg, i) == cs)
      return TRUE;
  }
  return FALSE;
}

RTLSError
r_tls_hello_msg_extension_first (const RTLSHelloMsg * msg, RTLSHelloExt * ext)
{
  if (R_UNLIKELY (msg == NULL || ext == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (msg->extlen < R_TLS_HELLO_EXT_HDR_SIZE)) return R_TLS_ERROR_EOB;

  ext->start = msg->ext;
  ext->type = RUINT16_FROM_BE (*(const ruint16 *)&ext->start[0]);
  ext->len = RUINT16_FROM_BE (*(const ruint16 *)&ext->start[2]);
  ext->data = ext->start + R_TLS_HELLO_EXT_HDR_SIZE;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_hello_msg_extension_next (const RTLSHelloMsg * msg, RTLSHelloExt * ext)
{
  if (R_UNLIKELY (msg == NULL || ext == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (ext->start == NULL || ext->data == NULL))
    return r_tls_hello_msg_extension_first (msg, ext);
  if (R_UNLIKELY (ext->data + ext->len + R_TLS_HELLO_EXT_HDR_SIZE > msg->ext + msg->extlen))
    return R_TLS_ERROR_EOB;

  ext->start = ext->data + ext->len;
  ext->type = RUINT16_FROM_BE (*(const ruint16 *)&ext->start[0]);
  ext->len = RUINT16_FROM_BE (*(const ruint16 *)&ext->start[2]);
  ext->data = ext->start + R_TLS_HELLO_EXT_HDR_SIZE;

  return R_TLS_ERROR_OK;
}

RCryptoCert *
r_tls_certificate_get_cert (const RTLSCertificate * cert)
{
  if (R_UNLIKELY (cert == NULL)) return NULL;
  return r_crypto_x509_cert_new (cert->cert, cert->len);
}

