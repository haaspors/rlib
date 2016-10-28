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

#include <rlib/rtime.h>

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

void
r_tls_parser_clear (RTLSParser * parser)
{
  if (R_LIKELY (parser->buf != NULL)) {
    if (R_LIKELY (parser->fragment.data != NULL))
      r_buffer_unmap (parser->buf, &parser->fragment);
    r_buffer_unref (parser->buf);
    r_memclear (parser, sizeof (RTLSParser));
  }
}

RTLSError
r_tls_parser_init (RTLSParser * parser, rconstpointer buf, rsize size)
{
  RBuffer * buffer;
  RTLSError ret;

  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size == 0)) return R_TLS_ERROR_BUF_TOO_SMALL;

  if ((buffer = r_buffer_new_take (r_memdup (buf, size), size)) != NULL) {
    ret = r_tls_parser_init_buffer (parser, buffer);
    r_buffer_unref (buffer);
  } else {
    ret = R_TLS_ERROR_INVAL;
  }

  return ret;
}

RTLSError
r_tls_parser_init_buffer (RTLSParser * parser, RBuffer * buf)
{
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSError ret;
  rsize fragoff;
  ruint16 fraglen;

  if (R_UNLIKELY (parser == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (buf == NULL)) return R_TLS_ERROR_INVAL;

  if (!r_buffer_map_byte_range (buf, 0, 5, &info, R_MEM_MAP_READ))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  parser->content = (RTLSContentType)info.data[0];
  if (parser->content < R_TLS_CONTENT_TYPE_FIRST ||
      parser->content > R_TLS_CONTENT_TYPE_LAST) {
    ret = R_TLS_ERROR_INVALID_RECORD;
    goto beach;
  }

  parser->version = (RTLSVersion)RUINT16_FROM_BE (*(const ruint16 *)&info.data[1]);

  if (!r_tls_parser_is_dtls (parser)) {
    if (R_UNLIKELY (parser->version < R_TLS_VERSION_TLS_1_0 ||
          parser->version > R_TLS_VERSION_TLS_1_3)) {
      ret = R_TLS_ERROR_VERSION;
      goto beach;
    }

    parser->epoch = 0;
    parser->seqno = 0;
    fragoff = 5;
    fraglen = RUINT16_FROM_BE (*(const ruint16 *)&info.data[3]);
  } else {
    RMemMapInfo dtlsext = R_MEM_MAP_INFO_INIT;

    if (R_UNLIKELY (parser->version > R_TLS_VERSION_DTLS_1_0 ||
        parser->version < R_TLS_VERSION_DTLS_1_3)) {
      ret = R_TLS_ERROR_VERSION;
      goto beach;
    }

    if (!r_buffer_map_byte_range (buf, 5, 6 + 2, &dtlsext, R_MEM_MAP_READ)) {
      ret = R_TLS_ERROR_BUF_TOO_SMALL;
      goto beach;
    }

    parser->epoch = RUINT16_FROM_BE (*(const ruint16 *)&info.data[3]);
    parser->seqno = _r_parse_u48 (&dtlsext.data[0]);
    fragoff = 13;
    fraglen = RUINT16_FROM_BE (*(const ruint16 *)&dtlsext.data[6]);
    r_buffer_unmap (buf, &dtlsext);
  }

  if ((fraglen & 0xc000) > 0) {
    ret = R_TLS_ERROR_CORRUPT_RECORD;
    goto beach;
  }
  if (!r_buffer_map_byte_range (buf, fragoff, (rssize)fraglen,
        &parser->fragment, R_MEM_MAP_READ)) {
    ret = R_TLS_ERROR_BUF_TOO_SMALL;
    goto beach;
  }

  ret = R_TLS_ERROR_OK;
  parser->buf = r_buffer_ref (buf);
  parser->recsize = fragoff + fraglen;

beach:
  r_buffer_unmap (buf, &info);
  return ret;
}

RTLSError
r_tls_parser_init_next (RTLSParser * parser, RBuffer ** buf)
{
  RBuffer * next;
  RTLSError ret;

  if ((next = r_tls_parser_next (parser)) != NULL) {
    r_tls_parser_clear (parser);
    ret = r_tls_parser_init_buffer (parser, next);
    if (buf != NULL)
      *buf = next;
    else
      r_buffer_unref (next);
  } else {
    r_tls_parser_clear (parser);
    ret = R_TLS_ERROR_EOB;
    if (buf != NULL)
      *buf = NULL;
  }

  return ret;
}

RBuffer *
r_tls_parser_next (RTLSParser * parser)
{
  RBuffer * ret;

  if ((ret = r_buffer_new ()) != NULL) {
    if (!r_buffer_append_region_from (ret, parser->buf, parser->recsize, -1)) {
      r_buffer_unref (ret);
      ret = NULL;
    }
  }

  return ret;
}

static RTLSError
r_tls_parser_parse_handshake_internal (const RTLSParser * parser,
    RTLSHandshakeType * type, const ruint8 ** body, const ruint8 ** end)
{
  if (R_UNLIKELY (parser->content != R_TLS_CONTENT_TYPE_HANDSHAKE))
    return R_TLS_ERROR_WRONG_TYPE;
  *type = (RTLSHandshakeType)parser->fragment.data[0];

  *end = parser->fragment.data + parser->fragment.size;
  *body = parser->fragment.data + (8 + 24) / 8;
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
  if (R_UNLIKELY (parser->fragment.size < 4)) return R_TLS_ERROR_BUF_TOO_SMALL;

  if (type != NULL)
    *type = (RTLSHandshakeType)parser->fragment.data[0];
  if (length != NULL)
    *length = _r_parse_u24 (&parser->fragment.data[1]);
  if (r_tls_parser_is_dtls (parser)) {
    if (R_UNLIKELY (parser->fragment.size < 12)) return R_TLS_ERROR_BUF_TOO_SMALL;
    if (msgseq != NULL)
      *msgseq = RUINT16_FROM_BE (*(const ruint16 *)&parser->fragment.data[4]);
    if (fragoff != NULL)
      *fragoff = _r_parse_u24 (&parser->fragment.data[6]);
    if (fraglen != NULL)
      *fraglen = _r_parse_u24 (&parser->fragment.data[9]);
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
    if (ptr + msg->complen > end) return R_TLS_ERROR_CORRUPT_RECORD;
    msg->compression = ptr;
    ptr += msg->complen;
  } else {
    msg->cookielen = 0;
    msg->cookie = NULL;
    if (ptr + sizeof (ruint16) + sizeof (ruint8) > end)
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
  if (ptr + sizeof (ruint16) > end) {
    msg->extlen = 0;
    msg->ext = NULL;
  } else {
    msg->extlen = RUINT16_FROM_BE (*(const ruint16 *)ptr);
    ptr += sizeof (ruint16);
    if (ptr + msg->extlen > end) return R_TLS_ERROR_CORRUPT_RECORD;
    msg->ext = ptr;
  }

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

RTLSError
r_tls_parser_parse_new_session_ticket (const RTLSParser * parser,
    ruint32 * lifetime, const ruint8 ** ticket, ruint16 * ticketsize)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint32) + sizeof (ruint16)) >
        RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if (lifetime != NULL)
    *lifetime = RUINT32_FROM_BE (*(const ruint32 *)ptr);
  ptr += sizeof (ruint32);
  if (ticketsize != NULL)
    *ticketsize = RUINT16_FROM_BE (*(const ruint16 *)ptr);
  if (ticket != NULL)
    *ticket = ptr + sizeof (ruint16);

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_parser_parse_certificate_verify (const RTLSParser * parser,
    RTLSSignatureScheme * sigscheme, const ruint8 ** sig, ruint16 * sigsize)
{
  RTLSHandshakeType type;
  const ruint8 * ptr, * end;
  RTLSError ret;

  ret = r_tls_parser_parse_handshake_internal (parser, &type, &ptr, &end);
  if (R_UNLIKELY (ret != R_TLS_ERROR_OK)) return ret;
  if (R_UNLIKELY (type != R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY))
    return R_TLS_ERROR_WRONG_TYPE;

  if (R_UNLIKELY (RPOINTER_TO_SIZE (ptr + sizeof (ruint16) + sizeof (ruint16)) >
        RPOINTER_TO_SIZE (end)))
    return R_TLS_ERROR_CORRUPT_RECORD;

  if (sigscheme != NULL)
    *sigscheme = (RTLSSignatureScheme)RUINT16_FROM_BE (*(const ruint16 *)ptr);
  ptr += sizeof (ruint16);
  if (sigsize != NULL)
    *sigsize = RUINT16_FROM_BE (*(const ruint16 *)ptr);
  if (sig != NULL)
    *sig = ptr + sizeof (ruint16);

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


RTLSError
r_tls_write_handshake (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, RTLSHandshakeType type, ruint16 len)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 9)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_TLS_HS_HDR_SIZE;
  p = data;
  p[0] = R_TLS_CONTENT_TYPE_HANDSHAKE;
  p[1] = (ver     >> 8) & 0xff;
  p[2] = (ver         ) & 0xff;
  p[3] = (hdrlen  >> 8) & 0xff;
  p[4] = (hdrlen      ) & 0xff;
  p[5] = type;
  p[6] = 0x00;
  p[7] = (len     >> 8) & 0xff;
  p[8] = (len         ) & 0xff;

  if (out != NULL)
    *out = R_TLS_RECORD_HDR_SIZE + R_TLS_HS_HDR_SIZE;

  return R_TLS_ERROR_OK;
}

RTLSError
r_dtls_write_handshake (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, RTLSHandshakeType type, ruint16 len,
    ruint16 epoch, ruint64 seqno, ruint16 msgseq,
    ruint32 foff, ruint32 flen)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 25)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_DTLS_HS_HDR_SIZE;
  p = data;
  p[ 0] = R_TLS_CONTENT_TYPE_HANDSHAKE;
  p[ 1] = (ver     >>  8) & 0xff;
  p[ 2] = (ver          ) & 0xff;
  p[ 3] = (epoch   >>  8) & 0xff;
  p[ 4] = (epoch        ) & 0xff;
  p[ 5] = (seqno   >> 40) & 0xff;
  p[ 6] = (seqno   >> 32) & 0xff;
  p[ 7] = (seqno   >> 24) & 0xff;
  p[ 8] = (seqno   >> 16) & 0xff;
  p[ 9] = (seqno   >>  8) & 0xff;
  p[10] = (seqno        ) & 0xff;
  p[11] = (hdrlen  >>  8) & 0xff;
  p[12] = (hdrlen       ) & 0xff;
  p[13] = type;
  p[14] = 0x00;
  p[15] = (len      >> 8) & 0xff;
  p[16] = (len          ) & 0xff;
  p[17] = (msgseq  >>  8) & 0xff;
  p[18] = (msgseq       ) & 0xff;
  p[19] = (foff    >> 16) & 0xff;
  p[20] = (foff    >>  8) & 0xff;
  p[21] = (foff         ) & 0xff;
  p[22] = (flen    >> 16) & 0xff;
  p[23] = (flen    >>  8) & 0xff;
  p[24] = (flen         ) & 0xff;

  if (out != NULL)
    *out = R_DTLS_RECORD_HDR_SIZE + R_DTLS_HS_HDR_SIZE;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_update_handshake_len (rpointer data, rsize size, ruint16 len)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 9)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_TLS_HS_HDR_SIZE;
  p = data;
  p[3] = (hdrlen  >> 8) & 0xff;
  p[4] = (hdrlen      ) & 0xff;
  p[7] = (len     >> 8) & 0xff;
  p[8] = (len         ) & 0xff;

  return R_TLS_ERROR_OK;
}

RTLSError
r_dtls_update_handshake_len (rpointer data, rsize size, ruint16 len,
    ruint32 foff, ruint32 flen)
{
  ruint hdrlen;
  ruint8 * p;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < 25)) return R_TLS_ERROR_BUF_TOO_SMALL;

  hdrlen = len + R_DTLS_HS_HDR_SIZE;
  p = data;
  p[11] = (hdrlen  >>  8) & 0xff;
  p[12] = (hdrlen       ) & 0xff;
  p[15] = (len      >> 8) & 0xff;
  p[16] = (len          ) & 0xff;
  p[19] = (foff    >> 16) & 0xff;
  p[20] = (foff    >>  8) & 0xff;
  p[21] = (foff         ) & 0xff;
  p[22] = (flen    >> 16) & 0xff;
  p[23] = (flen    >>  8) & 0xff;
  p[24] = (flen         ) & 0xff;

  return R_TLS_ERROR_OK;
}

RTLSError
r_tls_write_hs_server_hello (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, RPrng * prng, const ruint8 * sid, ruint8 sidsize,
    RCipherSuite cs, RTLSCompresssionMethod comp)
{
  ruint8 * p;
  ruint32 ts;

  if (R_UNLIKELY (data == NULL)) return R_TLS_ERROR_INVAL;
  if (R_UNLIKELY (size < (rsize)(2 + 4 + 28 + 1 + sidsize + 2 + 1)))
    return R_TLS_ERROR_BUF_TOO_SMALL;

  p = data;
  ts = (ruint32)(r_time_get_unix_time () & RUINT32_MAX);

  *p++ = (ver     >>  8) & 0xff;
  *p++ = (ver          ) & 0xff;
  *p++ = (ts      >> 24) & 0xff;
  *p++ = (ts      >> 16) & 0xff;
  *p++ = (ts      >>  8) & 0xff;
  *p++ = (ts           ) & 0xff;
  r_prng_fill (prng, p, 28); p += 28;
  *p++ = sidsize;
  r_memcpy (p, sid, sidsize); p += sidsize;
  *p++ = (cs      >>  8) & 0xff;
  *p++ = (cs           ) & 0xff;
  *p++ = (comp         ) & 0xff;

  if (out != NULL)
    *out = (2 + 4 + 28 + 1 + sidsize + 2 + 1);

  return R_TLS_ERROR_OK;
}

