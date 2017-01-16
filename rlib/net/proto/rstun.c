/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/net/proto/rstun.h>

#include <rlib/rcrc.h>
#include <rlib/crypto/rhmac.h>
#include <rlib/rmem.h>

rboolean
r_stun_is_valid_msg (rconstpointer buf, rsize size)
{
  const ruint8 * ptr;

  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (size < R_STUN_HEADER_SIZE)) return FALSE;

  ptr = buf;
  if (R_UNLIKELY ((*ptr & 0xc0) != 0)) return FALSE;
  if (R_UNLIKELY (size < (rsize)r_stun_msg_len (buf) + R_STUN_HEADER_SIZE)) return FALSE;

  return r_stun_msg_magic_cookie (buf) == RUINT32_FROM_BE (R_STUN_MAGIC_COOKIE);
}

rboolean
r_stun_msg_begin (RStunMsgCtx * ctx, rpointer buf, rsize size,
    RStunClass cls, RStunMethod method,
    const ruint8 transaction_id[R_STUN_TRANSACTION_ID_SIZE])
{
  ruint16 type;

  if (R_UNLIKELY (buf == NULL || size == 0)) return FALSE;
  if (R_UNLIKELY (((ruint16)cls & ~R_STUN_TYPE_CLASS_MASK) != 0)) return FALSE;
  if (R_UNLIKELY (((ruint16)method & ~R_STUN_TYPE_METHOD_MASK) != 0)) return FALSE;

  ctx->buf = buf;
  ctx->alloc_size = size;
  ctx->used_size = R_STUN_HEADER_SIZE;

  type = ((ruint16)cls & R_STUN_TYPE_CLASS_MASK) | ((ruint16)method & R_STUN_TYPE_METHOD_MASK);
  *(ruint16 *)ctx->buf = RUINT16_TO_BE (type);
  *(ruint16 *)&ctx->buf[R_STUN_MSGLEN_OFFSET] = 0;
  *(ruint32 *)&ctx->buf[R_STUN_MAGIC_COOKIE_OFFSET] = RUINT32_TO_BE (R_STUN_MAGIC_COOKIE);
  r_memcpy (&ctx->buf[R_STUN_TRANSACTION_ID_OFFSET], transaction_id, R_STUN_TRANSACTION_ID_SIZE);

  return TRUE;
}

rboolean
r_stun_msg_add_attribute (RStunMsgCtx * ctx, const RStunAttrTLV * tlv)
{
  ruint16 size = (tlv->len + R_STUN_ATTR_TLV_HEADER_SIZE + 0x3) & ~0x3;

  if (ctx->alloc_size - ctx->used_size >= size) {
    ruint8 * ptr = ctx->buf + ctx->used_size;
    ctx->used_size += size;

    *(ruint16 *)&ptr[0] = RUINT16_TO_BE (tlv->type);
    *(ruint16 *)&ptr[2] = RUINT16_TO_BE (tlv->len);
    r_memcpy (&ptr[R_STUN_ATTR_TLV_HEADER_SIZE], tlv->value, tlv->len);

    ptr += R_STUN_ATTR_TLV_HEADER_SIZE + tlv->len;
    r_memset (ptr, 0, ctx->buf + ctx->used_size - ptr); /* padding */

    return TRUE;
  }

  return FALSE;
}

rboolean
r_stun_msg_add_xor_address (RStunMsgCtx * ctx, RStunAttrType type,
    const RSocketAddress * addr)
{
  RStunAttrTLV tlv;
  ruint8 val[4 + 16];

  tlv.start = NULL;
  tlv.type = type;
  tlv.len = 0;
  tlv.value = val;

  val[0] = 0;
  switch (r_socket_address_get_family (addr)) {
    case R_SOCKET_FAMILY_IPV4:
      val[1] = 1;
      {
        ruint16 port = RUINT16_TO_BE (r_socket_address_ipv4_get_port (addr)) ^ *(ruint16 *)&ctx->buf[R_STUN_MAGIC_COOKIE_OFFSET];
        ruint32 ip = RUINT32_TO_BE (r_socket_address_ipv4_get_ip (addr))   ^ *(ruint32 *)&ctx->buf[R_STUN_MAGIC_COOKIE_OFFSET];
        r_memcpy (val + 2, &port, sizeof (ruint16));
        r_memcpy (val + 4, &ip, sizeof (ruint32));
      }
      tlv.len += 4 + sizeof (ruint32);
      break;
    case R_SOCKET_FAMILY_IPV6:
      val[1] = 2;
      /**(ruint16 *)&val[2] = RUINT16_TO_BE (r_socket_address_ipv6_get_port (addr)) ^ *(ruint16 *)&ctx->buf[R_STUN_MAGIC_COOKIE_OFFSET];*/
      /**(ruint32 *)&val[4] = RUINT32_TO_BE (r_socket_address_ipv6_get_ip (addr)   ^ R_STUN_MAGIC_COOKIE);*/
      tlv.len += 4 + (128 / 8);
      return FALSE; /* FIXME: Add support for ipv6 */
    default:
      return FALSE;
  }

  return r_stun_msg_add_attribute (ctx, &tlv);
}

rboolean
r_stun_msg_add_message_integrity_short_cred (RStunMsgCtx * ctx,
    rconstpointer key, rsize keysize)
{
  RStunAttrTLV tlv;
  ruint8 val[R_STUN_MSG_INTEGRITY_SIZE];
  RHmac * hmac;
  rboolean ret = FALSE;

  tlv.start = NULL;
  tlv.type = R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY;
  tlv.len = sizeof (val);
  tlv.value = val;

  if (ctx->alloc_size - ctx->used_size >= R_STUN_ATTR_TLV_HEADER_SIZE + R_STUN_MSG_INTEGRITY_SIZE) {
    /* Update message len including the MESSAGE-INTEGRITY attribute */
    ruint16 l = ctx->used_size + R_STUN_ATTR_TLV_HEADER_SIZE + tlv.len - R_STUN_HEADER_SIZE;
    *(ruint16 *)&ctx->buf[R_STUN_MSGLEN_OFFSET] = RUINT16_TO_BE (l);

    if ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, key, keysize)) != NULL) {
      rsize datasize;
      if (r_hmac_update (hmac, ctx->buf, ctx->used_size) &&
          r_hmac_get_data (hmac, val, sizeof (val), &datasize))
        ret = r_stun_msg_add_attribute (ctx, &tlv);
      r_hmac_free (hmac);
    }
  }
  return ret;
}

ruint16
r_stun_msg_end (RStunMsgCtx * ctx, rboolean fingerprint)
{
  ruint16 ret;

  if (fingerprint) {
    ruint32 crc;
    RStunAttrTLV tlv = { ctx->buf + ctx->used_size, R_STUN_ATTR_TYPE_FINGERPRINT, sizeof (ruint32), (const ruint8 *)&crc };
    ruint16 l = ctx->used_size + R_STUN_ATTR_TLV_HEADER_SIZE + tlv.len - R_STUN_HEADER_SIZE;
    /* Update message len including the FINGERPRINT attribute */
    *(ruint16 *)&ctx->buf[R_STUN_MSGLEN_OFFSET] = RUINT16_TO_BE (l);
    crc = RUINT32_TO_BE (r_stun_msg_calc_fingerprint (ctx->buf, &tlv));
    r_stun_msg_add_attribute (ctx, &tlv);
  }

  ret = ctx->used_size;
  *(ruint16 *)&ctx->buf[R_STUN_MSGLEN_OFFSET] = RUINT16_TO_BE (ctx->used_size - R_STUN_HEADER_SIZE);
  r_memclear (ctx, sizeof (RStunMsgCtx));

  return ret;
}

ruint
r_stun_msg_attribute_count (rconstpointer buf)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  ruint ret = 0;

  if (r_stun_attr_tlv_first (buf, &tlv)) {
    do {
      ret++;
    } while (r_stun_attr_tlv_next (buf, &tlv));
  }

  return ret;
}

rboolean
r_stun_attr_tlv_first (rconstpointer buf, RStunAttrTLV * tlv)
{
  if (r_stun_msg_len (buf) < 8) return FALSE;

  tlv->start  = &((const ruint8 *)buf)[R_STUN_HEADER_SIZE];
  tlv->type   = RUINT16_FROM_BE (*(ruint16 *)tlv->start);
  tlv->len    = RUINT16_FROM_BE (*((ruint16 *)(tlv->start + 2)));
  tlv->value  = tlv->start + R_STUN_ATTR_TLV_HEADER_SIZE;
  return TRUE;
}

rboolean
r_stun_attr_tlv_next (rconstpointer buf, RStunAttrTLV * tlv)
{
  const ruint8 * ptr = &((const ruint8 *)buf)[R_STUN_HEADER_SIZE];
  const ruint8 * start;
  rboolean ret;

  start = tlv->value + tlv->len;
  if (tlv->len & 0x3) start += (R_STUN_ATTR_TLV_HEADER_SIZE - (tlv->len & 0x3));

  if ((ret = ((rsize)r_stun_msg_len (buf) > RPOINTER_TO_SIZE (start) - RPOINTER_TO_SIZE (ptr)))) {
    tlv->start  = start;
    tlv->type   = RUINT16_FROM_BE (*(ruint16 *)tlv->start);
    tlv->len    = RUINT16_FROM_BE (*((ruint16 *)(tlv->start + 2)));
    tlv->value  = tlv->start + R_STUN_ATTR_TLV_HEADER_SIZE;
  }

  return ret;
}

RSocketAddress *
r_stun_attr_tlv_parse_xor_address (rconstpointer buf, const RStunAttrTLV * tlv)
{
  RSocketAddress * ret;

  if (R_UNLIKELY (tlv->len <= 4)) return NULL;

  switch (tlv->value[1]) {
    case 1: /* IPv4 */
      {
        ruint32 magic = r_stun_msg_magic_cookie (buf);
        ruint16 port = RUINT16_FROM_BE (*(ruint16 *)(&tlv->value[2]) ^ (ruint16)(magic & 0xffff));
        ruint32 ip   = RUINT32_FROM_BE (*(ruint32 *)(&tlv->value[4]) ^ magic);
        ret = r_socket_address_ipv4_new_uint32 (ip, port);
      }
      break;
      /* FIXME */
    /*case 2: [> IPv6 <]*/
      /*{*/
        /*ruint32 magic = r_stun_msg_magic_cookie (buf);*/
        /*ruint16 port = RUINT16_FROM_BE (*(ruint16 *)(&tlv->value[2]) ^ (ruint16)(magic & 0xffff));*/
        /*ruint8 * ip   = &tlv->value[4];*/
        /*ret = r_socket_address_ipv6_new (ip, port);*/
      /*}*/
      /*break;*/
    default:
      ret = NULL;
  }

  return ret;
}

RSocketAddress *
r_stun_attr_tlv_parse_address (rconstpointer buf, const RStunAttrTLV * tlv)
{
  RSocketAddress * ret;

  (void) buf;

  if (R_UNLIKELY (tlv->len <= 4)) return NULL;

  switch (tlv->value[1]) {
    case 1: /* IPv4 */
      {
        ruint16 port = RUINT16_FROM_BE (*(ruint16 *)(&tlv->value[2]));
        ruint32 ip   = RUINT32_FROM_BE (*(ruint32 *)(&tlv->value[4]));
        ret = r_socket_address_ipv4_new_uint32 (ip, port);
      }
      break;
      /* FIXME */
    /*case 2: [> IPv6 <]*/
      /*{*/
        /*ruint16 port = RUINT16_FROM_BE (*(ruint16 *)(&tlv->value[2]));*/
        /*ret = r_socket_address_ipv6_new (&tlv->value[4], port);*/
      /*}*/
      /*break;*/
    default:
      ret = NULL;
  }

  return ret;
}

ruint8
r_stun_attr_tlv_parse_reqested_transport_protocol (rconstpointer buf, const RStunAttrTLV * tlv)
{
  (void) buf;

  return *tlv->value;
}

ruint
r_stun_attr_tlv_parse_error_code (rconstpointer buf, const RStunAttrTLV * tlv)
{
  (void) buf;

  return (tlv->value[2] & 0x7) * 100 + MIN (tlv->value[3], 99);
}

rboolean
r_stun_msg_check_integrity_short_cred (rconstpointer buf,
    const RStunAttrTLV * tlv, rconstpointer key, rsize keysize)
{
  RHmac * hmac;
  rboolean ret;
  rsize len;

  if (R_UNLIKELY (tlv->type != R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY)) return FALSE;
  if (R_UNLIKELY (tlv->len != R_STUN_MSG_INTEGRITY_SIZE)) return FALSE;

  len = (ruint16)(tlv->start - (const ruint8 *)buf);
  if (R_UNLIKELY (len <= R_STUN_HEADER_SIZE)) return FALSE;

  if ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, key, keysize)) != NULL) {
    ruint8 data[R_STUN_MSG_INTEGRITY_SIZE];
    rsize datasize;
    ruint16 be = RUINT16_TO_BE ((ruint16)len +
        R_STUN_ATTR_TLV_HEADER_SIZE + tlv->len - R_STUN_HEADER_SIZE);

    if ((ret = r_hmac_update (hmac, buf, R_STUN_MSGLEN_OFFSET) &&
          r_hmac_update (hmac, &be, sizeof (ruint16)) &&
          r_hmac_update (hmac, ((const ruint8 *)buf) + R_STUN_MAGIC_COOKIE_OFFSET,
            len - (R_STUN_MSGLEN_OFFSET + sizeof (ruint16))) &&
          r_hmac_get_data (hmac, data, sizeof (data), &datasize)))
      ret = r_memcmp (data, tlv->value, tlv->len) == 0;
    r_hmac_free (hmac);
  } else {
    ret = FALSE;
  }

  return ret;
}

ruint32
r_stun_msg_calc_fingerprint (rconstpointer buf, const RStunAttrTLV * tlv)
{
  ruint32 crc;

  if (R_UNLIKELY (tlv->type != R_STUN_ATTR_TYPE_FINGERPRINT)) return FALSE;
  if (R_UNLIKELY (tlv->len != sizeof (ruint32))) return FALSE;

  crc = r_crc32 (buf, RPOINTER_TO_SIZE (tlv->start) - RPOINTER_TO_SIZE (buf));
  return crc ^ R_STUN_FINGERPRINT_XOR;
}

