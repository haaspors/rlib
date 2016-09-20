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
#include <rlib/net/proto/rstun.h>

#include <rlib/rmem.h>

rboolean
r_stun_is_valid_msg (rconstpointer buf, rsize size)
{
  const ruint8 * ptr;

  if (R_UNLIKELY (buf == NULL)) return FALSE;
  if (R_UNLIKELY (size < R_STUN_HEADER_SIZE)) return FALSE;

  ptr = buf;
  if (R_UNLIKELY ((*ptr & 0xc0) != 0)) return FALSE;
  if (R_UNLIKELY (size < r_stun_msg_len (buf) + R_STUN_HEADER_SIZE)) return FALSE;

  return r_stun_msg_magic_cookie (buf) == RUINT32_FROM_BE (R_STUN_MAGIC_COOKIE_BE);
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

  if ((ret = (r_stun_msg_len (buf) > start - ptr))) {
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

