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
#ifndef __R_NET_PROTO_STUN_H__
#define __R_NET_PROTO_STUN_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rsocketaddress.h>

R_BEGIN_DECLS

#define R_STUN_HEADER_SIZE              20
#define R_STUN_MSGLEN_OFFSET            2
#define R_STUN_MAGIC_COOKIE_OFFSET      4
#define R_STUN_TRANSACTION_ID_OFFSET    8
#define R_STUN_MSGLEN_SIZE              (R_STUN_MAGIC_COOKIE_OFFSET - R_STUN_MSGLEN_OFFSET)
#define R_STUN_MAGIC_COOKIE_SIZE        (R_STUN_TRANSACTION_ID_OFFSET - R_STUN_MAGIC_COOKIE_OFFSET)
#define R_STUN_TRANSACTION_ID_SIZE      (R_STUN_HEADER_SIZE - R_STUN_TRANSACTION_ID_OFFSET)
#define R_STUN_MAGIC_COOKIE_BE          0x2112a442
#define R_STUN_TYPE_CLASS_MASK_BE       0x0110
#define R_STUN_TYPE_METHOD_MASK_BE      0x3eef

R_API rboolean r_stun_is_valid_msg (rconstpointer buf, rsize size);


static inline ruint16 r_stun_msg_type (rconstpointer buf) { return RUINT16_FROM_BE (*(const ruint16 *)buf); }
static inline ruint16 r_stun_msg_len  (rconstpointer buf) { return RUINT16_FROM_BE (*(const ruint16 *)&((const ruint8 *)(buf))[R_STUN_MSGLEN_OFFSET]); }
#define r_stun_msg_magic_cookie(buf)      (*(const ruint32 *)&((const ruint8 *)(buf))[R_STUN_MAGIC_COOKIE_OFFSET])
#define r_stun_msg_transaction_id(buf)    (&((const ruint8 *)(buf))[R_STUN_TRANSACTION_ID_OFFSET])
#define r_stun_msg_is_request(buf)        ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK_BE)  == 0x0000)
#define r_stun_msg_is_indication(buf)     ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK_BE)  == 0x0010)
#define r_stun_msg_is_success_resp(buf)   ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK_BE)  == 0x0100)
#define r_stun_msg_is_err_resp(buf)       ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK_BE)  == 0x0110)
#define r_stun_msg_method_is_binding(buf) ((r_stun_msg_type (buf) & R_STUN_TYPE_METHOD_MASK_BE) == 0x0001)
#define r_stun_msg_method_is_allocate(buf)((r_stun_msg_type (buf) & R_STUN_TYPE_METHOD_MASK_BE) == 0x0003)
R_API ruint r_stun_msg_attribute_count (rconstpointer buf);

typedef enum {
  R_STUN_ATTR_TYPE_RESERVED_0             = 0x0000, /* Reserved */
  R_STUN_ATTR_TYPE_MAPPED_ADDRESS         = 0x0001,
  R_STUN_ATTR_TYPE_ESPONSE_ADDRESS        = 0x0002, /* Reserved */
  R_STUN_ATTR_TYPE_HANGE_ADDRESS          = 0x0003, /* Reserved */
  R_STUN_ATTR_TYPE_OURCE_ADDRESS          = 0x0004, /* Reserved */
  R_STUN_ATTR_TYPE_HANGED_ADDRESS         = 0x0005, /* Reserved */
  R_STUN_ATTR_TYPE_USERNAME               = 0x0006,
  R_STUN_ATTR_TYPE_PASSWORD               = 0x0007, /* Reserved */
  R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY      = 0x0008,
  R_STUN_ATTR_TYPE_ERROR_CODE             = 0x0009,
  R_STUN_ATTR_TYPE_UNKNOWN_ATTRIBUTES     = 0x000a,
  R_STUN_ATTR_TYPE_EFLECTED_FROM          = 0x000b, /* Reserved */
  R_STUN_ATTR_TYPE_CHANNEL_NUMBER         = 0x000c,
  R_STUN_ATTR_TYPE_LIFETIME               = 0x000d,
  R_STUN_ATTR_TYPE_BANDWIDTH              = 0x0010, /* Reserved */
  R_STUN_ATTR_TYPE_XOR_PEER_ADDRESS       = 0x0012,
  R_STUN_ATTR_TYPE_DATA                   = 0x0013,
  R_STUN_ATTR_TYPE_REALM                  = 0x0014,
  R_STUN_ATTR_TYPE_NONCE                  = 0x0015,
  R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS    = 0x0016,
  R_STUN_ATTR_TYPE_EVEN_PORT              = 0x0018,
  R_STUN_ATTR_TYPE_REQUESTED_TRANSPORT    = 0x0019,
  R_STUN_ATTR_TYPE_DONT_FRAGMENT          = 0x001a,
  R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS     = 0x0020,
  R_STUN_ATTR_TYPE_TIMER_VAL              = 0x0021, /* Reserved */
  R_STUN_ATTR_TYPE_RESERVATION_TOKEN      = 0x0022,

  R_STUN_ATTR_TYPE_SOFTWARE               = 0x8022,
  R_STUN_ATTR_TYPE_ALTERNATE_SERVER       = 0x8023,
  R_STUN_ATTR_TYPE_PRIORITY               = 0x0024,
  R_STUN_ATTR_TYPE_USE_CANDIDATE          = 0x0025,
  R_STUN_ATTR_TYPE_FINGERPRINT            = 0x8028,
  R_STUN_ATTR_TYPE_ICE_CONTROLLED         = 0x8029,
  R_STUN_ATTR_TYPE_ICE_CONTROLLING        = 0x802A,
} RStunAttrType;

#define r_stun_attr_type_is_optional(type)  ((type) & 0x8000)

typedef struct _RStunAttrTLV {
  const ruint8 *  start;  /* (first octet of tlv) */
  ruint16         type;   /* Type (parsed) */
  ruint16         len;    /* Length (parsed) */
  const ruint8 *  value;  /* Value  (pointer to first value octet) */
} RStunAttrTLV;
#define R_STUN_ATTR_TLV_INIT              { NULL, 0, 0, NULL }
#define R_STUN_ATTR_TLV_HEADER_SIZE       4

R_API rboolean r_stun_attr_tlv_first (rconstpointer buf, RStunAttrTLV * tlv);
R_API rboolean r_stun_attr_tlv_next (rconstpointer buf, RStunAttrTLV * tlv);

R_API RSocketAddress * r_stun_attr_tlv_parse_address (rconstpointer buf, const RStunAttrTLV * tlv);
R_API RSocketAddress * r_stun_attr_tlv_parse_xor_address (rconstpointer buf, const RStunAttrTLV * tlv);
R_API ruint8 r_stun_attr_tlv_parse_reqested_transport_protocol (rconstpointer buf, const RStunAttrTLV * tlv);
R_API ruint r_stun_attr_tlv_parse_error_code (rconstpointer buf, const RStunAttrTLV * tlv);
#define r_stun_att_tlv_parse_lifetime(buf, tlv) RUINT32_FROM_BE (*(ruint32 *)((tlv)->value))
#define r_stun_att_tlv_parse_priority(buf, tlv) RUINT32_FROM_BE (*(ruint32 *)((tlv)->value))

R_END_DECLS

#endif /* __R_NET_PROTO_STUN_H__ */

