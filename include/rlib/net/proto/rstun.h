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
#ifndef __R_NET_PROTO_STUN_H__
#define __R_NET_PROTO_STUN_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/net/proto/rstun.h
 * @brief STUN / TURN (RFC 5389) message validation, building and
 * attribute parsing.
 */

#include <rlib/rtypes.h>

#include <rlib/net/rsocketaddress.h>

/**
 * @defgroup r_stun STUN / TURN
 * @ingroup r_net
 *
 * @brief Validate, build and parse STUN / TURN messages and their
 * attributes (RFC 5389 / 5766), used by ICE in @ref r_rtc.
 *
 * Parsing is zero-copy over a caller-held buffer: validate with
 * @ref r_stun_is_valid_msg, read header fields with the
 * @c r_stun_msg_* accessors, and iterate attributes with
 * @ref r_stun_attr_tlv_first / @ref r_stun_attr_tlv_next into an
 * @ref RStunAttrTLV. Building uses an @ref RStunMsgCtx writing into a
 * caller buffer: @ref r_stun_msg_begin, add attributes, then
 * @ref r_stun_msg_end (optionally appending a FINGERPRINT).
 *
 * @{
 */

R_BEGIN_DECLS

/** @name Message header layout
 *  Byte offsets and sizes within the fixed 20-byte STUN header.
 *  @{ */
#define R_STUN_HEADER_SIZE              20  /**< @brief Fixed STUN header size in bytes. */
#define R_STUN_MSGLEN_OFFSET            2   /**< @brief Offset of the message-length field. */
#define R_STUN_MAGIC_COOKIE_OFFSET      4   /**< @brief Offset of the magic-cookie field. */
#define R_STUN_TRANSACTION_ID_OFFSET    8   /**< @brief Offset of the transaction-ID field. */
#define R_STUN_MSGLEN_SIZE              (R_STUN_MAGIC_COOKIE_OFFSET - R_STUN_MSGLEN_OFFSET) /**< @brief Size of the message-length field. */
#define R_STUN_MAGIC_COOKIE_SIZE        (R_STUN_TRANSACTION_ID_OFFSET - R_STUN_MAGIC_COOKIE_OFFSET) /**< @brief Size of the magic-cookie field. */
#define R_STUN_TRANSACTION_ID_SIZE      (R_STUN_HEADER_SIZE - R_STUN_TRANSACTION_ID_OFFSET) /**< @brief Size of the transaction-ID field. */
#define R_STUN_MSG_INTEGRITY_SIZE       20  /**< @brief Size of a MESSAGE-INTEGRITY value (HMAC-SHA1). */
#define R_STUN_FINGERPRINT_XOR          0x5354554e /**< @brief XOR constant applied to the CRC-32 FINGERPRINT. */
#define R_STUN_MAGIC_COOKIE             0x2112a442 /**< @brief The STUN magic cookie value. */
#define R_STUN_TYPE_CLASS_MASK          0x0110 /**< @brief Mask selecting the class bits of the message type. */
#define R_STUN_TYPE_METHOD_MASK         0x3eef /**< @brief Mask selecting the method bits of the message type. */
/** @} */

/** @brief @c TRUE if @p buf (@p size bytes) looks like a valid STUN message. */
R_API rboolean r_stun_is_valid_msg (rconstpointer buf, rsize size);

/** @brief STUN message class (the two class bits of the type). */
typedef enum {
  R_STUN_CLASS_REQUEST                    = 0x0000, /**< Request. */
  R_STUN_CLASS_INDICATION                 = 0x0010, /**< Indication (no response expected). */
  R_STUN_CLASS_SUCCESS_RESPONSE           = 0x0100, /**< Success response. */
  R_STUN_CLASS_ERROR_RESPONSE             = 0x0110, /**< Error response. */
} RStunClass;

/** @brief STUN / TURN method (the method bits of the type). */
typedef enum {
  R_STUN_METHOD_BINDING                   = 0x0001, /**< STUN Binding. */
  R_STUN_METHOD_ALLOCATE                  = 0x0003, /**< TURN Allocate. */
} RStunMethod;

/** @name Header-field accessors
 *  Read fields straight out of a STUN message buffer.
 *  @{ */
/** @brief Return the 16-bit message type from @p buf. */
static inline ruint16 r_stun_msg_type (rconstpointer buf) { return RUINT16_FROM_BE (*(const ruint16 *)buf); }
/** @brief Return the message-length field from @p buf. */
static inline ruint16 r_stun_msg_len  (rconstpointer buf) { return RUINT16_FROM_BE (*(const ruint16 *)&((const ruint8 *)(buf))[R_STUN_MSGLEN_OFFSET]); }
/** @brief Pointer to the magic-cookie field in @p buf. */
#define r_stun_msg_magic_cookie(buf)      (*(const ruint32 *)&((const ruint8 *)(buf))[R_STUN_MAGIC_COOKIE_OFFSET])
/** @brief Pointer to the transaction-ID field in @p buf. */
#define r_stun_msg_transaction_id(buf)    (&((const ruint8 *)(buf))[R_STUN_TRANSACTION_ID_OFFSET])
/** @brief @c TRUE if @p buf is a request. */
#define r_stun_msg_is_request(buf)        ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK)  == R_STUN_CLASS_REQUEST)
/** @brief @c TRUE if @p buf is an indication. */
#define r_stun_msg_is_indication(buf)     ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK)  == R_STUN_CLASS_INDICATION)
/** @brief @c TRUE if @p buf is a success response. */
#define r_stun_msg_is_success_resp(buf)   ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK)  == R_STUN_CLASS_SUCCESS_RESPONSE)
/** @brief @c TRUE if @p buf is an error response. */
#define r_stun_msg_is_err_resp(buf)       ((r_stun_msg_type (buf) & R_STUN_TYPE_CLASS_MASK)  == R_STUN_CLASS_ERROR_RESPONSE)
/** @brief @c TRUE if @p buf's method is Binding. */
#define r_stun_msg_method_is_binding(buf) ((r_stun_msg_type (buf) & R_STUN_TYPE_METHOD_MASK) == R_STUN_METHOD_BINDING)
/** @brief @c TRUE if @p buf's method is Allocate. */
#define r_stun_msg_method_is_allocate(buf)((r_stun_msg_type (buf) & R_STUN_TYPE_METHOD_MASK) == R_STUN_METHOD_ALLOCATE)
/** @} */

/** @brief STUN / TURN attribute type (RFC-registered values; @c 0x8000+ are comprehension-optional). */
typedef enum {
  R_STUN_ATTR_TYPE_RESERVED_0             = 0x0000, /* Reserved */
  R_STUN_ATTR_TYPE_MAPPED_ADDRESS         = 0x0001,
  R_STUN_ATTR_TYPE_RESPONSE_ADDRESS       = 0x0002, /* Reserved */
  R_STUN_ATTR_TYPE_CHANGE_ADDRESS         = 0x0003, /* Reserved */
  R_STUN_ATTR_TYPE_SOURCE_ADDRESS         = 0x0004, /* Reserved */
  R_STUN_ATTR_TYPE_CHANGED_ADDRESS        = 0x0005, /* Reserved */
  R_STUN_ATTR_TYPE_USERNAME               = 0x0006,
  R_STUN_ATTR_TYPE_PASSWORD               = 0x0007, /* Reserved */
  R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY      = 0x0008,
  R_STUN_ATTR_TYPE_ERROR_CODE             = 0x0009,
  R_STUN_ATTR_TYPE_UNKNOWN_ATTRIBUTES     = 0x000a,
  R_STUN_ATTR_TYPE_REFLECTED_FROM         = 0x000b, /* Reserved */
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

/** @brief @c TRUE if attribute @p type is comprehension-optional (@c 0x8000+). */
#define r_stun_attr_type_is_optional(type)  ((type) & 0x8000)

/** @brief One parsed STUN attribute, pointing into the message buffer. */
typedef struct RStunAttrTLV {
  const ruint8 *  start;  /**< First octet of the attribute (its type field). */
  ruint16         type;   /**< Parsed attribute type (@ref RStunAttrType). */
  ruint16         len;    /**< Parsed value length in bytes. */
  const ruint8 *  value;  /**< Pointer to the first value octet. */
} RStunAttrTLV;
/** @brief Static initialiser for an empty @ref RStunAttrTLV. */
#define R_STUN_ATTR_TLV_INIT              { NULL, 0, 0, NULL }
/** @brief Size of an attribute's type+length header, in bytes. */
#define R_STUN_ATTR_TLV_HEADER_SIZE       4

/** @brief Builder cursor writing a STUN message into a caller buffer. */
typedef struct {
  ruint8 * buf;       /**< Destination buffer. */
  rsize alloc_size;   /**< Capacity of @c buf in bytes. */
  ruint16 used_size;  /**< Bytes written so far. */
} RStunMsgCtx;

/** @name Building messages
 *  @{ */
/**
 * @brief Begin a STUN message in @p buf with the given class / method.
 * @param ctx            Builder cursor to initialise.
 * @param buf            Destination buffer.
 * @param size           Capacity of @p buf in bytes.
 * @param cls            Message class.
 * @param method         Message method.
 * @param transaction_id 12-byte transaction ID.
 */
R_API rboolean r_stun_msg_begin (RStunMsgCtx * ctx, rpointer buf, rsize size,
    RStunClass cls, RStunMethod method,
    const ruint8 transaction_id[R_STUN_TRANSACTION_ID_SIZE]);
/** @brief Append a pre-built attribute @p tlv. */
R_API rboolean r_stun_msg_add_attribute (RStunMsgCtx * ctx, const RStunAttrTLV * tlv);
/** @brief Append an XOR-mapped address attribute of the given @p type. */
R_API rboolean r_stun_msg_add_xor_address (RStunMsgCtx * ctx,
    RStunAttrType type, const RSocketAddress * addr);
/** @brief Append a short-term-credential MESSAGE-INTEGRITY attribute keyed by @p key. */
R_API rboolean r_stun_msg_add_message_integrity_short_cred (RStunMsgCtx * ctx,
    rconstpointer key, rsize keysize);
/**
 * @brief Finalise the message, patching the length field.
 * @param ctx         Builder cursor.
 * @param fingerprint @c TRUE to append a FINGERPRINT attribute.
 * @return Total message length in bytes.
 */
R_API ruint16 r_stun_msg_end (RStunMsgCtx * ctx, rboolean fingerprint);
/** @} */

/** @name Parsing messages
 *  @{ */
/** @brief Number of attributes in the STUN message @p buf. */
R_API ruint r_stun_msg_attribute_count (rconstpointer buf);
/** @brief Position @p tlv on the first attribute of @p buf. */
R_API rboolean r_stun_attr_tlv_first (rconstpointer buf, RStunAttrTLV * tlv);
/** @brief Advance @p tlv to the next attribute; @c FALSE past the last. */
R_API rboolean r_stun_attr_tlv_next (rconstpointer buf, RStunAttrTLV * tlv);

/** @brief Parse a MAPPED-ADDRESS-style attribute into a socket address. */
R_API RSocketAddress * r_stun_attr_tlv_parse_address (rconstpointer buf, const RStunAttrTLV * tlv);
/** @brief Parse an XOR-MAPPED-ADDRESS-style attribute (de-XORing against the header). */
R_API RSocketAddress * r_stun_attr_tlv_parse_xor_address (rconstpointer buf, const RStunAttrTLV * tlv);
/** @brief Parse a REQUESTED-TRANSPORT attribute's protocol byte. */
R_API ruint8 r_stun_attr_tlv_parse_reqested_transport_protocol (rconstpointer buf, const RStunAttrTLV * tlv);
/** @brief Parse an ERROR-CODE attribute's numeric code. */
R_API ruint r_stun_attr_tlv_parse_error_code (rconstpointer buf, const RStunAttrTLV * tlv);
/** @brief Parse a LIFETIME attribute (seconds). */
#define r_stun_att_tlv_parse_lifetime(buf, tlv) RUINT32_FROM_BE (*(ruint32 *)((tlv)->value))
/** @brief Parse a PRIORITY attribute (ICE candidate priority). */
#define r_stun_att_tlv_parse_priority(buf, tlv) RUINT32_FROM_BE (*(ruint32 *)((tlv)->value))

/** @brief Verify a short-term-credential MESSAGE-INTEGRITY against @p key. */
R_API rboolean r_stun_msg_check_integrity_short_cred (rconstpointer buf,
    const RStunAttrTLV * tlv, rconstpointer key, rsize keysize);
/** @brief Compute the FINGERPRINT (CRC-32 XOR @ref R_STUN_FINGERPRINT_XOR) over @p buf. */
R_API ruint32 r_stun_msg_calc_fingerprint (rconstpointer buf,
    const RStunAttrTLV * tlv);
/** @brief @c TRUE if the FINGERPRINT attribute @p tlv matches the computed value. */
#define r_stun_msg_check_fingerprint(buf, tlv)                                \
  (r_stun_msg_calc_fingerprint (buf, tlv) == RUINT32_FROM_BE (*(ruint32 *)((tlv)->value)))
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_STUN_H__ */

