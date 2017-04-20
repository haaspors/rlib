/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MSG_DIGEST_H__
#define __R_MSG_DIGEST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

typedef enum {
  R_MSG_DIGEST_TYPE_NONE = -1,
  R_MSG_DIGEST_TYPE_MD2,
  R_MSG_DIGEST_TYPE_MD4,
  R_MSG_DIGEST_TYPE_MD5,
  R_MSG_DIGEST_TYPE_SHA1,
  R_MSG_DIGEST_TYPE_SHA224,
  R_MSG_DIGEST_TYPE_SHA256,
  R_MSG_DIGEST_TYPE_SHA384,
  R_MSG_DIGEST_TYPE_SHA512,
  R_MSG_DIGEST_TYPE_COUNT,
} RMsgDigestType;

R_API rsize r_msg_digest_type_size (RMsgDigestType type);
R_API rsize r_msg_digest_type_blocksize (RMsgDigestType type);
R_API const rchar * r_msg_digest_type_string (RMsgDigestType type);
R_API RMsgDigestType r_msg_digest_type_from_str (const rchar * str, rssize size);

typedef struct _RMsgDigest RMsgDigest;

R_API RMsgDigest * r_msg_digest_new (RMsgDigestType type);
R_API void r_msg_digest_free (RMsgDigest * md);

R_API RMsgDigest * r_msg_digest_new_md2 (void);
R_API RMsgDigest * r_msg_digest_new_md4 (void);
R_API RMsgDigest * r_msg_digest_new_md5 (void);
R_API RMsgDigest * r_msg_digest_new_sha1 (void);
R_API RMsgDigest * r_msg_digest_new_sha224 (void);
R_API RMsgDigest * r_msg_digest_new_sha256 (void);
R_API RMsgDigest * r_msg_digest_new_sha384 (void);
R_API RMsgDigest * r_msg_digest_new_sha512 (void);
#define r_md2_new r_msg_digest_new_md2
#define r_md4_new r_msg_digest_new_md4
#define r_md5_new r_msg_digest_new_md5
#define r_sha1_new r_msg_digest_new_sha1
#define r_sha224_new r_msg_digest_new_sha224
#define r_sha256_new r_msg_digest_new_sha256
#define r_sha384_new r_msg_digest_new_sha384
#define r_sha512_new r_msg_digest_new_sha512

R_API rsize r_msg_digest_size (const RMsgDigest * md);
R_API rsize r_msg_digest_blocksize (const RMsgDigest * md);

R_API void r_msg_digest_reset (RMsgDigest * md);
R_API rboolean r_msg_digest_update (RMsgDigest * md, rconstpointer data, rsize size);
R_API rboolean r_msg_digest_finish (RMsgDigest * md);

R_API rboolean r_msg_digest_get_data (const RMsgDigest * md, ruint8 * data, rsize size, rsize * out);
R_API rchar * r_msg_digest_get_hex (const RMsgDigest * md);
R_API rchar * r_msg_digest_get_hex_full (const RMsgDigest * md,
    const rchar * divider, rsize interval);

R_END_DECLS

#endif /* __R_MSG_DIGEST_H__ */

