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
  R_HASH_TYPE_NONE,
  R_HASH_TYPE_MD2,
  R_HASH_TYPE_MD4,
  R_HASH_TYPE_MD5,
  R_HASH_TYPE_SHA1,
  R_HASH_TYPE_SHA224,
  R_HASH_TYPE_SHA256,
  R_HASH_TYPE_SHA384,
  R_HASH_TYPE_SHA512,
} RHashType;

R_API rsize r_hash_type_size (RHashType type);

typedef struct _RHash RHash;

#define r_hash_new_md2()      r_hash_new (R_HASH_TYPE_MD2)
#define r_hash_new_md4()      r_hash_new (R_HASH_TYPE_MD4)
#define r_hash_new_md5()      r_hash_new (R_HASH_TYPE_MD5)
#define r_hash_new_sha1()     r_hash_new (R_HASH_TYPE_SHA1)
#define r_hash_new_sha224()   r_hash_new (R_HASH_TYPE_SHA224)
#define r_hash_new_sha256()   r_hash_new (R_HASH_TYPE_SHA256)
#define r_hash_new_sha384()   r_hash_new (R_HASH_TYPE_SHA384)
#define r_hash_new_sha512()   r_hash_new (R_HASH_TYPE_SHA512)

R_API RHash * r_hash_new (RHashType type);
R_API void r_hash_free (RHash * hash);

R_API rsize r_hash_size (const RHash * hash);
R_API rsize r_hash_blocksize (const RHash * hash);

R_API void r_hash_reset (RHash * hash);
R_API rboolean r_hash_update (RHash * hash, rconstpointer data, rsize size);
R_API rboolean r_hash_finish (RHash * hash);

R_API rboolean r_hash_get_data (const RHash * hash, ruint8 * data, rsize * size);
R_API rchar * r_hash_get_hex (const RHash * hash);
R_API rchar * r_hash_get_hex_full (const RHash * hash,
    const rchar * divider, rsize interval);

R_END_DECLS

#endif /* __R_MSG_DIGEST_H__ */

