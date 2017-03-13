/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_CRYPTO_PEM_H__
#define __R_CRYPTO_PEM_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rmemfile.h>
#include <rlib/rref.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rkey.h>

R_BEGIN_DECLS

typedef struct _RPemParser RPemParser;
typedef struct _RPemBlock RPemBlock;

/* Convenience API */
R_API RCryptoKey * r_pem_parse_key_from_data (const rchar * data, rssize size,
    const rchar * passphrase, rsize ppsize);
R_API RCryptoCert * r_pem_parse_cert_from_data (const rchar * data, rssize size);

typedef enum {
  R_PEM_TYPE_UNKNOWN                  = -1,
  R_PEM_TYPE_CERTIFICATE              =  0, /* X.509 */
  R_PEM_TYPE_CERTIFICATE_LIST             , /* X.509 CRL */
  R_PEM_TYPE_CERTIFICATE_REQUEST          , /* PKCS#10 */
  R_PEM_TYPE_PUBLIC_KEY                   , /* PubKey inside a X.509 */
  R_PEM_TYPE_RSA_PRIVATE_KEY              , /* PKCS#1 */
  R_PEM_TYPE_DSA_PRIVATE_KEY              ,
  R_PEM_TYPE_PRIVATE_KEY                  , /* PKCS#8 */
  R_PEM_TYPE_ENCRYPTED_PRIVATE_KEY        , /* PKCS#8 */
  R_PEM_TYPE_COUNT,
  R_PEM_TYPE_KEY_START = R_PEM_TYPE_PUBLIC_KEY,
  R_PEM_TYPE_KEY_END   = R_PEM_TYPE_ENCRYPTED_PRIVATE_KEY
} RPemType;

R_API RPemParser * r_pem_parser_new_from_file (const rchar * filename) R_ATTR_MALLOC;
R_API RPemParser * r_pem_parser_new_from_memfile (RMemFile * file) R_ATTR_MALLOC;
R_API RPemParser * r_pem_parser_new (const rchar * data, rssize size) R_ATTR_MALLOC;
#define r_pem_parser_ref r_ref_ref
#define r_pem_parser_unref r_ref_unref

R_API void r_pem_parser_reset (RPemParser * parser);


R_API RPemBlock * r_pem_parser_next_block (RPemParser * parser) R_ATTR_MALLOC;
#define r_pem_block_ref r_ref_ref
#define r_pem_block_unref r_ref_unref

R_API RPemType r_pem_block_get_type (RPemBlock * block);
R_API rboolean r_pem_block_is_encrypted (RPemBlock * block);
R_API rboolean r_pem_block_is_key (RPemBlock * block);

R_API rsize r_pem_block_get_blob_size (RPemBlock * block);
R_API rsize r_pem_block_get_base64_size (RPemBlock * block);
R_API rchar * r_pem_block_get_base64 (RPemBlock * block, rsize * size) R_ATTR_MALLOC;
R_API ruint8 * r_pem_block_decode_base64 (RPemBlock * block, rsize * size) R_ATTR_MALLOC;
R_API RAsn1BinDecoder * r_pem_block_get_asn1_decoder (RPemBlock * block);

R_API RCryptoKey * r_pem_block_get_key (RPemBlock * block,
    const rchar * passphrase, rsize ppsize);
R_API RCryptoCert * r_pem_block_get_cert (RPemBlock * block);


R_API rchar * r_pem_write_public_key_dup (const RCryptoKey * key,
    rsize linesize, rsize * out);
R_API rboolean r_pem_write_public_key (const RCryptoKey * key,
    rpointer data, rsize size, rsize linesize, rsize * out);
R_API rchar * r_pem_write_cert_dup (const RCryptoCert * cert,
    rsize linesize, rsize * out);
R_API rboolean r_pem_write_cert (const RCryptoCert * cert,
    rpointer data, rsize size, rsize linesize, rsize * out);

R_END_DECLS

#endif /* __R_CRYPTO_PEM_H__ */

