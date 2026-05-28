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

/**
 * @defgroup r_crypto_pem PEM (RFC 7468)
 * @ingroup r_crypto_encoding
 *
 * @brief Textual container framing for keys, certificates and the
 * other ASN.1-shaped objects that ride a base64 + BEGIN/END envelope.
 *
 * PEM (Privacy-Enhanced Mail) is the ubiquitous "@c -----BEGIN X-----"
 * encoding for binary cryptographic objects on disk and in transport:
 * X.509 certificates, RSA / DSA private keys, certificate signing
 * requests, CRLs, etc. The format is base64-wrapped DER with a label
 * line and a CRC-ish ending that names the object class.
 *
 * Two layers are exposed:
 *
 *   - A convenience API (@ref r_pem_parse_key_from_data,
 *     @ref r_pem_parse_cert_from_data) that returns a parsed
 *     @ref RCryptoKey / @c RCryptoCert directly when the input
 *     contains a single object.
 *   - A streaming parser (@ref r_pem_parser_new and the
 *     @ref r_pem_parser_next_block iteration) that walks a file or
 *     buffer containing any number of PEM blocks, hands back each
 *     as an @ref RPemBlock, and lets the caller introspect its type
 *     or pull out the embedded key / certificate.
 *
 * Writing is the symmetric `r_pem_write_*` family which serialises
 * a key or cert back into PEM text.
 *
 * @{
 */

/**
 * @file rlib/crypto/rpem.h
 * @brief PEM (RFC 7468) container parsing and emission for keys and
 * certificates.
 */

#include <rlib/rtypes.h>

#include <rlib/rmemfile.h>
#include <rlib/rref.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rkey.h>

R_BEGIN_DECLS

/** @brief Opaque streaming PEM parser. Refcounted. */
typedef struct RPemParser RPemParser;
/** @brief Opaque PEM block (one BEGIN/END pair). Refcounted. */
typedef struct RPemBlock RPemBlock;

/**
 * @brief Parse a private key out of a single-block PEM buffer.
 *
 * @param data        PEM-formatted bytes.
 * @param size        Length of @p data, or @c -1 if NUL-terminated.
 * @param passphrase  Optional passphrase for encrypted private keys
 *                    (PKCS#8 EncryptedPrivateKeyInfo). Pass @c NULL
 *                    for unencrypted blocks.
 * @param ppsize      Length of @p passphrase.
 * @return Parsed @ref RCryptoKey, or @c NULL if the buffer does not
 *         contain a key block or the passphrase is wrong.
 */
R_API RCryptoKey * r_pem_parse_key_from_data (const rchar * data, rssize size,
    const rchar * passphrase, rsize ppsize);

/**
 * @brief Parse a certificate out of a single-block PEM buffer.
 *
 * @param data  PEM-formatted bytes.
 * @param size  Length of @p data, or @c -1 if NUL-terminated.
 * @return Parsed @c RCryptoCert, or @c NULL.
 */
R_API RCryptoCert * r_pem_parse_cert_from_data (const rchar * data, rssize size);

/**
 * @brief Object kind carried by a PEM block.
 *
 * Driven by the BEGIN-label string. Use @ref r_pem_block_is_key /
 * @ref r_pem_block_is_encrypted as shorthand for category checks.
 */
typedef enum {
  R_PEM_TYPE_UNKNOWN                  = -1,
  R_PEM_TYPE_CERTIFICATE              =  0, /**< X.509 certificate. */
  R_PEM_TYPE_CERTIFICATE_LIST             , /**< X.509 certificate revocation list. */
  R_PEM_TYPE_CERTIFICATE_REQUEST          , /**< PKCS#10 CSR. */
  R_PEM_TYPE_PUBLIC_KEY                   , /**< SubjectPublicKeyInfo (typically from an X.509). */
  R_PEM_TYPE_RSA_PRIVATE_KEY              , /**< PKCS#1 RSAPrivateKey. */
  R_PEM_TYPE_DSA_PRIVATE_KEY              , /**< Legacy SEC1-style DSA private key. */
  R_PEM_TYPE_PRIVATE_KEY                  , /**< PKCS#8 PrivateKeyInfo. */
  R_PEM_TYPE_ENCRYPTED_PRIVATE_KEY        , /**< PKCS#8 EncryptedPrivateKeyInfo. */
  R_PEM_TYPE_COUNT,
  R_PEM_TYPE_KEY_START = R_PEM_TYPE_PUBLIC_KEY,
  R_PEM_TYPE_KEY_END   = R_PEM_TYPE_ENCRYPTED_PRIVATE_KEY
} RPemType;

/** @brief Open a PEM parser reading from a file path. */
R_API RPemParser * r_pem_parser_new_from_file (const rchar * filename) R_ATTR_MALLOC;
/** @brief Open a PEM parser reading from a memory-mapped file. */
R_API RPemParser * r_pem_parser_new_from_memfile (RMemFile * file) R_ATTR_MALLOC;
/**
 * @brief Open a PEM parser reading from an in-memory buffer.
 *
 * @param data  Buffer holding PEM-encoded blocks.
 * @param size  Length of @p data, or @c -1 if NUL-terminated.
 */
R_API RPemParser * r_pem_parser_new (const rchar * data, rssize size) R_ATTR_MALLOC;
/** @brief Increment the parser's refcount. */
#define r_pem_parser_ref r_ref_ref
/** @brief Decrement the parser's refcount; frees when it reaches zero. */
#define r_pem_parser_unref r_ref_unref

/**
 * @brief Rewind the parser so the next @ref r_pem_parser_next_block
 * call starts from the first block of the input.
 */
R_API void r_pem_parser_reset (RPemParser * parser);


/**
 * @brief Return the next PEM block in the input, or @c NULL at EOF.
 *
 * The block is refcounted; the caller owns one reference and must
 * @ref r_pem_block_unref it.
 */
R_API RPemBlock * r_pem_parser_next_block (RPemParser * parser) R_ATTR_MALLOC;
/** @brief Increment the block's refcount. */
#define r_pem_block_ref r_ref_ref
/** @brief Decrement the block's refcount; frees when it reaches zero. */
#define r_pem_block_unref r_ref_unref

/** @brief Return the @ref RPemType encoded in the block's BEGIN label. */
R_API RPemType r_pem_block_get_type (RPemBlock * block);
/**
 * @brief True if the block holds an encrypted private key (PKCS#8
 * EncryptedPrivateKeyInfo); @ref r_pem_block_get_key needs a
 * passphrase to materialise it.
 */
R_API rboolean r_pem_block_is_encrypted (RPemBlock * block);
/**
 * @brief True if the block holds any key kind (public or private,
 * encrypted or not).
 */
R_API rboolean r_pem_block_is_key (RPemBlock * block);

/** @brief Byte length of the decoded (binary) blob. */
R_API rsize r_pem_block_get_blob_size (RPemBlock * block);
/** @brief Byte length of the base64 payload between BEGIN and END. */
R_API rsize r_pem_block_get_base64_size (RPemBlock * block);
/**
 * @brief Return the base64 payload as a freshly-allocated string.
 * @param block  The PEM block.
 * @param size   Out: length of the returned string (excluding NUL).
 */
R_API rchar * r_pem_block_get_base64 (RPemBlock * block, rsize * size) R_ATTR_MALLOC;
/**
 * @brief Decode the block's base64 payload and return the binary blob.
 * @param block  The PEM block.
 * @param size   Out: length of the returned blob in bytes.
 */
R_API ruint8 * r_pem_block_decode_base64 (RPemBlock * block, rsize * size) R_ATTR_MALLOC;
/**
 * @brief Return an ASN.1 BER/DER decoder over the block's binary
 * payload, for callers that want to walk the structure directly
 * rather than going through the key / cert builders.
 */
R_API RAsn1BinDecoder * r_pem_block_get_asn1_decoder (RPemBlock * block);

/**
 * @brief Materialise a key block as an @ref RCryptoKey.
 *
 * @param block       The PEM block. Must satisfy @ref r_pem_block_is_key.
 * @param passphrase  Required for encrypted PKCS#8 blocks; ignored
 *                    otherwise. Pass @c NULL when not applicable.
 * @param ppsize      Length of @p passphrase.
 */
R_API RCryptoKey * r_pem_block_get_key (RPemBlock * block,
    const rchar * passphrase, rsize ppsize);
/** @brief Materialise a certificate block as an @c RCryptoCert. */
R_API RCryptoCert * r_pem_block_get_cert (RPemBlock * block);


/**
 * @brief Emit @p key as a public-key PEM block into a freshly
 * allocated string.
 *
 * @param key       Key to emit (only the public side is written).
 * @param linesize  Base64 line wrap width (RFC 7468 prescribes 64).
 * @param out       Out: length of the returned string.
 */
R_API rchar * r_pem_write_public_key_dup (const RCryptoKey * key,
    rsize linesize, rsize * out);
/**
 * @brief Emit @p key as a public-key PEM block into @p data.
 * @param key       Key to emit (only the public side is written).
 * @param data      Destination buffer.
 * @param size      Capacity of @p data.
 * @param linesize  Base64 line wrap width (RFC 7468 prescribes 64).
 * @param out       Out: number of bytes written.
 */
R_API rboolean r_pem_write_public_key (const RCryptoKey * key,
    rpointer data, rsize size, rsize linesize, rsize * out);
/**
 * @brief Emit @p key as a private-key PEM block (PKCS#8 PrivateKeyInfo)
 * into a freshly allocated string.
 */
R_API rchar * r_pem_write_private_key_dup (const RCryptoKey * key,
    rsize linesize, rsize * out);
/** @brief Emit @p key as a private-key PEM block into @p data. */
R_API rboolean r_pem_write_private_key (const RCryptoKey * key,
    rpointer data, rsize size, rsize linesize, rsize * out);
/** @brief Emit @p cert as a CERTIFICATE PEM block into a fresh string. */
R_API rchar * r_pem_write_cert_dup (const RCryptoCert * cert,
    rsize linesize, rsize * out);
/** @brief Emit @p cert as a CERTIFICATE PEM block into @p data. */
R_API rboolean r_pem_write_cert (const RCryptoCert * cert,
    rpointer data, rsize size, rsize linesize, rsize * out);

R_END_DECLS

/** @} */

#endif /* __R_CRYPTO_PEM_H__ */

