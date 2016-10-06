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
#ifndef __R_CRYPTO_X509_H__
#define __R_CRYPTO_X509_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/asn1/rasn1.h>
#include <rlib/crypto/rcert.h>

R_BEGIN_DECLS

typedef enum {
  R_X509_VERSION_UNKNOWN  = -1,
  R_X509_VERSION_V1       = 0,
  R_X509_VERSION_V2       = 1,
  R_X509_VERSION_V3       = 2,
} RX509Version;
#define R_X509_VERSION_SUPPORTED R_X509_VERSION_V3

typedef enum {
  R_X509_KEY_USAGE_NONE                         = 0,
  R_X509_KEY_USAGE_DIGITAL_SIGNATURE            = (1 << 0), /* bit 0 */
  R_X509_KEY_USAGE_NON_REPUDIATION              = (1 << 1), /* bit 1 */
  R_X509_KEY_USAGE_KEY_ENCIPHERMENT             = (1 << 2), /* bit 2 */
  R_X509_KEY_USAGE_DATA_ENCIPHERMENT            = (1 << 3), /* bit 3 */
  R_X509_KEY_USAGE_KEY_AGREEMENT                = (1 << 4), /* bit 4 */
  R_X509_KEY_USAGE_KEY_CERT_SIGN                = (1 << 5), /* bit 5 */
  R_X509_KEY_USAGE_CRL_SIGN                     = (1 << 6), /* bit 6 */
  R_X509_KEY_USAGE_ENCIPHER_ONLY                = (1 << 7), /* bit 7 */
  R_X509_KEY_USAGE_DECIPHER_ONLY                = (1 << 8), /* bit 8 */
} RX509KeyUsage;

typedef enum {
  R_X509_EXT_KEY_USAGE_NONE                     = 0,
  R_X509_EXT_KEY_USAGE_ANY                      = (1 << 0),
  R_X509_EXT_KEY_USAGE_SERVER_AUTH              = (1 << 1),
  R_X509_EXT_KEY_USAGE_CLIENT_AUTH              = (1 << 2),
  R_X509_EXT_KEY_USAGE_CODE_SIGNING             = (1 << 3),
  R_X509_EXT_KEY_USAGE_EMAIL_PROTECTION         = (1 << 4),
  R_X509_EXT_KEY_USAGE_TIME_STAMPING            = (1 << 5),
  R_X509_EXT_KEY_USAGE_OCSP_SIGNING             = (1 << 6),
} RX509ExtKeyUsage;

R_API RCryptoCert * r_crypto_x509_cert_new (rconstpointer data, rsize size) R_ATTR_MALLOC;
R_API RCryptoCert * r_crypto_x509_cert_new_from_asn1 (RAsn1BinDecoder * dec) R_ATTR_MALLOC;

R_API RX509Version r_crypt_x509_cert_version (const RCryptoCert * cert);
R_API ruint64 r_crypt_x509_cert_serial_number (const RCryptoCert * cert);
R_API const rchar * r_crypt_x509_cert_issuer (const RCryptoCert * cert);
R_API const rchar * r_crypt_x509_cert_subject (const RCryptoCert * cert);
R_API const ruint8 * r_crypt_x509_cert_issuer_unique_id (const RCryptoCert * cert, rsize * size);
R_API const ruint8 * r_crypt_x509_cert_subject_unique_id (const RCryptoCert * cert, rsize * size);
R_API const ruint8 * r_crypt_x509_cert_subject_key_id (const RCryptoCert * cert, rsize * size);
R_API const ruint8 * r_crypt_x509_cert_authority_key_id (const RCryptoCert * cert, rsize * size);
R_API RX509KeyUsage r_crypt_x509_cert_key_usage (const RCryptoCert * cert);
R_API RX509ExtKeyUsage r_crypt_x509_cert_ext_key_usage (const RCryptoCert * cert);
R_API rboolean r_crypt_x509_cert_has_policy (const RCryptoCert * cert, const rchar * policy);

R_API rboolean r_crypt_x509_cert_is_ca (const RCryptoCert * cert);
R_API rboolean r_crypt_x509_cert_is_self_issued (const RCryptoCert * cert);
R_API rboolean r_crypt_x509_cert_is_self_signed (const RCryptoCert * cert);

R_END_DECLS

#endif /* __R_CRYPTO_X509_H__ */

