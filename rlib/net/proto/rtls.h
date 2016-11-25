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
#ifndef __R_NET_PROTO_TLS_H__
#define __R_NET_PROTO_TLS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rrand.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rciphersuite.h>

R_BEGIN_DECLS

#define R_TLS_RECORD_HDR_SIZE             5
#define R_TLS_RECORD_EXTRA_DTLS_SIZE      8
#define R_TLS_HS_HDR_SIZE                 4
#define R_TLS_HS_EXTRA_DTLS_SIZE          8
#define R_DTLS_RECORD_HDR_SIZE            (R_TLS_RECORD_HDR_SIZE + R_TLS_RECORD_EXTRA_DTLS_SIZE)
#define R_DTLS_HS_HDR_SIZE                (R_TLS_HS_HDR_SIZE + R_TLS_HS_EXTRA_DTLS_SIZE)

typedef enum {
  R_TLS_VERSION_UNKNOWN                                 = 0x0000,
  R_TLS_VERSION_SSL_1_0                                 = 0x0100,
  R_TLS_VERSION_SSL_2_0                                 = 0x0200,
  R_TLS_VERSION_SSL_3_0                                 = 0x0300,
  R_TLS_VERSION_TLS_1_0                                 = 0x0301,
  R_TLS_VERSION_TLS_1_1                                 = 0x0302,
  R_TLS_VERSION_TLS_1_2                                 = 0x0303,
  R_TLS_VERSION_TLS_1_3                                 = 0x0304,
  R_TLS_VERSION_DTLS_1_0                                = 0xfeff,
  R_TLS_VERSION_DTLS_1_2                                = 0xfefd,
  R_TLS_VERSION_DTLS_1_3                                = 0xfefc,
} RTLSVersion;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-2 */
typedef enum {
  R_TLS_CLIENT_CERT_TYPE_RSA_SIGN                       = 0x01, /* [RFC5246] */
  R_TLS_CLIENT_CERT_TYPE_DSS_SIGN                       = 0x02, /* [RFC5246] */
  R_TLS_CLIENT_CERT_TYPE_RSA_FIXED_DH                   = 0x03, /* [RFC5246] */
  R_TLS_CLIENT_CERT_TYPE_DSS_FIXED_DH                   = 0x04, /* [RFC5246] */
  R_TLS_CLIENT_CERT_TYPE_RSA_EPHEMERAL_DH               = 0x05, /* [RFC5246] */
  R_TLS_CLIENT_CERT_TYPE_DSS_EPHEMERAL_DH               = 0x06, /* [RFC5246] */
  R_TLS_CLIENT_CERT_TYPE_FORTEZZA_DMS                   = 0x14, /* [RFC5246] */

  R_TLS_CLIENT_CERT_TYPE_ECDSA_SIGN                     = 0x40, /* [RFC4492] */
  R_TLS_CLIENT_CERT_TYPE_RSA_FIXED_ECDH                 = 0x41, /* [RFC4492] */
  R_TLS_CLIENT_CERT_TYPE_ECDSA_FIXED_ECDH               = 0x42, /* [RFC4492] */
} RTLSClientCertificateType;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-5 */
typedef enum {
  R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC                 = 0x14, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_ALERT                              = 0x15, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_HANDSHAKE                          = 0x16, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_APPLICATION_DATA                   = 0x17, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_HEARTBEAT                          = 0x18, /* [RFC6520] */

  R_TLS_CONTENT_TYPE_FIRST                              = R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC,
  R_TLS_CONTENT_TYPE_LAST                               = R_TLS_CONTENT_TYPE_HEARTBEAT
} RTLSContentType;

typedef enum {
  R_TLS_ALERT_LEVEL_WARNING                             = 0x01,
  R_TLS_ALERT_LEVEL_FATAL                               = 0x02,
} RTLSAlertLevel;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-6 */
typedef enum {
  R_TLS_ALERT_TYPE_CLOSE_NOTIFY                         = 0x00, /* [RFC5246] */
  R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE                   = 0x0a, /* [RFC5246] */
  R_TLS_ALERT_TYPE_BAD_RECORD_MAC                       = 0x14, /* [RFC5246] */
  R_TLS_ALERT_TYPE_DECRYPTION_FAILED                    = 0x15, /* [RFC5246] */
  R_TLS_ALERT_TYPE_RECORD_OVERFLOW                      = 0x16, /* [RFC5246] */
  R_TLS_ALERT_TYPE_DECOMPRESSION_FAILURE                = 0x1e, /* [RFC5246] */
  R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE                    = 0x28, /* [RFC5246] */
  R_TLS_ALERT_TYPE_NO_CERTIFICATE                       = 0x29, /* [RFC5246] */
  R_TLS_ALERT_TYPE_BAD_CERTIFICATE                      = 0x2a, /* [RFC5246] */
  R_TLS_ALERT_TYPE_UNSUPPORTED_CERTIFICATE              = 0x2b, /* [RFC5246] */
  R_TLS_ALERT_TYPE_CERTIFICATE_REVOKED                  = 0x2c, /* [RFC5246] */
  R_TLS_ALERT_TYPE_CERTIFICATE_EXPIRED                  = 0x2d, /* [RFC5246] */
  R_TLS_ALERT_TYPE_CERTIFICATE_UNKNOWN                  = 0x2e, /* [RFC5246] */
  R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER                    = 0x2f, /* [RFC5246] */
  R_TLS_ALERT_TYPE_UNKNOWN_CA                           = 0x30, /* [RFC5246] */
  R_TLS_ALERT_TYPE_ACCESS_DENIED                        = 0x31, /* [RFC5246] */
  R_TLS_ALERT_TYPE_DECODE_ERROR                         = 0x32, /* [RFC5246] */
  R_TLS_ALERT_TYPE_DECRYPT_ERROR                        = 0x33, /* [RFC5246] */
  R_TLS_ALERT_TYPE_EXPORT_RESTRICTION                   = 0x3c, /* [RFC5246] */
  R_TLS_ALERT_TYPE_PROTOCOL_VERSION                     = 0x46, /* [RFC5246] */
  R_TLS_ALERT_TYPE_INSUFFICIENT_SECURITY                = 0x47, /* [RFC5246] */
  R_TLS_ALERT_TYPE_INTERNAL_ERROR                       = 0x50, /* [RFC5246] */
  R_TLS_ALERT_TYPE_INAPPROPRIATE_FALLBACK               = 0x56, /* [RFC7507] */
  R_TLS_ALERT_TYPE_USER_CANCELED                        = 0x5a, /* [RFC5246] */
  R_TLS_ALERT_TYPE_NO_RENEGOTIATION                     = 0x64, /* [RFC5246] */
  R_TLS_ALERT_TYPE_UNSUPPORTED_EXTENSION                = 0x6e, /* [RFC5246] */
  R_TLS_ALERT_TYPE_CERTIFICATE_UNOBTAINABLE             = 0x6f, /* [RFC6066] */
  R_TLS_ALERT_TYPE_UNRECOGNIZED_NAME                    = 0x70, /* [RFC6066] */
  R_TLS_ALERT_TYPE_BAD_CERTIFICATE_STATUS_RESPONSE      = 0x71, /* [RFC6066] */
  R_TLS_ALERT_TYPE_BAD_CERTIFICATE_HASH_VALUE           = 0x72, /* [RFC6066] */
  R_TLS_ALERT_TYPE_UNKNOWN_PSK_IDENTITY                 = 0x73, /* [RFC4279] */
} RTLSAlertType;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-7 */
typedef enum {
  R_TLS_HANDSHAKE_TYPE_HELLO_REQUEST                    = 0x00, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO                     = 0x01, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_SERVER_HELLO                     = 0x02, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST             = 0x03, /* [RFC6347] */
  R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET               = 0x04, /* [RFC4507] */
  R_TLS_HANDSHAKE_TYPE_CERTIFICATE                      = 0x0b, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE              = 0x0c, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST              = 0x0d, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE                = 0x0e, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY               = 0x0f, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE              = 0x10, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_FINISHED                         = 0x14, /* [RFC5246] */
  R_TLS_HANDSHAKE_TYPE_CERTIFICATE_URL                  = 0x15, /* [RFC6066] */
  R_TLS_HANDSHAKE_TYPE_CERTIFICATE_STATUS               = 0x16, /* [RFC6066] */
  R_TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA                = 0x17, /* [RFC4680] */
} RTLSHandshakeType;

/* http://www.iana.org/assignments/tls-extensiontype-values/ */
typedef enum {
  R_TLS_EXT_TYPE_SERVER_NAME                            = 0x0000, /* [RFC6066] */
  R_TLS_EXT_TYPE_MAX_FRAGMENT_LENGTH                    = 0x0001, /* [RFC6066] */
  R_TLS_EXT_TYPE_CLIENT_CERTIFICATE_URL                 = 0x0002, /* [RFC6066] */
  R_TLS_EXT_TYPE_TRUSTED_CA_KEYS                        = 0x0003, /* [RFC6066] */
  R_TLS_EXT_TYPE_TRUNCATED_HMAC                         = 0x0004, /* [RFC6066] */
  R_TLS_EXT_TYPE_STATUS_REQUEST                         = 0x0005, /* [RFC6066] */
  R_TLS_EXT_TYPE_USER_MAPPING                           = 0x0006, /* [RFC4681] */
  R_TLS_EXT_TYPE_CLIENT_AUTHZ                           = 0x0007, /* [RFC5878] */
  R_TLS_EXT_TYPE_SERVER_AUTHZ                           = 0x0008, /* [RFC5878] */
  R_TLS_EXT_TYPE_CERT_TYPE                              = 0x0009, /* [RFC6091] */
  R_TLS_EXT_TYPE_SUPPORTED_GROUPS                       = 0x000a, /* (renamed from elliptic_curves) [RFC4492][RFC7919] */
  R_TLS_EXT_TYPE_ELLIPTIC_CURVES                        = 0x000a, /* alias [RFC4492][RFC7919] */
  R_TLS_EXT_TYPE_EC_POINT_FORMATS                       = 0x000b, /* [RFC4492] */
  R_TLS_EXT_TYPE_SRP                                    = 0x000c, /* [RFC5054] */
  R_TLS_EXT_TYPE_SIGNATURE_ALGORITHMS                   = 0x000d, /* [RFC5246] */
  R_TLS_EXT_TYPE_USE_SRTP                               = 0x000e, /* [RFC5764] */
  R_TLS_EXT_TYPE_HEARTBEAT                              = 0x000f, /* [RFC6520] */
  R_TLS_EXT_TYPE_APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 0x0010, /* [RFC7301] */
  R_TLS_EXT_TYPE_STATUS_REQUEST_V2                      = 0x0011, /* [RFC6961] */
  R_TLS_EXT_TYPE_SIGNED_CERTIFICATE_TIMESTAMP           = 0x0012, /* [RFC6962] */
  R_TLS_EXT_TYPE_CLIENT_CERTIFICATE_TYPE                = 0x0013, /* [RFC7250] */
  R_TLS_EXT_TYPE_SERVER_CERTIFICATE_TYPE                = 0x0014, /* [RFC7250] */
  R_TLS_EXT_TYPE_PADDING                                = 0x0015, /* [RFC7685] */
  R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC                       = 0x0016, /* [RFC7366] */
  R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET                 = 0x0017, /* [RFC7627] */
  R_TLS_EXT_TYPE_TOKEN_BINDING                          = 0x0018, /* (TEMPORARY - registered 2016-02-04, expires 2017-02-04) [draft-ietf-tokbind-negotiation] */
  R_TLS_EXT_TYPE_CACHED_INFO                            = 0x0019, /* [RFC7924] */
  R_TLS_EXT_TYPE_SESSION_TICKET                         = 0x0023, /* [RFC4507] */
  R_TLS_EXT_TYPE_RENEGOTIATION_INFO                     = 0xff01, /* [RFC5746] */
} RTLSExtensionType;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-8 */
typedef enum {
  R_TLS_SUPPORTED_GROUP_SECT163K1                       = 0x0001, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT163R1                       = 0x0002, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT163R2                       = 0x0003, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT193R1                       = 0x0004, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT193R2                       = 0x0005, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT233K1                       = 0x0006, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT233R1                       = 0x0007, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT239K1                       = 0x0008, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT283K1                       = 0x0009, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT283R1                       = 0x000a, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT409K1                       = 0x000b, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT409R1                       = 0x000c, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT571K1                       = 0x000d, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECT571R1                       = 0x000e, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP160K1                       = 0x000f, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP160R1                       = 0x0010, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP160R2                       = 0x0011, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP192K1                       = 0x0012, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP192R1                       = 0x0013, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP224K1                       = 0x0014, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP224R1                       = 0x0015, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP256K1                       = 0x0016, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP256R1                       = 0x0017, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP384R1                       = 0x0018, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_SECP521R1                       = 0x0019, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_BRAINPOOLP256R1                 = 0x001a, /* [RFC7027] */
  R_TLS_SUPPORTED_GROUP_BRAINPOOLP348R1                 = 0x001b, /* [RFC7027] */
  R_TLS_SUPPORTED_GROUP_BRAINPOOLP512R1                 = 0x001c, /* [RFC7027] */
  R_TLS_SUPPORTED_GROUP_X25519                          = 0x001d, /* [TLS1.3] */
  R_TLS_SUPPORTED_GROUP_X448                            = 0x001e, /* [TLS1.3] */
  R_TLS_SUPPORTED_GROUP_FFDHE2048                       = 0x0100, /* [RFC7919] */
  R_TLS_SUPPORTED_GROUP_FFDHE3072                       = 0x0101, /* [RFC7919] */
  R_TLS_SUPPORTED_GROUP_FFDHE4096                       = 0x0102, /* [RFC7919] */
  R_TLS_SUPPORTED_GROUP_FFDHE6144                       = 0x0103, /* [RFC7919] */
  R_TLS_SUPPORTED_GROUP_FFDHE8192                       = 0x0104, /* [RFC7919] */
  R_TLS_SUPPORTED_GROUP_ARBITRARY_EXPLICIT_PRIME_CURVES = 0xff01, /* [RFC4492] */
  R_TLS_SUPPORTED_GROUP_ARBITRARY_EXPLICIT_CHAR2_CURVES = 0xff02, /* [RFC4492] */
} RTLSSupportedGroup;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-9 */
typedef enum {
  R_TLS_EC_POINT_FORMAT_UNCOMPRESSED                    = 0x00, /* [RFC4492] */
  R_TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME       = 0x01, /* [RFC4492] */
  R_TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2       = 0x02, /* [RFC4492] */
} RTLSEcPointFormat;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-10 */
typedef enum {
  R_TLS_EC_TYPE_EXPLICIT_PRIME                          = 0x01, /* [RFC4492] */
  R_TLS_EC_TYPE_EXPLICIT_CHAR2                          = 0x02, /* [RFC4492] */
  R_TLS_EC_TYPE_NAMED_CURVE                             = 0x03, /* [RFC4492] */
} RTLSEcCurveType;

/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-16 */
/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-18 */
typedef enum {
  R_TLS_SIGN_SCHEME_RSA_PKCS1_MD5                       = 0x0101, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA1                      = 0x0201, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA224                    = 0x0301, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256                    = 0x0401, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA384                    = 0x0501, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA512                    = 0x0601, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_DSA_MD5                             = 0x0102, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_DSA_SHA1                            = 0x0202, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_DSA_SHA224                          = 0x0302, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_DSA_SHA256                          = 0x0402, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_DSA_SHA384                          = 0x0502, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_DSA_SHA512                          = 0x0602, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_ECDSA_MD5                           = 0x0103, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_ECDSA_SHA1                          = 0x0203, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_ECDSA_SECP224R1_SHA224              = 0x0303, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256              = 0x0403, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384              = 0x0503, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512              = 0x0603, /* [RFC5246] */
  R_TLS_SIGN_SCHEME_RSA_PSS_SHA256                      = 0x0804, /* [TLS1.3] */
  R_TLS_SIGN_SCHEME_RSA_PSS_SHA384                      = 0x0805, /* [TLS1.3] */
  R_TLS_SIGN_SCHEME_RSA_PSS_SHA512                      = 0x0806, /* [TLS1.3] */
  R_TLS_SIGN_SCHEME_ED25519                             = 0x0807, /* [TLS1.3] */
  R_TLS_SIGN_SCHEME_ED448                               = 0x0808, /* [TLS1.3] */
} RTLSSignatureScheme;

/* http://www.iana.org/assignments/tls-parameters/#authorization-data */
typedef enum {
  R_TLS_AUTH_DATA_FORMAT_X509_ATTR_CERT                 = 0x00, /* [RFC5878] */
  R_TLS_AUTH_DATA_FORMAT_SAML_ASSERTION                 = 0x01, /* [RFC5878] */
  R_TLS_AUTH_DATA_FORMAT_X509_ATTR_CERT_URL             = 0x02, /* [RFC5878] */
  R_TLS_AUTH_DATA_FORMAT_SAML_ASSERTION_URL             = 0x03, /* [RFC5878] */
  R_TLS_AUTH_DATA_FORMAT_KEYNOTE_ASSERTION_LIST         = 0x40, /* [RFC6042] */
  R_TLS_AUTH_DATA_FORMAT_KEYNOTE_ASSERTION_LIST_URL     = 0x41, /* [RFC6042] */
  R_TLS_AUTH_DATA_FORMAT_DTCP_AUTHORIZATION             = 0x42, /* [RFC7562] */
} RTLSAuthorizationDataFormats;

/* http://www.iana.org/assignments/tls-parameters/#heartbeat-message-types */
typedef enum {
  R_TLS_HEARTBEAT_MSG_TYPE_REQUEST                      = 0x01, /* [RFC6520] */
  R_TLS_HEARTBEAT_MSG_TYPE_RESPONSE                     = 0x02, /* [RFC6520] */
} RTLSHeartbeatMessageType;

/* http://www.iana.org/assignments/tls-parameters/#heartbeat-modes */
typedef enum {
  R_TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND             = 0x01, /* [RFC6520] */
  R_TLS_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND         = 0x02, /* [RFC6520] */
} RTLSHeartbeatMode;

/* http://www.iana.org/assignments/srtp-protection/ */
typedef enum {
  R_DTLS_SRTP_AES128_CM_HMAC_SHA1_80                    = 0x0001, /* [RFC5764] */
  R_DTLS_SRTP_AES128_CM_HMAC_SHA1_32                    = 0x0002, /* [RFC5764] */
  R_DTLS_SRTP_NULL_HMAC_SHA1_80                         = 0x0005, /* [RFC5764] */
  R_DTLS_SRTP_NULL_HMAC_SHA1_32                         = 0x0006, /* [RFC5764] */
  R_DTLS_SRTP_AEAD_AES_128_GCM                          = 0x0007, /* [RFC7714] */
  R_DTLS_SRTP_AEAD_AES_256_GCM                          = 0x0008, /* [RFC7714] */
} RDTLSSRTPProtectionProfile;

typedef enum {
  R_TLS_ERROR_EOB                                       =  1,
  R_TLS_ERROR_OK                                        =  0,
  R_TLS_ERROR_INVAL                                     = -1,
  R_TLS_ERROR_INVALID_RECORD                            = -2,
  R_TLS_ERROR_CORRUPT_RECORD                            = -3,
  R_TLS_ERROR_BUF_TOO_SMALL                             = -4,
  R_TLS_ERROR_VERSION                                   = -5,
  R_TLS_ERROR_WRONG_TYPE                                = -6,
  R_TLS_ERROR_NOT_DTLS                                  = -7,
} RTLSError;

typedef enum {
  R_TLS_COMPRESSION_NULL                                =  0,
} RTLSCompresssionMethod;


#define R_TLS_HELLO_RANDOM_BYTES              32
#define R_TLS_HELLO_EXT_HDR_SIZE              (2 * sizeof (ruint16))

typedef struct {
  RBuffer * buf;
  rsize recsize;

  RTLSContentType content;
  RTLSVersion version;
  ruint16 epoch;                              /* DTLS only */
  ruint64 seqno;                              /* DTLS only */
  RMemMapInfo fragment;
} RTLSParser;
#define R_TLS_PARSER_INIT           { NULL, 0, 0, 0, 0, 0, R_MEM_MAP_INFO_INIT }

typedef struct {
  RTLSVersion version;

  const ruint8 * random;

  ruint8 sidlen;
  const ruint8 * sid; /* session id */
  ruint8 cookielen;
  const ruint8 * cookie; /* Only for DTLS ClientHello */
  ruint16 cslen;
  const ruint8 * cs; /* cipher suites */
  ruint8 complen;
  const ruint8 * compression;
  ruint16 extlen;
  const ruint8 * ext; /* extensions */
} RTLSHelloMsg;

typedef struct {
  const ruint8 *  start;
  ruint16         type;
  ruint16         len;
  const ruint8 *  data;
} RTLSHelloExt;
#define R_TLS_HELLO_EXT_INIT                { NULL, 0, 0, NULL }

typedef struct {
  const ruint8 * start;
  ruint32 len;
  const ruint8 * cert;
} RTLSCertificate;
#define R_TLS_CERTIFICATE_INIT              { NULL, 0, NULL }

typedef struct {
  ruint8 certtypecount;
  const ruint8 * certtype;
  ruint16 signschemecount;
  const ruint8 * signscheme;
  ruint16 cacount;
  const ruint8 * ca;
} RTLSCertReq;

R_API RTLSVersion r_tls_parse_data_shallow (rconstpointer buf, rsize size);

R_API RTLSError r_tls_parser_init (RTLSParser * parser, rconstpointer buf, rsize size);
R_API RTLSError r_tls_parser_init_buffer (RTLSParser * parser, RBuffer * buf);
R_API RTLSError r_tls_parser_init_next (RTLSParser * parser, RBuffer ** buf);
R_API RBuffer * r_tls_parser_next (RTLSParser * parser);
R_API void r_tls_parser_clear (RTLSParser * parser);

#define r_tls_version_is_dtls(version) ((version) > RUINT16_MAX / 2)
#define r_tls_parser_is_dtls(parser) r_tls_version_is_dtls ((parser)->version)
R_API RTLSError r_tls_parser_parse_handshake_peek_type (const RTLSParser * parser,
    RTLSHandshakeType * type);
#define r_tls_parser_parse_handshake(parser, type, length)                    \
  r_tls_parser_parse_handshake_full (parser, type, length, NULL, NULL, NULL)
R_API RTLSError r_tls_parser_parse_handshake_full (const RTLSParser * parser,
    RTLSHandshakeType * type, ruint32 * length, ruint16 * msgseq,
    ruint32 * fragoff, ruint32 * fraglen);
R_API rboolean r_tls_parser_dtls_is_complete_handshake_fragment (const RTLSParser * parser);
R_API RTLSError r_tls_parser_parse_hello (const RTLSParser * parser, RTLSHelloMsg * msg);
R_API RTLSError r_tls_parser_parse_certificate_next (const RTLSParser * parser, RTLSCertificate * cert);
R_API RTLSError r_tls_parser_parse_certificate_request (const RTLSParser * parser, RTLSCertReq * req);
R_API RTLSError r_tls_parser_parse_new_session_ticket (const RTLSParser * parser,
    ruint32 * lifetime, const ruint8 ** ticket, ruint16 * ticketsize);
R_API RTLSError r_tls_parser_parse_certificate_verify (const RTLSParser * parser,
    RTLSSignatureScheme * sigscheme, const ruint8 ** sig, ruint16 * sigsize);
R_API RTLSError r_tls_parser_parse_client_key_exchange_rsa (const RTLSParser * parser,
    const ruint8 ** encprems, rsize * size);

R_API RTLSError r_tls_parser_parse_alert (const RTLSParser * parser,
    RTLSAlertLevel * level, RTLSAlertType * type);

/* Hello msg */
#define r_tls_hello_msg_cipher_suite_count(msg) ((msg)->cslen / sizeof (ruint16))
#define r_tls_hello_msg_compression_count(msg)  ((msg)->complen / sizeof (ruint8))
static inline RCipherSuite r_tls_hello_msg_cipher_suite (const RTLSHelloMsg * msg, int n)
{ return (RCipherSuite)RUINT16_FROM_BE (((const ruint16 *)msg->cs)[n]); }
static inline RTLSCompresssionMethod r_tls_hello_msg_compression_method (const RTLSHelloMsg * msg, int n)
{ return (RTLSCompresssionMethod)msg->compression[n]; }
R_API rboolean r_tls_hello_msg_has_cipher_suite (const RTLSHelloMsg * msg, RCipherSuite cs);
R_API RTLSError r_tls_hello_msg_extension_first (const RTLSHelloMsg * msg, RTLSHelloExt * ext);
R_API RTLSError r_tls_hello_msg_extension_next (const RTLSHelloMsg * msg, RTLSHelloExt * ext);

/* signature_algorithms extension */
static inline ruint16 r_tls_hello_ext_sign_scheme_count (const RTLSHelloExt * ext)
{ return RUINT16_FROM_BE (*(const ruint16 *)ext->data) / sizeof (ruint16); }
static inline RTLSSignatureScheme r_tls_hello_ext_sign_scheme (const RTLSHelloExt * ext, int n)
{ return (RTLSSignatureScheme)RUINT16_FROM_BE (((const ruint16 *)ext->data)[n+1]); }

/* ec_point_format extension */
static inline ruint16 r_tls_hello_ext_ec_point_format_count (const RTLSHelloExt * ext)
{ return ext->data[0]; }
static inline RTLSEcPointFormat r_tls_hello_ext_ec_point_format (const RTLSHelloExt * ext, int n)
{ return (RTLSEcPointFormat)ext->data[n+1]; }

/* supported_groups/elliptic_curves extension */
static inline ruint16 r_tls_hello_ext_supported_groups_count (const RTLSHelloExt * ext)
{ return RUINT16_FROM_BE (*(const ruint16 *)ext->data) / sizeof (ruint16); }
static inline RTLSSupportedGroup r_tls_hello_ext_supported_group (const RTLSHelloExt * ext, int n)
{ return (RTLSSupportedGroup)RUINT16_FROM_BE (((const ruint16 *)ext->data)[n+1]); }

/* use_srtp extension */
static inline ruint16 r_tls_hello_ext_use_srtp_profile_count (const RTLSHelloExt * ext)
{ return RUINT16_FROM_BE (*(const ruint16 *)ext->data) / sizeof (ruint16); }
static inline ruint16 r_tls_hello_ext_use_srtp_profile(const RTLSHelloExt * ext, int n)
{ return (RTLSSignatureScheme)RUINT16_FROM_BE (((const ruint16 *)ext->data)[n+1]); }
static inline ruint8 r_tls_hello_ext_use_srtp_mki_size (const RTLSHelloExt * ext)
{ return ext->data[sizeof (ruint16) + RUINT16_FROM_BE (*(const ruint16 *)ext->data)]; }
static inline const ruint8 * r_tls_hello_ext_use_srtp_mki (const RTLSHelloExt * ext)
{ return &ext->data[sizeof (ruint16) + RUINT16_FROM_BE (*(const ruint16 *)ext->data) + sizeof (ruint8)]; }


/* Certificate */
R_API RCryptoCert * r_tls_certificate_get_cert (const RTLSCertificate * cert);

/* Certificate request */
static inline RTLSClientCertificateType r_tls_cert_req_cert_type (const RTLSCertReq * req, int n)
{ return (RTLSClientCertificateType)req->certtype[n]; }
static inline RTLSSignatureScheme r_tls_cert_req_sign_scheme (const RTLSCertReq * req, int n)
{ return (RTLSSignatureScheme)RUINT16_FROM_BE (((const ruint16 *)req->signscheme)[n]); }



R_API RTLSError r_tls_write_handshake (rpointer data, rsize size,
    rsize * out, RTLSVersion ver, RTLSHandshakeType type, ruint16 len);
R_API RTLSError r_dtls_write_handshake (rpointer data, rsize size,
    rsize * out, RTLSVersion ver, RTLSHandshakeType type, ruint16 len,
    ruint16 epoch, ruint64 seqno, ruint16 msgseq, ruint32 foff, ruint32 flen);
R_API RTLSError r_tls_update_handshake_len (rpointer data, rsize size, ruint16 len);
R_API RTLSError r_dtls_update_handshake_len (rpointer data, rsize size, ruint16 len,
    ruint32 foff, ruint32 flen);

R_API RTLSError r_tls_write_hs_server_hello (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, RPrng * prng, const ruint8 * sid, ruint8 sidsize,
    RCipherSuite cs, RTLSCompresssionMethod comp);
#define r_dtls_write_hs_server_hello r_tls_write_hs_server_hello

R_END_DECLS

#endif /* __R_NET_PROTO_TLS_H__ */

