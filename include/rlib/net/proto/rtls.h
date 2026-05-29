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

/**
 * @file rlib/net/proto/rtls.h
 * @brief TLS / DTLS wire-protocol constants, record / handshake parsing
 * and message building.
 */

#include <rlib/rtypes.h>

#include <rlib/rbuffer.h>
#include <rlib/rrand.h>

#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rcipher.h>
#include <rlib/crypto/rhmac.h>
#include <rlib/crypto/rsrtpciphersuite.h>
#include <rlib/crypto/rtlsciphersuite.h>

/**
 * @defgroup r_tls_proto TLS / DTLS protocol
 * @ingroup r_net
 *
 * @brief TLS and DTLS wire-protocol constants (versions, content / handshake
 * types, alerts, extensions, signature schemes and related IANA-registered
 * tables), together with the record / handshake structures and the parsing
 * and building helpers operating directly on the wire bytes.
 *
 * Parsing centres on @ref RTLSParser, which walks records out of an
 * @c RBuffer, optionally decrypts them, and feeds the handshake-message
 * parsers (@ref RTLSHelloMsg, @ref RTLSCertificate, @ref RTLSCertReq, ...).
 * Building helpers write records and handshake headers straight into a caller
 * buffer, with parallel @c r_tls_ / @c r_dtls_ entry points for the stream and
 * datagram framings. The higher-level server session that drives these
 * primitives lives in @ref r_tls_server.
 *
 * @{
 */

R_BEGIN_DECLS

/** @name Record and handshake header layout
 *  Fixed header sizes for TLS records / handshakes and their extra DTLS bytes.
 *  @{ */
#define R_TLS_RECORD_HDR_SIZE             5  /**< @brief TLS record header size in bytes. */
#define R_TLS_RECORD_EXTRA_DTLS_SIZE      8  /**< @brief Extra DTLS record-header bytes (epoch + sequence number). */
#define R_TLS_HS_HDR_SIZE                 4  /**< @brief TLS handshake header size in bytes. */
#define R_TLS_HS_EXTRA_DTLS_SIZE          8  /**< @brief Extra DTLS handshake-header bytes (message seq + fragment offset/length). */
#define R_DTLS_RECORD_HDR_SIZE            (R_TLS_RECORD_HDR_SIZE + R_TLS_RECORD_EXTRA_DTLS_SIZE) /**< @brief DTLS record header size in bytes. */
#define R_DTLS_HS_HDR_SIZE                (R_TLS_HS_HDR_SIZE + R_TLS_HS_EXTRA_DTLS_SIZE) /**< @brief DTLS handshake header size in bytes. */
#define R_TLS_SESSION_TICKET_LIFETIME     7200 /**< @brief Default session-ticket lifetime hint, in seconds. */
/** @} */

/** @brief TLS / DTLS protocol version (the 16-bit version field; DTLS uses 0xfe**). */
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

/** @brief Client certificate type for CertificateRequest (IANA TLS ClientCertificateType). */
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

/** @brief TLS record content type (IANA TLS ContentType). */
/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-5 */
typedef enum {
  R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC                 = 0x14, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_ALERT                              = 0x15, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_HANDSHAKE                          = 0x16, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_APPLICATION_DATA                   = 0x17, /* [RFC5246] */
  R_TLS_CONTENT_TYPE_HEARTBEAT                          = 0x18, /* [RFC6520] */

  R_TLS_CONTENT_TYPE_FIRST                              = R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC, /**< Lowest valid content type. */
  R_TLS_CONTENT_TYPE_LAST                               = R_TLS_CONTENT_TYPE_HEARTBEAT /**< Highest valid content type. */
} RTLSContentType;

/** @brief Severity level of a TLS alert. */
typedef enum {
  R_TLS_ALERT_LEVEL_WARNING                             = 0x01,
  R_TLS_ALERT_LEVEL_FATAL                               = 0x02,
} RTLSAlertLevel;

/** @brief TLS alert description (IANA TLS Alert registry). */
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

/** @brief Handshake message type (IANA TLS HandshakeType). */
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

/** @brief TLS extension type (IANA TLS ExtensionType). */
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

/** @brief Named group / elliptic curve for key exchange (IANA TLS Supported Groups). */
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

/** @brief Elliptic-curve point format (IANA TLS EC Point Formats). */
/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-9 */
typedef enum {
  R_TLS_EC_POINT_FORMAT_UNCOMPRESSED                    = 0x00, /* [RFC4492] */
  R_TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME       = 0x01, /* [RFC4492] */
  R_TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2       = 0x02, /* [RFC4492] */
} RTLSEcPointFormat;

/** @brief Elliptic-curve description type (IANA TLS EC Curve Type). */
/* http://www.iana.org/assignments/tls-parameters/#tls-parameters-10 */
typedef enum {
  R_TLS_EC_TYPE_EXPLICIT_PRIME                          = 0x01, /* [RFC4492] */
  R_TLS_EC_TYPE_EXPLICIT_CHAR2                          = 0x02, /* [RFC4492] */
  R_TLS_EC_TYPE_NAMED_CURVE                             = 0x03, /* [RFC4492] */
} RTLSEcCurveType;

/** @brief Signature scheme / hash-and-signature algorithm pair (IANA TLS SignatureScheme). */
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

/** @brief Authorization-data format for the supplemental-data extension (IANA TLS Authorization Data Formats). */
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

/** @brief Heartbeat message type (IANA TLS Heartbeat Message Types). */
/* http://www.iana.org/assignments/tls-parameters/#heartbeat-message-types */
typedef enum {
  R_TLS_HEARTBEAT_MSG_TYPE_REQUEST                      = 0x01, /* [RFC6520] */
  R_TLS_HEARTBEAT_MSG_TYPE_RESPONSE                     = 0x02, /* [RFC6520] */
} RTLSHeartbeatMessageType;

/** @brief Heartbeat mode negotiated by the heartbeat extension (IANA TLS Heartbeat Modes). */
/* http://www.iana.org/assignments/tls-parameters/#heartbeat-modes */
typedef enum {
  R_TLS_HEARTBEAT_MODE_PEER_ALLOWED_TO_SEND             = 0x01, /* [RFC6520] */
  R_TLS_HEARTBEAT_MODE_PEER_NOT_ALLOWED_TO_SEND         = 0x02, /* [RFC6520] */
} RTLSHeartbeatMode;

/** @brief Result code returned by the TLS / DTLS parsing and building API (negative values are errors). */
typedef enum {
  R_TLS_ERROR_NOT_NEEDED                                =  0x02, /**< Operation was a no-op / not required. */
  R_TLS_ERROR_EOB                                       =  0x01, /**< End of buffer reached. */
  R_TLS_ERROR_OK                                        =  0x00, /**< Success. */
  R_TLS_ERROR_INVAL                                     = -0x01, /**< Invalid argument. */
  R_TLS_ERROR_OOM                                       = -0x02, /**< Out of memory. */
  R_TLS_ERROR_INVALID_RECORD                            = -0x03, /**< Record failed validation. */
  R_TLS_ERROR_CORRUPT_RECORD                            = -0x04, /**< Record is malformed / truncated. */
  R_TLS_ERROR_BUF_TOO_SMALL                             = -0x05, /**< Output buffer too small. */
  R_TLS_ERROR_VERSION                                   = -0x06, /**< Unexpected or unsupported protocol version. */
  R_TLS_ERROR_WRONG_TYPE                                = -0x07, /**< Wrong record / handshake type for the operation. */
  R_TLS_ERROR_NOT_DTLS                                  = -0x08, /**< DTLS-only operation on a non-DTLS parser. */
  R_TLS_ERROR_QUEUE_FULL                                = -0x09, /**< Reassembly / output queue is full. */
  R_TLS_ERROR_NO_CERTIFICATE                            = -0x0a, /**< Expected certificate is missing. */
  R_TLS_ERROR_CORRUPT_CERTIFICATE                       = -0x0b, /**< Certificate is malformed. */
  R_TLS_ERROR_WRONG_STATE                               = -0x0c, /**< Operation not valid in the current state. */
  R_TLS_ERROR_HANDSHAKE_FAILURE                         = -0x0d, /**< Generic handshake failure. */
  R_TLS_ERROR_INVALID_MAC                               = -0x0e, /**< Record MAC verification failed. */
  R_TLS_ERROR_HS_VERIFICATION_FAILED                    = -0x0f, /**< Handshake verify-data check failed. */
  R_TLS_ERROR_ENCRYPTION_FAILED                         = -0x10, /**< Record encryption failed. */
} RTLSError;

/** @brief TLS record compression method (only @c NULL is supported / non-deprecated). */
typedef enum {
  R_TLS_COMPRESSION_NULL                                =  0,
} RTLSCompresssionMethod;


/** @name Hello message layout
 *  Sizes used when parsing / building Hello messages.
 *  @{ */
#define R_TLS_HELLO_RANDOM_BYTES              32 /**< @brief Size of the Hello @c random field in bytes. */
#define R_TLS_HELLO_EXT_HDR_SIZE              (2 * sizeof (ruint16)) /**< @brief Size of an extension's type + length header. */
/** @} */

/** @brief Cursor over a (D)TLS record being parsed out of a buffer. */
typedef struct {
  RBuffer * buf;          /**< @brief Source buffer holding the record(s). */
  rsize recsize;          /**< @brief Size of the current record's payload. */

  RTLSContentType content; /**< @brief Content type of the current record. */
  RTLSVersion version;     /**< @brief Protocol version of the current record. */
  ruint16 epoch;           /**< @brief DTLS epoch (DTLS only). */
  ruint64 seqno;           /**< @brief DTLS record sequence number (DTLS only). */
  rsize offset;            /**< @brief Read offset within the buffer. */
  RMemMapInfo fragment;    /**< @brief Mapping of the current record's payload. */
} RTLSParser;
/** @brief Static initialiser for an empty @ref RTLSParser. */
#define R_TLS_PARSER_INIT           { NULL, 0, 0, 0, 0, 0, 0, R_MEM_MAP_INFO_INIT }

/** @brief Parsed ClientHello / ServerHello, pointing into the record buffer. */
typedef struct {
  RTLSVersion version;     /**< @brief Advertised / selected protocol version. */

  const ruint8 * random;   /**< @brief The @ref R_TLS_HELLO_RANDOM_BYTES random field. */

  ruint8 sidlen;           /**< @brief Session-ID length in bytes. */
  const ruint8 * sid;      /**< @brief Session ID. */
  ruint8 cookielen;        /**< @brief Cookie length (DTLS ClientHello only). */
  const ruint8 * cookie;   /**< @brief DTLS ClientHello cookie. */
  ruint16 cslen;           /**< @brief Cipher-suites list length in bytes. */
  const ruint8 * cs;       /**< @brief Cipher-suites list. */
  ruint8 complen;          /**< @brief Compression-methods list length in bytes. */
  const ruint8 * compression; /**< @brief Compression-methods list. */
  ruint16 extlen;          /**< @brief Extensions block length in bytes. */
  const ruint8 * ext;      /**< @brief Extensions block. */
} RTLSHelloMsg;

/** @brief One parsed Hello extension, pointing into the Hello buffer. */
typedef struct {
  const ruint8 *  start;   /**< @brief First octet of the extension (its type field). */
  ruint16         type;    /**< @brief Extension type (@ref RTLSExtensionType). */
  ruint16         len;     /**< @brief Extension data length in bytes. */
  const ruint8 *  data;    /**< @brief Pointer to the first data octet. */
} RTLSHelloExt;
/** @brief Static initialiser for an empty @ref RTLSHelloExt. */
#define R_TLS_HELLO_EXT_INIT                { NULL, 0, 0, NULL }

/** @brief One certificate entry from a Certificate handshake message. */
typedef struct {
  const ruint8 * start;    /**< @brief First octet of the entry (its length field). */
  ruint32 len;             /**< @brief Certificate length in bytes. */
  const ruint8 * cert;     /**< @brief Pointer to the DER-encoded certificate. */
} RTLSCertificate;
/** @brief Static initialiser for an empty @ref RTLSCertificate. */
#define R_TLS_CERTIFICATE_INIT              { NULL, 0, NULL }

/** @brief Parsed CertificateRequest message, pointing into the record buffer. */
typedef struct {
  ruint8 certtypecount;       /**< @brief Number of accepted certificate types. */
  const ruint8 * certtype;    /**< @brief Accepted certificate types (@ref RTLSClientCertificateType). */
  ruint16 signschemecount;    /**< @brief Number of accepted signature schemes. */
  const ruint8 * signscheme;  /**< @brief Accepted signature schemes (@ref RTLSSignatureScheme). */
  ruint16 cacount;            /**< @brief Length of the accepted-CA list in bytes. */
  const ruint8 * ca;          /**< @brief Distinguished names of accepted CAs. */
} RTLSCertReq;

/** @brief Peek the protocol version of the record in @p buf without full parsing; @c R_TLS_VERSION_UNKNOWN if not a record. */
R_API RTLSVersion r_tls_parse_data_shallow (rconstpointer buf, rsize size);

/** @brief Initialise @p parser over a raw @p buf of @p size bytes. */
R_API RTLSError r_tls_parser_init (RTLSParser * parser, rconstpointer buf, rsize size);
/** @brief Initialise @p parser over an existing @c RBuffer. */
R_API RTLSError r_tls_parser_init_buffer (RTLSParser * parser, RBuffer * buf);
/**
 * @brief Initialise @p parser on the next record, taking ownership of @p buf.
 * @param parser Parser to initialise.
 * @param buf In/out pointer to the buffer to consume; advanced past the record.
 */
R_API RTLSError r_tls_parser_init_next (RTLSParser * parser, RBuffer ** buf);
/** @brief Return the buffer for the next record, advancing past the current one. */
R_API RBuffer * r_tls_parser_next (RTLSParser * parser);
/** @brief Release resources held by @p parser. */
R_API void r_tls_parser_clear (RTLSParser * parser);

/** @brief Decrypt and MAC-verify the current record in place. */
R_API RTLSError r_tls_parser_decrypt (RTLSParser * parser,
    const RCryptoCipher * cipher, RHmac * mac);

/** @brief @c TRUE if protocol @p version is a DTLS version. */
#define r_tls_version_is_dtls(version) ((version) > RUINT16_MAX / 2)
/** @brief @c TRUE if @p parser holds a DTLS record. */
#define r_tls_parser_is_dtls(parser) r_tls_version_is_dtls ((parser)->version)
/** @brief @c TRUE if the current DTLS handshake fragment completes its message. */
R_API rboolean r_tls_parser_dtls_is_complete_handshake_fragment (const RTLSParser * parser);

/** @brief Read the handshake message type without consuming the header. */
R_API RTLSError r_tls_parser_parse_handshake_peek_type (const RTLSParser * parser,
    RTLSHandshakeType * type);
/** @brief Parse the handshake header, returning only type and length. */
#define r_tls_parser_parse_handshake(parser, type, length)                    \
  r_tls_parser_parse_handshake_full (parser, type, length, NULL, NULL, NULL)
/**
 * @brief Parse the handshake header, including DTLS reassembly fields.
 * @param parser Parser positioned on a handshake record.
 * @param type Out: handshake message type.
 * @param length Out: total handshake message length.
 * @param msgseq Out: DTLS message sequence (may be @c NULL).
 * @param fragoff Out: DTLS fragment offset (may be @c NULL).
 * @param fraglen Out: DTLS fragment length (may be @c NULL).
 */
R_API RTLSError r_tls_parser_parse_handshake_full (const RTLSParser * parser,
    RTLSHandshakeType * type, ruint32 * length, ruint16 * msgseq,
    ruint32 * fragoff, ruint32 * fraglen);
/** @brief Parse the current record as a ClientHello / ServerHello into @p msg. */
R_API RTLSError r_tls_parser_parse_hello (const RTLSParser * parser, RTLSHelloMsg * msg);
/** @brief Parse the next certificate entry of a Certificate message into @p cert. */
R_API RTLSError r_tls_parser_parse_certificate_next (const RTLSParser * parser, RTLSCertificate * cert);
/** @brief Parse the current record as a CertificateRequest into @p req. */
R_API RTLSError r_tls_parser_parse_certificate_request (const RTLSParser * parser, RTLSCertReq * req);
/**
 * @brief Parse the current record as a NewSessionTicket.
 * @param parser Parser positioned on the message.
 * @param lifetime Out: ticket lifetime hint in seconds.
 * @param ticket Out: pointer to the ticket bytes.
 * @param ticketsize Out: ticket length in bytes.
 */
R_API RTLSError r_tls_parser_parse_new_session_ticket (const RTLSParser * parser,
    ruint32 * lifetime, const ruint8 ** ticket, ruint16 * ticketsize);
/**
 * @brief Parse the current record as a CertificateVerify.
 * @param parser Parser positioned on the message.
 * @param sigscheme Out: signature scheme used.
 * @param sig Out: pointer to the signature bytes.
 * @param sigsize Out: signature length in bytes.
 */
R_API RTLSError r_tls_parser_parse_certificate_verify (const RTLSParser * parser,
    RTLSSignatureScheme * sigscheme, const ruint8 ** sig, ruint16 * sigsize);
/**
 * @brief Parse the current record as an RSA ClientKeyExchange.
 * @param parser Parser positioned on the message.
 * @param encprems Out: pointer to the encrypted pre-master secret.
 * @param size Out: length of the encrypted pre-master secret in bytes.
 */
R_API RTLSError r_tls_parser_parse_client_key_exchange_rsa (const RTLSParser * parser,
    const ruint8 ** encprems, rsize * size);
/**
 * @brief Parse the current record as a Finished message.
 * @param parser Parser positioned on the message.
 * @param verify_data Out: pointer to the verify-data bytes.
 * @param size Out: verify-data length in bytes.
 */
R_API RTLSError r_tls_parser_parse_finished (const RTLSParser * parser,
    const ruint8 ** verify_data, rsize * size);

/** @brief Parse the current record as an Alert into @p level and @p type. */
R_API RTLSError r_tls_parser_parse_alert (const RTLSParser * parser,
    RTLSAlertLevel * level, RTLSAlertType * type);

/** @name Hello message accessors
 *  Read fields and lists out of a parsed @ref RTLSHelloMsg.
 *  @{ */
/** @brief Number of cipher suites advertised in @p msg. */
#define r_tls_hello_msg_cipher_suite_count(msg) ((msg)->cslen / sizeof (ruint16))
/** @brief Number of compression methods advertised in @p msg. */
#define r_tls_hello_msg_compression_count(msg)  ((msg)->complen / sizeof (ruint8))
/** @brief Return the @p n th cipher suite in @p msg. */
static inline RTLSCipherSuite r_tls_hello_msg_cipher_suite (const RTLSHelloMsg * msg, int n)
{ return (RTLSCipherSuite) r_load_be16 (msg->cs + n * sizeof (ruint16)); }
/** @brief Return the @p n th compression method in @p msg. */
static inline RTLSCompresssionMethod r_tls_hello_msg_compression_method (const RTLSHelloMsg * msg, int n)
{ return (RTLSCompresssionMethod)msg->compression[n]; }
/** @brief @c TRUE if @p msg advertises cipher suite @p cs. */
R_API rboolean r_tls_hello_msg_has_cipher_suite (const RTLSHelloMsg * msg, RTLSCipherSuite cs);
/** @brief Position @p ext on the first extension of @p msg. */
R_API RTLSError r_tls_hello_msg_extension_first (const RTLSHelloMsg * msg, RTLSHelloExt * ext);
/** @brief Advance @p ext to the next extension of @p msg. */
R_API RTLSError r_tls_hello_msg_extension_next (const RTLSHelloMsg * msg, RTLSHelloExt * ext);
/** @} */

/** @name signature_algorithms extension accessors
 *  @{ */
/** @brief Number of signature schemes in the signature_algorithms extension @p ext. */
static inline ruint16 r_tls_hello_ext_sign_scheme_count (const RTLSHelloExt * ext)
{ return r_load_be16 (ext->data) / sizeof (ruint16); }
/** @brief Return the @p n th signature scheme in @p ext. */
static inline RTLSSignatureScheme r_tls_hello_ext_sign_scheme (const RTLSHelloExt * ext, int n)
{ return (RTLSSignatureScheme) r_load_be16 (ext->data + (n + 1) * sizeof (ruint16)); }
/** @} */

/** @name ec_point_format extension accessors
 *  @{ */
/** @brief Number of point formats in the ec_point_format extension @p ext. */
static inline ruint16 r_tls_hello_ext_ec_point_format_count (const RTLSHelloExt * ext)
{ return ext->data[0]; }
/** @brief Return the @p n th EC point format in @p ext. */
static inline RTLSEcPointFormat r_tls_hello_ext_ec_point_format (const RTLSHelloExt * ext, int n)
{ return (RTLSEcPointFormat)ext->data[n+1]; }
/** @} */

/** @name supported_groups / elliptic_curves extension accessors
 *  @{ */
/** @brief Number of named groups in the supported_groups extension @p ext. */
static inline ruint16 r_tls_hello_ext_supported_groups_count (const RTLSHelloExt * ext)
{ return r_load_be16 (ext->data) / sizeof (ruint16); }
/** @brief Return the @p n th named group in @p ext. */
static inline RTLSSupportedGroup r_tls_hello_ext_supported_group (const RTLSHelloExt * ext, int n)
{ return (RTLSSupportedGroup) r_load_be16 (ext->data + (n + 1) * sizeof (ruint16)); }
/** @} */

/** @name use_srtp extension accessors
 *  @{ */
/** @brief Number of SRTP protection profiles in the use_srtp extension @p ext. */
static inline ruint16 r_tls_hello_ext_use_srtp_profile_count (const RTLSHelloExt * ext)
{ return r_load_be16 (ext->data) / sizeof (ruint16); }
/** @brief Return the @p n th SRTP protection profile in @p ext. */
static inline RSRTPCipherSuite r_tls_hello_ext_use_srtp_profile(const RTLSHelloExt * ext, int n)
{ return (RSRTPCipherSuite) r_load_be16 (ext->data + (n + 1) * sizeof (ruint16)); }
/** @brief Size of the SRTP MKI field in @p ext, in bytes. */
static inline ruint8 r_tls_hello_ext_use_srtp_mki_size (const RTLSHelloExt * ext)
{ return ext->data[sizeof (ruint16) + r_load_be16 (ext->data)]; }
/** @brief Pointer to the SRTP MKI field in @p ext. */
static inline const ruint8 * r_tls_hello_ext_use_srtp_mki (const RTLSHelloExt * ext)
{ return &ext->data[sizeof (ruint16) + r_load_be16 (ext->data) + sizeof (ruint8)]; }
/** @} */


/** @brief Decode the certificate entry @p cert into an @c RCryptoCert (caller owns the result). */
R_API RCryptoCert * r_tls_certificate_get_cert (const RTLSCertificate * cert);

/** @name CertificateRequest accessors
 *  @{ */
/** @brief Return the @p n th accepted certificate type in @p req. */
static inline RTLSClientCertificateType r_tls_cert_req_cert_type (const RTLSCertReq * req, int n)
{ return (RTLSClientCertificateType)req->certtype[n]; }
/** @brief Return the @p n th accepted signature scheme in @p req. */
static inline RTLSSignatureScheme r_tls_cert_req_sign_scheme (const RTLSCertReq * req, int n)
{ return (RTLSSignatureScheme) r_load_be16 (req->signscheme + n * sizeof (ruint16)); }
/** @} */

/** @brief TLS pseudo-random function: expand @p secret into @p dst, fed a @c NULL-terminated list of seed chunks. */
typedef RTLSError (*RTLSPrfFunc) (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...);

/** @brief TLS 1.0 / 1.1 PRF (MD5+SHA1) over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_0_prf (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-224 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha224 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-256 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha256 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-384 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha384 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;
/** @brief TLS 1.2 PRF based on HMAC-SHA-512 over a @c NULL-terminated seed list. */
R_API RTLSError r_tls_1_2_prf_sha512 (ruint8 * dst, rsize dsize,
    const ruint8 * secret, rsize secsize, ...) R_ATTR_NULL_TERMINATED;


/**
 * @brief Encrypt and MAC a TLS record buffer.
 * @param buf Plaintext record payload.
 * @param seqno Record sequence number fed to the MAC.
 * @param cipher Record-protection cipher.
 * @param iv Explicit IV, or @c NULL.
 * @param hmac Record MAC, or @c NULL.
 * @return New buffer holding the protected record, or @c NULL on failure.
 */
R_API RBuffer * r_tls_encrypt_buffer (RBuffer * buf, ruint64 seqno,
    const RCryptoCipher * cipher, const ruint8 * iv, RHmac * hmac);
/**
 * @brief Encrypt and MAC a DTLS record buffer (sequence taken from the record).
 * @param buf Plaintext record payload.
 * @param cipher Record-protection cipher.
 * @param iv Explicit IV, or @c NULL.
 * @param hmac Record MAC, or @c NULL.
 * @return New buffer holding the protected record, or @c NULL on failure.
 */
R_API RBuffer * r_dtls_encrypt_buffer (RBuffer * buf,
    const RCryptoCipher * cipher, const ruint8 * iv, RHmac * hmac);

/**
 * @brief Write a TLS handshake record header into @p data.
 * @param data Destination buffer.
 * @param size Capacity of @p data in bytes.
 * @param out Out: bytes written.
 * @param ver Protocol version.
 * @param type Handshake message type.
 * @param len Handshake message body length.
 */
R_API RTLSError r_tls_write_handshake (rpointer data, rsize size,
    rsize * out, RTLSVersion ver, RTLSHandshakeType type, ruint16 len);
/**
 * @brief Write a DTLS handshake record header into @p data.
 * @param data Destination buffer.
 * @param size Capacity of @p data in bytes.
 * @param out Out: bytes written.
 * @param ver Protocol version.
 * @param type Handshake message type.
 * @param len Handshake message body length.
 * @param epoch DTLS epoch.
 * @param seqno DTLS record sequence number.
 * @param msgseq DTLS handshake message sequence.
 * @param foff Fragment offset.
 * @param flen Fragment length.
 */
R_API RTLSError r_dtls_write_handshake (rpointer data, rsize size,
    rsize * out, RTLSVersion ver, RTLSHandshakeType type, ruint16 len,
    ruint16 epoch, ruint64 seqno, ruint16 msgseq, ruint32 foff, ruint32 flen);
/** @brief Patch the body length of a previously written TLS handshake header. */
R_API RTLSError r_tls_update_handshake_len (rpointer data, rsize size, ruint16 len);
/**
 * @brief Patch the length / fragment fields of a written DTLS handshake header.
 * @param data Buffer holding the handshake header.
 * @param size Size of @p data in bytes.
 * @param len Handshake message body length.
 * @param foff Fragment offset.
 * @param flen Fragment length.
 */
R_API RTLSError r_dtls_update_handshake_len (rpointer data, rsize size, ruint16 len,
    ruint32 foff, ruint32 flen);

/** @brief Generate a Hello @c random field using @c RPrng @p prng. */
R_API RTLSError r_tls_generate_hello_random (ruint8 randrom[R_TLS_HELLO_RANDOM_BYTES], RPrng * prng);
/**
 * @brief Write a ServerHello handshake message into @p data.
 * @param data Destination buffer.
 * @param size Capacity of @p data in bytes.
 * @param out Out: bytes written.
 * @param ver Selected protocol version.
 * @param srvrand Server random field.
 * @param sid Session ID, or @c NULL.
 * @param sidsize Session-ID length in bytes.
 * @param cs Selected cipher suite.
 * @param comp Selected compression method.
 */
R_API RTLSError r_tls_write_hs_server_hello (rpointer data, rsize size, rsize * out,
    RTLSVersion ver, const ruint8 srvrand[R_TLS_HELLO_RANDOM_BYTES],
    const ruint8 * sid, ruint8 sidsize,
    RTLSCipherSuite cs, RTLSCompresssionMethod comp);
/** @brief DTLS alias for @ref r_tls_write_hs_server_hello. */
#define r_dtls_write_hs_server_hello r_tls_write_hs_server_hello
/**
 * @brief Write a NewSessionTicket handshake message into @p buf.
 * @param buf Destination buffer.
 * @param size Capacity of @p buf in bytes.
 * @param out Out: bytes written.
 * @param lifetime Ticket lifetime hint in seconds.
 * @param ticket Ticket bytes.
 * @param tsize Ticket length in bytes.
 */
R_API RTLSError r_tls_write_hs_new_session_ticket (rpointer buf, rsize size, rsize * out,
    ruint32 lifetime, const ruint8 * ticket, ruint16 tsize);
/** @brief DTLS alias for @ref r_tls_write_hs_new_session_ticket. */
#define r_dtls_write_hs_new_session_ticket r_tls_write_hs_new_session_ticket


/** @brief Write a TLS ChangeCipherSpec record into @p data. */
R_API RTLSError r_tls_write_change_cipher (rpointer data, rsize size,
    rsize * out, RTLSVersion ver);
/**
 * @brief Write a DTLS ChangeCipherSpec record into @p data.
 * @param data Destination buffer.
 * @param size Capacity of @p data in bytes.
 * @param out Out: bytes written.
 * @param ver Protocol version.
 * @param epoch DTLS epoch.
 * @param seqno DTLS record sequence number.
 */
R_API RTLSError r_dtls_write_change_cipher (rpointer data, rsize size,
    rsize * out, RTLSVersion ver, ruint16 epoch, ruint64 seqno);

R_END_DECLS

/** @} */

#endif /* __R_NET_PROTO_TLS_H__ */

