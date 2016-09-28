#include <rlib/rlib.h>

RTEST (rtls, parse_errors, RTEST_FAST)
{
  static const ruint8 pkt_bogus[] = { 0x16, 0x11, 0x12, 0x00, 0x04 };
  RTLSParser parser;

  r_assert_cmpint (R_TLS_ERROR_INVAL, ==, r_tls_parser_init (NULL, NULL, 0));
  r_assert_cmpint (R_TLS_ERROR_INVAL, ==, r_tls_parser_init (&parser, NULL, 0));
  r_assert_cmpint (R_TLS_ERROR_BUF_TOO_SMALL, ==, r_tls_parser_init (&parser, pkt_bogus, 0));
  r_assert_cmpint (R_TLS_ERROR_VERSION, ==, r_tls_parser_init (&parser, pkt_bogus, sizeof (pkt_bogus)));
}
RTEST_END;

RTEST (rtls, parse_dtls_client_hello, RTEST_FAST)
{
  static const ruint8 pkt_dtls_client_hallo[] = {
    0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9e, 0x01, 0x00, 0x00,
    0x92, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x92, 0xfe, 0xfd, 0x69, 0x03, 0x27, 0x0d, 0xab,
    0x7e, 0x39, 0x4d, 0x78, 0x67, 0x5c, 0x98, 0x4b, 0x7b, 0x2e, 0xf5, 0xeb, 0x3f, 0x2a, 0xaf, 0x8f,
    0xf7, 0xfa, 0x55, 0xbd, 0x0b, 0x6b, 0x97, 0xf3, 0x91, 0x4a, 0x34, 0x00, 0x00, 0x00, 0x22, 0xc0,
    0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x09, 0xc0,
    0x13, 0x00, 0x33, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0x00, 0x9c, 0x00, 0x2f, 0x00, 0x35, 0x00,
    0x0a, 0x01, 0x00, 0x00, 0x46, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23,
    0x00, 0x00, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x08, 0x06, 0x06, 0x01, 0x06, 0x03, 0x08, 0x05,
    0x05, 0x01, 0x05, 0x03, 0x08, 0x04, 0x04, 0x01, 0x04, 0x03, 0x02, 0x01, 0x02, 0x03, 0x00, 0x0e,
    0x00, 0x07, 0x00, 0x04, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
    0x0a, 0x00, 0x08, 0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18
  };
  RTLSParser parser;
  RTLSHandshakeType hstype;
  ruint32 hslen;
  RTLSHelloMsg msg;
  RTLSHelloExt ext;

  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_parser_init (&parser, pkt_dtls_client_hallo, sizeof (pkt_dtls_client_hallo)));
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_0);
  r_assert_cmpuint (parser.epoch, ==, 0);
  r_assert_cmpuint (parser.seqno, ==, 0);
  r_assert_cmpuint (parser.fraglen, ==, 158);

  r_assert (r_tls_parser_dtls_is_complete_handshake_fragment (&parser));
  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_parser_parse_handshake (&parser, &hstype, &hslen));
  r_assert_cmpuint (hstype, ==, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO);
  r_assert_cmpuint (hslen, ==, 146);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_parser_parse_hello (&parser, &msg));
  r_assert_cmpuint (msg.version, ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpuint (msg.sidlen, ==, 0);
  r_assert_cmpuint (msg.cookielen, ==, 0);
  r_assert_cmpuint (msg.cslen, ==, 34);
  r_assert_cmpuint (msg.complen, ==, 1);
  r_assert_cmpuint (msg.extlen, ==, 70);

  r_assert_cmpuint (r_tls_hello_msg_cipher_suite_count (&msg), ==, 17);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  0), ==, R_CS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  1), ==, R_CS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  2), ==, R_CS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  3), ==, R_CS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  4), ==, R_CS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  5), ==, R_CS_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256_OLD);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  6), ==, R_CS_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256_OLD);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  7), ==, R_CS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  8), ==, R_CS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  9), ==, R_CS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg, 10), ==, R_CS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg, 11), ==, R_CS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg, 12), ==, R_CS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg, 13), ==, R_CS_TLS_RSA_WITH_AES_128_GCM_SHA256);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg, 14), ==, R_CS_TLS_RSA_WITH_AES_128_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg, 15), ==, R_CS_TLS_RSA_WITH_AES_256_CBC_SHA);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg, 16), ==, R_CS_TLS_RSA_WITH_3DES_EDE_CBC_SHA);
  r_assert (r_tls_hello_msg_has_cipher_suite (&msg, R_CS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA));
  r_assert (!r_tls_hello_msg_has_cipher_suite (&msg, R_CS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA));
  r_assert_cmpuint (r_tls_hello_msg_compression_count (&msg), ==, 1);
  r_assert_cmpuint (r_tls_hello_msg_compression_method (&msg, 0), ==, R_TLS_COMPRESSION_NULL);

  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_first (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_RENEGOTIATION_INFO);
  r_assert_cmpuint (ext.len, ==, 1);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET);
  r_assert_cmpuint (ext.len, ==, 0);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_SESSION_TICKET);
  r_assert_cmpuint (ext.len, ==, 0);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_SIGNATURE_ALGORITHMS);
  r_assert_cmpuint (ext.len, ==, 24);
  r_assert_cmpuint (r_tls_hello_ext_sign_scheme_count (&ext), ==, 11);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  0), ==, R_TLS_SIGN_SCHEME_RSA_PSS_SHA512);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  1), ==, R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA512);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  2), ==, R_TLS_SIGN_SCHEME_ECDSA_SECP521R1_SHA512);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  3), ==, R_TLS_SIGN_SCHEME_RSA_PSS_SHA384);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  4), ==, R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA384);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  5), ==, R_TLS_SIGN_SCHEME_ECDSA_SECP384R1_SHA384);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  6), ==, R_TLS_SIGN_SCHEME_RSA_PSS_SHA256);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  7), ==, R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA256);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  8), ==, R_TLS_SIGN_SCHEME_ECDSA_SECP256R1_SHA256);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext,  9), ==, R_TLS_SIGN_SCHEME_RSA_PKCS1_SHA1);
  r_assert_cmphex (r_tls_hello_ext_sign_scheme (&ext, 10), ==, R_TLS_SIGN_SCHEME_ECDSA_SHA1);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_USE_SRTP);
  r_assert_cmpuint (ext.len, ==, 7);
  r_assert_cmpuint (r_tls_hello_ext_use_srtp_profile_count (&ext), ==, 2);
  r_assert_cmphex (r_tls_hello_ext_use_srtp_profile (&ext, 0), ==, R_DTLS_SRTP_AES128_CM_HMAC_SHA1_32);
  r_assert_cmphex (r_tls_hello_ext_use_srtp_profile (&ext, 1), ==, R_DTLS_SRTP_AES128_CM_HMAC_SHA1_80);
  r_assert_cmpuint (r_tls_hello_ext_use_srtp_mki_size (&ext), ==, 0);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_EC_POINT_FORMATS);
  r_assert_cmpuint (ext.len, ==, 2);
  r_assert_cmpuint (r_tls_hello_ext_ec_point_format_count (&ext), ==, 1);
  r_assert_cmphex (r_tls_hello_ext_ec_point_format (&ext, 0), ==, R_TLS_EC_POINT_FORMAT_UNCOMPRESSED);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_SUPPORTED_GROUPS);
  r_assert_cmpuint (ext.len, ==, 8);
  r_assert_cmpuint (r_tls_hello_ext_supported_groups_count (&ext), ==, 3);
  r_assert_cmphex (r_tls_hello_ext_supported_group (&ext, 0), ==, R_TLS_SUPPORTED_GROUP_X25519);
  r_assert_cmphex (r_tls_hello_ext_supported_group (&ext, 1), ==, R_TLS_SUPPORTED_GROUP_SECP256R1);
  r_assert_cmphex (r_tls_hello_ext_supported_group (&ext, 2), ==, R_TLS_SUPPORTED_GROUP_SECP384R1);
  r_assert_cmpint (R_TLS_ERROR_EOB, ==, r_tls_hello_msg_extension_next (&msg, &ext));
}
RTEST_END;

RTEST (rtls, parse_tls_server_hello, RTEST_FAST)
{
  static const ruint8 pkt_tls_server_hallo[] = {
    0x16, 0x03, 0x03, 0x00, 0x41, 0x02, 0x00, 0x00, 0x3d, 0x03, 0x03, 0xe2, 0xbf, 0xfe, 0xd7, 0x55,
    0x11, 0xa0, 0x9a, 0xa0, 0x63, 0x7b, 0x10, 0x01, 0xe7, 0xec, 0x32, 0x24, 0xe2, 0x94, 0x48, 0xfd,
    0x6e, 0x9b, 0x56, 0xa1, 0xc1, 0xfc, 0x6a, 0xd1, 0x60, 0x4b, 0x65, 0x00, 0xc0, 0x2f, 0x00, 0x00,
    0x15, 0x00, 0x00, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
    0x01, 0x02, 0x00, 0x23, 0x00, 0x00
  };
  RTLSParser parser;
  RTLSHandshakeType hstype;
  ruint32 hslen;
  RTLSHelloMsg msg;
  RTLSHelloExt ext;

  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_parser_init (&parser, pkt_tls_server_hallo, sizeof (pkt_tls_server_hallo)));
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpuint (parser.fraglen, ==, 65);

  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_parser_parse_handshake (&parser, &hstype, &hslen));
  r_assert_cmpuint (hstype, ==, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO);
  r_assert_cmpuint (hslen, ==, 61);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_parser_parse_hello (&parser, &msg));
  r_assert_cmpuint (msg.version, ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpuint (msg.sidlen, ==, 0);
  r_assert_cmpuint (msg.cookielen, ==, 0);
  r_assert_cmpuint (msg.cslen, ==, 2);
  r_assert_cmpuint (msg.complen, ==, 1);
  r_assert_cmpuint (msg.extlen, ==, 21);

  r_assert_cmpuint (r_tls_hello_msg_cipher_suite_count (&msg), ==, 1);
  r_assert_cmphex (r_tls_hello_msg_cipher_suite (&msg,  0), ==, R_CS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
  r_assert_cmpuint (r_tls_hello_msg_compression_count (&msg), ==, 1);
  r_assert_cmpuint (r_tls_hello_msg_compression_method (&msg, 0), ==, R_TLS_COMPRESSION_NULL);

  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_first (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_SERVER_NAME);
  r_assert_cmpuint (ext.len, ==, 0);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_RENEGOTIATION_INFO);
  r_assert_cmpuint (ext.len, ==, 1);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_EC_POINT_FORMATS);
  r_assert_cmpuint (ext.len, ==, 4);
  r_assert_cmpuint (r_tls_hello_ext_ec_point_format_count (&ext), ==, 3);
  r_assert_cmphex (r_tls_hello_ext_ec_point_format (&ext, 0), ==, R_TLS_EC_POINT_FORMAT_UNCOMPRESSED);
  r_assert_cmphex (r_tls_hello_ext_ec_point_format (&ext, 1), ==, R_TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_PRIME);
  r_assert_cmphex (r_tls_hello_ext_ec_point_format (&ext, 2), ==, R_TLS_EC_POINT_FORMAT_ANSIX962_COMPRESSED_CHAR2);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_hello_msg_extension_next (&msg, &ext));
  r_assert_cmpuint (ext.type, ==, R_TLS_EXT_TYPE_SESSION_TICKET);
  r_assert_cmpuint (ext.len, ==, 0);
  r_assert_cmpint (R_TLS_ERROR_EOB, ==, r_tls_hello_msg_extension_next (&msg, &ext));
}
RTEST_END;

