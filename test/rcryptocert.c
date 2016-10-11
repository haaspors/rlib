#include <rlib/rlib.h>

RTEST (rcryptocert, self_signed_x509v3, RTEST_FAST)
{
  static const ruint8 x509v3[] = {
    0x30, 0x82, 0x02, 0x3e, 0x30, 0x82, 0x01, 0xa7, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x11,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30,
    0x43, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01,
    0x19, 0x16, 0x03, 0x63, 0x6f, 0x6d, 0x31, 0x17, 0x30, 0x15, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89,
    0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x34, 0x30, 0x34, 0x33, 0x30, 0x31, 0x34,
    0x32, 0x35, 0x33, 0x34, 0x5a, 0x17, 0x0d, 0x30, 0x35, 0x30, 0x34, 0x33, 0x30, 0x31, 0x34, 0x32,
    0x35, 0x33, 0x34, 0x5a, 0x30, 0x43, 0x31, 0x13, 0x30, 0x11, 0x06, 0x0a, 0x09, 0x92, 0x26, 0x89,
    0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x03, 0x63, 0x6f, 0x6d, 0x31, 0x17, 0x30, 0x15, 0x06,
    0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19, 0x16, 0x07, 0x65, 0x78, 0x61,
    0x6d, 0x70, 0x6c, 0x65, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a, 0x45,
    0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30,
    0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xc2, 0xd7, 0x97, 0x6d, 0x28, 0x70, 0xaa, 0x5b, 0xcf, 0x23,
    0x2e, 0x80, 0x70, 0x39, 0xee, 0xdb, 0x6f, 0xd5, 0x2d, 0xd5, 0x6a, 0x4f, 0x7a, 0x34, 0x2d, 0xf9,
    0x22, 0x72, 0x47, 0x70, 0x1d, 0xef, 0x80, 0xe9, 0xca, 0x30, 0x8c, 0x00, 0xc4, 0x9a, 0x6e, 0x5b,
    0x45, 0xb4, 0x6e, 0xa5, 0xe6, 0x6c, 0x94, 0x0d, 0xfa, 0x91, 0xe9, 0x40, 0xfc, 0x25, 0x9d, 0xc7,
    0xb7, 0x68, 0x19, 0x56, 0x8f, 0x11, 0x70, 0x6a, 0xd7, 0xf1, 0xc9, 0x11, 0x4f, 0x3a, 0x7e, 0x3f,
    0x99, 0x8d, 0x6e, 0x76, 0xa5, 0x74, 0x5f, 0x5e, 0xa4, 0x55, 0x53, 0xe5, 0xc7, 0x68, 0x36, 0x53,
    0xc7, 0x1d, 0x3b, 0x12, 0xa6, 0x85, 0xfe, 0xbd, 0x6e, 0xa1, 0xca, 0xdf, 0x35, 0x50, 0xac, 0x08,
    0xd7, 0xb9, 0xb4, 0x7e, 0x5c, 0xfe, 0xe2, 0xa3, 0x2c, 0xd1, 0x23, 0x84, 0xaa, 0x98, 0xc0, 0x9b,
    0x66, 0x18, 0x9a, 0x68, 0x47, 0xe9, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x42, 0x30, 0x40, 0x30,
    0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x08, 0x68, 0xaf, 0x85, 0x33, 0xc8,
    0x39, 0x4a, 0x7a, 0xf8, 0x82, 0x93, 0x8e, 0x70, 0x6a, 0x4a, 0x20, 0x84, 0x2c, 0x32, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x06, 0x30, 0x0f,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30,
    0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81,
    0x81, 0x00, 0x6c, 0xf8, 0x02, 0x74, 0xa6, 0x61, 0xe2, 0x64, 0x04, 0xa6, 0x54, 0x0c, 0x6c, 0x72,
    0x13, 0xad, 0x3c, 0x47, 0xfb, 0xf6, 0x65, 0x13, 0xa9, 0x85, 0x90, 0x33, 0xea, 0x76, 0xa3, 0x26,
    0xd9, 0xfc, 0xd1, 0x0e, 0x15, 0x5f, 0x28, 0xb7, 0xef, 0x93, 0xbf, 0x3c, 0xf3, 0xe2, 0x3e, 0x7c,
    0xb9, 0x52, 0xfc, 0x16, 0x6e, 0x29, 0xaa, 0xe1, 0xf4, 0x7a, 0x6f, 0xd5, 0x7f, 0xef, 0xb3, 0x95,
    0xca, 0xf3, 0x66, 0x88, 0x83, 0x4e, 0xa1, 0x35, 0x45, 0x84, 0xcb, 0xbc, 0x9b, 0xb8, 0xc8, 0xad,
    0xc5, 0x5e, 0x46, 0xd9, 0x0b, 0x0e, 0x8d, 0x80, 0xe1, 0x33, 0x2b, 0xdc, 0xbe, 0x2b, 0x92, 0x7e,
    0x4a, 0x43, 0xa9, 0x6a, 0xef, 0x8a, 0x63, 0x61, 0xb3, 0x6e, 0x47, 0x38, 0xbe, 0xe8, 0x0d, 0xa3,
    0x67, 0x5d, 0xf3, 0xfa, 0x91, 0x81, 0x3c, 0x92, 0xbb, 0xc5, 0x5f, 0x25, 0x25, 0xeb, 0x7c, 0xe7,
    0xd8, 0xa1
  };
  RCryptoCert * cert;
  RCryptoKey * pk;
  RHashType signalgo;
  rsize size;

  r_assert_cmpptr ((cert = r_crypto_x509_cert_new (x509v3, sizeof (x509v3))), !=, NULL);
  r_assert_cmpuint (r_crypto_cert_get_type (cert), ==, R_CRYPTO_CERT_X509);
  r_assert_cmpstr (r_crypto_cert_get_strtype (cert), ==, "X.509");
  r_assert_cmpptr (r_crypto_cert_get_signature (cert, &signalgo, &size), !=, NULL);
  r_assert_cmpuint (size, ==, 1024);
  r_assert_cmpuint (signalgo, ==, R_HASH_TYPE_SHA1);
  r_assert_cmpuint (r_crypt_x509_cert_version (cert), ==, R_X509_VERSION_V3);
  r_assert_cmpuint (r_crypt_x509_cert_serial_number (cert), ==, 17);
  r_assert_cmpstr (r_crypt_x509_cert_issuer (cert),   ==, "CN=Example CA,DC=example,DC=com");
  r_assert_cmpstr (r_crypt_x509_cert_subject (cert),  ==, "CN=Example CA,DC=example,DC=com");
  r_assert_cmpuint (r_crypto_cert_get_valid_from (cert),  ==, r_time_create_unix_time (2004, 4, 30, 14, 25, 34));
  r_assert_cmpuint (r_crypto_cert_get_valid_to (cert),    ==, r_time_create_unix_time (2005, 4, 30, 14, 25, 34));

  r_assert_cmpptr ((pk = r_crypto_cert_get_public_key (cert)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_type (pk), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert_cmpuint (r_crypto_key_get_algo (pk), ==, R_CRYPTO_ALGO_RSA);
  r_assert_cmpuint (r_crypto_key_get_bitsize (pk), ==, 1024);
  r_crypto_key_unref (pk);

  r_assert_cmphex (r_crypt_x509_cert_key_usage (cert), ==,
      R_X509_KEY_USAGE_DIGITAL_SIGNATURE | R_X509_KEY_USAGE_NON_REPUDIATION);
  r_assert_cmphex (r_crypt_x509_cert_ext_key_usage (cert), ==,
      R_X509_EXT_KEY_USAGE_NONE);
  r_assert_cmpptr (r_crypt_x509_cert_issuer_unique_id (cert, NULL), ==, NULL);
  r_assert_cmpptr (r_crypt_x509_cert_subject_unique_id (cert, NULL), ==, NULL);
  r_assert_cmpptr (r_crypt_x509_cert_subject_key_id (cert, &size), !=, NULL);
  r_assert_cmpuint (size, ==, 20);

  r_assert (r_crypt_x509_cert_is_ca (cert));
  r_assert (r_crypt_x509_cert_is_self_issued (cert));
  r_assert (r_crypt_x509_cert_is_self_signed (cert));

  /* This is just for fun. Basically SubjectKeyIdentifier is what RFC5280 discribes;
   *  (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
   *       value of the BIT STRING subjectPublicKey (excluding the tag,
   *       length, and number of unused bits).
   */
  {
    RHash * h = r_hash_new_sha1 ();
    ruint8 sha1[20];
    size = sizeof (sha1);

    r_assert (r_hash_update (h, x509v3 + 223, 140));
    r_assert (r_hash_get_data (h, sha1, &size));
    r_assert_cmpmem (r_crypt_x509_cert_subject_key_id (cert, NULL), ==, sha1, size);

    r_hash_free (h);
  }

  r_assert_cmpuint (r_crypto_x509_cert_verify_signature (cert, cert), ==, R_CRYPTO_OK);

  r_crypto_cert_unref (cert);
}
RTEST_END;

RTEST (rcryptocert, valid_x509v3, RTEST_FAST)
{
  static const ruint8 x509v3[] = {
    0x30, 0x82, 0x03, 0x79, 0x30, 0x82, 0x02, 0x61, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
    0x40, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x1f,
    0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x16, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x65,
    0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x20, 0x32, 0x30, 0x31, 0x31, 0x31,
    0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x07, 0x47, 0x6f, 0x6f, 0x64, 0x20, 0x43,
    0x41, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30,
    0x30, 0x5a, 0x17, 0x0d, 0x33, 0x30, 0x31, 0x32, 0x33, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x30,
    0x5a, 0x30, 0x53, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
    0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13, 0x16, 0x54, 0x65, 0x73, 0x74, 0x20,
    0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x20, 0x32, 0x30, 0x31,
    0x31, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1a, 0x56, 0x61, 0x6c, 0x69,
    0x64, 0x20, 0x45, 0x45, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
    0x20, 0x54, 0x65, 0x73, 0x74, 0x31, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
    0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xd9, 0xdc, 0x77, 0x18, 0x10, 0x10, 0x18, 0x60, 0x41,
    0xfb, 0xe7, 0x78, 0x10, 0x0f, 0xf8, 0x84, 0x77, 0x70, 0xef, 0x2d, 0x6e, 0x55, 0x3b, 0x11, 0xa6,
    0x99, 0x52, 0x3f, 0x6d, 0xf4, 0xbd, 0xa1, 0x97, 0xfa, 0x36, 0x1e, 0x6e, 0x44, 0x42, 0x11, 0xc8,
    0x53, 0xfe, 0x75, 0x86, 0x9b, 0x5e, 0x37, 0x12, 0x88, 0xa2, 0x7d, 0xd9, 0x71, 0x08, 0xd4, 0x49,
    0x35, 0x71, 0xce, 0x46, 0xcf, 0x5b, 0xd0, 0x59, 0x8e, 0x65, 0x1f, 0xeb, 0x42, 0x3d, 0xca, 0x0e,
    0xdc, 0x4c, 0x90, 0xd8, 0x54, 0x69, 0xcf, 0x5e, 0x38, 0xb2, 0x20, 0x60, 0xdd, 0x83, 0x51, 0x2e,
    0xdf, 0xdb, 0xd5, 0x5b, 0x38, 0x91, 0x5a, 0x2d, 0xcf, 0x9a, 0x33, 0xb4, 0x6f, 0x96, 0x90, 0xe5,
    0x76, 0x14, 0x62, 0x43, 0x69, 0x84, 0x10, 0xcf, 0x54, 0x41, 0xf9, 0x35, 0xea, 0x9e, 0xd4, 0x5a,
    0x97, 0x9d, 0x5e, 0x10, 0x59, 0xbd, 0xe0, 0xe4, 0xc3, 0x59, 0x89, 0xd7, 0xde, 0xf2, 0x79, 0xb0,
    0x87, 0x6b, 0x02, 0xc0, 0x59, 0xa1, 0x2a, 0x00, 0x82, 0x15, 0x6f, 0x6b, 0x11, 0x11, 0x00, 0x53,
    0x34, 0x74, 0x3d, 0xf4, 0xe1, 0xcc, 0x56, 0x62, 0xa2, 0xe4, 0x65, 0xe8, 0x23, 0xb1, 0x83, 0x1d,
    0x58, 0x53, 0x08, 0xb2, 0x33, 0x2d, 0x96, 0xbe, 0xe5, 0x7d, 0x33, 0x9e, 0x10, 0x5a, 0x27, 0x73,
    0x53, 0xdd, 0x5d, 0x98, 0xe2, 0x4b, 0x11, 0x53, 0x58, 0x91, 0x8f, 0xea, 0x72, 0x11, 0xec, 0xbb,
    0x94, 0xf2, 0x0d, 0x0f, 0x50, 0xad, 0xf2, 0x16, 0xb5, 0x1a, 0x00, 0x24, 0x31, 0xe5, 0x15, 0xbd,
    0x17, 0x06, 0x90, 0xaa, 0x24, 0xb1, 0xac, 0xdd, 0x0c, 0x52, 0x1e, 0xf0, 0x8b, 0x6a, 0xab, 0xb8,
    0xf7, 0xed, 0xdf, 0x63, 0xb4, 0xce, 0x94, 0x68, 0xbf, 0x5e, 0x96, 0xd0, 0x44, 0x96, 0xf1, 0xf8,
    0xf4, 0x7a, 0x3a, 0x0a, 0x79, 0x15, 0x53, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x6b, 0x30, 0x69,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x58, 0x01, 0x84,
    0x24, 0x1b, 0xbc, 0x2b, 0x52, 0x94, 0x4a, 0x3d, 0xa5, 0x10, 0x72, 0x14, 0x51, 0xf5, 0xaf, 0x3a,
    0xc9, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xa8, 0x3c, 0x09, 0x9d,
    0x67, 0xf6, 0xd8, 0x47, 0xba, 0xa2, 0xd0, 0xfc, 0x18, 0x72, 0x56, 0x88, 0x40, 0x6d, 0x95, 0x95,
    0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x04, 0xf0,
    0x30, 0x17, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x0a, 0x60,
    0x86, 0x48, 0x01, 0x65, 0x03, 0x02, 0x01, 0x30, 0x01, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
    0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x1e, 0x5a, 0xd9,
    0x0f, 0xaf, 0x62, 0xa5, 0xb9, 0x52, 0xbc, 0xbc, 0xec, 0x0c, 0x61, 0x88, 0x13, 0x01, 0xaa, 0x0a,
    0x0f, 0x0d, 0x47, 0xa3, 0x9e, 0xa9, 0xb2, 0x17, 0x1b, 0xf8, 0xa3, 0xd9, 0x2c, 0xd2, 0x8d, 0x38,
    0xbe, 0x3b, 0xb2, 0xcf, 0xd4, 0x31, 0x88, 0xcf, 0xce, 0x69, 0xf4, 0x8e, 0xc7, 0xb9, 0x70, 0x05,
    0x51, 0xc0, 0x06, 0x87, 0xc6, 0x95, 0xb4, 0xf6, 0x6a, 0xfa, 0x31, 0x9e, 0x2d, 0xc4, 0x17, 0xb3,
    0xed, 0xe5, 0x7a, 0x19, 0x61, 0x18, 0x6e, 0x8c, 0xd1, 0xe4, 0x0e, 0xda, 0x9b, 0x6d, 0x6c, 0x8d,
    0x06, 0x90, 0xee, 0x2c, 0xd1, 0x79, 0x58, 0xd8, 0x84, 0xcd, 0x9b, 0x41, 0xd3, 0x18, 0xe2, 0xfe,
    0x91, 0xc6, 0x5f, 0x00, 0x27, 0x14, 0x65, 0x7b, 0x12, 0xfa, 0x2f, 0xbd, 0xa8, 0xbf, 0x34, 0x8e,
    0x2d, 0xcf, 0x17, 0x4c, 0x58, 0x5b, 0x30, 0x0f, 0x2e, 0x69, 0x66, 0x45, 0x26, 0x26, 0x21, 0x98,
    0xd3, 0xf3, 0x90, 0xae, 0x29, 0x87, 0x5a, 0x4e, 0xc6, 0xbd, 0xe8, 0x28, 0x7e, 0x0f, 0xa0, 0x94,
    0xe6, 0xff, 0x5c, 0xb5, 0x5c, 0x4f, 0xdd, 0x8a, 0x61, 0x59, 0x0e, 0x05, 0xd2, 0xff, 0xc5, 0x69,
    0xc0, 0xd3, 0x89, 0x4a, 0xd1, 0xc2, 0xe5, 0xc8, 0xf4, 0xc8, 0x08, 0xc3, 0xfd, 0x2a, 0x23, 0x4f,
    0x84, 0x00, 0x5c, 0x2c, 0x44, 0x2d, 0x83, 0x8a, 0xc2, 0x3d, 0x22, 0xc7, 0x3c, 0x60, 0xf2, 0x8a,
    0x78, 0xe3, 0x1b, 0x46, 0x65, 0xda, 0x99, 0x8f, 0xf8, 0x63, 0xc1, 0xd4, 0x7a, 0xa0, 0x70, 0xa6,
    0x7a, 0xa7, 0x10, 0x9b, 0x9d, 0xac, 0x7f, 0xbe, 0x14, 0xf0, 0x44, 0x23, 0x87, 0x58, 0xac, 0x10,
    0x15, 0xe8, 0xf3, 0xa0, 0xbf, 0x1e, 0x25, 0xcb, 0x36, 0xab, 0x02, 0x69, 0x5a, 0xae, 0xff, 0xc0,
    0x6e, 0xb0, 0x43, 0x9e, 0x08, 0x9e, 0x19, 0x3c, 0xa7, 0x30, 0x6e, 0x8d, 0xc2
  };
  RCryptoCert * cert;
  RCryptoKey * pk;
  RHashType signalgo;
  rsize size;


  r_assert_cmpptr ((cert = r_crypto_x509_cert_new (x509v3, sizeof (x509v3))), !=, NULL);
  r_assert_cmpuint (r_crypto_cert_get_type (cert), ==, R_CRYPTO_CERT_X509);
  r_assert_cmpstr (r_crypto_cert_get_strtype (cert), ==, "X.509");
  r_assert_cmpptr (r_crypto_cert_get_signature (cert, &signalgo, &size), !=, NULL);
  r_assert_cmpuint (size, ==, 2048);
  r_assert_cmpuint (signalgo, ==, R_HASH_TYPE_SHA256);
  r_assert_cmpuint (r_crypt_x509_cert_version (cert), ==, R_X509_VERSION_V3);
  r_assert_cmpuint (r_crypt_x509_cert_serial_number (cert), ==, 1);
  r_assert_cmpstr (r_crypt_x509_cert_issuer (cert),   ==, "CN=Good CA,O=Test Certificates 2011,C=US");
  r_assert_cmpstr (r_crypt_x509_cert_subject (cert),  ==, "CN=Valid EE Certificate Test1,O=Test Certificates 2011,C=US");
  r_assert_cmpuint (r_crypto_cert_get_valid_from (cert),  ==, r_time_create_unix_time (2010,  1,  1, 8, 30, 0));
  r_assert_cmpuint (r_crypto_cert_get_valid_to (cert),    ==, r_time_create_unix_time (2030, 12, 31, 8, 30, 0));

  r_assert_cmpptr ((pk = r_crypto_cert_get_public_key (cert)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_type (pk), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert_cmpuint (r_crypto_key_get_algo (pk), ==, R_CRYPTO_ALGO_RSA);
  r_assert_cmpuint (r_crypto_key_get_bitsize (pk), ==, 2048);
  r_crypto_key_unref (pk);

  r_assert_cmphex (r_crypt_x509_cert_key_usage (cert), ==,
      R_X509_KEY_USAGE_DIGITAL_SIGNATURE | R_X509_KEY_USAGE_NON_REPUDIATION |
      R_X509_KEY_USAGE_KEY_ENCIPHERMENT  | R_X509_KEY_USAGE_DATA_ENCIPHERMENT);
  r_assert_cmpptr (r_crypt_x509_cert_issuer_unique_id (cert, NULL), ==, NULL);
  r_assert_cmpptr (r_crypt_x509_cert_subject_unique_id (cert, NULL), ==, NULL);
  r_assert_cmpptr (r_crypt_x509_cert_subject_key_id (cert, &size), !=, NULL);
  r_assert_cmpuint (size, ==, 20);
  r_assert_cmpptr (r_crypt_x509_cert_authority_key_id (cert, &size), !=, NULL);
  r_assert_cmpuint (size, ==, 20);
  r_assert (r_crypt_x509_cert_has_policy (cert, "2.16.840.1.101.3.2.1.48.1")); /* nistTestPolicy1 */

  r_assert (!r_crypt_x509_cert_is_ca (cert));
  r_assert (!r_crypt_x509_cert_is_self_issued (cert));
  r_assert (!r_crypt_x509_cert_is_self_signed (cert));

  r_assert_cmpuint (r_crypto_x509_cert_verify_signature (cert, cert), ==, R_CRYPTO_VERIFY_FAILED);

  r_crypto_cert_unref (cert);
}
RTEST_END;


RTEST (rcryptocert, openssl_gen_x509_rsa_1024, RTEST_FAST)
{
  static const ruint8 x509v3[] = {
    0x30, 0x82, 0x02, 0xAA, 0x30, 0x82, 0x02, 0x13, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
    0x83, 0x72, 0x37, 0xD9, 0xEF, 0x01, 0xD1, 0x2F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
    0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00, 0x30, 0x43, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55,
    0x04, 0x06, 0x13, 0x02, 0x4E, 0x4F, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13,
    0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65, 0x31, 0x10, 0x30, 0x0E, 0x06,
    0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x38, 0x32, 0x20, 0x62, 0x69, 0x74, 0x73, 0x31, 0x0D, 0x30,
    0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x69, 0x65, 0x65, 0x69, 0x30, 0x1E, 0x17, 0x0D,
    0x31, 0x36, 0x31, 0x30, 0x30, 0x35, 0x31, 0x38, 0x30, 0x35, 0x34, 0x36, 0x5A, 0x17, 0x0D, 0x31,
    0x36, 0x31, 0x31, 0x30, 0x34, 0x31, 0x38, 0x30, 0x35, 0x34, 0x36, 0x5A, 0x30, 0x43, 0x31, 0x0B,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4E, 0x4F, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74, 0x65,
    0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x38, 0x32, 0x20, 0x62, 0x69,
    0x74, 0x73, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x69, 0x65, 0x65,
    0x69, 0x30, 0x81, 0x9F, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x81, 0x8D, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xA0, 0xA7,
    0xEC, 0x29, 0x00, 0x9D, 0xF3, 0x06, 0x84, 0x95, 0xAB, 0xD3, 0xE5, 0x01, 0x59, 0x66, 0x48, 0x84,
    0x18, 0x11, 0x63, 0xB6, 0x49, 0x2C, 0xFD, 0x08, 0x8E, 0x9C, 0xC5, 0xB4, 0x13, 0x7E, 0x53, 0x1B,
    0x07, 0xA0, 0xD9, 0xC6, 0x9F, 0x54, 0x04, 0x64, 0x0E, 0x0C, 0x78, 0x0F, 0x1A, 0xC3, 0xDD, 0x50,
    0xEA, 0xF9, 0xB9, 0xD1, 0x6B, 0xF0, 0xC9, 0xB1, 0x31, 0xC3, 0x3C, 0x6B, 0x54, 0x5E, 0x37, 0x65,
    0xAE, 0x3E, 0xF5, 0xC3, 0x14, 0xFD, 0x9C, 0xFA, 0xAC, 0x5D, 0x4B, 0x02, 0xB5, 0xC7, 0xFC, 0x97,
    0xC3, 0xD9, 0x49, 0xE7, 0xE3, 0x95, 0x52, 0x60, 0x38, 0x0B, 0x92, 0x1B, 0x81, 0xEF, 0x5A, 0x1B,
    0xF8, 0x0E, 0x63, 0x10, 0xB1, 0x30, 0x6C, 0xC6, 0x07, 0x47, 0xEF, 0xFF, 0x30, 0x51, 0xD1, 0xFF,
    0xB2, 0x66, 0x5D, 0xC0, 0x1C, 0x62, 0x65, 0x9B, 0x7A, 0xBC, 0x64, 0x32, 0xF3, 0xD1, 0x02, 0x03,
    0x01, 0x00, 0x01, 0xA3, 0x81, 0xA5, 0x30, 0x81, 0xA2, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E,
    0x04, 0x16, 0x04, 0x14, 0x9E, 0x5C, 0xA0, 0xDA, 0xD7, 0x3B, 0x42, 0x80, 0x3A, 0xEA, 0xC1, 0x79,
    0x0C, 0x5A, 0x6C, 0x8F, 0xC8, 0xAC, 0x60, 0x0C, 0x30, 0x73, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04,
    0x6C, 0x30, 0x6A, 0x80, 0x14, 0x9E, 0x5C, 0xA0, 0xDA, 0xD7, 0x3B, 0x42, 0x80, 0x3A, 0xEA, 0xC1,
    0x79, 0x0C, 0x5A, 0x6C, 0x8F, 0xC8, 0xAC, 0x60, 0x0C, 0xA1, 0x47, 0xA4, 0x45, 0x30, 0x43, 0x31,
    0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x4E, 0x4F, 0x31, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0A, 0x53, 0x6F, 0x6D, 0x65, 0x2D, 0x53, 0x74, 0x61, 0x74,
    0x65, 0x31, 0x10, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x07, 0x38, 0x32, 0x20, 0x62,
    0x69, 0x74, 0x73, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x04, 0x69, 0x65,
    0x65, 0x69, 0x82, 0x09, 0x00, 0x83, 0x72, 0x37, 0xD9, 0xEF, 0x01, 0xD1, 0x2F, 0x30, 0x0C, 0x06,
    0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xFF, 0x30, 0x0D, 0x06, 0x09, 0x2A,
    0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x92, 0x6A,
    0xE8, 0xF8, 0xF7, 0x07, 0xF8, 0x4E, 0x5B, 0x1C, 0x09, 0x0C, 0x65, 0x4E, 0xAB, 0x0F, 0x41, 0x47,
    0x20, 0x0C, 0xF1, 0x33, 0x22, 0xCF, 0x74, 0x8F, 0xD4, 0x4A, 0x2E, 0xBC, 0x2E, 0xB9, 0x09, 0x03,
    0x1E, 0xE1, 0x68, 0x40, 0x42, 0x78, 0xB1, 0xE0, 0xD2, 0x3A, 0xEF, 0x25, 0xD3, 0x66, 0xC1, 0xCF,
    0x71, 0x98, 0xFD, 0xAC, 0x28, 0x20, 0xC2, 0x2D, 0x20, 0x78, 0x9E, 0xD6, 0xE6, 0x1F, 0xD0, 0x70,
    0x84, 0x74, 0x4C, 0x94, 0x4F, 0xF5, 0xEA, 0x10, 0xC9, 0x12, 0x2C, 0xEB, 0x89, 0x69, 0x5C, 0x45,
    0x48, 0xF6, 0x09, 0x90, 0xE4, 0x81, 0xDA, 0xF6, 0x28, 0x65, 0x15, 0xA9, 0x94, 0x4E, 0x4E, 0xD2,
    0xB7, 0x43, 0x80, 0xBB, 0xFF, 0x3D, 0x6D, 0x37, 0x3A, 0xFA, 0xE5, 0xA3, 0x7B, 0x45, 0x60, 0x31,
    0x6F, 0x1F, 0x40, 0xF2, 0x7F, 0xB6, 0xB5, 0x32, 0x84, 0x5E, 0x37, 0x66, 0x6A, 0xD9
  };
  RCryptoCert * cert;
  RCryptoKey * pk;
  RHashType signalgo;
  rsize size;

  r_assert_cmpptr ((cert = r_crypto_x509_cert_new (x509v3, sizeof (x509v3))), !=, NULL);
  r_assert_cmpuint (r_crypto_cert_get_type (cert), ==, R_CRYPTO_CERT_X509);
  r_assert_cmpstr (r_crypto_cert_get_strtype (cert), ==, "X.509");
  r_assert_cmpptr (r_crypto_cert_get_signature (cert, &signalgo, &size), !=, NULL);
  r_assert_cmpuint (size, ==, 1024);
  r_assert_cmpuint (signalgo, ==, R_HASH_TYPE_SHA1);
  r_assert_cmpuint (r_crypt_x509_cert_version (cert), ==, R_X509_VERSION_V3);
  r_assert_cmpuint (r_crypt_x509_cert_serial_number (cert), ==, RUINT64_CONSTANT (9471694375470879023));
  r_assert_cmpstr (r_crypt_x509_cert_issuer (cert),   ==, "CN=ieei,O=82 bits,ST=Some-State,C=NO");
  r_assert_cmpstr (r_crypt_x509_cert_subject (cert),  ==, "CN=ieei,O=82 bits,ST=Some-State,C=NO");
  r_assert_cmpuint (r_crypto_cert_get_valid_from (cert),  ==, r_time_create_unix_time (2016, 10, 5, 18, 5, 46));
  r_assert_cmpuint (r_crypto_cert_get_valid_to (cert),    ==, r_time_create_unix_time (2016, 11, 4, 18, 5, 46));

  r_assert_cmpptr ((pk = r_crypto_cert_get_public_key (cert)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_type (pk), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert_cmpuint (r_crypto_key_get_algo (pk), ==, R_CRYPTO_ALGO_RSA);
  r_assert_cmpuint (r_crypto_key_get_bitsize (pk), ==, 1024);
  r_crypto_key_unref (pk);

  r_assert (r_crypt_x509_cert_is_ca (cert));
  r_assert (r_crypt_x509_cert_is_self_issued (cert));
  r_assert (r_crypt_x509_cert_is_self_signed (cert));

  r_assert_cmpuint (r_crypto_x509_cert_verify_signature (cert, cert), ==, R_CRYPTO_OK);

  r_crypto_cert_unref (cert);
}
RTEST_END;

RTEST (rcryptocert, nodejs_pem_gen_x509_self_signed_rsa_2048_days_1, RTEST_FAST)
{
  static const rchar * x509_base64 =
    "MIICpDCCAYwCCQDz+4pqXkrUmjANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDEwls"
    "b2NhbGhvc3QwHhcNMTYxMDA1MjEwMzU1WhcNMTYxMDA2MjEwMzU1WjAUMRIwEAYD"
    "VQQDEwlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDR"
    "TOEwF+M6sw5AKOTf8ID4douHxYmhhZ/b8y7WzoTUTOh76ZzEO3FKYBK7zDwV2TC1"
    "p1nazr8vHpR773UdST6dsVzU+6EGRrzOUVq88shcA9uMJ6xK2TzbbXogyBXvsKtR"
    "8x0TbCY8r74nT8OGjKTSgvTQtaPJZNw0BN8owUhbX3MHcBBwzbWWzbsj6GvOWLrS"
    "tT8pyw1DHMvz4OlEE2Q0h+BCk2ikgyedSRTfK05syVwkoVk2VinxNa/adIqW4jHX"
    "/bSlCemhWb/FCEsdnmKNhB5OF9KJnooOpXRPemRG+WdVYtKcV67GfTI5aGO//6yY"
    "GKfQzLmsufvyycky/w1fAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACMVM7zZxdxn"
    "X+cWml5gErov30W4LoeGM4R3/kI6kXke+HI86f6tPqIjRualHlxGy//QZgS7bZZJ"
    "QTz8emBzY4ZyP6b3wSKdHdJ0u+DKQ5gv3bK8sGw7IN08xSRGx0snYWbSrWhTHZTJ"
    "H8z1fkHNDdAFcCsvWSF9S/WiTDyJw1v4Lcxr+2nZxpUOWEfSE6r7rDSIs93fGlG4"
    "XozSfCUV2AQAO9gcQYrwG7nh2b4uzfirF3Srh+3l3upw8MpNsZzeaEhb/wvZqwHY"
    "jZUavcNP8pWiVYmNaGnP9jL24wZpv+gExknNFMheiFiSwMFFLNY81TSFhFG0n4Zw"
    "pKbc1ltQGjw=";
  rsize size;
  ruint8 * x509v3;
  RCryptoCert * cert;
  RCryptoKey * pk;
  RHashType signalgo;

  r_assert_cmpptr ((x509v3 = r_base64_decode (x509_base64, -1, &size)), !=, NULL);

  r_assert_cmpptr ((cert = r_crypto_x509_cert_new (x509v3, size)), !=, NULL);
  r_free (x509v3);

  r_assert_cmpuint (r_crypto_cert_get_type (cert), ==, R_CRYPTO_CERT_X509);
  r_assert_cmpstr (r_crypto_cert_get_strtype (cert), ==, "X.509");
  r_assert_cmpptr (r_crypto_cert_get_signature (cert, &signalgo, &size), !=, NULL);
  r_assert_cmpuint (size, ==, 2048);
  r_assert_cmpuint (signalgo, ==, R_HASH_TYPE_SHA256);
  r_assert_cmpuint (r_crypt_x509_cert_version (cert), ==, R_X509_VERSION_V1);
  r_assert_cmpuint (r_crypt_x509_cert_serial_number (cert), ==, RUINT64_CONSTANT (17580797759823991962));
  r_assert_cmpstr (r_crypt_x509_cert_issuer (cert),   ==, "CN=localhost");
  r_assert_cmpstr (r_crypt_x509_cert_subject (cert),  ==, "CN=localhost");
  r_assert_cmpuint (r_crypto_cert_get_valid_from (cert),  ==, r_time_create_unix_time (2016, 10, 5, 21, 3, 55));
  r_assert_cmpuint (r_crypto_cert_get_valid_to (cert),    ==, r_time_create_unix_time (2016, 10, 6, 21, 3, 55));

  r_assert_cmpptr ((pk = r_crypto_cert_get_public_key (cert)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_type (pk), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert_cmpuint (r_crypto_key_get_algo (pk), ==, R_CRYPTO_ALGO_RSA);
  r_assert_cmpuint (r_crypto_key_get_bitsize (pk), ==, 2048);
  r_crypto_key_unref (pk);

  r_assert (!r_crypt_x509_cert_is_ca (cert));
  r_assert (r_crypt_x509_cert_is_self_issued (cert));
  r_assert (r_crypt_x509_cert_is_self_signed (cert));

  r_assert_cmpuint (r_crypto_x509_cert_verify_signature (cert, cert), ==, R_CRYPTO_OK);

  r_crypto_cert_unref (cert);
}
RTEST_END;
