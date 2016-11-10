#include <rlib/rlib.h>

RTEST (rasn1enc_ber, add, RTEST_FAST)
{
  static ruint8 expected_ber[] = {
    0x01, 0x01, 0xff,       /* BOOL */
    0x02, 0x01, 0x2a,       /* INTEGER */
    0x02, 0x02, 0xc0, 0xff, /* INTEGER (signed, negative) */
  };
  RAsn1BinEncoder * enc;
  ruint8 * out;
  rsize size;

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_BER)), !=, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), ==, NULL);

  r_assert_cmpint (r_asn1_bin_encoder_add_boolean (enc, TRUE), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_integer_i32 (enc, 42), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_integer_i32 (enc, -16129), ==, R_ASN1_ENCODER_OK);

  r_assert_cmpptr (r_asn1_bin_encoder_get_data (NULL, NULL), ==, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, sizeof (expected_ber));
  r_assert_cmpmem (out, ==, expected_ber, size);

  r_free (out);
  r_asn1_bin_encoder_unref (enc);
}
RTEST_END;

RTEST (rasn1enc_ber, constructed, RTEST_FAST)
{
  static ruint8 expected_ber[] = { 0x30, 0x80,
    0x01, 0x01, 0xff, /* BOOL */
    0x02, 0x01, 0x2a, /* INTEGER */
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, /* OBEJCT IDENTIFIER */
    0x00, 0x00 };
  RAsn1BinEncoder * enc;
  ruint8 * out;
  rsize size;

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_BER)), !=, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), ==, NULL);

  r_assert_cmpint (r_asn1_bin_encoder_begin_constructed (enc,
        R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE),
        0), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_boolean (enc, TRUE), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_integer_i32 (enc, 42), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_oid_rawsz (enc, R_RSA_OID_SHA1_WITH_RSA), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_end_constructed (enc), ==, R_ASN1_ENCODER_OK);

  r_assert_cmpptr (r_asn1_bin_encoder_get_data (NULL, NULL), ==, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, sizeof (expected_ber));
  r_assert_cmpmem (out, ==, expected_ber, size);

  r_free (out);
  r_asn1_bin_encoder_unref (enc);
}
RTEST_END;

RTEST (rasn1enc_der, add, RTEST_FAST)
{
  static ruint8 expected_der[] = {
    0x01, 0x01, 0x00, /* BOOL */
    0x02, 0x01, 0x2a, /* INTEGER */
  };
  RAsn1BinEncoder * enc;
  ruint8 * out;
  rsize size;

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), ==, NULL);

  r_assert_cmpint (r_asn1_bin_encoder_add_boolean (enc, FALSE), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_integer_i32 (enc, 42), ==, R_ASN1_ENCODER_OK);

  r_assert_cmpptr (r_asn1_bin_encoder_get_data (NULL, NULL), ==, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, sizeof (expected_der));
  r_assert_cmpmem (out, ==, expected_der, size);

  r_free (out);
  r_asn1_bin_encoder_unref (enc);
}
RTEST_END;

RTEST (rasn1enc_der, constructed, RTEST_FAST)
{
  static ruint8 expected_der[] = { 0x30, 0x23,
    0x01, 0x01, 0x00, /* BOOL */
    0x02, 0x01, 0x2a, /* INTEGER */
    0x02, 0x10, 0x2f, 0xa1, 0x76, 0xb3, 0x6e, 0xe9, 0xf0, 0x49,
    0xf4, 0x44, 0xb4, 0x00, 0x99, 0x66, 0x19, 0x45, /* INTEGER */
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, /* OBEJCT IDENTIFIER */
    };
  RAsn1BinEncoder * enc;
  ruint8 * out;
  rsize size;
  rmpint mpi;
  r_mpint_init_str (&mpi, "0x2fa176b36ee9f049f444b40099661945", NULL, 16);

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), ==, NULL);

  r_assert_cmpint (r_asn1_bin_encoder_begin_constructed (enc,
        R_ASN1_ID (R_ASN1_ID_UNIVERSAL, R_ASN1_ID_CONSTRUCTED, R_ASN1_ID_SEQUENCE),
        0), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_boolean (enc, FALSE), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_integer_i32 (enc, 42), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_integer_mpint (enc, &mpi), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_add_oid_rawsz (enc, R_RSA_OID_SHA1_WITH_RSA), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpint (r_asn1_bin_encoder_end_constructed (enc), ==, R_ASN1_ENCODER_OK);

  r_assert_cmpptr (r_asn1_bin_encoder_get_data (NULL, NULL), ==, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, sizeof (expected_der));
  r_assert_cmpmem (out, ==, expected_der, size);

  r_mpint_clear (&mpi);
  r_free (out);
  r_asn1_bin_encoder_unref (enc);
}
RTEST_END;

RTEST (rasn1enc_der, distinguished_name, RTEST_FAST)
{
  static ruint8 expected_der[] = { 0x30, 0x40,
    0x31, 0x0b,
      0x30, 0x09,
        0x06, 0x03, 0x55, 0x04, 0x06,
        0x0c, 0x02, 0x55, 0x53,
    0x31, 0x1f,
      0x30, 0x1d,
        0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x16, 0x54, 0x65, 0x73, 0x74, 0x20, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x20, 0x32, 0x30, 0x31, 0x31,
    0x31, 0x10,
      0x30, 0x0e,
        0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x07, 0x47, 0x6f, 0x6f, 0x64, 0x20, 0x43, 0x41
  };
  RAsn1BinEncoder * enc;
  ruint8 * out;
  rsize size;

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);

  r_assert_cmpint (r_asn1_bin_encoder_add_distinguished_name (enc,
        "CN=Good CA,O=Test Certificates 2011,C=US"), ==, R_ASN1_ENCODER_OK);

  r_assert_cmpptr (r_asn1_bin_encoder_get_data (NULL, NULL), ==, NULL);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, sizeof (expected_der));
  r_assert_cmpmem (out, ==, expected_der, size);

  r_free (out);
  r_asn1_bin_encoder_unref (enc);
}
RTEST_END;

