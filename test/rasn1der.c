#include <rlib/rlib.h>

RTEST (rasn1der, into_out, RTEST_FAST)
{
  static ruint8 der_encoded[] = {
    0x30, 0x11,
      0x31, 0x0f,
        0x30, 0x03,
          0x01, 0x01, 0xff, /* BOOL */
        0x30, 0x03,
          0x01, 0x01, 0xff, /* BOOL */
        0x30, 0x03,
          0x01, 0x01, 0xff  /* BOOL */
  };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          der_encoded, sizeof (der_encoded))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_SEQUENCE);

  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_SET);

  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_SEQUENCE);

  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_PRIMITIVE);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_BOOLEAN);

  /* next gives EOC, so it will basically takes us out and up one level */
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_EOC);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_SEQUENCE);

  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_PRIMITIVE);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_BOOLEAN);

  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_SEQUENCE);

  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_EOS);
  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, x500_distinguished_name, RTEST_FAST)
{
  static ruint8 der_encoded[] = { 0x30, 0x43,
    0x31, 0x13, 0x30, 0x11,
      /* oid 0.9.2342.19200300.100.1.25 */
      0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19,
      0x16, 0x03, 0x63, 0x6f, 0x6d, /* "com" */
    0x31, 0x17, 0x30, 0x15,
      /* oid 0.9.2342.19200300.100.1.25 */
      0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19,
      0x16, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, /* "example" */
    0x31, 0x13, 0x30, 0x11,
      0x06, 0x03, 0x55, 0x04, 0x03, /* oid 2.5.4.3 */
      /* "Example CA" */
      0x13, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41
  };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rchar * dn;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          der_encoded, sizeof (der_encoded))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);

  r_assert_cmpint (r_asn1_bin_tlv_parse_distinguished_name (dec, &tlv, &dn), ==,
      R_ASN1_DECODER_EOS);
  r_assert_cmpstr (dn, ==, "CN=Example CA,DC=example,DC=com");
  r_free (dn);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

