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

