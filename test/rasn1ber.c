#include <rlib/rlib.h>

RTEST (rasn1ber, new, RTEST_FAST)
{
  static ruint8 foobar[] = { 0x30, 0x80, 0x00, 0x00 };
  RAsn1BinDecoder * dec;

  r_assert_cmpptr (r_asn1_bin_decoder_new (R_ASN1_BER, NULL, 42), ==, NULL);
  r_assert_cmpptr (r_asn1_bin_decoder_new (R_ASN1_BER, foobar, 0), ==, NULL);
  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER,
          foobar, sizeof (foobar))), !=, NULL);
  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1ber, sequence_primitives, RTEST_FAST)
{
  static ruint8 ber_encoded[] = { 0x30, 0x80,
    0x01, 0x01, 0xff, /* BOOL */
    0x02, 0x01, 0x2a, /* INTEGER */
    0x02, 0x10, 0x2f, 0xa1, 0x76, 0xb3, 0x6e, 0xe9, 0xf0, 0x49,
    0xf4, 0x44, 0xb4, 0x00, 0x99, 0x66, 0x19, 0x45, /* INTEGER */
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01, /* OBEJCT IDENTIFIER */
    0x00, 0x00 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rboolean v_bool;
  rint32 v_int;
  rmpint v_mpint;
  ruint32 v_oid[8];
  rsize size_oid = R_N_ELEMENTS (v_oid);
  rchar * str_oid;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER,
          ber_encoded, sizeof (ber_encoded))), !=, NULL);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_SEQUENCE);

  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_PRIMITIVE);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_BOOLEAN);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i32 (&tlv, &v_int), ==, R_ASN1_DECODER_WRONG_TYPE);
  r_assert_cmpint (r_asn1_bin_tlv_parse_boolean (&tlv, &v_bool), ==, R_ASN1_DECODER_OK);
  r_assert (v_bool);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_PRIMITIVE);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_INTEGER);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i32 (&tlv, &v_int), ==, R_ASN1_DECODER_OK);
  r_assert_cmpint (v_int, ==, 42);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_PRIMITIVE);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_INTEGER);
  r_mpint_init (&v_mpint);
  r_assert_cmpint (r_asn1_bin_tlv_parse_boolean (&tlv, &v_bool), ==, R_ASN1_DECODER_WRONG_TYPE);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i32 (&tlv, &v_int), ==, R_ASN1_DECODER_OVERFLOW);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_mpint (&tlv, &v_mpint), ==, R_ASN1_DECODER_OK);
  r_mpint_clear (&v_mpint);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_PRIMITIVE);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_OBJECT_IDENTIFIER);
  r_assert_cmpint (r_asn1_bin_tlv_parse_oid (&tlv, v_oid, &size_oid), ==, R_ASN1_DECODER_OK);
  /* 1.2.840.113549.1.7.1 */
  r_assert_cmpuint (size_oid, ==, 7);
  r_assert_cmpuint (v_oid[0], ==, 1);
  r_assert_cmpuint (v_oid[1], ==, 2);
  r_assert_cmpuint (v_oid[2], ==, 840);
  r_assert_cmpuint (v_oid[3], ==, 113549);
  r_assert_cmpuint (v_oid[4], ==, 1);
  r_assert_cmpuint (v_oid[5], ==, 7);
  r_assert_cmpuint (v_oid[6], ==, 1);
  r_assert_cmpint (r_asn1_bin_tlv_parse_oid_to_dot (&tlv, &str_oid), ==, R_ASN1_DECODER_OK);
  r_assert_cmpstr (str_oid, ==, "1.2.840.113549.1.7.1");
  r_free (str_oid);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_CLASS (&tlv), ==, R_ASN1_ID_UNIVERSAL);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_PRIMITIVE);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_EOC);

  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_EOS);
  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1ber, invalid_decode_args, RTEST_FAST)
{
  static ruint8 ber_encoded[] = { 0x30, 0x80,
    0x01, 0x01, 0xff, /* BOOL */
    0x00, 0x00 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER,
          ber_encoded, sizeof (ber_encoded))), !=, NULL);

  r_assert_cmpint (r_asn1_bin_decoder_next (NULL, &tlv), ==, R_ASN1_DECODER_INVALID_ARG);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, NULL), ==, R_ASN1_DECODER_INVALID_ARG);

  r_assert_cmpint (r_asn1_bin_decoder_into (NULL, &tlv), ==, R_ASN1_DECODER_INVALID_ARG);
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, NULL), ==, R_ASN1_DECODER_INVALID_ARG);
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_INVALID_ARG);

  r_assert_cmpint (r_asn1_bin_decoder_out (NULL, &tlv), ==, R_ASN1_DECODER_INVALID_ARG);
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, NULL), ==, R_ASN1_DECODER_INVALID_ARG);
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_INVALID_ARG);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_INVALID_ARG);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_EOS);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1ber, incomplete_stream, RTEST_FAST)
{
  static ruint8 ber_encoded[] = { 0x30, 0x80,
    0x01, 0x01, 0xff, /* BOOL */
    0x02, 0x01, 0x2a, /* INTEGER */
    /*0x00, 0x00*/ };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER,
          ber_encoded, sizeof (ber_encoded))), !=, NULL);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OVERFLOW);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1ber, sequence_definite_length, RTEST_FAST)
{
  static ruint8 ber_encoded[] = { 0x30, 0x80,
    0x30, 0x06,
      0x01, 0x01, 0xff, /* BOOL */
      0x02, 0x01, 0x2a, /* INTEGER */
    0x02, 0x01, 0x02, /* INTEGER */
    0x00, 0x00 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rint32 v_int;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER,
          ber_encoded, sizeof (ber_encoded))), !=, NULL);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONSTRUCTED | R_ASN1_ID_SEQUENCE));
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONSTRUCTED | R_ASN1_ID_SEQUENCE));
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_BOOLEAN));
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i32 (&tlv, &v_int), ==, R_ASN1_DECODER_OK);
  r_assert_cmpint (v_int, ==, 42);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_EOC);
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i32 (&tlv, &v_int), ==, R_ASN1_DECODER_OK);
  r_assert_cmpint (v_int, ==, 2);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_EOC));
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_EOS);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1ber, stop_no_leak, RTEST_FAST)
{
  static ruint8 ber_encoded[] = { 0x30, 0x80,
    0x30, 0x06,
      0x01, 0x01, 0xff, /* BOOL */
      0x02, 0x01, 0x2a, /* INTEGER */
    0x02, 0x01, 0x02, /* INTEGER */
    0x00, 0x00 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER,
          ber_encoded, sizeof (ber_encoded))), !=, NULL);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONSTRUCTED | R_ASN1_ID_SEQUENCE));
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONSTRUCTED | R_ASN1_ID_SEQUENCE));
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_BOOLEAN));
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1ber, constructed_definite_long_form, RTEST_FAST)
{
  static ruint8 ber_encoded[] = {
    0x30, 0x81, 0x06,
      0x01, 0x01, 0xff, /* BOOL */
      0x02, 0x01, 0x2a /* INTEGER */
    };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER,
          ber_encoded, sizeof (ber_encoded))), !=, NULL);

  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_IS_ID (&tlv, R_ASN1_ID_CONSTRUCTED | R_ASN1_ID_SEQUENCE));
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_BOOLEAN));
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

