#include <rlib/rasn1.h>

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

  /* next gives EOC, so we will need to go out */
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_EOC);
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_OK);
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

RTEST (rasn1der, time, RTEST_FAST)
{
  static const struct {
    ruint64 expected;
    const ruint8 data[25];
  } cases[] = {
    /* UTC-TIME in form YYMMDDhhmmssZ */
    { 1262334600, { 0x17, 0x0d, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x30, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { 1924936200, { 0x17, 0x0d, 0x33, 0x30, 0x31, 0x32, 0x33, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x30, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { 1224083021, { 0x17, 0x0d, 0x30, 0x38, 0x31, 0x30, 0x31, 0x35, 0x31, 0x35, 0x30, 0x33, 0x34, 0x31, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* UTC-TIME in form YYMMDDhhmmZ */
    { 1262334600, { 0x17, 0x0b, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x30, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { 1924936200, { 0x17, 0x0b, 0x33, 0x30, 0x31, 0x32, 0x33, 0x31, 0x30, 0x38, 0x33, 0x30, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { 1224082980, { 0x17, 0x0b, 0x30, 0x38, 0x31, 0x30, 0x31, 0x35, 0x31, 0x35, 0x30, 0x33, 0x5a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    /* UTC-TIME in form YYMMDDhhmmss[+\-]hhmm */
    { 1262327400, { 0x17, 0x11, 0x31, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x38, 0x33, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { 1924900200, { 0x17, 0x11, 0x33, 0x30, 0x31, 0x32, 0x33, 0x31, 0x30, 0x36, 0x33, 0x30, 0x30, 0x30, 0x2b, 0x30, 0x38, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    { 1224126221, { 0x17, 0x11, 0x30, 0x38, 0x31, 0x30, 0x31, 0x35, 0x32, 0x33, 0x30, 0x33, 0x34, 0x31, 0x2d, 0x30, 0x34, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },

    /* GENERALIZED-TIME */
    {  978296399, { 0x18, 0x13, 0x32, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x30, 0x35, 0x39, 0x35, 0x39, 0x2e, 0x39, 0x39, 0x39, 0x5a, 0x00, 0x00, 0x00, 0x00 } },
    {  978289199, { 0x18, 0x17, 0x32, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x30, 0x35, 0x39, 0x35, 0x39, 0x2e, 0x39, 0x39, 0x39, 0x2b, 0x30, 0x32, 0x30, 0x30 } },
    {  978289199, { 0x18, 0x13, 0x32, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x30, 0x35, 0x39, 0x35, 0x39, 0x2b, 0x30, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00 } },
    {  978289140, { 0x18, 0x11, 0x32, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x30, 0x35, 0x39, 0x2b, 0x30, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
    {  978285600, { 0x18, 0x0f, 0x32, 0x30, 0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x30, 0x2b, 0x30, 0x32, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
  };
  ruint i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    RAsn1BinDecoder * dec;
    RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
    ruint64 res;

    r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
            cases[i].data, sizeof (cases[i].data))), !=, NULL);
    r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);

    r_assert_cmpint (r_asn1_bin_tlv_parse_time (&tlv, &res), ==, R_ASN1_DECODER_OK);
    r_assert_cmpuint (res, ==, cases[i].expected);
    r_asn1_bin_decoder_unref (dec);
  }
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

RTEST (rasn1der, parse_bit_string, RTEST_FAST)
{
  static ruint8 der_encoded[] = { 0x03, 0x02, 0x04, 0xf0 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  RBitset * bitset = NULL;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          der_encoded, sizeof (der_encoded))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);

  r_assert_cmpuint (tlv.len, ==, 2);
  r_assert_cmpint (r_asn1_bin_tlv_parse_bit_string (&tlv, &bitset), ==,
      R_ASN1_DECODER_OK);
  r_assert_cmpptr (bitset, !=, NULL);
  r_assert_cmpuint (bitset->bits, ==, 4);
  r_assert_cmpuint (r_bitset_popcount (bitset), ==, 4);
  r_free (bitset);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, parse_integer_small, RTEST_FAST)
{
  static const ruint8 int_u8[] = { 0x02, 0x01, 0x02 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint bits;
  rboolean unsign;
  rint32 i32;
  ruint32 u32;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, int_u8, sizeof (int_u8))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);

  r_assert_cmpint (R_ASN1_DECODER_OK, ==,
      r_asn1_bin_tlv_parse_integer_bits (&tlv, &bits, &unsign));
  r_assert_cmpuint (bits, ==, 8);
  r_assert (unsign);
  r_assert_cmpint (R_ASN1_DECODER_OK, ==,
      r_asn1_bin_tlv_parse_integer_i32 (&tlv, &i32));
  r_assert_cmpint (i32, ==, 2);
  r_assert_cmpint (R_ASN1_DECODER_OK, ==,
      r_asn1_bin_tlv_parse_integer_u32 (&tlv, &u32));
  r_assert_cmpuint (u32, ==, 2);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, parse_time_out_of_range, RTEST_FAST)
{
  /* Hour, minute, second, and timezone offset components have spec
   * ranges that the parser must reject when violated. *time must not
   * be written on the error path. */
  static const struct {
    rsize size;
    ruint8 data[20];
  } cases[] = {
    /* UTC-TIME hh=25 (>= 24): 250101253000Z */
    { 15, { 0x17, 0x0d, '2','5','0','1','0','1','2','5','3','0','0','0','Z' } },
    /* UTC-TIME mm=60 (>= 60): 100101086000Z */
    { 15, { 0x17, 0x0d, '1','0','0','1','0','1','0','8','6','0','0','0','Z' } },
    /* UTC-TIME ss=60 (>= 60): 100101083060Z */
    { 15, { 0x17, 0x0d, '1','0','0','1','0','1','0','8','3','0','6','0','Z' } },
    /* UTC-TIME offset hd=25 (>= 24): 100101083000+2500 */
    { 19, { 0x17, 0x11, '1','0','0','1','0','1','0','8','3','0','0','0',
            '+','2','5','0','0' } },
    /* UTC-TIME offset md=60 (>= 60): 100101083000+0260 */
    { 19, { 0x17, 0x11, '1','0','0','1','0','1','0','8','3','0','0','0',
            '+','0','2','6','0' } },
  };
  ruint i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    RAsn1BinDecoder * dec;
    RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
    ruint64 res = 0xdeadbeef;

    r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
            cases[i].data, cases[i].size)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
    r_assert_cmpint (r_asn1_bin_tlv_parse_time (&tlv, &res), !=, R_ASN1_DECODER_OK);
    r_assert_cmpuint (res, ==, 0xdeadbeef);
    r_asn1_bin_decoder_unref (dec);
  }
}
RTEST_END;

RTEST (rasn1der, parse_time_heap_buffer, RTEST_FAST)
{
  /* Decode UTC_TIME from a heap buffer so the encoded byte after the
   * last digit is NOT zero-initialized. r_strscanf uses vsscanf which
   * expects a NUL-terminated string; this probes whether the time
   * parser reads past tlv->value + tlv->len. */
  static const ruint8 encoded[] = { 0x17, 0x0A,
      '9', '6', '0', '4', '2', '2', '1', '0', '0', '0' };
  ruint8 * buf = r_memdup (encoded, sizeof (encoded));
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint64 t = 0;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          buf, sizeof (encoded))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_UTC_TIME));
  r_assert_cmpint (r_asn1_bin_tlv_parse_time (&tlv, &t), ==, R_ASN1_DECODER_OK);

  r_asn1_bin_decoder_unref (dec);
  r_free (buf);
}
RTEST_END;

RTEST (rasn1der, parse_empty_bit_string, RTEST_FAST)
{
  /* BIT STRING with zero content bytes. parse_bit_string_bits used
   * to dereference tlv->value[0] unconditionally and compute
   * (tlv->len - 1) * 8 - value[0] which wraps when tlv->len == 0. */
  static const ruint8 encoded[] = { 0x03, 0x00 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rsize bits;
  RBitset * bitset = NULL;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          encoded, sizeof (encoded))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_BIT_STRING));
  r_assert_cmpuint (tlv.len, ==, 0);

  r_assert_cmpint (r_asn1_bin_tlv_parse_bit_string_bits (&tlv, &bits),
      !=, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_tlv_parse_bit_string (&tlv, &bitset),
      !=, R_ASN1_DECODER_OK);
  r_assert_cmpptr (bitset, ==, NULL);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, parse_oid_malformed, RTEST_FAST)
{
  /* Three malformed OID encodings the parser must reject. */
  static const ruint8 empty[]      = { 0x06, 0x00 };
  static const ruint8 trailing_c[] = { 0x06, 0x01, 0x80 };
  static const ruint8 all_c[]      = { 0x06, 0x03, 0x80, 0x80, 0x80 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv;
  ruint32 v[8];
  rsize n;

  tlv = (RAsn1BinTLV)R_ASN1_BIN_TLV_INIT;
  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          empty, sizeof (empty))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_OBJECT_IDENTIFIER));
  n = R_N_ELEMENTS (v);
  r_assert_cmpint (r_asn1_bin_tlv_parse_oid (&tlv, v, &n), !=, R_ASN1_DECODER_OK);
  r_asn1_bin_decoder_unref (dec);

  tlv = (RAsn1BinTLV)R_ASN1_BIN_TLV_INIT;
  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          trailing_c, sizeof (trailing_c))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_OBJECT_IDENTIFIER));
  n = R_N_ELEMENTS (v);
  r_assert_cmpint (r_asn1_bin_tlv_parse_oid (&tlv, v, &n), !=, R_ASN1_DECODER_OK);
  r_asn1_bin_decoder_unref (dec);

  tlv = (RAsn1BinTLV)R_ASN1_BIN_TLV_INIT;
  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          all_c, sizeof (all_c))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_OBJECT_IDENTIFIER));
  n = R_N_ELEMENTS (v);
  r_assert_cmpint (r_asn1_bin_tlv_parse_oid (&tlv, v, &n), !=, R_ASN1_DECODER_OK);
  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, parse_empty_integer, RTEST_FAST)
{
  /* An INTEGER TLV with length 0 is malformed per spec, but the
   * decoder currently accepts it. Parse functions must not read
   * tlv->value[0] when tlv->len is 0. */
  static const ruint8 encoded[] = { 0x02, 0x00 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  rint32 i32;
  ruint32 u32;
  rint64 i64;
  ruint64 u64;
  ruint bits;
  rboolean unsign;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          encoded, sizeof (encoded))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));
  r_assert_cmpuint (tlv.len, ==, 0);

  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_bits (&tlv, &bits, &unsign),
      !=, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i32 (&tlv, &i32),
      !=, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_u32 (&tlv, &u32),
      !=, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i64 (&tlv, &i64),
      !=, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_tlv_parse_integer_u64 (&tlv, &u64),
      !=, R_ASN1_DECODER_OK);

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, length_long_form_truncated, RTEST_FAST)
{
  /* Long-form length declares N value-bytes follow, but the buffer
   * has fewer than N trailing bytes. The decoder must reject without
   * reading past the end of the input. */
  static const ruint8 trunc_1[] = { 0x04, 0x81 };
  static const ruint8 trunc_2[] = { 0x04, 0x82, 0x00 };
  static const ruint8 trunc_4[] = { 0x04, 0x84, 0x00, 0x00, 0x00 };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv;

  tlv = (RAsn1BinTLV)R_ASN1_BIN_TLV_INIT;
  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          trunc_1, sizeof (trunc_1))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OVERFLOW);
  r_asn1_bin_decoder_unref (dec);

  tlv = (RAsn1BinTLV)R_ASN1_BIN_TLV_INIT;
  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          trunc_2, sizeof (trunc_2))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OVERFLOW);
  r_asn1_bin_decoder_unref (dec);

  tlv = (RAsn1BinTLV)R_ASN1_BIN_TLV_INIT;
  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER,
          trunc_4, sizeof (trunc_4))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OVERFLOW);
  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, parse_integer_unsigned_16, RTEST_FAST)
{
  static const ruint8 int_s8[] = { 0x02, 0x02, 0xc0, 0xff };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint bits;
  rboolean unsign;
  rint32 i32;
  ruint32 u32;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, int_s8, sizeof (int_s8))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);

  r_assert_cmpint (R_ASN1_DECODER_OK, ==,
      r_asn1_bin_tlv_parse_integer_bits (&tlv, &bits, &unsign));
  r_assert_cmpuint (bits, ==, 16);
  r_assert (!unsign);
  r_assert_cmpint (R_ASN1_DECODER_OK, ==,
      r_asn1_bin_tlv_parse_integer_i32 (&tlv, &i32));
  r_assert_cmpint (i32, ==, -16129);
  r_assert_cmpint (R_ASN1_DECODER_OVERFLOW, ==,
      r_asn1_bin_tlv_parse_integer_u32 (&tlv, &u32));

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

RTEST (rasn1der, parse_integer_unsigned_64_full, RTEST_FAST)
{
  static const ruint8 int_64[] = { 0x02, 0x09, 0x00, 0x83, 0x72, 0x37, 0xd9, 0xef, 0x01, 0xd1, 0x2f };
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint bits;
  rboolean unsign;
  rint32 i32;
  ruint32 u32;
  rint64 i64;
  ruint64 u64;

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, int_64, sizeof (int_64))), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);

  r_assert_cmpint (R_ASN1_DECODER_OK, ==,
      r_asn1_bin_tlv_parse_integer_bits (&tlv, &bits, &unsign));
  r_assert_cmpuint (bits, ==, 64);
  r_assert (unsign);
  r_assert_cmpint (R_ASN1_DECODER_OVERFLOW, ==,
      r_asn1_bin_tlv_parse_integer_i32 (&tlv, &i32));
  r_assert_cmpint (R_ASN1_DECODER_OVERFLOW, ==,
      r_asn1_bin_tlv_parse_integer_u32 (&tlv, &u32));
  r_assert_cmpint (R_ASN1_DECODER_OVERFLOW, ==,
      r_asn1_bin_tlv_parse_integer_i64 (&tlv, &i64));
  r_assert_cmpint (R_ASN1_DECODER_OK, ==,
      r_asn1_bin_tlv_parse_integer_u64 (&tlv, &u64));
  r_assert_cmpuint (u64, ==, RUINT64_CONSTANT (9471694375470879023));

  r_asn1_bin_decoder_unref (dec);
}
RTEST_END;

