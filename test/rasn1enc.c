#include <rlib/rasn1.h>

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


RTEST (rasn1enc_der, distinguished_name_escaped_comma, RTEST_FAST)
{
  /* DN value with an escaped comma. The inner loop that scans
   * backwards for an unescaped comma used to be an infinite spin
   * because it kept calling r_strnrchr with the same arguments. */
  RAsn1BinEncoder * enc;
  ruint8 * out;
  rsize size;

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpint (r_asn1_bin_encoder_add_distinguished_name (enc,
        "CN=Foo\\,Bar,O=Acme"), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);

  r_free (out);
  r_asn1_bin_encoder_unref (enc);
}
RTEST_END;

RTEST (rasn1enc_der, utc_time_with_seconds, RTEST_FAST)
{
  /* UTC_TIME with non-zero seconds writes "YYMMDDhhmmssZ" via
   * r_sprintf (13 chars + NUL = 14 bytes) but the encoder maps
   * only 2 + 12 + 1 = 15 bytes total, with 13 reserved for the
   * string. The NUL byte overflows by one. */
  RAsn1BinEncoder * enc;
  ruint8 * out;
  rsize size;
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint64 t = 1224083021ULL;  /* 2008-10-15 15:03:41 UTC */
  ruint64 round = 0;

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpint (r_asn1_bin_encoder_add_utc_time (enc, t), ==, R_ASN1_ENCODER_OK);
  r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, out, size)), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpint (r_asn1_bin_tlv_parse_time (&tlv, &round), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (round, ==, t);

  r_asn1_bin_decoder_unref (dec);
  r_free (out);
  r_asn1_bin_encoder_unref (enc);
}
RTEST_END;

RTEST (rasn1enc_der, integer_roundtrip_u32, RTEST_FAST)
{
  /* Roundtrip various unsigned 32-bit values through encoder/decoder. */
  static const ruint32 cases[] = {
    0, 1, 127, 128, 255, 256, 0x12FF, 0x80, 0x8000, 0x800000, 0x80000000,
    0x12345678, 0x12FF, 0xCAFEBABEu, 0xFFFFFFFFu,
  };
  ruint i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    RAsn1BinEncoder * enc;
    RAsn1BinDecoder * dec;
    RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
    ruint8 * out;
    rsize size;
    ruint32 round = 0;

    r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_encoder_add_integer_u32 (enc, cases[i]),
        ==, R_ASN1_ENCODER_OK);
    r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);

    r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, out, size)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
    r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));
    r_assert_cmpint (r_asn1_bin_tlv_parse_integer_u32 (&tlv, &round),
        ==, R_ASN1_DECODER_OK);
    r_assert_cmpuint (round, ==, cases[i]);

    r_asn1_bin_decoder_unref (dec);
    r_free (out);
    r_asn1_bin_encoder_unref (enc);
  }
}
RTEST_END;

RTEST (rasn1enc_der, integer_roundtrip_u64, RTEST_FAST)
{
  static const ruint64 cases[] = {
    0, 1, 127, 128, 255, 256, 0x12FF, 0x8000, 0x800000,
    RUINT64_CONSTANT (0x80000000),
    RUINT64_CONSTANT (0x8000000000),
    RUINT64_CONSTANT (0x800000000000),
    RUINT64_CONSTANT (0x80000000000000),
    RUINT64_CONSTANT (0x8000000000000000),
    RUINT64_CONSTANT (0xFFFFFFFFFFFFFFFF),
  };
  ruint i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    RAsn1BinEncoder * enc;
    RAsn1BinDecoder * dec;
    RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
    ruint8 * out;
    rsize size;
    ruint64 round = 0;

    r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_encoder_add_integer_u64 (enc, cases[i]),
        ==, R_ASN1_ENCODER_OK);
    r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);

    r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, out, size)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
    r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));
    r_assert_cmpint (r_asn1_bin_tlv_parse_integer_u64 (&tlv, &round),
        ==, R_ASN1_DECODER_OK);
    r_assert_cmpuint (round, ==, cases[i]);

    r_asn1_bin_decoder_unref (dec);
    r_free (out);
    r_asn1_bin_encoder_unref (enc);
  }
}
RTEST_END;

RTEST (rasn1enc_der, integer_roundtrip_negative, RTEST_FAST)
{
  static const rint64 cases[] = {
    -1, -127, -128, -129, -255, -256, -32768, -32769,
    -8388608LL, -8388609LL,
    -2147483647LL - 1,
    -2147483648LL - 1LL,
    -549755813888LL,
    -140737488355328LL,
  };
  ruint i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    RAsn1BinEncoder * enc;
    RAsn1BinDecoder * dec;
    RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
    ruint8 * out;
    rsize size;
    rint64 round = 0;

    r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_encoder_add_integer_i64 (enc, cases[i]),
        ==, R_ASN1_ENCODER_OK);
    r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);

    r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, out, size)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
    r_assert (R_ASN1_BIN_TLV_ID_IS_TAG (&tlv, R_ASN1_ID_INTEGER));
    r_assert_cmpint (r_asn1_bin_tlv_parse_integer_i64 (&tlv, &round),
        ==, R_ASN1_DECODER_OK);
    r_assert_cmpint (round, ==, cases[i]);

    r_asn1_bin_decoder_unref (dec);
    r_free (out);
    r_asn1_bin_encoder_unref (enc);
  }
}
RTEST_END;

RTEST (rasn1enc_der, integer_roundtrip_negative_mpint, RTEST_FAST)
{
  /* Encode negative mpints; verify the bytes match the expected DER and
   * round-trip back through the mpint decoder. */
  static const struct {
    const rchar * magnitude;  /* decimal string of |value| */
    rsize expected_size;      /* total DER bytes including tag+len */
    ruint8 expected[12];
  } cases[] = {
    /* -1 */
    { "1", 3, { 0x02, 0x01, 0xff } },
    /* -127: 0x81 */
    { "127", 3, { 0x02, 0x01, 0x81 } },
    /* -128: 0x80 (magnitude is exact power of 2) */
    { "128", 3, { 0x02, 0x01, 0x80 } },
    /* -129: 0xFF 0x7F (extra byte needed) */
    { "129", 4, { 0x02, 0x02, 0xff, 0x7f } },
    /* -256: 0xFF 0x00 */
    { "256", 4, { 0x02, 0x02, 0xff, 0x00 } },
    /* -32768: 0x80 0x00 (exact power of 2) */
    { "32768", 4, { 0x02, 0x02, 0x80, 0x00 } },
    /* -2^40 = 0xFF 00 00 00 00 00 (six bytes) */
    { "1099511627776", 8, { 0x02, 0x06, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 } },
  };
  ruint i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    RAsn1BinEncoder * enc;
    RAsn1BinDecoder * dec;
    RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
    rmpint v, round;
    ruint8 * out;
    rsize size;

    r_mpint_init_str (&v, cases[i].magnitude, NULL, 10);
    v.sign = 1;  /* make it negative */

    r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_encoder_add_integer_mpint (enc, &v),
        ==, R_ASN1_ENCODER_OK);
    r_assert_cmpptr ((out = r_asn1_bin_encoder_get_data (enc, &size)), !=, NULL);
    r_assert_cmpuint (size, ==, cases[i].expected_size);
    r_assert_cmpmem (out, ==, cases[i].expected, size);

    r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, out, size)), !=, NULL);
    r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
    r_mpint_init (&round);
    r_assert_cmpint (r_asn1_bin_tlv_parse_integer_mpint (&tlv, &round),
        ==, R_ASN1_DECODER_OK);
    r_assert_cmpuint (round.sign, ==, 1);
    r_assert_cmpint (r_mpint_ucmp (&round, &v), ==, 0);

    r_asn1_bin_decoder_unref (dec);
    r_free (out);
    r_asn1_bin_encoder_unref (enc);
    r_mpint_clear (&v);
    r_mpint_clear (&round);
  }
}
RTEST_END;
