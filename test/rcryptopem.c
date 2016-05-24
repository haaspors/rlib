#include <rlib/rlib.h>

static const rchar pem_invalid[] =
  "---BEGIN PRIVATE KEY-----\n"
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0\n"
  "FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/\n"
  "3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB\n"
  "-----END PRIVATE KEY-----\n";

RTEST (rcryptopem, invalid, RTEST_FAST)
{
  RPemParser * parser;

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_invalid, sizeof (pem_invalid))), !=, NULL);
  r_assert_cmpptr (r_pem_parser_next_block (parser), == , NULL);

  r_pem_parser_unref (parser);
}
RTEST_END;

static const rchar pem_pubkey[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0\n"
  "FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/\n"
  "3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB\n"
  "-----END PUBLIC KEY-----\n";
static const ruint8 raw_pubkey[] =
{
  0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xaa, 0x18, 0xab,
  0xa4, 0x3b, 0x50, 0xde, 0xef, 0x38, 0x59, 0x8f, 0xaf, 0x87, 0xd2, 0xab, 0x63, 0x4e, 0x45, 0x71,
  0xc1, 0x30, 0xa9, 0xbc, 0xa7, 0xb8, 0x78, 0x26, 0x74, 0x14, 0xfa, 0xab, 0x8b, 0x47, 0x1b, 0xd8,
  0x96, 0x5f, 0x5c, 0x9f, 0xc3, 0x81, 0x84, 0x85, 0xea, 0xf5, 0x29, 0xc2, 0x62, 0x46, 0xf3, 0x05,
  0x50, 0x64, 0xa8, 0xde, 0x19, 0xc8, 0xc3, 0x38, 0xbe, 0x54, 0x96, 0xcb, 0xae, 0xb0, 0x59, 0xdc,
  0x0b, 0x35, 0x81, 0x43, 0xb4, 0x4a, 0x35, 0x44, 0x9e, 0xb2, 0x64, 0x11, 0x31, 0x21, 0xa4, 0x55,
  0xbd, 0x7f, 0xde, 0x3f, 0xac, 0x91, 0x9e, 0x94, 0xb5, 0x6f, 0xb9, 0xbb, 0x4f, 0x65, 0x1c, 0xdb,
  0x23, 0xea, 0xd4, 0x39, 0xd6, 0xcd, 0x52, 0x3e, 0xb0, 0x81, 0x91, 0xe7, 0x5b, 0x35, 0xfd, 0x13,
  0xa7, 0x41, 0x9b, 0x30, 0x90, 0xf2, 0x47, 0x87, 0xbd, 0x4f, 0x4e, 0x19, 0x67, 0x02, 0x03, 0x01,
  0x00, 0x01
};

RTEST (rcryptopem, parser_block_basics, RTEST_FAST)
{
  RPemParser * parser;
  RPemBlock * block;
  rchar * base64;
  ruint8 * raw;
  rsize size;
  RAsn1DerDecoder * der;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint32 oid[8];
  const ruint32 rsapubkeyoid[] = { 1, 2, 840, 113549, 1, 1, 1 };

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_pubkey, sizeof (pem_pubkey))), !=, NULL);
  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), != , NULL);
  r_assert_cmpuint (r_pem_block_get_type (block), ==, R_PEM_TYPE_PUBLIC_KEY);
  r_assert (r_pem_block_is_key (block));
  r_assert (!r_pem_block_is_encrypted (block));
  r_assert_cmpuint (r_pem_block_get_blob_size (block), ==, 219);
  r_assert_cmpuint (r_pem_block_get_base64_size (block), ==, 219);

  r_assert_cmpptr ((base64 = r_pem_block_get_base64 (block, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, 219);
  r_assert_cmpstr (base64, ==,
      "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0\n"
      "FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/\n"
      "3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB\n");
  r_free (base64);

  r_assert_cmpptr ((raw = r_pem_block_decode_base64 (block, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, ((219 - 3) / 4 ) * 3); /* = 162 */
  r_assert_cmpmem (raw, ==, raw_pubkey, size);
  r_free (raw);

  r_assert_cmpptr ((der = r_pem_block_get_der_decoder (block)), !=, NULL);
  r_assert_cmpint (r_asn1_der_decoder_next (der, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpint (r_asn1_der_decoder_into (der, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpint (r_asn1_der_decoder_into (der, &tlv), ==, R_ASN1_DECODER_OK);
  size = sizeof (oid);
  r_assert_cmpint (r_asn1_der_tlv_parse_oid (&tlv, oid, &size), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (size, ==, 7);
  r_assert_cmpmem (oid, ==, rsapubkeyoid, size);
  r_assert_cmpint (r_asn1_der_decoder_out (der, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_BIT_STRING);
  r_assert_cmpint (r_asn1_der_decoder_into (der, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpint (r_asn1_der_decoder_into (der, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_INTEGER);
  r_assert_cmpint (r_asn1_der_decoder_next (der, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_INTEGER);
  r_asn1_der_decoder_unref (der);

  r_pem_block_unref (block);
  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), == , NULL);
  r_pem_parser_unref (parser);
}
RTEST_END;

static const rchar pem_multiple[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0\n"
  "FPqri0cb2JZfXJ/DgYSF6vUpwmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/\n"
  "3j+skZ6UtW+5u09lHNsj6tQ51s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQAB\n"
  "-----END PUBLIC KEY-----\n"
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIICXAIBAAKBgQCqGKukO1De7zhZj6+H0qtjTkVxwTCpvKe4eCZ0FPqri0cb2JZfXJ/DgYSF6vUp\n"
  "wmJG8wVQZKjeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1/3j+skZ6UtW+5u09lHNsj6tQ5\n"
  "1s1SPrCBkedbNf0Tp0GbMJDyR4e9T04ZZwIDAQABAoGAFijko56+qGyN8M0RVyaRAXz++xTqHBLh\n"
  "3tx4VgMtrQ+WEgCjhoTwo23KMBAuJGSYnRmoBZM3lMfTKevIkAidPExvYCdm5dYq3XToLkkLv5L2\n"
  "pIIVOFMDG+KESnAFV7l2c+cnzRMW0+b6f8mR1CJzZuxVLL6Q02fvLi55/mbSYxECQQDeAw6fiIQX\n"
  "GukBI4eMZZt4nscy2o12KyYner3VpoeE+Np2q+Z3pvAMd/aNzQ/W9WaI+NRfcxUJrmfPwIGm63il\n"
  "AkEAxCL5HQb2bQr4ByorcMWm/hEP2MZzROV73yF41hPsRC9m66KrheO9HPTJuo3/9s5p+sqGxOlF\n"
  "L0NDt4SkosjgGwJAFklyR1uZ/wPJjj611cdBcztlPdqoxssQGnh85BzCj/u3WqBpE2vjvyyvyI5k\n"
  "X6zk7S0ljKtt2jny2+00VsBerQJBAJGC1Mg5Oydo5NwD6BiROrPxGo2bpTbu/fhrT8ebHkTz2epl\n"
  "U9VQQSQzY1oZMVX8i1m5WUTLPz2yLJIBQVdXqhMCQBGoiuSoSjafUhV7i1cEGpb88h5NBYZzWXGZ\n"
  "37sJ5QsW+sJyoNde3xH8vdXhzU7eT82D6X/scw9RZz+/6rCJ4p0=\n"
  "-----END RSA PRIVATE KEY-----\n";
RTEST (rcryptopem, multiple_blocks, RTEST_FAST)
{
  RPemParser * parser;
  RPemBlock * block;

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_multiple, sizeof (pem_multiple))), !=, NULL);
  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), != , NULL);
  r_assert_cmpuint (r_pem_block_get_type (block), ==, R_PEM_TYPE_PUBLIC_KEY);
  r_assert (r_pem_block_is_key (block));
  r_pem_block_unref (block);

  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), != , NULL);
  r_assert_cmpuint (r_pem_block_get_type (block), ==, R_PEM_TYPE_RSA_PRIVATE_KEY);
  r_assert (r_pem_block_is_key (block));
  r_pem_block_unref (block);

  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), == , NULL);
  r_pem_parser_unref (parser);
}
RTEST_END;

