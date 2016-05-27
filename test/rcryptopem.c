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

static const rchar pem_rsa_pubkey[] =
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
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint32 oid[8];
  const ruint32 rsapubkeyoid[] = { 1, 2, 840, 113549, 1, 1, 1 };

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_rsa_pubkey, sizeof (pem_rsa_pubkey))), !=, NULL);
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

  r_assert_cmpptr ((dec = r_pem_block_get_asn1_decoder (block)), !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  size = sizeof (oid);
  r_assert_cmpint (r_asn1_bin_tlv_parse_oid (&tlv, oid, &size), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (size, ==, 7);
  r_assert_cmpmem (oid, ==, rsapubkeyoid, size);
  r_assert_cmpint (r_asn1_bin_decoder_out (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_BIT_STRING);
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_PC (&tlv), ==, R_ASN1_ID_CONSTRUCTED);
  r_assert_cmpint (r_asn1_bin_decoder_into (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_INTEGER);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpuint (R_ASN1_BIN_TLV_ID_TAG (&tlv), ==, R_ASN1_ID_INTEGER);
  r_asn1_bin_decoder_unref (dec);

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

RTEST (rcryptopem, rsa_pubkey, RTEST_FAST)
{
  RPemParser * parser;
  RPemBlock * block;
  RCryptoKey * key;
  rmpint mpint, mod;

  r_mpint_init (&mpint);
  r_mpint_init_str (&mod,
      "0x00aa18aba43b50deef38598faf87d2ab634e4571c130a9bca7b878267414faab8b47"
      "1bd8965f5c9fc3818485eaf529c26246f3055064a8de19c8c338be5496cbaeb059dc0b"
      "358143b44a35449eb264113121a455bd7fde3fac919e94b56fb9bb4f651cdb23ead439"
      "d6cd523eb08191e75b35fd13a7419b3090f24787bd4f4e1967", NULL, 16);

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_rsa_pubkey, sizeof (pem_rsa_pubkey))), !=, NULL);
  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), != , NULL);
  r_assert_cmpuint (r_pem_block_get_type (block), ==, R_PEM_TYPE_PUBLIC_KEY);
  r_assert (r_pem_block_is_key (block));

  r_assert_cmpptr (r_pem_block_get_key (NULL, NULL, 0), ==, NULL);
  r_assert_cmpptr ((key = r_pem_block_get_key (block, NULL, 0)), !=, NULL);
  r_pem_block_unref (block);

  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), == , NULL);
  r_pem_parser_unref (parser);

  r_assert_cmpuint (key->type, ==, R_CRYPTO_PUBLIC_KEY);
  r_assert_cmpuint (key->algo, ==, R_CRYPTO_ALGO_RSA);
  r_assert (r_rsa_pub_key_get_e (key, &mpint));
  r_assert_cmpint (r_mpint_ucmp_u32 (&mpint, 65537), ==, 0);
  r_assert (r_rsa_pub_key_get_n (key, &mpint));
  r_assert_cmpint (r_mpint_cmp (&mpint, &mod), ==, 0);

  r_mpint_clear (&mod);
  r_mpint_clear (&mpint);
  r_crypto_key_unref (key);
}
RTEST_END;

static const rchar pem_rsa_privkey[] =
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
RTEST (rcryptopem, rsa_privkey, RTEST_FAST)
{
  RPemParser * parser;
  RPemBlock * block;
  RCryptoKey * key;
  rmpint mpint, expected;

  r_mpint_init (&mpint);

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_rsa_privkey, sizeof (pem_rsa_privkey))), !=, NULL);
  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), != , NULL);
  r_assert_cmpuint (r_pem_block_get_type (block), ==, R_PEM_TYPE_RSA_PRIVATE_KEY);
  r_assert (r_pem_block_is_key (block));

  r_assert_cmpptr (r_pem_block_get_key (NULL, NULL, 0), ==, NULL);
  r_assert_cmpptr ((key = r_pem_block_get_key (block, NULL, 0)), !=, NULL);
  r_pem_block_unref (block);

  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), == , NULL);
  r_pem_parser_unref (parser);

  r_assert_cmpuint (key->type, ==, R_CRYPTO_PRIVATE_KEY);
  r_assert_cmpuint (key->algo, ==, R_CRYPTO_ALGO_RSA);

  r_assert (r_rsa_priv_key_get_e (key, &mpint));
  r_assert_cmpint (r_mpint_ucmp_u32 (&mpint, 65537), ==, 0);

  r_assert (r_rsa_pub_key_get_n (key, &mpint));
  r_mpint_init_str (&expected,
      "0x00aa18aba43b50deef38598faf87d2ab634e4571c130a9bca7b878267414faab8b47"
      "1bd8965f5c9fc3818485eaf529c26246f3055064a8de19c8c338be5496cbaeb059dc0b"
      "358143b44a35449eb264113121a455bd7fde3fac919e94b56fb9bb4f651cdb23ead439"
      "d6cd523eb08191e75b35fd13a7419b3090f24787bd4f4e1967", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&mpint, &expected), ==, 0);
  r_mpint_clear (&expected);

  r_assert (r_rsa_priv_key_get_d (key, &mpint));
  r_mpint_init_str (&expected,
      "0x1628e4a39ebea86c8df0cd11572691017cfefb14ea1c12e1dedc7856032dad0f9612"
      "00a38684f0a36dca30102e2464989d19a805933794c7d329ebc890089d3c4c6f602766"
      "e5d62add74e82e490bbf92f6a482153853031be2844a700557b97673e727cd1316d3e6"
      "fa7fc991d4227366ec552cbe90d367ef2e2e79fe66d26311", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&mpint, &expected), ==, 0);
  r_mpint_clear (&expected);
  r_mpint_clear (&mpint);
  r_crypto_key_unref (key);
}
RTEST_END;

static const rchar pem_dsa_privkey[] =
  "-----BEGIN DSA PRIVATE KEY-----\n"
  "MIIDVgIBAAKCAQEAxua7q5J1lZHGc7k+14BHPkiet0zu8lp3Mlxj1Kl/RwCFQNbI\n"
  "g0KtQOfyHxCNsyIDF34Tu/k3zlNt++tb7+DuVhp7sMHS5fTZHDb3Kgr5MT/Oc1M2\n"
  "rod0+f8fiWXvu4mqmRaBDBeABDeoMpG/3pBpN+t9JdhHEb028rNQGz1LtahvLsro\n"
  "+CHv8SaB6I4cpJfj1cP6KG+QVFIV14vmpXmHMN96l+TwaGXRzIr2Okz/IqVG5RSQ\n"
  "/WlIzBSsKum3JGmqpeZqbRR8W4WExPZInI1PKjZJ+fJlvvyVthxUslAskD47eXjr\n"
  "144fc52/8+rtu86y0EqD3pDuKbPm3SGid/rcQwIhALDsV5jRBBvFZjL4wjz/SbaS\n"
  "JHMiu4DxFQ9wSziKXWbDAoIBAHhbdAt6lBFNaFHr1e/58LkksQPKeDD0oRqUqiuW\n"
  "Dqjhn2EBIxsUzAQKOVdkLEp380WNQxu09yswKhr8q5qpG8cuzZup73hflVHiVYK/\n"
  "RKA66coGPnyOdW4386SQu7hxJlD+OJr/I+R1wy/DxmMXvOM9cZWGH1cLRBT2KlV+\n"
  "ut4ZoFI37TM4MpjlPJAjzgWxkVk1605MhPQdPZJ8gNEZhov/TEx9DHTvRnTtx1NO\n"
  "6JvMkdWvfyqMqoQOLABTKNdV0T4YnXlkPh3noR/SqBGnMOa69SM62/W3wevY7YdM\n"
  "AGpEy0ApmwsRU+PCekqlxK2LF+DS4g8ZUgpt6PgXMcek7psCggEBAJNRaaTFe253\n"
  "sOVm/JmUgsO1QB5GI5hOEWLpC8KHxgwnnf/GQUaJLrN8TT4hXgJM2CdvdAkY6et1\n"
  "HpT6BUoz1cYTgsE3ToIsbH3SzPJvU7jzcPOvY1jQv+xVBrU8Ydw2D8pydbAcw/L6\n"
  "JZnGpFBqeHa1iFAQc0B8ToXEgxnmGAdPIOAKAHX0S4m6CrP5fKwYbmzu8WuWO4bR\n"
  "qvX7QJofrs2RaGFESulw0VrMFffJ/gufHTvhDaMW7TSCKo1tBZK9SdEbWCQN2stn\n"
  "fnRSyZFQ+v02oyQtLg+3vSuCx4PS9DM9/Uh3r9JDDH3GveUMbqw8Dmy6WH9iV3oO\n"
  "Jt8aVF8F4CMCIH86vMIuSZ2+Lmo2YYJXTrVLQq2cRCcDjFYOtRtQYtyb\n"
  "-----END DSA PRIVATE KEY-----\n";
RTEST (rcryptopem, dsa_privkey, RTEST_FAST)
{
  RPemParser * parser;
  RPemBlock * block;
  RCryptoKey * key;
  rmpint mpint, expected;

  r_mpint_init (&mpint);

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_dsa_privkey, sizeof (pem_dsa_privkey))), !=, NULL);
  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), != , NULL);
  r_assert_cmpuint (r_pem_block_get_type (block), ==, R_PEM_TYPE_DSA_PRIVATE_KEY);
  r_assert (r_pem_block_is_key (block));

  r_assert_cmpptr (r_pem_block_get_key (NULL, NULL, 0), ==, NULL);
  r_assert_cmpptr ((key = r_pem_block_get_key (block, NULL, 0)), !=, NULL);
  r_pem_block_unref (block);

  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), == , NULL);
  r_pem_parser_unref (parser);

  r_assert_cmpuint (key->type, ==, R_CRYPTO_PRIVATE_KEY);
  r_assert_cmpuint (key->algo, ==, R_CRYPTO_ALGO_DSA);

  r_assert (r_dsa_pub_key_get_p (key, &mpint));
  r_mpint_init_str (&expected,
      "0x00c6e6bbab92759591c673b93ed780473e489eb74ceef25a77325c63d4a97f470085"
      "40d6c88342ad40e7f21f108db32203177e13bbf937ce536dfbeb5befe0ee561a7bb0c1"
      "d2e5f4d91c36f72a0af9313fce735336ae8774f9ff1f8965efbb89aa9916810c178004"
      "37a83291bfde906937eb7d25d84711bd36f2b3501b3d4bb5a86f2ecae8f821eff12681"
      "e88e1ca497e3d5c3fa286f90545215d78be6a5798730df7a97e4f06865d1cc8af63a4c"
      "ff22a546e51490fd6948cc14ac2ae9b72469aaa5e66a6d147c5b8584c4f6489c8d4f2a"
      "3649f9f265befc95b61c54b2502c903e3b7978ebd78e1f739dbff3eaedbbceb2d04a83"
      "de90ee29b3e6dd21a277fadc43", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&mpint, &expected), ==, 0);
  r_mpint_clear (&expected);

  r_assert (r_dsa_pub_key_get_y (key, &mpint));
  r_mpint_init_str (&expected,
      "0x00935169a4c57b6e77b0e566fc999482c3b5401e4623984e1162e90bc287c60c279d"
      "ffc64146892eb37c4d3e215e024cd8276f740918e9eb751e94fa054a33d5c61382c137"
      "4e822c6c7dd2ccf26f53b8f370f3af6358d0bfec5506b53c61dc360fca7275b01cc3f2"
      "fa2599c6a4506a7876b588501073407c4e85c48319e618074f20e00a0075f44b89ba0a"
      "b3f97cac186e6ceef16b963b86d1aaf5fb409a1faecd916861444ae970d15acc15f7c9"
      "fe0b9f1d3be10da316ed34822a8d6d0592bd49d11b58240ddacb677e7452c99150fafd"
      "36a3242d2e0fb7bd2b82c783d2f4333dfd4877afd2430c7dc6bde50c6eac3c0e6cba58"
      "7f62577a0e26df1a545f05e023", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&mpint, &expected), ==, 0);
  r_mpint_clear (&expected);

  r_assert (r_dsa_priv_key_get_x (key, &mpint));
  r_mpint_init_str (&expected,
      "0x7f3abcc22e499dbe2e6a366182574eb54b42ad9c4427038c560eb51b5062dc9b",
      NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&mpint, &expected), ==, 0);
  r_mpint_clear (&expected);
  r_mpint_clear (&mpint);
  r_crypto_key_unref (key);
}
RTEST_END;

static const rchar pem_dsa_pubkey[] =
  "-----BEGIN PUBLIC KEY-----\n"
  "MIIDRzCCAjkGByqGSM44BAEwggIsAoIBAQDG5rurknWVkcZzuT7XgEc+SJ63TO7y\n"
  "WncyXGPUqX9HAIVA1siDQq1A5/IfEI2zIgMXfhO7+TfOU23761vv4O5WGnuwwdLl\n"
  "9NkcNvcqCvkxP85zUzauh3T5/x+JZe+7iaqZFoEMF4AEN6gykb/ekGk3630l2EcR\n"
  "vTbys1AbPUu1qG8uyuj4Ie/xJoHojhykl+PVw/oob5BUUhXXi+aleYcw33qX5PBo\n"
  "ZdHMivY6TP8ipUblFJD9aUjMFKwq6bckaaql5mptFHxbhYTE9kicjU8qNkn58mW+\n"
  "/JW2HFSyUCyQPjt5eOvXjh9znb/z6u27zrLQSoPekO4ps+bdIaJ3+txDAiEAsOxX\n"
  "mNEEG8VmMvjCPP9JtpIkcyK7gPEVD3BLOIpdZsMCggEAeFt0C3qUEU1oUevV7/nw\n"
  "uSSxA8p4MPShGpSqK5YOqOGfYQEjGxTMBAo5V2QsSnfzRY1DG7T3KzAqGvyrmqkb\n"
  "xy7Nm6nveF+VUeJVgr9EoDrpygY+fI51bjfzpJC7uHEmUP44mv8j5HXDL8PGYxe8\n"
  "4z1xlYYfVwtEFPYqVX663hmgUjftMzgymOU8kCPOBbGRWTXrTkyE9B09knyA0RmG\n"
  "i/9MTH0MdO9GdO3HU07om8yR1a9/KoyqhA4sAFMo11XRPhideWQ+HeehH9KoEacw\n"
  "5rr1Izrb9bfB69jth0wAakTLQCmbCxFT48J6SqXErYsX4NLiDxlSCm3o+Bcxx6Tu\n"
  "mwOCAQYAAoIBAQCTUWmkxXtud7DlZvyZlILDtUAeRiOYThFi6QvCh8YMJ53/xkFG\n"
  "iS6zfE0+IV4CTNgnb3QJGOnrdR6U+gVKM9XGE4LBN06CLGx90szyb1O483Dzr2NY\n"
  "0L/sVQa1PGHcNg/KcnWwHMPy+iWZxqRQanh2tYhQEHNAfE6FxIMZ5hgHTyDgCgB1\n"
  "9EuJugqz+XysGG5s7vFrljuG0ar1+0CaH67NkWhhRErpcNFazBX3yf4Lnx074Q2j\n"
  "Fu00giqNbQWSvUnRG1gkDdrLZ350UsmRUPr9NqMkLS4Pt70rgseD0vQzPf1Id6/S\n"
  "Qwx9xr3lDG6sPA5sulh/Yld6DibfGlRfBeAj\n"
  "-----END PUBLIC KEY-----\n";

RTEST (rcryptopem, dsa_pubkey, RTEST_FAST)
{
  RPemParser * parser;
  RPemBlock * block;
  RCryptoKey * key;
  rmpint mpint, expected;

  r_mpint_init (&mpint);

  r_assert_cmpptr (
      (parser = r_pem_parser_new (pem_dsa_pubkey, sizeof (pem_dsa_pubkey))), !=, NULL);
  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), != , NULL);
  r_assert_cmpuint (r_pem_block_get_type (block), ==, R_PEM_TYPE_PUBLIC_KEY);
  r_assert (r_pem_block_is_key (block));

  r_assert_cmpptr (r_pem_block_get_key (NULL, NULL, 0), ==, NULL);
  r_assert_cmpptr ((key = r_pem_block_get_key (block, NULL, 0)), !=, NULL);
  r_assert_cmpuint (key->type, ==, R_CRYPTO_PUBLIC_KEY);
  r_assert_cmpuint (key->algo, ==, R_CRYPTO_ALGO_DSA);
  r_pem_block_unref (block);

  r_assert_cmpptr ((block = r_pem_parser_next_block (parser)), == , NULL);
  r_pem_parser_unref (parser);

  r_assert (r_dsa_pub_key_get_p (key, &mpint));
  r_assert (!r_mpint_iszero (&mpint));
  r_assert (r_dsa_pub_key_get_q (key, &mpint));
  r_assert (!r_mpint_iszero (&mpint));
  r_assert (r_dsa_pub_key_get_g (key, &mpint));
  r_assert (!r_mpint_iszero (&mpint));

  r_assert (r_dsa_pub_key_get_y (key, &mpint));
  r_mpint_init_str (&expected,
      "0x00935169a4c57b6e77b0e566fc999482c3b5401e4623984e1162e90bc287c60c279d"
      "ffc64146892eb37c4d3e215e024cd8276f740918e9eb751e94fa054a33d5c61382c137"
      "4e822c6c7dd2ccf26f53b8f370f3af6358d0bfec5506b53c61dc360fca7275b01cc3f2"
      "fa2599c6a4506a7876b588501073407c4e85c48319e618074f20e00a0075f44b89ba0a"
      "b3f97cac186e6ceef16b963b86d1aaf5fb409a1faecd916861444ae970d15acc15f7c9"
      "fe0b9f1d3be10da316ed34822a8d6d0592bd49d11b58240ddacb677e7452c99150fafd"
      "36a3242d2e0fb7bd2b82c783d2f4333dfd4877afd2430c7dc6bde50c6eac3c0e6cba58"
      "7f62577a0e26df1a545f05e023", NULL, 16);
  r_assert_cmpint (r_mpint_cmp (&mpint, &expected), ==, 0);
  r_mpint_clear (&expected);

  r_mpint_clear (&mpint);
  r_crypto_key_unref (key);
}
RTEST_END;

