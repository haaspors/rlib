#include <rlib/rlib.h>

RTEST (rrsa, pub_key_init, RTEST_FAST)
{
  rmpint n, e;
  RCryptoKey * key;

  r_mpint_init_str (&n, "988672111837205085526346618740053", 0, 10);
  r_mpint_init_str (&e, "65537", 0, 10);
  r_assert_cmpptr ((key = r_rsa_pub_key_new (NULL, &e)), ==, NULL);
  r_assert_cmpptr ((key = r_rsa_pub_key_new (&n, NULL)), ==, NULL);

  r_assert_cmpptr ((key = r_rsa_pub_key_new (&n, &e)), !=, NULL);
  r_mpint_clear (&n);
  r_mpint_clear (&e);

  r_crypto_key_unref (key);
}
RTEST_END;

static const ruint8 rsa_encrypted[] = {
  0x07, 0x19, 0xde, 0x9c, 0xbf, 0xea, 0x34, 0xbd, 0x0f, 0x9a, 0x15, 0x6f, 0x13, 0xa6, 0x3e, 0xb6,
  0xc3, 0x23, 0x5f, 0x08, 0x73, 0x4a, 0x8e, 0x25, 0x31, 0xea, 0xa7, 0xbc, 0xd3, 0x62, 0x4a, 0x53,
  0xc3, 0x6f, 0xa7, 0x76, 0xad, 0x91, 0xda, 0xe1, 0x44, 0x52, 0xa4, 0x75, 0x63, 0x25, 0x88, 0x00,
  0xa8, 0xe6, 0xbd, 0xa3, 0x3b, 0xeb, 0xc9, 0xfe, 0x5b, 0x67, 0x51, 0xdf, 0x11, 0xf4, 0xdb, 0xa2,
  0x47, 0x20, 0x54, 0x4c, 0x3f, 0x8f, 0x94, 0x24, 0x20, 0x71, 0xdf, 0xde, 0x44, 0x87, 0xc4, 0x36,
  0x8e, 0x9c, 0x09, 0x45, 0x3e, 0x86, 0xf5, 0x8a, 0x60, 0x4b, 0x66, 0x3f, 0x90, 0x8c, 0x71, 0x39,
  0xe0, 0x97, 0xbb, 0xf9, 0x81, 0xaf, 0xa5, 0xb2, 0x44, 0xa0, 0x84, 0x09, 0xd2, 0x3e, 0x9c, 0xf0,
  0x98, 0x4d, 0xc9, 0xa7, 0xe2, 0x67, 0x37, 0x42, 0x23, 0xc3, 0x3e, 0xfb, 0x06, 0xdf, 0x6a, 0xb2
};
RTEST (rrsa, decrypt_raw, RTEST_FAST)
{
  static const ruint8 expected[] = {
    0x00, 0x02, 0x7b, 0xd2, 0xaf, 0x47, 0xbf, 0xc4, 0x5a, 0x7a, 0x94, 0x2f, 0x1d, 0x21, 0xee, 0x75,
    0xc7, 0x78, 0x33, 0xe0, 0x97, 0x36, 0x0c, 0xf8, 0x2a, 0x26, 0xec, 0x1e, 0x44, 0xe2, 0xe8, 0x5a,
    0x41, 0x06, 0x69, 0xcc, 0x61, 0x3d, 0x0e, 0xd8, 0x1b, 0x43, 0x94, 0x5d, 0x71, 0xba, 0xc4, 0xd8,
    0xe7, 0x9c, 0x12, 0x79, 0x21, 0x83, 0xbd, 0x30, 0xa5, 0xe8, 0x5e, 0x3f, 0x89, 0x9b, 0x6b, 0xa4,
    0xe3, 0xea, 0x32, 0xd7, 0x9e, 0xdc, 0xfb, 0xa8, 0xe9, 0xc2, 0x38, 0xfd, 0xc1, 0x39, 0x7c, 0xf8,
    0x4e, 0xb2, 0xc3, 0x67, 0xa8, 0xd9, 0x5e, 0xa0, 0x42, 0xe2, 0x5c, 0xf4, 0x56, 0xe8, 0xa2, 0x1d,
    0x95, 0xc9, 0xf0, 0x7d, 0x31, 0x6c, 0xbc, 0xa6, 0x9e, 0x7d, 0x4c, 0x58, 0xeb, 0xde, 0xf5, 0xa3,
    0xa1, 0x52, 0x14, 0xd5, 0x47, 0xd5, 0x16, 0x82, 0x00, 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72, 0x0a
  };

  ruint8 decrypted[sizeof (expected)];
  rmpint n, e, d;
  RCryptoKey * key;
  rsize size = sizeof (expected);

  r_mpint_init_str (&n,
      "0x00aa18aba43b50deef38598faf87d2ab634e4571c130a9bca7b878267414faab8b47"
      "1bd8965f5c9fc3818485eaf529c26246f3055064a8de19c8c338be5496cbaeb059dc0b"
      "358143b44a35449eb264113121a455bd7fde3fac919e94b56fb9bb4f651cdb23ead439"
      "d6cd523eb08191e75b35fd13a7419b3090f24787bd4f4e1967", NULL, 16);
  r_mpint_init_str (&d,
      "0x1628e4a39ebea86c8df0cd11572691017cfefb14ea1c12e1dedc7856032dad0f9612"
      "00a38684f0a36dca30102e2464989d19a805933794c7d329ebc890089d3c4c6f602766"
      "e5d62add74e82e490bbf92f6a482153853031be2844a700557b97673e727cd1316d3e6"
      "fa7fc991d4227366ec552cbe90d367ef2e2e79fe66d26311", NULL, 16);
  r_mpint_init_str (&e, "65537", NULL, 10);

  r_assert_cmpptr ((key = r_rsa_priv_key_new (&n, &e, &d)), !=, NULL);
  r_assert (r_rsa_raw_decrypt (key, rsa_encrypted, sizeof (rsa_encrypted),
        decrypted, &size));
  r_assert_cmpuint (size, ==, sizeof (expected));
  r_assert_cmpmem (decrypted, ==, expected, sizeof (expected));

  r_mpint_clear (&n);
  r_mpint_clear (&d);
  r_mpint_clear (&e);

  r_crypto_key_unref (key);
}
RTEST_END;

RTEST (rrsa, decrypt_pkcs, RTEST_FAST)
{
  rchar expected[] = "foobar\n";
  ruint8 decrypted[sizeof (expected)];
  rmpint n, e, d;
  RCryptoKey * key;
  rsize size = sizeof (expected);

  r_mpint_init_str (&n,
      "0x00aa18aba43b50deef38598faf87d2ab634e4571c130a9bca7b878267414faab8b47"
      "1bd8965f5c9fc3818485eaf529c26246f3055064a8de19c8c338be5496cbaeb059dc0b"
      "358143b44a35449eb264113121a455bd7fde3fac919e94b56fb9bb4f651cdb23ead439"
      "d6cd523eb08191e75b35fd13a7419b3090f24787bd4f4e1967", NULL, 16);
  r_mpint_init_str (&d,
      "0x1628e4a39ebea86c8df0cd11572691017cfefb14ea1c12e1dedc7856032dad0f9612"
      "00a38684f0a36dca30102e2464989d19a805933794c7d329ebc890089d3c4c6f602766"
      "e5d62add74e82e490bbf92f6a482153853031be2844a700557b97673e727cd1316d3e6"
      "fa7fc991d4227366ec552cbe90d367ef2e2e79fe66d26311", NULL, 16);
  r_mpint_init_str (&e, "65537", NULL, 10);

  r_assert_cmpptr ((key = r_rsa_priv_key_new (&n, &e, &d)), !=, NULL);
  r_assert (r_rsa_pkcs1v1_5_decrypt (key, rsa_encrypted, sizeof (rsa_encrypted),
        decrypted, &size));
  r_assert_cmpuint (size, ==, r_strlen (expected));
  r_assert_cmpmem (decrypted, ==, expected, r_strlen (expected));

  r_mpint_clear (&n);
  r_mpint_clear (&d);
  r_mpint_clear (&e);

  r_crypto_key_unref (key);
}
RTEST_END;

RTEST (rrsa, encrypt_decrypt_1024, RTEST_FAST)
{
  rchar before[] = "foobar\n";
  ruint8 intermediate[128];
  ruint8 after[sizeof (before)];
  rsize size = sizeof (intermediate);
  rmpint n, e, d;
  RCryptoKey * key;
  RPrng * prng;

  r_mpint_init_str (&n,
      "0x00aa18aba43b50deef38598faf87d2ab634e4571c130a9bca7b878267414faab8b47"
      "1bd8965f5c9fc3818485eaf529c26246f3055064a8de19c8c338be5496cbaeb059dc0b"
      "358143b44a35449eb264113121a455bd7fde3fac919e94b56fb9bb4f651cdb23ead439"
      "d6cd523eb08191e75b35fd13a7419b3090f24787bd4f4e1967", NULL, 16);
  r_mpint_init_str (&d,
      "0x1628e4a39ebea86c8df0cd11572691017cfefb14ea1c12e1dedc7856032dad0f9612"
      "00a38684f0a36dca30102e2464989d19a805933794c7d329ebc890089d3c4c6f602766"
      "e5d62add74e82e490bbf92f6a482153853031be2844a700557b97673e727cd1316d3e6"
      "fa7fc991d4227366ec552cbe90d367ef2e2e79fe66d26311", NULL, 16);
  r_mpint_init_str (&e, "65537", NULL, 10);

  r_assert_cmpptr ((key = r_rsa_priv_key_new (&n, &e, &d)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert (r_rsa_pkcs1v1_5_encrypt (key, prng,
        before, r_strlen (before), intermediate, &size));
  r_assert_cmpuint (size, ==, 128);
  size = sizeof (after);
  r_assert (r_rsa_pkcs1v1_5_decrypt (key, intermediate, 128, after, &size));

  r_mpint_clear (&n);
  r_mpint_clear (&d);
  r_mpint_clear (&e);

  r_prng_unref (prng);
  r_crypto_key_unref (key);
}
RTEST_END;

