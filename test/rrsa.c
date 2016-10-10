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
  r_assert_cmpuint (r_rsa_raw_decrypt (key, rsa_encrypted, sizeof (rsa_encrypted),
        decrypted, &size), ==, R_CRYPTO_OK);
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
  r_assert_cmpuint (r_rsa_pkcs1v1_5_decrypt (key, rsa_encrypted, sizeof (rsa_encrypted),
        decrypted, &size), ==, R_CRYPTO_OK);
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
  r_assert_cmpuint (r_rsa_pkcs1v1_5_encrypt (key, prng,
        before, r_strlen (before), intermediate, &size), ==, R_CRYPTO_OK);
  r_assert_cmpuint (size, ==, 128);
  size = sizeof (after);
  r_assert_cmpuint (r_rsa_pkcs1v1_5_decrypt (key,
        intermediate, 128, after, &size), ==, R_CRYPTO_OK);

  r_mpint_clear (&n);
  r_mpint_clear (&d);
  r_mpint_clear (&e);

  r_prng_unref (prng);
  r_crypto_key_unref (key);
}
RTEST_END;

RTEST (rrsa, sign_FIPS_186_3_SHA256, RTEST_FAST)
{
  rmpint n, e, d;
  RCryptoKey * key;
  ruint8 * msg, * expected, sig[2048];
  rsize msgsize, expectedsize, sigsize = sizeof (sig);
  RPrng * prng;

  r_mpint_init_str (&n, "0xcea80475324c1dc8347827818da58bac069d3419c614a6ea1a"
      "c6a3b510dcd72cc516954905e9fef908d45e13006adf27d467a7d83c111d1a5df15ef2"
      "93771aefb920032a5bb989f8e4f5e1b05093d3f130f984c07a772a3683f4dc6fb28a96"
      "815b32123ccdd13954f19d5b8b24a103e771a34c328755c65ed64e1924ffd04d30b214"
      "2cc262f6e0048fef6dbc652f21479ea1c4b1d66d28f4d46ef7185e390cbfa2e0238058"
      "2f3188bb94ebbf05d31487a09aff01fcbb4cd4bfd1f0a833b38c11813c84360bb53c7d"
      "4481031c40bad8713bb6b835cb08098ed15ba31ee4ba728a8c8e10f7294e1b4163b7ae"
      "e57277bfd881a6f9d43e02c6925aa3a043fb7fb78d", NULL, 16);
  r_mpint_init_str (&d, "0x0997634c477c1a039d44c810b2aaa3c7862b0b88d3708272e1"
      "e15f66fc9389709f8a11f3ea6a5af7effa2d01c189c50f0d5bcbe3fa272e56cfc4a4e1"
      "d388a9dcd65df8628902556c8b6bb6a641709b5a35dd2622c73d4640bfa1359d0e76e1"
      "f219f8e33eb9bd0b59ec198eb2fccaae0346bd8b401e12e3c67cb629569c185a2e0f35"
      "a2f741644c1cca5ebb139d77a89a2953fc5e30048c0e619f07c8d21d1e56b8af07193d"
      "0fdf3f49cd49f2ef3138b5138862f1470bd2d16e34a2b9e7777a6c8c8d4cb94b4e8b5d"
      "616cd5393753e7b0f31cc7da559ba8e98d888914e334773baf498ad88d9631eb5fe32e"
      "53a4145bf0ba548bf2b0a50c63f67b14e398a34b0d", NULL, 16);
  r_mpint_init_str (&e, "0x260445", NULL, 16);
  r_assert_cmpptr ((key = r_rsa_priv_key_new (&n, &e, &d)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpptr ((msg = r_str_hex_mem (
          "0xc43011f3ee88c9c9adcac8bf37221afa31769d347dec705e53aca98993e74606"
          "591867ccd289ba1b4f19365f983e0c578346da76c5e2228a07e4fc9b3d48071633"
          "71a52b68b66873201dc7d6b56616ac2e4cb522120787df7f15a5e8763a54c179c6"
          "35d65816bc19485de3eb35a52040591094fe0e6485a7e0c60e38e7c61551",
          &msgsize)), !=, NULL);
  r_assert_cmpptr ((expected = r_str_hex_mem (
          "0xaa3a4e12eb87596c711c9a22bcabcb9dadffcabcecbd16228889e9bb457d5d22"
          "571a72f034be4783384f43ce6fffc60534b8331cdd5d7c77f49180bfd194b5fd43"
          "a508c66d786c558876735894e6a9300952de792f747045e74d87fd50980230707a"
          "34a4df013ce050bbff0d6f570885c9c7bf8dc499132caee071b41d81ff91b8ce21"
          "aa2f282cbf52389f239afe1490890be21f9d808b3d70b97efd59c0b60e466088bb"
          "42714f212bc90db7e942ebcee60e7b107fff44fb3564ff07d6d02850215fd357d8"
          "97c4d32bef8661689f2d84ff897637fb6d5568a7270e783426b74b7037493e5155"
          "fd7cb3ddddfd36bd8a9c877d71d2a966057c08263d2939c84987",
          &expectedsize)), !=, NULL);

  r_assert_cmpuint (r_rsa_pkcs1v1_5_sign_msg (key, prng, R_HASH_TYPE_SHA256,
        msg, msgsize, sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpuint (sigsize, ==, expectedsize);
  r_assert_cmpmem (sig, ==, expected, sigsize);

  r_mpint_clear (&n);
  r_mpint_clear (&d);
  r_mpint_clear (&e);

  r_prng_unref (prng);
  r_crypto_key_unref (key);
  r_free (msg);
  r_free (expected);
}
RTEST_END;

RTEST (rrsa, verify_FIPS_186_3_SHA1, RTEST_FAST)
{
  rmpint n, e, d;
  RCryptoKey * key;
  ruint8 * msg, * expected;
  rsize msgsize, expectedsize;

  r_mpint_init_str (&n,
      "0xdd07f43534adefb5407cc163aacc7abe9f93cb749643eaec22a3ef16e77813d77df2"
      "0e84a755088872fde21d3d3192f9a78d726ef3d0daa9d6bc19daf6822eb834fbf837ed"
      "03d0f84a7fc7709be382e880e77ba3ce3d91ca1cbf567fc2e62169843489188a128ec8"
      "53079e7942e6590508ea2faab1cf87b860b21b9546442455", NULL, 16);
  r_mpint_init_str (&d, "0x00", NULL, 16);
  r_mpint_init_str (&e, "0xfe3fa1", NULL, 16);
  r_assert_cmpptr ((msg = r_str_hex_mem (
          "0x73ef115a1dec6d91e1aa51c5e11708ead45b2419fb0313d9565ff39e1928a78f"
          "5a662b8c0c91247030f7bc934a5dac9412e99a556d40a6469beb40e7b2ff3c884b"
          "fd28537bf7dd8d05f45419cd96bb3e90fac8aad3e04eb6190c0eeb59eccfc5af7a"
          "b1b85264be71c66ac25e53085c70b5565620152c32b0388905b3f73689cf",
          &msgsize)), !=, NULL);
  r_assert_cmpptr ((expected = r_str_hex_mem (
          "0x25493b7d70cc07e9269a248632c2c89c8514fe8298ed84319ec664f01db980e2"
          "4bbb59eea5867316792fec36cbe9ee9d3c69346b992377f35c08d19de0d6dd3748"
          "2074cf5d3c5cd2b54d09a3ed296187f4ee5b30926a7aa794c88a2c0f9d09f72143"
          "6e5a9bd4fef62e20e43095faee7f5f1e6ce87705c27aa5cdb08d50bd2cf0",
          &expectedsize)), !=, NULL);

  r_assert_cmpptr ((key = r_rsa_priv_key_new (&n, &e, &d)), !=, NULL);

  r_assert_cmpuint (r_rsa_pkcs1v1_5_verify_msg (key, msg, msgsize,
        expected, expectedsize), ==, R_CRYPTO_OK);
  {
    RHash * h = r_hash_new_sha1 ();
    ruint8 hash[20];
    rsize hashsize = sizeof (hash);
    r_assert (r_hash_update (h, msg, msgsize));
    r_assert (r_hash_get_data (h, hash, &hashsize));
    r_assert (r_rsa_pkcs1v1_5_verify_msg_with_hash (key,
          R_HASH_TYPE_SHA1, hash, hashsize, expected, expectedsize));
    r_hash_free (h);
  }

  r_mpint_clear (&n);
  r_mpint_clear (&d);
  r_mpint_clear (&e);

  r_crypto_key_unref (key);
  r_free (msg);
  r_free (expected);
}
RTEST_END;

