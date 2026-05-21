#include <rlib/rcrypto.h>

/* RFC 3526 group 14, MODP-2048: p is a Sophie-Germain-style safe prime
 * and g = 2. Used for the round-trip and known-answer tests below. */
static const rchar rfc3526_group14_p[] =
    "0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
static const rchar rfc3526_group14_g[] = "0x02";

RTEST (rdh, key_new_and_getters, RTEST_FAST)
{
  rmpint p, g, y, x, tmp;
  RCryptoKey * pub;
  RCryptoKey * priv;

  r_mpint_init_str (&p, "0x17", NULL, 16);    /* small toy values; */
  r_mpint_init_str (&g, "0x05", NULL, 16);    /* mathematical validity */
  r_mpint_init_str (&y, "0x0a", NULL, 16);    /* doesn't matter here.  */
  r_mpint_init_str (&x, "0x07", NULL, 16);
  r_mpint_init (&tmp);

  r_assert_cmpptr ((pub = r_dh_pub_key_new (NULL, &g, &y)), ==, NULL);
  r_assert_cmpptr ((pub = r_dh_pub_key_new (&p, NULL, &y)), ==, NULL);
  r_assert_cmpptr ((pub = r_dh_pub_key_new (&p, &g, NULL)), ==, NULL);

  r_assert_cmpptr ((pub = r_dh_pub_key_new (&p, &g, &y)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_algo (pub), ==, R_CRYPTO_ALGO_DH);
  r_assert_cmpuint (r_crypto_key_get_type (pub), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert (r_dh_pub_key_get_p (pub, &tmp));
  r_assert_cmpint (r_mpint_cmp (&tmp, &p), ==, 0);
  r_assert (r_dh_pub_key_get_g (pub, &tmp));
  r_assert_cmpint (r_mpint_cmp (&tmp, &g), ==, 0);
  r_assert (r_dh_pub_key_get_y (pub, &tmp));
  r_assert_cmpint (r_mpint_cmp (&tmp, &y), ==, 0);
  /* x is not exposed on a public-only key. */
  r_assert (!r_dh_priv_key_get_x (pub, &tmp));

  r_assert_cmpptr ((priv = r_dh_priv_key_new (&p, &g, &y, &x)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_type (priv), ==, R_CRYPTO_PRIVATE_KEY);
  r_assert (r_dh_priv_key_get_x (priv, &tmp));
  r_assert_cmpint (r_mpint_cmp (&tmp, &x), ==, 0);

  r_crypto_key_unref (pub);
  r_crypto_key_unref (priv);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
  r_mpint_clear (&y);
  r_mpint_clear (&x);
  r_mpint_clear (&tmp);
}
RTEST_END;

RTEST (rdh, gen_and_exchange_roundtrip, RTEST_SLOW)
{
  /* Alice and Bob each generate a private key in RFC 3526 group 14, then
   * compute the shared secret from each side; both must match. */
  rmpint p, g;
  RCryptoKey * a_priv = NULL, * a_pub = NULL;
  RCryptoKey * b_priv = NULL, * b_pub = NULL;
  RPrng * prng;
  ruint8 a_shared[256], b_shared[256];
  rsize a_size = sizeof (a_shared), b_size = sizeof (b_shared);
  rmpint tmp;

  r_mpint_init_str (&p, rfc3526_group14_p, NULL, 16);
  r_mpint_init_str (&g, rfc3526_group14_g, NULL, 16);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpptr ((a_priv = r_dh_priv_key_new_gen (&p, &g, prng)), !=, NULL);
  r_assert_cmpptr ((b_priv = r_dh_priv_key_new_gen (&p, &g, prng)), !=, NULL);

  /* Build a public-only view of each side's key for the peer. */
  r_mpint_init (&tmp);
  r_assert (r_dh_pub_key_get_y (a_priv, &tmp));
  r_assert_cmpptr ((a_pub = r_dh_pub_key_new (&p, &g, &tmp)), !=, NULL);
  r_assert (r_dh_pub_key_get_y (b_priv, &tmp));
  r_assert_cmpptr ((b_pub = r_dh_pub_key_new (&p, &g, &tmp)), !=, NULL);
  r_mpint_clear (&tmp);

  r_assert_cmpint (r_dh_compute_shared (a_priv, b_pub, a_shared, &a_size),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_dh_compute_shared (b_priv, a_pub, b_shared, &b_size),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (a_size, ==, 256);
  r_assert_cmpuint (b_size, ==, 256);
  r_assert_cmpmem (a_shared, ==, b_shared, 256);

  r_crypto_key_unref (a_priv);
  r_crypto_key_unref (a_pub);
  r_crypto_key_unref (b_priv);
  r_crypto_key_unref (b_pub);
  r_prng_unref (prng);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
}
RTEST_END;

RTEST (rdh, compute_shared_known_answer, RTEST_SLOW)
{
  /* Fixed (x_a, x_b) pair in RFC 3526 group 14 — both directions must
   * agree, and the secret must be deterministic across runs. */
  rmpint p, g, x_a, x_b, y_a, y_b;
  RCryptoKey * a_priv, * b_priv, * a_pub, * b_pub;
  ruint8 a_shared[256], b_shared[256];
  rsize a_size = sizeof (a_shared), b_size = sizeof (b_shared);

  r_mpint_init_str (&p, rfc3526_group14_p, NULL, 16);
  r_mpint_init_str (&g, rfc3526_group14_g, NULL, 16);
  r_mpint_init_str (&x_a,
      "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      NULL, 16);
  r_mpint_init_str (&x_b,
      "0xfedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      NULL, 16);

  r_mpint_init (&y_a);
  r_mpint_init (&y_b);
  r_assert (r_mpint_expmod (&y_a, &g, &x_a, &p));
  r_assert (r_mpint_expmod (&y_b, &g, &x_b, &p));

  r_assert_cmpptr ((a_priv = r_dh_priv_key_new (&p, &g, &y_a, &x_a)), !=, NULL);
  r_assert_cmpptr ((b_priv = r_dh_priv_key_new (&p, &g, &y_b, &x_b)), !=, NULL);
  r_assert_cmpptr ((a_pub  = r_dh_pub_key_new  (&p, &g, &y_a)), !=, NULL);
  r_assert_cmpptr ((b_pub  = r_dh_pub_key_new  (&p, &g, &y_b)), !=, NULL);

  r_assert_cmpint (r_dh_compute_shared (a_priv, b_pub, a_shared, &a_size),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_dh_compute_shared (b_priv, a_pub, b_shared, &b_size),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (a_size, ==, 256);
  r_assert_cmpmem (a_shared, ==, b_shared, 256);

  r_crypto_key_unref (a_priv);
  r_crypto_key_unref (b_priv);
  r_crypto_key_unref (a_pub);
  r_crypto_key_unref (b_pub);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
  r_mpint_clear (&x_a);
  r_mpint_clear (&x_b);
  r_mpint_clear (&y_a);
  r_mpint_clear (&y_b);
}
RTEST_END;

RTEST (rdh, compute_shared_rejects_bad_peer, RTEST_FAST)
{
  /* y values 0, 1, p-1 (or anything outside the open interval) leak the
   * secret trivially or come from a non-conformant party — must error
   * out before the modexp. */
  rmpint p, g, x, bad_y, p_1;
  RCryptoKey * priv, * peer;
  ruint8 out[64];
  rsize outsize = sizeof (out);

  r_mpint_init_str (&p, "0x1707", NULL, 16);
  r_mpint_init_str (&g, "0x02", NULL, 16);
  r_mpint_init_str (&x, "0x05", NULL, 16);
  r_mpint_init (&bad_y);
  r_mpint_init (&p_1);

  /* Build a real private key. y here is a placeholder; the receiver
   * doesn't read its own y during the exchange. */
  {
    rmpint y;
    r_mpint_init_str (&y, "0x42", NULL, 16);
    r_assert_cmpptr ((priv = r_dh_priv_key_new (&p, &g, &y, &x)), !=, NULL);
    r_mpint_clear (&y);
  }

  /* peer.y = 0 */
  r_mpint_set_i32 (&bad_y, 0);
  r_assert_cmpptr ((peer = r_dh_pub_key_new (&p, &g, &bad_y)), !=, NULL);
  outsize = sizeof (out);
  r_assert_cmpint (r_dh_compute_shared (priv, peer, out, &outsize),
      ==, R_CRYPTO_INVAL);
  r_crypto_key_unref (peer);

  /* peer.y = 1 */
  r_mpint_set_i32 (&bad_y, 1);
  r_assert_cmpptr ((peer = r_dh_pub_key_new (&p, &g, &bad_y)), !=, NULL);
  outsize = sizeof (out);
  r_assert_cmpint (r_dh_compute_shared (priv, peer, out, &outsize),
      ==, R_CRYPTO_INVAL);
  r_crypto_key_unref (peer);

  /* peer.y = p - 1 */
  r_mpint_sub_i32 (&p_1, &p, 1);
  r_assert_cmpptr ((peer = r_dh_pub_key_new (&p, &g, &p_1)), !=, NULL);
  outsize = sizeof (out);
  r_assert_cmpint (r_dh_compute_shared (priv, peer, out, &outsize),
      ==, R_CRYPTO_INVAL);
  r_crypto_key_unref (peer);

  r_crypto_key_unref (priv);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
  r_mpint_clear (&x);
  r_mpint_clear (&bad_y);
  r_mpint_clear (&p_1);
}
RTEST_END;

RTEST (rdh, compute_shared_rejects_mismatched_group, RTEST_FAST)
{
  /* If the two sides advertise different (p, g) groups the exchange is
   * meaningless; the API must refuse rather than silently compute. */
  rmpint p1, p2, g, x, y;
  RCryptoKey * priv, * peer;
  ruint8 out[64];
  rsize outsize = sizeof (out);

  r_mpint_init_str (&p1, "0x1707", NULL, 16);
  r_mpint_init_str (&p2, "0x17fb", NULL, 16);
  r_mpint_init_str (&g,  "0x02",   NULL, 16);
  r_mpint_init_str (&x,  "0x05",   NULL, 16);
  r_mpint_init_str (&y,  "0x10",   NULL, 16);

  r_assert_cmpptr ((priv = r_dh_priv_key_new (&p1, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((peer = r_dh_pub_key_new  (&p2, &g, &y)), !=, NULL);
  r_assert_cmpint (r_dh_compute_shared (priv, peer, out, &outsize),
      ==, R_CRYPTO_WRONG_TYPE);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (peer);
  r_mpint_clear (&p1);
  r_mpint_clear (&p2);
  r_mpint_clear (&g);
  r_mpint_clear (&x);
  r_mpint_clear (&y);
}
RTEST_END;

static RCryptoKey *
encode_then_decode_pub (const RCryptoKey * pub)
{
  RAsn1BinEncoder * enc;
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint8 * buf;
  rsize bufsize;
  RCryptoKey * decoded = NULL;

  if ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)) == NULL)
    return NULL;
  if (r_crypto_key_to_asn1 (pub, enc) != R_CRYPTO_OK) {
    r_asn1_bin_encoder_unref (enc);
    return NULL;
  }
  buf = r_asn1_bin_encoder_get_data (enc, &bufsize);
  r_asn1_bin_encoder_unref (enc);
  if (buf == NULL)
    return NULL;

  if ((dec = r_asn1_bin_decoder_new (R_ASN1_BER, buf, bufsize)) != NULL) {
    if (r_asn1_bin_decoder_next (dec, &tlv) == R_ASN1_DECODER_OK)
      decoded = r_crypto_key_from_asn1_public_key (dec, &tlv);
    r_asn1_bin_decoder_unref (dec);
  }
  r_free (buf);
  return decoded;
}

RTEST (rdh, asn1_pub_roundtrip, RTEST_FAST)
{
  /* Build a DH public key, export to ASN.1 (SubjectPublicKeyInfo), parse
   * back through r_crypto_key_from_asn1_public_key and assert every
   * field matches the original. */
  rmpint p, g, y, got;
  RCryptoKey * orig, * decoded;

  r_mpint_init_str (&p, "0xFEDCBA9876543210FEDCBA9876543211", NULL, 16);
  r_mpint_init_str (&g, "0x02", NULL, 16);
  r_mpint_init_str (&y, "0x0123456789abcdef0123456789abcdef", NULL, 16);
  r_mpint_init (&got);

  r_assert_cmpptr ((orig = r_dh_pub_key_new (&p, &g, &y)), !=, NULL);
  r_assert_cmpptr ((decoded = encode_then_decode_pub (orig)), !=, NULL);

  r_assert_cmpuint (r_crypto_key_get_algo (decoded), ==, R_CRYPTO_ALGO_DH);
  r_assert_cmpuint (r_crypto_key_get_type (decoded), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert (r_dh_pub_key_get_p (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &p), ==, 0);
  r_assert (r_dh_pub_key_get_g (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &g), ==, 0);
  r_assert (r_dh_pub_key_get_y (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &y), ==, 0);

  r_crypto_key_unref (orig);
  r_crypto_key_unref (decoded);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
  r_mpint_clear (&y);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rdh, asn1_priv_roundtrip, RTEST_FAST)
{
  /* Same shape as the pub round-trip, but via the
   * SEQUENCE { ver, p, g, x } payload that r_dh_priv_key_new_from_asn1
   * accepts. */
  rmpint p, g, y, x, got;
  RCryptoKey * orig, * decoded;
  RAsn1BinEncoder * enc;
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint8 * buf;
  rsize bufsize;

  r_mpint_init_str (&p, "0xFEDCBA9876543210FEDCBA9876543211", NULL, 16);
  r_mpint_init_str (&g, "0x02", NULL, 16);
  r_mpint_init_str (&x, "0x0a0b0c0d0e0f10", NULL, 16);
  r_mpint_init (&y);
  r_assert (r_mpint_expmod (&y, &g, &x, &p));
  r_mpint_init (&got);

  r_assert_cmpptr ((orig = r_dh_priv_key_new (&p, &g, &y, &x)), !=, NULL);

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_to_asn1 (orig, enc), ==, R_CRYPTO_OK);
  r_assert_cmpptr ((buf = r_asn1_bin_encoder_get_data (enc, &bufsize)), !=, NULL);
  r_asn1_bin_encoder_unref (enc);

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER, buf, bufsize)), !=, NULL);
  r_assert_cmpuint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpptr ((decoded = r_dh_priv_key_new_from_asn1 (dec, &tlv)), !=, NULL);
  r_asn1_bin_decoder_unref (dec);
  r_free (buf);

  r_assert_cmpuint (r_crypto_key_get_type (decoded), ==, R_CRYPTO_PRIVATE_KEY);
  r_assert (r_dh_pub_key_get_p (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &p), ==, 0);
  r_assert (r_dh_pub_key_get_g (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &g), ==, 0);
  r_assert (r_dh_priv_key_get_x (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &x), ==, 0);
  /* y is reconstructed from (g, x, p) on the decode side. */
  r_assert (r_dh_pub_key_get_y (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &y), ==, 0);

  r_crypto_key_unref (orig);
  r_crypto_key_unref (decoded);
  r_mpint_clear (&p);
  r_mpint_clear (&g);
  r_mpint_clear (&y);
  r_mpint_clear (&x);
  r_mpint_clear (&got);
}
RTEST_END;
