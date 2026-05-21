#include <rlib/rcrypto.h>

/* Marshalling-only tests for r_dsa_*_export; arbitrary self-consistent
 * INTEGERs are good enough — round-trip checks don't care whether the
 * parameters form a valid DSA group. */
static const rchar dsa_p_str[] =
    "0xE0A67598CD1B763B"
    "C98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338"
    "FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3"
    "307DED2299A0EE606DF035177A239C34A912C202AA5F83B9"
    "C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440"
    "F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B";
static const rchar dsa_q_str[] = "0xE950511EAB424B9A19A2AEB4E159B7844C589C4F";
static const rchar dsa_g_str[] =
    "0xD29D5121B0423C27"
    "69AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15"
    "C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A"
    "9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B"
    "76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA"
    "3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75";
static const rchar dsa_y_str[] =
    "0x25282217F5730501"
    "DD8DBA3EDFCF349AAFFEC20921128D70FAC44110332201BB"
    "A3F10986140CBB97C726938060473C8EC97B4731DB004293"
    "B5E730363609DF9780F8D883D8C4D41DED6A2F1E1BBBDC97"
    "9E1B9D6D3C940301F4E978D65B19041FCF1E8B518F5C0576"
    "C770FE5A7A485D8329EE2914A2DE1B5C1379045729E5E5B6";
static const rchar dsa_x_str[] = "0xBC372967702082E1AA4FCE892209F71AE4AD25A6";

static void
init_dsa_mpints (rmpint * p, rmpint * q, rmpint * g, rmpint * y, rmpint * x)
{
  r_mpint_init_str (p, dsa_p_str, NULL, 16);
  r_mpint_init_str (q, dsa_q_str, NULL, 16);
  r_mpint_init_str (g, dsa_g_str, NULL, 16);
  r_mpint_init_str (y, dsa_y_str, NULL, 16);
  r_mpint_init_str (x, dsa_x_str, NULL, 16);
}

static void
clear_dsa_mpints (rmpint * p, rmpint * q, rmpint * g, rmpint * y, rmpint * x)
{
  r_mpint_clear (p);
  r_mpint_clear (q);
  r_mpint_clear (g);
  r_mpint_clear (y);
  r_mpint_clear (x);
}

RTEST (rdsa, asn1_pub_roundtrip, RTEST_FAST)
{
  rmpint p, q, g, y, x, got;
  RCryptoKey * orig, * decoded;
  RAsn1BinEncoder * enc;
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint8 * buf;
  rsize bufsize;

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_init (&got);

  r_assert_cmpptr ((orig = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_to_asn1 (orig, enc), ==, R_CRYPTO_OK);
  r_assert_cmpptr ((buf = r_asn1_bin_encoder_get_data (enc, &bufsize)), !=, NULL);
  r_asn1_bin_encoder_unref (enc);

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER, buf, bufsize)), !=, NULL);
  r_assert_cmpuint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpptr ((decoded = r_crypto_key_from_asn1_public_key (dec, &tlv)), !=, NULL);
  r_asn1_bin_decoder_unref (dec);
  r_free (buf);

  r_assert_cmpuint (r_crypto_key_get_algo (decoded), ==, R_CRYPTO_ALGO_DSA);
  r_assert_cmpuint (r_crypto_key_get_type (decoded), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert (r_dsa_pub_key_get_p (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &p), ==, 0);
  r_assert (r_dsa_pub_key_get_q (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &q), ==, 0);
  r_assert (r_dsa_pub_key_get_g (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &g), ==, 0);
  r_assert (r_dsa_pub_key_get_y (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &y), ==, 0);

  r_crypto_key_unref (orig);
  r_crypto_key_unref (decoded);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rdsa, asn1_priv_roundtrip, RTEST_FAST)
{
  rmpint p, q, g, y, x, got;
  RCryptoKey * orig, * decoded;
  RAsn1BinEncoder * enc;
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  ruint8 * buf;
  rsize bufsize;

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_init (&got);

  r_assert_cmpptr ((orig = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_to_asn1 (orig, enc), ==, R_CRYPTO_OK);
  r_assert_cmpptr ((buf = r_asn1_bin_encoder_get_data (enc, &bufsize)), !=, NULL);
  r_asn1_bin_encoder_unref (enc);

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_BER, buf, bufsize)), !=, NULL);
  r_assert_cmpuint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  r_assert_cmpptr ((decoded = r_dsa_priv_key_new_from_asn1 (dec, &tlv)), !=, NULL);
  r_asn1_bin_decoder_unref (dec);
  r_free (buf);

  r_assert_cmpuint (r_crypto_key_get_type (decoded), ==, R_CRYPTO_PRIVATE_KEY);
  r_assert (r_dsa_pub_key_get_p (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &p), ==, 0);
  r_assert (r_dsa_pub_key_get_q (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &q), ==, 0);
  r_assert (r_dsa_pub_key_get_g (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &g), ==, 0);
  r_assert (r_dsa_pub_key_get_y (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &y), ==, 0);
  r_assert (r_dsa_priv_key_get_x (decoded, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &x), ==, 0);

  r_crypto_key_unref (orig);
  r_crypto_key_unref (decoded);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_clear (&got);
}
RTEST_END;
