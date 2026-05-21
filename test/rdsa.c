#include <rlib/rcrypto.h>

#include "wycheproof_dsa.h"

/* FIPS 186-2 Appendix 5 sample DSA-1024 / SHA-1 parameters: p is a
 * 1024-bit prime, q is a 160-bit prime dividing p-1, g has order q
 * in (Z/pZ)*. (x, y) is a valid keypair: y = g^x mod p. */
static const rchar dsa_p_str[] =
    "0x8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7"
    "cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac"
    "49693dfbf83724c2ec0736ee31c80291";
static const rchar dsa_q_str[] = "0xc773218c737ec8ee993b4f2ded30f48edace915f";
static const rchar dsa_g_str[] =
    "0x626d027839ea0a13413163a55b4cb500299d5522956cefcb"
    "3bff10f399ce2c2e71cb9de5fa24babf58e5b79521925c9c"
    "c42e9f6f464b088cc572af53e6d78802";
static const rchar dsa_y_str[] =
    "0x19131871d75b1612a819f29d78d1b0d7346f7aa77bb62a85"
    "9bfd6c5675da9d212d3a36ef1672ef660b8c7c255cc0ec74"
    "858fba33f44c06699630a76b030ee333";
static const rchar dsa_x_str[] = "0x2070b3223dba372fde1c0ffc7b2e3b498b260614";

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

RTEST (rdsa, pub_key_new_full_rejects_null_y, RTEST_FAST)
{
  rmpint p, q, g;
  RCryptoKey * key;

  r_mpint_init_str (&p, dsa_p_str, NULL, 16);
  r_mpint_init_str (&q, dsa_q_str, NULL, 16);
  r_mpint_init_str (&g, dsa_g_str, NULL, 16);

  /* y is required; the params themselves are documented optional via
   * the r_dsa_pub_key_new(y) shortcut, but a NULL y must still fail. */
  r_assert_cmpptr ((key = r_dsa_pub_key_new_full (&p, &q, &g, NULL)), ==, NULL);

  r_mpint_clear (&p);
  r_mpint_clear (&q);
  r_mpint_clear (&g);
}
RTEST_END;

RTEST (rdsa, pub_key_new_shortcut_only_y, RTEST_FAST)
{
  /* The r_dsa_pub_key_new(y) macro builds a public key with no group
   * parameters — useful when the verifier already knows (p, q, g) from
   * a peer's full key and only needs y to validate signatures. */
  rmpint y, got;
  RCryptoKey * key;

  r_mpint_init_str (&y, dsa_y_str, NULL, 16);
  r_mpint_init (&got);

  r_assert_cmpptr ((key = r_dsa_pub_key_new (&y)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_algo (key), ==, R_CRYPTO_ALGO_DSA);
  r_assert_cmpuint (r_crypto_key_get_type (key), ==, R_CRYPTO_PUBLIC_KEY);

  r_assert (r_dsa_pub_key_get_y (key, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &y), ==, 0);

  /* Unset params come back as zero rather than uninitialised. */
  r_assert (r_dsa_pub_key_get_p (key, &got));
  r_assert (r_mpint_iszero (&got));
  r_assert (r_dsa_pub_key_get_q (key, &got));
  r_assert (r_mpint_iszero (&got));
  r_assert (r_dsa_pub_key_get_g (key, &got));
  r_assert (r_mpint_iszero (&got));

  r_crypto_key_unref (key);
  r_mpint_clear (&y);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rdsa, pub_key_new_binary, RTEST_FAST)
{
  /* Round-trip through the byte-array constructor: encode each field
   * with r_mpint_to_binary_new, build a key, and assert the getters
   * return the same value. */
  rmpint p, q, g, y, x, got;
  RCryptoKey * key;
  ruint8 * pb, * qb, * gb, * yb;
  rsize psize, qsize, gsize, ysize;

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_init (&got);

  pb = r_mpint_to_binary_new (&p, &psize);
  qb = r_mpint_to_binary_new (&q, &qsize);
  gb = r_mpint_to_binary_new (&g, &gsize);
  yb = r_mpint_to_binary_new (&y, &ysize);
  r_assert (pb != NULL && qb != NULL && gb != NULL && yb != NULL);

  r_assert_cmpptr ((key = r_dsa_pub_key_new_binary (pb, psize, qb, qsize,
          gb, gsize, yb, ysize)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_algo (key), ==, R_CRYPTO_ALGO_DSA);

  r_assert (r_dsa_pub_key_get_p (key, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &p), ==, 0);
  r_assert (r_dsa_pub_key_get_q (key, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &q), ==, 0);
  r_assert (r_dsa_pub_key_get_g (key, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &g), ==, 0);
  r_assert (r_dsa_pub_key_get_y (key, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &y), ==, 0);

  r_free (pb); r_free (qb); r_free (gb); r_free (yb);
  r_crypto_key_unref (key);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rdsa, priv_key_new_rejects_null, RTEST_FAST)
{
  rmpint p, q, g, y, x;
  RCryptoKey * key;
  init_dsa_mpints (&p, &q, &g, &y, &x);

  r_assert_cmpptr ((key = r_dsa_priv_key_new (NULL, &q, &g, &y, &x)), ==, NULL);
  r_assert_cmpptr ((key = r_dsa_priv_key_new (&p, NULL, &g, &y, &x)), ==, NULL);
  r_assert_cmpptr ((key = r_dsa_priv_key_new (&p, &q, NULL, &y, &x)), ==, NULL);
  r_assert_cmpptr ((key = r_dsa_priv_key_new (&p, &q, &g, NULL, &x)), ==, NULL);
  r_assert_cmpptr ((key = r_dsa_priv_key_new (&p, &q, &g, &y, NULL)), ==, NULL);

  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;

RTEST (rdsa, priv_key_new_binary, RTEST_FAST)
{
  rmpint p, q, g, y, x, got;
  RCryptoKey * key;
  ruint8 * pb, * qb, * gb, * yb, * xb;
  rsize psize, qsize, gsize, ysize, xsize;

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_init (&got);

  pb = r_mpint_to_binary_new (&p, &psize);
  qb = r_mpint_to_binary_new (&q, &qsize);
  gb = r_mpint_to_binary_new (&g, &gsize);
  yb = r_mpint_to_binary_new (&y, &ysize);
  xb = r_mpint_to_binary_new (&x, &xsize);

  r_assert_cmpptr ((key = r_dsa_priv_key_new_binary (pb, psize, qb, qsize,
          gb, gsize, yb, ysize, xb, xsize)), !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_type (key), ==, R_CRYPTO_PRIVATE_KEY);

  r_assert (r_dsa_pub_key_get_p (key, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &p), ==, 0);
  r_assert (r_dsa_priv_key_get_x (key, &got));
  r_assert_cmpint (r_mpint_cmp (&got, &x), ==, 0);

  r_free (pb); r_free (qb); r_free (gb); r_free (yb); r_free (xb);
  r_crypto_key_unref (key);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_clear (&got);
}
RTEST_END;

RTEST (rdsa, getter_guards, RTEST_FAST)
{
  /* Getters must reject NULL args, wrong-algorithm keys (RSA here), and
   * — for priv_key_get_x — keys that are public-only. */
  rmpint p, q, g, y, x, n, e, got;
  RCryptoKey * pub, * priv, * rsa_key;

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_init_str (&n, dsa_p_str, NULL, 16);
  r_mpint_init_str (&e, "65537", NULL, 10);
  r_mpint_init (&got);

  r_assert_cmpptr ((pub  = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((rsa_key = r_rsa_pub_key_new (&n, &e)), !=, NULL);

  /* NULL args. */
  r_assert (!r_dsa_pub_key_get_p (NULL, &got));
  r_assert (!r_dsa_pub_key_get_p (pub, NULL));
  r_assert (!r_dsa_pub_key_get_q (NULL, &got));
  r_assert (!r_dsa_pub_key_get_g (NULL, &got));
  r_assert (!r_dsa_pub_key_get_y (NULL, &got));
  r_assert (!r_dsa_priv_key_get_x (NULL, &got));
  r_assert (!r_dsa_priv_key_get_x (priv, NULL));

  /* Wrong algorithm. */
  r_assert (!r_dsa_pub_key_get_p (rsa_key, &got));
  r_assert (!r_dsa_priv_key_get_x (rsa_key, &got));

  /* Public-only key does not expose x. */
  r_assert (!r_dsa_priv_key_get_x (pub, &got));

  r_crypto_key_unref (pub);
  r_crypto_key_unref (priv);
  r_crypto_key_unref (rsa_key);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
  r_mpint_clear (&n);
  r_mpint_clear (&e);
  r_mpint_clear (&got);
}
RTEST_END;

/* The 160-bit q in our test parameters matches SHA-1's output size, so
 * a 20-byte hash maps directly to z without truncation. */
static const ruint8 dsa_hash_a[20] = {
  0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
  0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
};
static const ruint8 dsa_hash_b[20] = {
  0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
  0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
};

RTEST (rdsa, sign_verify_roundtrip, RTEST_FAST)
{
  rmpint p, q, g, y, x;
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[64];
  rsize sigsize = sizeof (sig);

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((pub  = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpuint (sigsize, >, 0);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig, sigsize), ==, R_CRYPTO_OK);

  /* Verifying with the priv key (which exposes the public half) also
   * works — algo info has verify on both pub and priv. */
  r_assert_cmpint (r_crypto_key_verify (priv, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig, sigsize), ==, R_CRYPTO_OK);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;

RTEST (rdsa, verify_rejects_tampered_hash, RTEST_FAST)
{
  /* Signature is for hash_a; verifying against hash_b must fail. */
  rmpint p, q, g, y, x;
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[64];
  rsize sigsize = sizeof (sig);

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((pub  = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_b, sizeof (dsa_hash_b), sig, sigsize), ==, R_CRYPTO_VERIFY_FAILED);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;

RTEST (rdsa, verify_rejects_malformed_signature, RTEST_FAST)
{
  /* Garbage bytes that aren't a valid Dss-Sig-Value SEQUENCE must
   * surface as VERIFY_FAILED rather than crashing the ASN.1 decoder. */
  rmpint p, q, g, y, x;
  RCryptoKey * pub;
  static const ruint8 junk[] = { 0xde, 0xad, 0xbe, 0xef };
  /* A well-formed SEQUENCE whose r is 0 — must be rejected by the
   * 0 < r < q check before any modexp work. */
  static const ruint8 r_zero[] = { 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 };

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_assert_cmpptr ((pub = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);

  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), junk, sizeof (junk)),
      ==, R_CRYPTO_VERIFY_FAILED);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), r_zero, sizeof (r_zero)),
      ==, R_CRYPTO_VERIFY_FAILED);

  r_crypto_key_unref (pub);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;

RTEST (rdsa, sign_fresh_k_each_call, RTEST_FAST)
{
  /* Signing the same hash twice must yield different (r, s) pairs —
   * deterministic outputs would mean a constant k, which leaks x. */
  rmpint p, q, g, y, x;
  RCryptoKey * priv;
  RPrng * prng;
  ruint8 sig1[64], sig2[64];
  rsize sig1size = sizeof (sig1), sig2size = sizeof (sig2);

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig1, &sig1size), ==, R_CRYPTO_OK);
  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig2, &sig2size), ==, R_CRYPTO_OK);
  r_assert (sig1size != sig2size || r_memcmp (sig1, sig2, sig1size) != 0);

  r_crypto_key_unref (priv);
  r_prng_unref (prng);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;

/* Hash msg with mdtype, build the corresponding RCryptoKey from a
 * Wycheproof DsaKey row, then call r_crypto_key_verify. Factored out
 * so the per-vector loop body stays focused on the assertion logic. */
static RCryptoResult
wp_dsa_verify_one (const WycheproofDsaKey * k, RMsgDigestType mdtype,
    const ruint8 * msg, rsize msg_len, const ruint8 * sig, rsize sig_len)
{
  RMsgDigest * md;
  RCryptoKey * pub;
  ruint8 * hash;
  rsize hash_len;
  RCryptoResult ret;

  if ((md = r_msg_digest_new (mdtype)) == NULL)
    return R_CRYPTO_ERROR;
  hash_len = r_msg_digest_size (md);
  hash = r_alloca (hash_len);
  if (!r_msg_digest_update (md, msg, msg_len) ||
      !r_msg_digest_get_data (md, hash, hash_len, NULL)) {
    r_msg_digest_free (md);
    return R_CRYPTO_HASH_FAILED;
  }
  r_msg_digest_free (md);

  if ((pub = r_dsa_pub_key_new_binary (k->p, k->p_len, k->q, k->q_len,
          k->g, k->g_len, k->y, k->y_len)) == NULL)
    return R_CRYPTO_ERROR;
  ret = r_crypto_key_verify (pub, mdtype, hash, hash_len, sig, sig_len);
  r_crypto_key_unref (pub);
  return ret;
}

/* Walk every Wycheproof DSA-2048/256 + SHA-256 verify vector. "valid"
 * entries must verify; "invalid" entries must produce a non-OK result;
 * "acceptable" entries are allowed either outcome (those flag spec-
 * legal-but-discouraged signature encodings). Vectors cover the bait
 * historically used to break DSA verifiers: leading-zero / padding /
 * length-prefix games on r and s, signatures with r or s out of range,
 * BER-vs-DER quirks, edge cases for the modexp identities, etc. */
RTEST_LOOP (rdsa, wycheproof_2048_256_sha256_verify, RTEST_SLOW,
    0, R_N_ELEMENTS (wp_dsa_2048_256_sha256_tests))
{
  const WycheproofDsaTest * t = &wp_dsa_2048_256_sha256_tests[__i];
  const WycheproofDsaKey * k = &wp_dsa_2048_256_sha256_keys[t->key_idx];
  RCryptoResult res = wp_dsa_verify_one (k, R_MSG_DIGEST_TYPE_SHA256,
      t->msg, t->msg_len, t->sig, t->sig_len);

  switch (t->expected) {
    case WYCHEPROOF_VALID:
      r_assert_cmpint (res, ==, R_CRYPTO_OK);
      break;
    case WYCHEPROOF_INVALID:
      r_assert_cmpint (res, !=, R_CRYPTO_OK);
      break;
    case WYCHEPROOF_ACCEPTABLE:
      /* Either outcome is spec-conformant. */
      break;
  }
}
RTEST_END;

RTEST (rdsa, sign_msg_verify_msg_roundtrip, RTEST_FAST)
{
  /* The _msg helpers hash internally and produce signatures verify-able
   * both by the matching _msg verifier and by the pre-hashed verifier
   * path. */
  static const ruint8 message[] =
      "The quick brown fox jumps over the lazy dog.";
  rmpint p, q, g, y, x;
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[64];
  rsize sigsize = sizeof (sig);

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((pub  = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_dsa_sign_msg (priv, prng, R_MSG_DIGEST_TYPE_SHA1,
        message, sizeof (message) - 1, sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpuint (sigsize, >, 0);

  r_assert_cmpint (r_dsa_verify_msg (pub, R_MSG_DIGEST_TYPE_SHA1,
        message, sizeof (message) - 1, sig, sigsize), ==, R_CRYPTO_OK);

  /* Cross-check: hashing manually and using verify_msg_with_hash must
   * land on the same internal hash and so accept the same sig. */
  {
    RMsgDigest * md;
    ruint8 hash[20];
    rsize hashsize;
    r_assert_cmpptr ((md = r_msg_digest_new (R_MSG_DIGEST_TYPE_SHA1)), !=, NULL);
    hashsize = r_msg_digest_size (md);
    r_assert_cmpuint (hashsize, ==, sizeof (hash));
    r_assert (r_msg_digest_update (md, message, sizeof (message) - 1));
    r_assert (r_msg_digest_get_data (md, hash, hashsize, NULL));
    r_msg_digest_free (md);

    r_assert_cmpint (r_dsa_verify_msg_with_hash (pub, R_MSG_DIGEST_TYPE_SHA1,
          hash, hashsize, sig, sigsize), ==, R_CRYPTO_OK);
  }

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;

RTEST (rdsa, sign_msg_hash_matches_crypto_key_sign, RTEST_FAST)
{
  /* r_dsa_sign_msg_hash and r_dsa_verify_msg_with_hash are name-
   * symmetric thin shells over r_crypto_key_sign / _verify. Confirm
   * they round-trip and that tampered hashes are still rejected via
   * the shortcut. */
  rmpint p, q, g, y, x;
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[64];
  rsize sigsize = sizeof (sig);

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((pub  = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_dsa_sign_msg_hash (priv, prng, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpint (r_dsa_verify_msg_with_hash (pub, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_a, sizeof (dsa_hash_a), sig, sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpint (r_dsa_verify_msg_with_hash (pub, R_MSG_DIGEST_TYPE_SHA1,
        dsa_hash_b, sizeof (dsa_hash_b), sig, sigsize),
      ==, R_CRYPTO_VERIFY_FAILED);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;

RTEST (rdsa, sign_msg_rejects_empty, RTEST_FAST)
{
  /* msg == NULL / msgsize == 0 must be refused up front rather than
   * silently signing the empty hash. */
  rmpint p, q, g, y, x;
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[64];
  rsize sigsize = sizeof (sig);

  init_dsa_mpints (&p, &q, &g, &y, &x);
  r_assert_cmpptr ((priv = r_dsa_priv_key_new (&p, &q, &g, &y, &x)), !=, NULL);
  r_assert_cmpptr ((pub  = r_dsa_pub_key_new_full (&p, &q, &g, &y)), !=, NULL);
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_dsa_sign_msg (priv, prng, R_MSG_DIGEST_TYPE_SHA1,
        NULL, 0, sig, &sigsize), ==, R_CRYPTO_INVAL);
  r_assert_cmpint (r_dsa_verify_msg (pub, R_MSG_DIGEST_TYPE_SHA1,
        NULL, 0, sig, sigsize), ==, R_CRYPTO_INVAL);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
  clear_dsa_mpints (&p, &q, &g, &y, &x);
}
RTEST_END;
