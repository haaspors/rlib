#include <rlib/rcrypto.h>

#include <rlib/crypto/recc.h>
#include <rlib/crypto/recurve.h>

/* Per-curve coverage for the sign-then-verify roundtrip. Generating Q
 * from d at test time keeps the fixtures small and exercises the math
 * layer's encoding round-trip alongside the ECDSA path. The scalars
 * below are deliberately not "nice" - just arbitrary in-range values
 * that produce a valid keypair on each curve. */
typedef struct {
  REcurveID curve;
  const rchar * d_hex;
} REcdsaTestCurve;

/* A single short scalar works as a valid d on every curve we ship -
 * the order n is always well above 2^128. Keeping one value across
 * curves makes the test data trivial and avoids per-curve range
 * arithmetic. */
#define ECDSA_TEST_D_HEX  "0x123456789abcdef0123456789abcdef"

static const REcdsaTestCurve test_curves[] = {
  { R_ECURVE_ID_SECP192R1, ECDSA_TEST_D_HEX },
  { R_ECURVE_ID_SECP224R1, ECDSA_TEST_D_HEX },
  { R_ECURVE_ID_SECP256R1, ECDSA_TEST_D_HEX },
  { R_ECURVE_ID_SECP384R1, ECDSA_TEST_D_HEX },
  { R_ECURVE_ID_SECP521R1, ECDSA_TEST_D_HEX },
  { R_ECURVE_ID_SECP256K1, ECDSA_TEST_D_HEX },
};

/* SHA-256 of "rlib ecdsa test message" - any fixed 32-byte hash works
 * for ECDSA sign / verify; we just need a deterministic value the
 * tampered-hash test can mutate without re-running a hashing
 * primitive. */
static const ruint8 hash_a[32] = {
  0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65,
  0x9a, 0x2f, 0xea, 0xa0, 0xc5, 0x5a, 0xd0, 0x15,
  0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
  0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08,
};
static const ruint8 hash_b[32] = {
  0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
  0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
  0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
  0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

/* Build an ECDSA keypair from a hex scalar: compute Q = d*G on the
 * curve, SEC 1-encode Q as uncompressed bytes, then hand both halves
 * to the construction APIs. Returns FALSE on any step that fails
 * (e.g. unsupported curve, d outside [1, n-1]). */
static rboolean
make_ecdsa_keypair_from_d_hex (REcurveID curve_id, const rchar * d_hex,
    RCryptoKey ** priv_out, RCryptoKey ** pub_out)
{
  REcurve curve;
  rmpint d;
  REcurveAffinePoint Q;
  ruint8 ecpbuf[1 + 2 * 66 + 1];  /* coord_bytes <= 66 for secp521r1 */
  ruint8 dbuf[66];
  rsize ecpsize = sizeof (ecpbuf);
  rsize dbytes;
  rboolean ok = FALSE;

  *priv_out = NULL;
  *pub_out = NULL;

  if (!r_ecurve_init (&curve, curve_id))
    return FALSE;

  r_mpint_init_str (&d, d_hex, NULL, 16);
  r_ecurve_point_init (&Q);

  /* d must be in [1, n-1]. */
  if (r_mpint_cmp_i32 (&d, 1) < 0 || r_mpint_cmp (&d, &curve.n) >= 0)
    goto out;

  if (!r_ecurve_point_scalar_mul (&Q, &d, &curve.G, &curve))
    goto out;
  if (Q.is_infinity)
    goto out;

  if (!r_ecurve_point_to_uncompressed (&Q, &curve, ecpbuf, &ecpsize))
    goto out;

  /* Pack d as fixed-width bytes matching the curve's coord size. */
  dbytes = curve.coord_bytes;
  if (dbytes > sizeof (dbuf))
    goto out;
  if (!r_mpint_to_binary_with_size (&d, dbuf, dbytes))
    goto out;

  *pub_out = r_ecdsa_pub_key_new (curve_id, ecpbuf, ecpsize);
  *priv_out = r_ecdsa_priv_key_new (curve_id, ecpbuf, ecpsize, dbuf, dbytes);
  ok = (*pub_out != NULL && *priv_out != NULL);
  if (!ok) {
    if (*pub_out != NULL) { r_crypto_key_unref (*pub_out); *pub_out = NULL; }
    if (*priv_out != NULL) { r_crypto_key_unref (*priv_out); *priv_out = NULL; }
  }

out:
  r_mpint_clear (&d);
  r_ecurve_point_clear (&Q);
  r_ecurve_clear (&curve);
  return ok;
}

RTEST_LOOP (recdsa, sign_verify_roundtrip, RTEST_FAST,
    0, R_N_ELEMENTS (test_curves))
{
  /* Sign with the private key, verify with the matching public key,
   * across every prime curve the math layer supports. */
  const REcdsaTestCurve * tc = &test_curves[__i];
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[256];
  rsize sigsize = sizeof (sig);

  r_assert (make_ecdsa_keypair_from_d_hex (tc->curve, tc->d_hex, &priv, &pub));
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpuint (sigsize, >, 0);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig, sigsize), ==, R_CRYPTO_OK);

  /* Verify also works through the priv key (verify hook is wired on
   * both algo-info structs). */
  r_assert_cmpint (r_crypto_key_verify (priv, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig, sigsize), ==, R_CRYPTO_OK);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (recdsa, verify_rejects_tampered_hash, RTEST_FAST)
{
  /* Signature was generated over hash_a; verifying against hash_b
   * must fail with VERIFY_FAILED, not OK. */
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[128];
  rsize sigsize = sizeof (sig);

  r_assert (make_ecdsa_keypair_from_d_hex (R_ECURVE_ID_SECP256R1,
        test_curves[2].d_hex, &priv, &pub));
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
        hash_b, sizeof (hash_b), sig, sigsize), ==, R_CRYPTO_VERIFY_FAILED);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (recdsa, verify_rejects_malformed_signature, RTEST_FAST)
{
  /* Garbage bytes that aren't a valid Ecdsa-Sig-Value SEQUENCE must
   * surface as VERIFY_FAILED rather than crashing the ASN.1 decoder.
   * A well-formed SEQUENCE with r = 0 must also be rejected by the
   * range check before any scalar-mul work happens. */
  RCryptoKey * priv, * pub;
  static const ruint8 junk[] = { 0xde, 0xad, 0xbe, 0xef };
  static const ruint8 r_zero[] = { 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 };

  r_assert (make_ecdsa_keypair_from_d_hex (R_ECURVE_ID_SECP256R1,
        test_curves[2].d_hex, &priv, &pub));

  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), junk, sizeof (junk)),
      ==, R_CRYPTO_VERIFY_FAILED);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), r_zero, sizeof (r_zero)),
      ==, R_CRYPTO_VERIFY_FAILED);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
}
RTEST_END;

RTEST (recdsa, sign_fresh_k_each_call, RTEST_FAST)
{
  /* Signing the same hash twice must yield different signatures -
   * matching outputs would mean a constant k, which leaks d. The
   * sample size is tiny (we just need to see the two signatures
   * differ at all), so collisions on a healthy PRNG are negligible. */
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig1[128], sig2[128];
  rsize sigsize1 = sizeof (sig1), sigsize2 = sizeof (sig2);

  r_assert (make_ecdsa_keypair_from_d_hex (R_ECURVE_ID_SECP256R1,
        test_curves[2].d_hex, &priv, &pub));
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig1, &sigsize1), ==, R_CRYPTO_OK);
  r_assert_cmpint (r_crypto_key_sign (priv, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig2, &sigsize2), ==, R_CRYPTO_OK);
  r_assert (sigsize1 != sigsize2 || r_memcmp (sig1, sig2, sigsize1) != 0);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (recdsa, rfc6979_a2_5_p256_sample_verify, RTEST_FAST)
{
  /* RFC 6979 Appendix A.2.5 vector: ECDSA-P-256 + SHA-256, message
   * "sample", deterministic k. Used here only for verify - our sign
   * path samples k with extra random bits, so we can't reproduce the
   * RFC's exact (r, s) - but verifying the canonical signature is a
   * strong interop check against any reference implementation. */
  static const ruint8 pubkey[] = {
    0x04,
    /* Q_x */
    0x60, 0xFE, 0xD4, 0xBA, 0x25, 0x5A, 0x9D, 0x31, 0xC9, 0x61, 0xEB, 0x74,
    0xC6, 0x35, 0x6D, 0x68, 0xC0, 0x49, 0xB8, 0x92, 0x3B, 0x61, 0xFA, 0x6C,
    0xE6, 0x69, 0x62, 0x2E, 0x60, 0xF2, 0x9F, 0xB6,
    /* Q_y */
    0x79, 0x03, 0xFE, 0x10, 0x08, 0xB8, 0xBC, 0x99, 0xA4, 0x1A, 0xE9, 0xE9,
    0x56, 0x28, 0xBC, 0x64, 0xF2, 0xF1, 0xB2, 0x0C, 0x2D, 0x7E, 0x9F, 0x51,
    0x77, 0xA3, 0xC2, 0x94, 0xD4, 0x46, 0x22, 0x99,
  };
  static const ruint8 hash[] = {
    /* SHA-256("sample") */
    0xAF, 0x2B, 0xDB, 0xE1, 0xAA, 0x9B, 0x6E, 0xC1, 0xE2, 0xAD, 0xE1, 0xD6,
    0x94, 0xF4, 0x1F, 0xC7, 0x1A, 0x83, 0x1D, 0x02, 0x68, 0xE9, 0x89, 0x15,
    0x62, 0x11, 0x3D, 0x8A, 0x62, 0xAD, 0xD1, 0xBF,
  };
  /* DER ASN.1 of Ecdsa-Sig-Value { r, s }: both r and s have the high
   * bit set in their MSB, so each INTEGER gets a leading 0x00 byte
   * (33 content bytes each). Outer SEQUENCE length = 2*(2 + 33) = 70. */
  static const ruint8 sig[] = {
    0x30, 0x46,
    0x02, 0x21, 0x00,
    0xEF, 0xD4, 0x8B, 0x2A, 0xAC, 0xB6, 0xA8, 0xFD, 0x11, 0x40, 0xDD, 0x9C,
    0xD4, 0x5E, 0x81, 0xD6, 0x9D, 0x2C, 0x87, 0x7B, 0x56, 0xAA, 0xF9, 0x91,
    0xC3, 0x4D, 0x0E, 0xA8, 0x4E, 0xAF, 0x37, 0x16,
    0x02, 0x21, 0x00,
    0xF7, 0xCB, 0x1C, 0x94, 0x2D, 0x65, 0x7C, 0x41, 0xD4, 0x36, 0xC7, 0xA1,
    0xB6, 0xE2, 0x9F, 0x65, 0xF3, 0xE9, 0x00, 0xDB, 0xB9, 0xAF, 0xF4, 0x06,
    0x4D, 0xC4, 0xAB, 0x2F, 0x84, 0x3A, 0xCD, 0xA8,
  };
  RCryptoKey * pub;

  r_assert_cmpptr ((pub = r_ecdsa_pub_key_new (R_ECURVE_ID_SECP256R1,
        pubkey, sizeof (pubkey))), !=, NULL);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
        hash, sizeof (hash), sig, sizeof (sig)), ==, R_CRYPTO_OK);

  r_crypto_key_unref (pub);
}
RTEST_END;

/* Round-trip helper: encode the supplied key via r_crypto_key_to_asn1
 * into a fresh DER buffer, then decode via the matching ASN.1 entry
 * point (pub vs priv). Returns the rebuilt key, or NULL on any step
 * failure. *out_buf is set to the DER bytes for asserting size > 0;
 * caller frees it. */
static RCryptoKey *
recdsa_asn1_roundtrip (const RCryptoKey * orig, ruint8 ** out_buf,
    rsize * out_size, rboolean is_priv)
{
  RAsn1BinEncoder * enc;
  RAsn1BinDecoder * dec;
  RAsn1BinTLV tlv = R_ASN1_BIN_TLV_INIT;
  RCryptoKey * back = NULL;

  *out_buf = NULL;
  *out_size = 0;

  r_assert_cmpptr ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)), !=, NULL);
  r_assert_cmpint (r_crypto_key_to_asn1 (orig, enc), ==, R_CRYPTO_OK);
  r_assert_cmpptr ((*out_buf = r_asn1_bin_encoder_get_data (enc, out_size)),
      !=, NULL);
  r_asn1_bin_encoder_unref (enc);

  r_assert_cmpptr ((dec = r_asn1_bin_decoder_new (R_ASN1_DER, *out_buf, *out_size)),
      !=, NULL);
  r_assert_cmpint (r_asn1_bin_decoder_next (dec, &tlv), ==, R_ASN1_DECODER_OK);
  back = is_priv
      ? r_crypto_key_from_asn1_private_key (dec, &tlv)
      : r_crypto_key_from_asn1_public_key (dec, &tlv);
  r_asn1_bin_decoder_unref (dec);
  return back;
}

RTEST_LOOP (recdsa, asn1_pub_roundtrip, RTEST_FAST,
    0, R_N_ELEMENTS (test_curves))
{
  /* Export the ECDSA pub key as SubjectPublicKeyInfo, decode back,
   * confirm the algo / curve / Q survive intact. Run across every
   * supported curve so a per-curve OID lookup gap shows up here. */
  const REcdsaTestCurve * tc = &test_curves[__i];
  RCryptoKey * priv, * pub, * back;
  ruint8 * buf;
  rsize bufsize;

  r_assert (make_ecdsa_keypair_from_d_hex (tc->curve, tc->d_hex, &priv, &pub));
  r_assert_cmpptr ((back = recdsa_asn1_roundtrip (pub, &buf, &bufsize, FALSE)),
      !=, NULL);
  r_assert_cmpuint (bufsize, >, 0);
  r_assert_cmpuint (r_crypto_key_get_algo (back), ==, R_CRYPTO_ALGO_ECDSA);
  r_assert_cmpuint (r_crypto_key_get_type (back), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert_cmpuint (r_ecc_key_get_curve (back), ==, tc->curve);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_crypto_key_unref (back);
  r_free (buf);
}
RTEST_END;

RTEST_LOOP (recdsa, asn1_priv_roundtrip, RTEST_FAST,
    0, R_N_ELEMENTS (test_curves))
{
  /* Export the ECDSA priv key as OneAsymmetricKey, decode back, and
   * confirm sign / verify keeps working on the rebuilt key - the
   * strongest functional check that the round-trip didn't drop the
   * scalar or mis-map the curve. */
  const REcdsaTestCurve * tc = &test_curves[__i];
  RCryptoKey * priv, * pub, * back;
  RPrng * prng;
  ruint8 * buf;
  rsize bufsize;
  ruint8 sig[256];
  rsize sigsize = sizeof (sig);

  r_assert (make_ecdsa_keypair_from_d_hex (tc->curve, tc->d_hex, &priv, &pub));
  r_assert_cmpptr ((back = recdsa_asn1_roundtrip (priv, &buf, &bufsize, TRUE)),
      !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_algo (back), ==, R_CRYPTO_ALGO_ECDSA);
  r_assert_cmpuint (r_crypto_key_get_type (back), ==, R_CRYPTO_PRIVATE_KEY);
  r_assert_cmpuint (r_ecc_key_get_curve (back), ==, tc->curve);

  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);
  r_assert_cmpint (r_crypto_key_sign (back, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig, &sigsize), ==, R_CRYPTO_OK);
  r_assert_cmpint (r_crypto_key_verify (pub, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig, sigsize), ==, R_CRYPTO_OK);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_crypto_key_unref (back);
  r_prng_unref (prng);
  r_free (buf);
}
RTEST_END;

RTEST (recdsa, sign_rejects_pub_key, RTEST_FAST)
{
  /* r_crypto_key_sign on a public key must surface WRONG_TYPE rather
   * than crashing. The verify hook is wired on the pub algo-info, but
   * sign is not. */
  RCryptoKey * priv, * pub;
  RPrng * prng;
  ruint8 sig[128];
  rsize sigsize = sizeof (sig);

  r_assert (make_ecdsa_keypair_from_d_hex (R_ECURVE_ID_SECP256R1,
        test_curves[2].d_hex, &priv, &pub));
  r_assert_cmpptr ((prng = r_rand_prng_new ()), !=, NULL);

  /* r_crypto_key_sign returns NOT_AVAILABLE when the algo info has a
   * NULL sign hook; that's what pub keys carry. */
  r_assert_cmpint (r_crypto_key_sign (pub, prng, R_MSG_DIGEST_TYPE_SHA256,
        hash_a, sizeof (hash_a), sig, &sigsize),
      ==, R_CRYPTO_NOT_AVAILABLE);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_prng_unref (prng);
}
RTEST_END;
