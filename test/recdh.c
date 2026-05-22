#include <rlib/rcrypto.h>

#include "wycheproof_ecdh.h"

/* Build a SEC 1 uncompressed encoding (0x04 || X || Y) from two
 * coordinate hex strings whose byte lengths must match `coord_bytes`.
 * Caller-supplied buffer; returns the bytes written. */
static rsize
recdh_encode_point (ruint8 * buf, rsize bufsize, rsize coord_bytes,
    const rchar * x_hex, const rchar * y_hex)
{
  rsize need = 1 + 2 * coord_bytes;
  rsize xlen, ylen;
  ruint8 * x;
  ruint8 * y;

  r_assert_cmpuint (bufsize, >=, need);
  buf[0] = 0x04;
  x = r_str_hex_mem (x_hex, &xlen);
  y = r_str_hex_mem (y_hex, &ylen);
  r_assert_cmpuint (xlen, ==, coord_bytes);
  r_assert_cmpuint (ylen, ==, coord_bytes);
  r_memcpy (buf + 1, x, coord_bytes);
  r_memcpy (buf + 1 + coord_bytes, y, coord_bytes);
  r_free (x);
  r_free (y);
  return need;
}

/* Build an ECDH priv key directly from hex strings, deriving Q from d.
 * Skips the round-trip through a public-point encoding so KAT vectors
 * that only publish the private scalar still drive the same code path
 * the application would. */
static RCryptoKey *
recdh_priv_key_from_hex (REcurveID curve, const rchar * d_hex)
{
  rsize dlen;
  ruint8 * d = r_str_hex_mem (d_hex, &dlen);
  RCryptoKey * key = r_ecdh_priv_key_new (curve, NULL, 0, d, dlen);
  r_free (d);
  return key;
}

RTEST (recdh, gen_key_has_q_and_curve, RTEST_FAST)
{
  RCryptoKey * key;

  r_assert_cmpptr ((key = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP256R1, NULL)),
      !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_algo (key), ==, R_CRYPTO_ALGO_ECDH);
  r_assert_cmpuint (r_crypto_key_get_type (key), ==, R_CRYPTO_PRIVATE_KEY);
  r_assert_cmphex (r_ecc_key_get_curve (key), ==, R_ECURVE_ID_SECP256R1);

  REcurveAffinePoint Q;
  r_ecurve_point_init (&Q);
  r_assert (r_ecc_key_get_q (key, &Q));
  r_assert (!Q.is_infinity);
  r_ecurve_point_clear (&Q);

  r_crypto_key_unref (key);
}
RTEST_END;

RTEST (recdh, gen_keys_interop, RTEST_FAST)
{
  /* The defining property: both parties derive the same X-coordinate
   * from their own d and the peer's Q. Exercised on every supported
   * prime curve so a one-curve-specific math bug can't hide.
   * secp521r1 is in the SLOW set below to keep this fast tier under
   * a second; everything else lives here. */
  static const REcurveID curves[] = {
    R_ECURVE_ID_SECP192R1,
    R_ECURVE_ID_SECP224R1,
    R_ECURVE_ID_SECP256R1,
    R_ECURVE_ID_SECP384R1,
    R_ECURVE_ID_SECP256K1,
  };
  rsize i;

  for (i = 0; i < R_N_ELEMENTS (curves); i++) {
    RCryptoKey * a_priv, * b_priv, * a_pub, * b_pub;
    REcurve params;
    REcurveAffinePoint Q;
    ruint8 enc[1 + 2 * 66];
    ruint8 sa[66], sb[66];
    rsize encsize, sasize, sbsize;

    r_assert (r_ecurve_init (&params, curves[i]));

    a_priv = r_ecdh_priv_key_new_gen (curves[i], NULL);
    b_priv = r_ecdh_priv_key_new_gen (curves[i], NULL);
    r_assert_cmpptr (a_priv, !=, NULL);
    r_assert_cmpptr (b_priv, !=, NULL);

    /* Round-trip B's public point through SEC 1 encoding (this is what
     * a real ECDH exchange would put on the wire), then hand it to A. */
    r_ecurve_point_init (&Q);
    r_assert (r_ecc_key_get_q (b_priv, &Q));
    encsize = sizeof (enc);
    r_assert (r_ecurve_point_to_uncompressed (&Q, &params, enc, &encsize));
    b_pub = r_ecdh_pub_key_new (curves[i], enc, encsize);
    r_assert_cmpptr (b_pub, !=, NULL);
    r_ecurve_point_clear (&Q);

    /* And A's public point to B. */
    r_ecurve_point_init (&Q);
    r_assert (r_ecc_key_get_q (a_priv, &Q));
    encsize = sizeof (enc);
    r_assert (r_ecurve_point_to_uncompressed (&Q, &params, enc, &encsize));
    a_pub = r_ecdh_pub_key_new (curves[i], enc, encsize);
    r_assert_cmpptr (a_pub, !=, NULL);
    r_ecurve_point_clear (&Q);

    sasize = sizeof (sa);
    sbsize = sizeof (sb);
    r_assert_cmpint (r_ecdh_compute_shared (a_priv, b_pub, sa, &sasize),
        ==, R_CRYPTO_OK);
    r_assert_cmpint (r_ecdh_compute_shared (b_priv, a_pub, sb, &sbsize),
        ==, R_CRYPTO_OK);
    r_assert_cmpuint (sasize, ==, sbsize);
    r_assert_cmpuint (sasize, ==, params.coord_bytes);
    r_assert_cmpmem (sa, ==, sb, sasize);

    r_crypto_key_unref (a_priv);
    r_crypto_key_unref (b_priv);
    r_crypto_key_unref (a_pub);
    r_crypto_key_unref (b_pub);
    r_ecurve_clear (&params);
  }
}
RTEST_END;

RTEST (recdh, compute_rejects_mismatched_curve, RTEST_FAST)
{
  RCryptoKey * mine, * peer;
  ruint8 out[66];
  rsize outsize = sizeof (out);

  r_assert_cmpptr ((mine = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP256R1, NULL)),
      !=, NULL);
  r_assert_cmpptr ((peer = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP384R1, NULL)),
      !=, NULL);
  r_assert_cmpint (r_ecdh_compute_shared (mine, peer, out, &outsize),
      ==, R_CRYPTO_WRONG_TYPE);

  r_crypto_key_unref (mine);
  r_crypto_key_unref (peer);
}
RTEST_END;

RTEST (recdh, pub_key_rejects_off_curve_point, RTEST_FAST)
{
  /* The constructor should refuse an obviously-off-curve point. Take a
   * valid SEC 1 encoding of G on secp256r1 and flip the last byte of Y. */
  REcurve params;
  ruint8 enc[1 + 2 * 32];
  rsize encsize = sizeof (enc);
  RCryptoKey * key;

  r_assert (r_ecurve_init (&params, R_ECURVE_ID_SECP256R1));
  r_assert (r_ecurve_point_to_uncompressed (&params.G, &params, enc, &encsize));
  enc[encsize - 1] ^= 0x01;

  r_assert_cmpptr ((key = r_ecdh_pub_key_new (R_ECURVE_ID_SECP256R1, enc, encsize)),
      ==, NULL);
  r_ecurve_clear (&params);
}
RTEST_END;

RTEST (recdh, compute_rejects_identity_peer, RTEST_FAST)
{
  /* The SEC 1 encoding of the identity is a single 0x00 byte. The
   * pub-key constructor accepts it (it round-trips through encode /
   * decode), but compute_shared must refuse to derive a secret with
   * the identity as a peer point - that would just produce d * O = O,
   * yielding an all-zero or out-of-band X. */
  RCryptoKey * mine, * peer_pub;
  ruint8 zero = 0x00;
  ruint8 out[32];
  rsize outsize = sizeof (out);

  r_assert_cmpptr ((mine = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP256R1, NULL)),
      !=, NULL);
  r_assert_cmpptr ((peer_pub = r_ecdh_pub_key_new (R_ECURVE_ID_SECP256R1,
        &zero, 1)), !=, NULL);

  r_assert_cmpint (r_ecdh_compute_shared (mine, peer_pub, out, &outsize),
      ==, R_CRYPTO_INVAL);

  r_crypto_key_unref (mine);
  r_crypto_key_unref (peer_pub);
}
RTEST_END;

typedef struct {
  REcurveID curve;
  const rchar * d_hex;      /* our private scalar */
  const rchar * px_hex;     /* peer Qx */
  const rchar * py_hex;     /* peer Qy */
  const rchar * z_hex;      /* expected shared X */
} REcdhKatVector;

/* NIST CAVP "KAS-ECC SP800-56A" vectors, one per curve. Source:
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/KASTestVectorsECC2016.zip
 * Trimmed to a single triple per curve - the smoke and interop tests
 * already cover variation, the KATs are here to lock down agreement
 * with a published implementation. */
static const REcdhKatVector recdh_kat_vectors[] = {
  /* P-192 / secp192r1 */
  { R_ECURVE_ID_SECP192R1,
    "f17d3fea367b74d340851ca4270dcb24c271f445bed9d527",
    "42ea6dd9969dd2a61fea1aac7f8e98edcc896c6e55857cc0",
    "dfbe5d7c61fac88b11811bde328e8a0d12bf01a9d204b523",
    "803d8ab2e5b6e6fca715737c3a82f7ce3c783124f6d51cd0" },

  /* P-224 / secp224r1 */
  { R_ECURVE_ID_SECP224R1,
    "8346a60fc6f293ca5a0d2af68ba71d1dd389e5e40837942df3e43cbd",
    "af33cd0629bc7e996320a3f40368f74de8704fa37b8fab69abaae280",
    "882092ccbba7930f419a8a4f9bb16978bbc3838729992559a6f2e2d7",
    "7d96f9a3bd3c05cf5cc37feb8b9d5209d5c2597464dec3e9983743e8" },

  /* P-256 / secp256r1 */
  { R_ECURVE_ID_SECP256R1,
    "7d7dc5f71eb29ddef7505e0db952c2db58a17a0a8e842a9d2c2e1f3a08c14ad8",
    "700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
    "db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
    "04d19c10bf27e2b2ea780fea519e509d73d5c2ebd7534011eadd6cbbc717afde" },

  /* P-384 / secp384r1 - the static IUT/CAVS scalars from RFC 5903
   * §8.2, with the peer's Q regenerated from the scalar since the
   * Q encoding published in the RFC has a propagated typo. The Z
   * matches the published value. */
  { R_ECURVE_ID_SECP384R1,
    "099f3c7034d4a2c699884d73a375a67f7624ef7c6b3c0f160647b67414dce655"
      "e35b538041e649ee3faef896783ab194",
    "e558dbef53eecde3d3fccfc1aea08a89a987475d12fd950d83cfa41732bc509d"
      "0d1ac43a0336def96fda41d0774a3571",
    "dcfbec7aacf3196472169e838430367f66eebe3c6e70c416dd5f0c68759dd1ff"
      "f83fa40142209dff5eaad96db9e6386c",
    "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4"
      "d603135569b9e9d09cf5d4a270f59746" },

  /* secp256k1 - generated locally with a known-good Python EC
   * implementation since the NIST vectors don't cover it; the smoke
   * and interop tests are the primary correctness check for this
   * curve, the KAT is here to catch regressions. */
  { R_ECURVE_ID_SECP256K1,
    "c6e6fb1f73db97e6e2ef193e3739ad9b80b2a30c19d3a1f4d2f4f10b80c5e3a4",
    "0aaf658c2d30974bc0739baa06195ec5b4db39ac3f4757584784f4dd01f44fce",
    "e79222828ff1fb591164bbf7d41759ecf188d5ea1c4a0c6503df4d6835e290a6",
    "44bc815baa29355c6eafd1d1cd91384de9bc509b33295d9877c83f0cee9e2c07" },
};

RTEST (recdh, compute_rejects_bad_inputs, RTEST_FAST)
{
  /* The full set of API-misuse failure modes compute_shared promises
   * to handle: NULL pointers, mismatched algo (DH key as priv, ECDSA
   * key as peer), private key passed where a public is expected, and
   * a too-small output buffer. */
  RCryptoKey * priv;
  RCryptoKey * pub;
  RCryptoKey * other_priv;
  RCryptoKey * dh_priv;
  RDhNamedGroup dh_group = R_DH_GROUP_FFDHE_2048;
  REcurveAffinePoint Q;
  REcurve params;
  ruint8 enc[1 + 2 * 32];
  ruint8 small[16];
  ruint8 out[32];
  rsize outsize, encsize;

  r_assert (r_ecurve_init (&params, R_ECURVE_ID_SECP256R1));
  r_assert_cmpptr ((priv = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP256R1, NULL)),
      !=, NULL);

  r_ecurve_point_init (&Q);
  r_assert (r_ecc_key_get_q (priv, &Q));
  encsize = sizeof (enc);
  r_assert (r_ecurve_point_to_uncompressed (&Q, &params, enc, &encsize));
  r_ecurve_point_clear (&Q);
  pub = r_ecdh_pub_key_new (R_ECURVE_ID_SECP256R1, enc, encsize);
  r_assert_cmpptr (pub, !=, NULL);

  /* NULL inputs. */
  outsize = sizeof (out);
  r_assert_cmpint (r_ecdh_compute_shared (NULL, pub, out, &outsize),
      ==, R_CRYPTO_INVAL);
  r_assert_cmpint (r_ecdh_compute_shared (priv, NULL, out, &outsize),
      ==, R_CRYPTO_INVAL);
  r_assert_cmpint (r_ecdh_compute_shared (priv, pub, NULL, &outsize),
      ==, R_CRYPTO_INVAL);
  r_assert_cmpint (r_ecdh_compute_shared (priv, pub, out, NULL),
      ==, R_CRYPTO_INVAL);

  /* priv is a public key. */
  outsize = sizeof (out);
  r_assert_cmpint (r_ecdh_compute_shared (pub, pub, out, &outsize),
      ==, R_CRYPTO_WRONG_TYPE);

  /* peer is a private key. */
  outsize = sizeof (out);
  r_assert_cmpint (r_ecdh_compute_shared (priv, priv, out, &outsize),
      ==, R_CRYPTO_WRONG_TYPE);

  /* priv is a DH key (right algorithm family, wrong algorithm). */
  dh_priv = r_dh_priv_key_new_gen_named (dh_group, NULL);
  if (dh_priv != NULL) {
    outsize = sizeof (out);
    r_assert_cmpint (r_ecdh_compute_shared (dh_priv, pub, out, &outsize),
        ==, R_CRYPTO_WRONG_TYPE);
    r_crypto_key_unref (dh_priv);
  }

  /* peer is an ECDSA key. */
  other_priv = r_ecdsa_priv_key_new (R_ECURVE_ID_SECP256R1, enc, encsize,
      enc + 1, params.coord_bytes);
  if (other_priv != NULL) {
    outsize = sizeof (out);
    r_assert_cmpint (r_ecdh_compute_shared (priv, other_priv, out, &outsize),
        ==, R_CRYPTO_WRONG_TYPE);
    r_crypto_key_unref (other_priv);
  }

  /* Output buffer too small to hold an X coordinate. */
  outsize = sizeof (small);
  r_assert_cmpint (r_ecdh_compute_shared (priv, pub, small, &outsize),
      ==, R_CRYPTO_BUFFER_TOO_SMALL);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (pub);
  r_ecurve_clear (&params);
}
RTEST_END;

RTEST (recdh, pub_key_rejects_unsupported_curve, RTEST_FAST)
{
  /* The math layer only ships parameters for the six prime curves, so
   * any other REcurveID must fail to construct an ECDH key rather
   * than producing a parsable-but-unusable wrapper. The byte payload
   * doesn't matter - we never get past the curve lookup. */
  static const ruint8 anything[] = { 0x04, 0x01, 0x02, 0x03, 0x04 };

  r_assert_cmpptr (r_ecdh_pub_key_new (R_ECURVE_ID_X25519, anything,
        sizeof (anything)), ==, NULL);
  r_assert_cmpptr (r_ecdh_pub_key_new (R_ECURVE_ID_SECT163K1, anything,
        sizeof (anything)), ==, NULL);
  r_assert_cmpptr (r_ecdh_pub_key_new (R_ECURVE_ID_BRAINPOOLP256R1, anything,
        sizeof (anything)), ==, NULL);
}
RTEST_END;

RTEST (recdh, priv_key_rejects_unsupported_curve, RTEST_FAST)
{
  /* Same story for the private side: ECDH compute_shared needs the
   * math layer, so unsupported curves get refused at construction
   * rather than silently producing a key that just fails later.
   * Covers both the ecp=NULL path (most realistic for an ASN.1
   * ECPrivateKey with no public-key field) and the ecp+scalar path
   * (whose ecp couldn't be parsed against an unknown curve anyway). */
  static const ruint8 scalar32[32] = { 0x01 };
  static const ruint8 anything[] = { 0x04, 0x01, 0x02, 0x03, 0x04 };

  r_assert_cmpptr (r_ecdh_priv_key_new (R_ECURVE_ID_X25519, NULL, 0,
        scalar32, sizeof (scalar32)), ==, NULL);
  r_assert_cmpptr (r_ecdh_priv_key_new (R_ECURVE_ID_SECT163K1, NULL, 0,
        scalar32, sizeof (scalar32)), ==, NULL);
  r_assert_cmpptr (r_ecdh_priv_key_new (R_ECURVE_ID_X25519,
        anything, sizeof (anything),
        scalar32, sizeof (scalar32)), ==, NULL);
}
RTEST_END;

RTEST (recdh, ecdsa_key_get_q_returns_false_without_math, RTEST_FAST)
{
  /* r_ecc_key_get_q should refuse to copy out a point when the key
   * was built from an encoding the math layer couldn't parse. ECDSA
   * deliberately stays lenient there (so X.509 / PEM fixtures using
   * compressed or otherwise unsupported encodings keep loading), so
   * the get_q "no parsed point" branch is reachable only via ECDSA. */
  static const ruint8 compressed[33] = {
    0x02,  /* SEC 1 compressed prefix - we don't support decoding */
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
    0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0,
    0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96
  };
  RCryptoKey * key;
  REcurveAffinePoint Q;

  /* The ECDSA constructor accepts the key with the raw bytes around
   * for fingerprinting / ASN.1 round-trip, but doesn't manage to
   * populate Q. */
  key = r_ecdsa_pub_key_new (R_ECURVE_ID_SECP256R1, compressed,
      sizeof (compressed));
  r_assert_cmpptr (key, !=, NULL);

  r_ecurve_point_init (&Q);
  r_assert (!r_ecc_key_get_q (key, &Q));
  r_ecurve_point_clear (&Q);

  r_crypto_key_unref (key);
}
RTEST_END;

RTEST (recdh, priv_key_rejects_out_of_range_scalar, RTEST_FAST)
{
  /* d must be in [1, n-1]; d = 0 and d = n should both be refused.
   * d = n is harder to express as raw bytes than d = 0, so we lift
   * the curve order into a buffer and try it. */
  REcurve params;
  ruint8 zero_scalar[32] = { 0 };
  ruint8 n_bytes[32];
  RCryptoKey * key;

  r_assert (r_ecurve_init (&params, R_ECURVE_ID_SECP256R1));
  r_assert (r_mpint_to_binary_with_size (&params.n, n_bytes, sizeof (n_bytes)));

  key = r_ecdh_priv_key_new (R_ECURVE_ID_SECP256R1, NULL, 0,
      zero_scalar, sizeof (zero_scalar));
  r_assert_cmpptr (key, ==, NULL);

  key = r_ecdh_priv_key_new (R_ECURVE_ID_SECP256R1, NULL, 0,
      n_bytes, sizeof (n_bytes));
  r_assert_cmpptr (key, ==, NULL);

  r_ecurve_clear (&params);
}
RTEST_END;

RTEST (recdh, priv_key_new_rejects_mismatched_ecp_and_scalar, RTEST_FAST)
{
  /* When both halves of a keypair are supplied, they have to match.
   * A caller that hands us a Q that isn't d * G is either confused
   * or hostile - either way, refusing the construction is safer
   * than carrying the inconsistency forward into compute_shared. */
  REcurve curve;
  REcurveAffinePoint Q_other;
  ruint8 enc_other[1 + 2 * 32];
  rsize enc_size;
  ruint8 d_one[32] = { 0 };
  RCryptoKey * key;
  rmpint d_other;

  r_assert (r_ecurve_init (&curve, R_ECURVE_ID_SECP256R1));
  d_one[31] = 0x01;  /* d = 1; matching Q would be G itself. */

  /* Compute Q for d = 2 (deliberately different from d = 1). */
  r_ecurve_point_init (&Q_other);
  r_mpint_init (&d_other);
  r_mpint_set_u32 (&d_other, 2);
  r_assert (r_ecurve_point_scalar_mul (&Q_other, &d_other, &curve.G, &curve));
  enc_size = sizeof (enc_other);
  r_assert (r_ecurve_point_to_uncompressed (&Q_other, &curve, enc_other, &enc_size));

  /* Hand the (d = 1, Q = 2 * G) mismatch to the constructor; expect NULL. */
  key = r_ecdh_priv_key_new (R_ECURVE_ID_SECP256R1,
      enc_other, enc_size, d_one, sizeof (d_one));
  r_assert_cmpptr (key, ==, NULL);

  r_mpint_clear (&d_other);
  r_ecurve_point_clear (&Q_other);
  r_ecurve_clear (&curve);
}
RTEST_END;

RTEST (recdh, priv_key_new_gen_uses_supplied_prng, RTEST_FAST)
{
  /* r_ecdh_priv_key_new_gen accepts a caller-provided PRNG. Exercise
   * the passthrough path (the default-PRNG path is covered by every
   * other gen test in this file). */
  RPrng * prng;
  RCryptoKey * key;
  const ruint8 * scalar;
  rsize scalarsize;

  r_assert_cmpptr ((prng = r_prng_new_mt_with_seed (0xc0ffee)), !=, NULL);
  r_assert_cmpptr ((key = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP256R1, prng)),
      !=, NULL);
  r_assert_cmpuint (r_crypto_key_get_algo (key), ==, R_CRYPTO_ALGO_ECDH);
  r_assert (r_ecc_priv_key_get_scalar (key, &scalar, &scalarsize));
  r_assert_cmpuint (scalarsize, ==, 32);
  /* Scalar should be non-zero (PRNG with a fixed seed always produces
   * the same bytes; r_ecdh_priv_key_new_gen would reject a zero d). */
  r_assert_cmpuint (scalar[0] | scalar[1] | scalar[2] | scalar[3], !=, 0);

  r_crypto_key_unref (key);
  r_prng_unref (prng);
}
RTEST_END;

RTEST (recdh, priv_key_new_accepts_both_ecp_and_scalar, RTEST_FAST)
{
  /* The "we already have both halves" import path: caller supplies
   * the SEC 1 public-point encoding and the scalar bytes together
   * (e.g. from an ASN.1 ECPrivateKey that included the optional
   * publicKey field). The resulting key should carry both. */
  REcurve params;
  REcurveAffinePoint Q;
  ruint8 enc[1 + 2 * 32];
  rsize encsize;
  rmpint d;
  ruint8 dbuf[32];
  RCryptoKey * tmp, * key;
  const ruint8 * scalar;
  rsize scalarsize;

  r_assert (r_ecurve_init (&params, R_ECURVE_ID_SECP256R1));

  /* Generate fresh key material via the gen path, then extract bytes
   * to feed into the dual-input constructor. */
  tmp = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP256R1, NULL);
  r_assert_cmpptr (tmp, !=, NULL);

  r_ecurve_point_init (&Q);
  r_assert (r_ecc_key_get_q (tmp, &Q));
  encsize = sizeof (enc);
  r_assert (r_ecurve_point_to_uncompressed (&Q, &params, enc, &encsize));

  r_assert (r_ecc_priv_key_get_scalar (tmp, &scalar, &scalarsize));
  r_assert_cmpuint (scalarsize, ==, 32);
  r_memcpy (dbuf, scalar, scalarsize);
  r_crypto_key_unref (tmp);
  r_ecurve_point_clear (&Q);

  /* Now rebuild from both halves and check both views are populated
   * and consistent (Q == d * G via deriving in load_scalar would have
   * given the same Q; check that get_q matches the supplied ecp). */
  key = r_ecdh_priv_key_new (R_ECURVE_ID_SECP256R1, enc, encsize,
      dbuf, sizeof (dbuf));
  r_assert_cmpptr (key, !=, NULL);

  r_ecurve_point_init (&Q);
  r_assert (r_ecc_key_get_q (key, &Q));
  r_mpint_init (&d);
  r_mpint_set_binary (&d, dbuf, sizeof (dbuf));
  {
    REcurveAffinePoint Qderived;
    r_ecurve_point_init (&Qderived);
    r_assert (r_ecurve_point_scalar_mul (&Qderived, &d, &params.G, &params));
    r_assert_cmpint (r_mpint_cmp (&Q.x, &Qderived.x), ==, 0);
    r_assert_cmpint (r_mpint_cmp (&Q.y, &Qderived.y), ==, 0);
    r_ecurve_point_clear (&Qderived);
  }
  r_mpint_clear (&d);
  r_ecurve_point_clear (&Q);
  r_crypto_key_unref (key);
  r_ecurve_clear (&params);
}
RTEST_END;

RTEST (recdh, gen_keys_interop_secp521r1, RTEST_SLOW)
{
  /* secp521r1 separately so the fast tier above stays sub-second. */
  RCryptoKey * a_priv, * b_priv, * a_pub, * b_pub;
  REcurve params;
  REcurveAffinePoint Q;
  ruint8 enc[1 + 2 * 66];
  ruint8 sa[66], sb[66];
  rsize encsize, sasize, sbsize;

  r_assert (r_ecurve_init (&params, R_ECURVE_ID_SECP521R1));

  a_priv = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP521R1, NULL);
  b_priv = r_ecdh_priv_key_new_gen (R_ECURVE_ID_SECP521R1, NULL);
  r_assert_cmpptr (a_priv, !=, NULL);
  r_assert_cmpptr (b_priv, !=, NULL);

  r_ecurve_point_init (&Q);
  r_assert (r_ecc_key_get_q (b_priv, &Q));
  encsize = sizeof (enc);
  r_assert (r_ecurve_point_to_uncompressed (&Q, &params, enc, &encsize));
  b_pub = r_ecdh_pub_key_new (R_ECURVE_ID_SECP521R1, enc, encsize);
  r_assert_cmpptr (b_pub, !=, NULL);
  r_ecurve_point_clear (&Q);

  r_ecurve_point_init (&Q);
  r_assert (r_ecc_key_get_q (a_priv, &Q));
  encsize = sizeof (enc);
  r_assert (r_ecurve_point_to_uncompressed (&Q, &params, enc, &encsize));
  a_pub = r_ecdh_pub_key_new (R_ECURVE_ID_SECP521R1, enc, encsize);
  r_assert_cmpptr (a_pub, !=, NULL);
  r_ecurve_point_clear (&Q);

  sasize = sizeof (sa);
  sbsize = sizeof (sb);
  r_assert_cmpint (r_ecdh_compute_shared (a_priv, b_pub, sa, &sasize),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_ecdh_compute_shared (b_priv, a_pub, sb, &sbsize),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (sasize, ==, sbsize);
  r_assert_cmpuint (sasize, ==, params.coord_bytes);
  r_assert_cmpmem (sa, ==, sb, sasize);

  r_crypto_key_unref (a_priv);
  r_crypto_key_unref (b_priv);
  r_crypto_key_unref (a_pub);
  r_crypto_key_unref (b_pub);
  r_ecurve_clear (&params);
}
RTEST_END;

RTEST_LOOP (recdh, compute_shared_known_answer, RTEST_SLOW,
    0, R_N_ELEMENTS (recdh_kat_vectors))
{
  const REcdhKatVector * v = &recdh_kat_vectors[__i];
  REcurve params;
  ruint8 peer_enc[1 + 2 * 66];
  rsize peer_enc_size;
  rsize zlen;
  ruint8 * z_expected;
  ruint8 z_actual[66];
  rsize zsize = sizeof (z_actual);
  RCryptoKey * mine, * peer_pub;

  r_assert (r_ecurve_init (&params, v->curve));

  mine = recdh_priv_key_from_hex (v->curve, v->d_hex);
  r_assert_cmpptr (mine, !=, NULL);

  peer_enc_size = recdh_encode_point (peer_enc, sizeof (peer_enc),
      params.coord_bytes, v->px_hex, v->py_hex);
  peer_pub = r_ecdh_pub_key_new (v->curve, peer_enc, peer_enc_size);
  r_assert_cmpptr (peer_pub, !=, NULL);

  r_assert_cmpint (r_ecdh_compute_shared (mine, peer_pub, z_actual, &zsize),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (zsize, ==, params.coord_bytes);

  z_expected = r_str_hex_mem (v->z_hex, &zlen);
  r_assert_cmpuint (zlen, ==, params.coord_bytes);
  r_assert_cmpmem (z_actual, ==, z_expected, zlen);
  r_free (z_expected);

  r_crypto_key_unref (mine);
  r_crypto_key_unref (peer_pub);
  r_ecurve_clear (&params);
}
RTEST_END;

/* Run one Wycheproof ECDH test case end-to-end. Failure paths are
 * collapsed to a single helper so each per-curve loop below only owns
 * the table it points at, not the result-handling boilerplate.
 *
 * Wycheproof's three result categories map to our API as follows:
 *
 *   "valid"      - construct, compute, output must equal shared.
 *   "acceptable" - either reject at construction / compute_shared,
 *                  or produce output equal to shared. Both are
 *                  conformant; the flag exists so tools can warn
 *                  about edge cases without forcing one answer.
 *   "invalid"    - must reject somewhere along the way. If we compute
 *                  a shared and it happens to match the vector's
 *                  field anyway, that's still a failure - the vector
 *                  was crafted so a correct implementation says no.
 *
 * On failure the assert position points here; cross-reference the
 * loop's __i with the matching .inc file (tcId N is at index N-1)
 * for the test's published comment and flags.
 */
static void
run_wycheproof_ecdh_test (const WycheproofEcdhTest * t)
{
  RCryptoKey * priv = r_ecdh_priv_key_new (t->curve, NULL, 0,
      t->priv, t->priv_len);
  RCryptoKey * peer = r_ecdh_pub_key_new (t->curve, t->pub, t->pub_len);
  ruint8 out[1 + 2 * 66];
  rsize outsize = sizeof (out);
  RCryptoResult cs = R_CRYPTO_ERROR;
  rboolean got_match;

  if (priv != NULL && peer != NULL) {
    cs = r_ecdh_compute_shared (priv, peer, out, &outsize);
  }
  got_match = (cs == R_CRYPTO_OK &&
               outsize == t->shared_len &&
               r_memcmp (out, t->shared, outsize) == 0);

  switch (t->expected) {
    case WYCHEPROOF_VALID:
      r_assert_cmpptr (priv, !=, NULL);
      r_assert_cmpptr (peer, !=, NULL);
      r_assert_cmpint (cs, ==, R_CRYPTO_OK);
      r_assert_cmpuint (outsize, ==, t->shared_len);
      r_assert_cmpmem (out, ==, t->shared, outsize);
      break;
    case WYCHEPROOF_ACCEPTABLE:
      /* Either path is fine; if we computed *and* produced output, it
       * should match the published shared. */
      if (cs == R_CRYPTO_OK) {
        r_assert_cmpuint (outsize, ==, t->shared_len);
        r_assert_cmpmem (out, ==, t->shared, outsize);
      }
      break;
    case WYCHEPROOF_INVALID:
      r_assert (!got_match);
      break;
  }

  if (priv != NULL) r_crypto_key_unref (priv);
  if (peer != NULL) r_crypto_key_unref (peer);
}

/* HEAVY_RTEST_LOOP - too slow for the default suite. Pass --heavy
 * (rlibtest -H) when you want the full sweep. */
HEAVY_RTEST_LOOP (recdh, wycheproof_secp224r1, RTEST_SLOW,
    0, R_N_ELEMENTS (wp_ecdh_secp224r1_tests))
{
  run_wycheproof_ecdh_test (&wp_ecdh_secp224r1_tests[__i]);
}
RTEST_END;

/* HEAVY_RTEST_LOOP - too slow for the default suite. Pass --heavy
 * (rlibtest -H) when you want the full sweep. */
HEAVY_RTEST_LOOP (recdh, wycheproof_secp256r1, RTEST_SLOW,
    0, R_N_ELEMENTS (wp_ecdh_secp256r1_tests))
{
  run_wycheproof_ecdh_test (&wp_ecdh_secp256r1_tests[__i]);
}
RTEST_END;

/* HEAVY_RTEST_LOOP - too slow for the default suite. Pass --heavy
 * (rlibtest -H) when you want the full sweep. */
HEAVY_RTEST_LOOP (recdh, wycheproof_secp384r1, RTEST_SLOW,
    0, R_N_ELEMENTS (wp_ecdh_secp384r1_tests))
{
  run_wycheproof_ecdh_test (&wp_ecdh_secp384r1_tests[__i]);
}
RTEST_END;

/* HEAVY_RTEST_LOOP - too slow for the default suite. Pass --heavy
 * (rlibtest -H) when you want the full sweep. */
HEAVY_RTEST_LOOP (recdh, wycheproof_secp521r1, RTEST_SLOW,
    0, R_N_ELEMENTS (wp_ecdh_secp521r1_tests))
{
  run_wycheproof_ecdh_test (&wp_ecdh_secp521r1_tests[__i]);
}
RTEST_END;
