#include <rlib/rcrypto.h>

#include <rlib/asn1/roid.h>

static const REcurveID all_curves[] = {
  R_ECURVE_ID_SECP192R1,
  R_ECURVE_ID_SECP224R1,
  R_ECURVE_ID_SECP256R1,
  R_ECURVE_ID_SECP384R1,
  R_ECURVE_ID_SECP521R1,
  R_ECURVE_ID_SECP256K1,
};

static const ruint expected_bits[] = { 192, 224, 256, 384, 521, 256 };

RTEST_LOOP (recurve, curve_smoke, RTEST_FAST,
    0, R_N_ELEMENTS (all_curves))
{
  REcurve curve;
  REcurveAffinePoint decoded;
  ruint8 buf[1 + 2 * 66];
  rsize bufsize = sizeof (buf);

  r_assert (r_ecurve_init (&curve, all_curves[__i]));
  r_assert_cmpuint (r_mpint_bits_used (&curve.p), ==, expected_bits[__i]);
  r_assert (!curve.G.is_infinity);

  /* Generator is on the curve and round-trips through uncompressed
   * encoding without losing precision or failing validation. */
  r_assert (r_ecurve_point_is_on_curve (&curve.G, &curve));

  r_assert (r_ecurve_point_to_uncompressed (&curve.G, &curve, buf, &bufsize));
  r_assert_cmpuint (bufsize, ==, 1 + 2 * curve.coord_bytes);
  r_assert_cmpuint (buf[0], ==, 0x04);

  r_ecurve_point_init (&decoded);
  r_assert (r_ecurve_point_from_uncompressed (buf, bufsize, &curve, &decoded));
  r_assert (!decoded.is_infinity);
  r_assert_cmpint (r_mpint_cmp (&decoded.x, &curve.G.x), ==, 0);
  r_assert_cmpint (r_mpint_cmp (&decoded.y, &curve.G.y), ==, 0);

  r_ecurve_point_clear (&decoded);
  r_ecurve_clear (&curve);
}
RTEST_END;

RTEST_LOOP (recurve, add_dbl_consistency, RTEST_FAST,
    0, R_N_ELEMENTS (all_curves))
{
  REcurve curve;
  REcurveAffinePoint dbl_G, add_GG, neg_G, sum, infinity;

  r_assert (r_ecurve_init (&curve, all_curves[__i]));
  r_ecurve_point_init (&dbl_G);
  r_ecurve_point_init (&add_GG);
  r_ecurve_point_init (&neg_G);
  r_ecurve_point_init (&sum);
  r_ecurve_point_init (&infinity);
  r_ecurve_point_set_infinity (&infinity);

  /* G + G == dbl(G) */
  r_assert (r_ecurve_point_add (&add_GG, &curve.G, &curve.G, &curve));
  r_assert (r_ecurve_point_dbl (&dbl_G, &curve.G, &curve));
  r_assert (!add_GG.is_infinity && !dbl_G.is_infinity);
  r_assert_cmpint (r_mpint_cmp (&add_GG.x, &dbl_G.x), ==, 0);
  r_assert_cmpint (r_mpint_cmp (&add_GG.y, &dbl_G.y), ==, 0);
  r_assert (r_ecurve_point_is_on_curve (&dbl_G, &curve));

  /* G + (-G) == infinity */
  r_assert (r_ecurve_point_neg (&neg_G, &curve.G, &curve));
  r_assert (r_ecurve_point_add (&sum, &curve.G, &neg_G, &curve));
  r_assert (sum.is_infinity);

  /* infinity + G == G */
  r_assert (r_ecurve_point_add (&sum, &infinity, &curve.G, &curve));
  r_assert (!sum.is_infinity);
  r_assert_cmpint (r_mpint_cmp (&sum.x, &curve.G.x), ==, 0);

  /* dbl(infinity) == infinity */
  r_assert (r_ecurve_point_dbl (&sum, &infinity, &curve));
  r_assert (sum.is_infinity);

  r_ecurve_point_clear (&dbl_G);
  r_ecurve_point_clear (&add_GG);
  r_ecurve_point_clear (&neg_G);
  r_ecurve_point_clear (&sum);
  r_ecurve_point_clear (&infinity);
  r_ecurve_clear (&curve);
}
RTEST_END;

RTEST (recurve, point_validation_rejects_invalid, RTEST_FAST)
{
  REcurve curve;
  REcurveAffinePoint tampered, decoded;
  ruint8 buf[1 + 2 * 32];
  rsize bufsize = sizeof (buf);

  r_assert (r_ecurve_init (&curve, R_ECURVE_ID_SECP256R1));
  r_ecurve_point_init (&tampered);
  r_ecurve_point_init (&decoded);

  /* Tweak y by +1 (mod p). The generator's y already lies in [0, p),
   * and p > 1, so adding one keeps it in range while almost surely
   * moving it off the curve. */
  r_mpint_set (&tampered.x, &curve.G.x);
  r_assert (r_mpint_add_u32 (&tampered.y, &curve.G.y, 1));
  tampered.is_infinity = FALSE;
  r_assert (!r_ecurve_point_is_on_curve (&tampered, &curve));

  /* Same shape through the SEC 1 decode path. */
  r_assert (r_ecurve_point_to_uncompressed (&tampered, &curve, buf, &bufsize));
  r_assert (!r_ecurve_point_from_uncompressed (buf, bufsize, &curve, &decoded));

  r_ecurve_point_clear (&tampered);
  r_ecurve_point_clear (&decoded);
  r_ecurve_clear (&curve);
}
RTEST_END;

RTEST_LOOP (recurve, scalar_mul_identity, RTEST_FAST,
    0, R_N_ELEMENTS (all_curves))
{
  REcurve curve;
  REcurveAffinePoint product;
  rmpint zero, one;

  r_assert (r_ecurve_init (&curve, all_curves[__i]));
  r_ecurve_point_init (&product);
  r_mpint_init (&zero);
  r_mpint_init (&one);
  r_mpint_set_u32 (&one, 1);

  /* 0 * G == infinity */
  r_assert (r_ecurve_point_scalar_mul (&product, &zero, &curve.G, &curve));
  r_assert (product.is_infinity);

  /* 1 * G == G */
  r_assert (r_ecurve_point_scalar_mul (&product, &one, &curve.G, &curve));
  r_assert (!product.is_infinity);
  r_assert_cmpint (r_mpint_cmp (&product.x, &curve.G.x), ==, 0);
  r_assert_cmpint (r_mpint_cmp (&product.y, &curve.G.y), ==, 0);

  /* n * G == infinity (G generates a prime-order subgroup of order n). */
  r_assert (r_ecurve_point_scalar_mul (&product, &curve.n, &curve.G, &curve));
  r_assert (product.is_infinity);

  r_ecurve_point_clear (&product);
  r_mpint_clear (&zero);
  r_mpint_clear (&one);
  r_ecurve_clear (&curve);
}
RTEST_END;

typedef struct {
  REcurveID curve;
  const rchar * d_hex;
  const rchar * qx_hex;
  const rchar * qy_hex;
} REcKatVector;

/* Generated locally with a known-good pure-Python implementation:
 * Q = d * G under each curve's parameters. Two vectors per curve
 * (small d, larger d) for the moderate sizes; secp521r1 gets one to
 * keep the SLOW-tagged runtime bounded. */
static const REcKatVector kat_vectors[] = {
  { R_ECURVE_ID_SECP192R1, "0x2",
    "0xdafebf5828783f2ad35534631588a3f629a70fb16982a888",
    "0xdd6bda0d993da0fa46b27bbc141b868f59331afa5c7e93ab" },
  { R_ECURVE_ID_SECP192R1, "0x123456789abcdef",
    "0xf262420ea5f28e5140716def549d276bba81e680facf2ed4",
    "0x66e6151154abb7387156e93fa6955e643082215f0c1718e2" },

  { R_ECURVE_ID_SECP224R1, "0x2",
    "0x706a46dc76dcb76798e60e6d89474788d16dc18032d268fd1a704fa6",
    "0x1c2b76a7bc25e7702a704fa986892849fca629487acf3709d2e4e8bb" },
  { R_ECURVE_ID_SECP224R1, "0x123456789abcdef",
    "0x09773973eb65b19439e795be5cacf515fa5b065f1d9c31be24f3f8d0",
    "0xea89075e0194643852dd8676cc41c2873c61f92c5e715caf5515b9e5" },

  { R_ECURVE_ID_SECP256R1, "0x2",
    "0x7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
    "0x07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1" },
  { R_ECURVE_ID_SECP256R1, "0x123456789abcdef",
    "0x3988322ab9f52c7f11d5d1aa92a2ac0b00275bcad8e934682257323fda672482",
    "0x855b7389f116c19c0014311c3d57dc02001e3a0ec8bd90c797732034aacd9918" },

  { R_ECURVE_ID_SECP384R1, "0x2",
    "0x08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e"
      "4fe0e86ebe0e64f85b96a9c75295df61",
    "0x8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab425"
      "5ffd43e94d39e22d61501e700a940e80" },
  { R_ECURVE_ID_SECP384R1, "0x123456789abcdef",
    "0x2ca8c560f92280756d4d4e5903043a370532b246669e6110b033f9ab150d5186"
      "3208e24bd70ce3738d027638bbd54cd2",
    "0x1fc91a81a4cd7ea2ab6c205986767e830926c1bbf7eff71c25a2245d787dd8cc"
      "01731db7c2d9b1f4ab7ce1959c83624f" },

  { R_ECURVE_ID_SECP521R1, "0x2",
    "0x00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769"
      "be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d",
    "0x00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c4"
      "2dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02" },

  { R_ECURVE_ID_SECP256K1, "0x2",
    "0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
    "0x1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a" },
  { R_ECURVE_ID_SECP256K1, "0x123456789abcdef",
    "0x1a1fd15fce078234aa292fc024178056bf006433c9b4bd208f59eb4c9efec95b",
    "0xa18af1fe46980989d3ff75bf9601121151ef46e2cfab8999408319ce8f3be725" },
};

RTEST_LOOP (recurve, scalar_mul_known_answer, RTEST_SLOW,
    0, R_N_ELEMENTS (kat_vectors))
{
  const REcKatVector * v = &kat_vectors[__i];
  REcurve curve;
  REcurveAffinePoint product;
  rmpint d, expected_x, expected_y;

  r_assert (r_ecurve_init (&curve, v->curve));
  r_ecurve_point_init (&product);
  r_mpint_init_str (&d, v->d_hex, NULL, 16);
  r_mpint_init_str (&expected_x, v->qx_hex, NULL, 16);
  r_mpint_init_str (&expected_y, v->qy_hex, NULL, 16);

  r_assert (r_ecurve_point_scalar_mul (&product, &d, &curve.G, &curve));
  r_assert (!product.is_infinity);
  r_assert_cmpint (r_mpint_cmp (&product.x, &expected_x), ==, 0);
  r_assert_cmpint (r_mpint_cmp (&product.y, &expected_y), ==, 0);
  r_assert (r_ecurve_point_is_on_curve (&product, &curve));

  r_ecurve_point_clear (&product);
  r_mpint_clear (&d);
  r_mpint_clear (&expected_x);
  r_mpint_clear (&expected_y);
  r_ecurve_clear (&curve);
}
RTEST_END;

RTEST (recurve, id_from_oid, RTEST_FAST)
{
  REcurveID id;
  static const ruint8 bogus_oid[] = { 0x06, 0x04, 0xde, 0xad, 0xbe, 0xef };

#define R_ASSERT_OID_MAPS(oid_macro, expected)                            \
  do {                                                                    \
    r_assert (r_ecurve_id_from_oid (&id,                                  \
          (oid_macro), R_STR_SIZEOF (oid_macro)));                        \
    r_assert_cmpint (id, ==, (expected));                                 \
  } while (0)

  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP192R1, R_ECURVE_ID_SECP192R1);
  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP224R1, R_ECURVE_ID_SECP224R1);
  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP256R1, R_ECURVE_ID_SECP256R1);
  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP384R1, R_ECURVE_ID_SECP384R1);
  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP521R1, R_ECURVE_ID_SECP521R1);
  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP192K1, R_ECURVE_ID_SECP192K1);
  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP224K1, R_ECURVE_ID_SECP224K1);
  R_ASSERT_OID_MAPS (R_EC_GRP_OID_SECP256K1, R_ECURVE_ID_SECP256K1);

#undef R_ASSERT_OID_MAPS

  /* Unknown OIDs and degenerate inputs are all rejected. */
  r_assert (!r_ecurve_id_from_oid (&id, bogus_oid, sizeof (bogus_oid)));
  r_assert (!r_ecurve_id_from_oid (NULL,
        R_EC_GRP_OID_SECP256R1, R_STR_SIZEOF (R_EC_GRP_OID_SECP256R1)));
  r_assert (!r_ecurve_id_from_oid (&id, NULL, 4));
  r_assert (!r_ecurve_id_from_oid (&id, R_EC_GRP_OID_SECP256R1, 0));
}
RTEST_END;

RTEST (recurve, init_rejects_unsupported_curve, RTEST_FAST)
{
  /* The math layer only ships parameters for the six prime curves;
   * any other REcurveID value should fail to initialise rather than
   * silently grow a junk REcurve. */
  REcurve curve;

  r_assert (!r_ecurve_init (&curve, R_ECURVE_ID_NONE));
  r_assert (!r_ecurve_init (&curve, R_ECURVE_ID_SECT163K1));
  r_assert (!r_ecurve_init (&curve, R_ECURVE_ID_BRAINPOOLP256R1));
  r_assert (!r_ecurve_init (&curve, R_ECURVE_ID_X25519));
  r_assert (!r_ecurve_init (&curve, R_ECURVE_ID_FFDHE2048));
  r_assert (!r_ecurve_init (NULL, R_ECURVE_ID_SECP256R1));
}
RTEST_END;

RTEST (recurve, codec_rejects_malformed, RTEST_FAST)
{
  REcurve curve;
  REcurveAffinePoint decoded, infinity;
  ruint8 buf[1 + 2 * 32];
  ruint8 tiny[1];
  rsize bufsize;
  rsize tinysize;

  r_assert (r_ecurve_init (&curve, R_ECURVE_ID_SECP256R1));
  r_ecurve_point_init (&decoded);
  r_ecurve_point_init (&infinity);
  r_ecurve_point_set_infinity (&infinity);

  /* Infinity round-trips as a single 0x00 byte. */
  tinysize = sizeof (tiny);
  r_assert (r_ecurve_point_to_uncompressed (&infinity, &curve, tiny, &tinysize));
  r_assert_cmpuint (tinysize, ==, 1);
  r_assert_cmpuint (tiny[0], ==, 0x00);
  r_assert (r_ecurve_point_from_uncompressed (tiny, tinysize, &curve, &decoded));
  r_assert (decoded.is_infinity);

  /* Encode refuses to write past a too-small buffer. */
  bufsize = 1 + 2 * curve.coord_bytes - 1;
  r_assert (!r_ecurve_point_to_uncompressed (&curve.G, &curve, buf, &bufsize));

  /* A valid uncompressed encoding of G — used as the starting point
   * for each malformed-decode case below. */
  bufsize = sizeof (buf);
  r_assert (r_ecurve_point_to_uncompressed (&curve.G, &curve, buf, &bufsize));

  /* Wrong size: truncate or extend the otherwise-valid buffer. */
  r_assert (!r_ecurve_point_from_uncompressed (buf, bufsize - 1, &curve, &decoded));
  r_assert (!r_ecurve_point_from_uncompressed (buf, bufsize + 1, &curve, &decoded));

  /* Compressed encodings (0x02 / 0x03) and arbitrary garbage prefixes
   * are not supported and should be rejected. */
  buf[0] = 0x02; r_assert (!r_ecurve_point_from_uncompressed (buf, bufsize, &curve, &decoded));
  buf[0] = 0x03; r_assert (!r_ecurve_point_from_uncompressed (buf, bufsize, &curve, &decoded));
  buf[0] = 0x05; r_assert (!r_ecurve_point_from_uncompressed (buf, bufsize, &curve, &decoded));

  r_ecurve_point_clear (&decoded);
  r_ecurve_point_clear (&infinity);
  r_ecurve_clear (&curve);
}
RTEST_END;
