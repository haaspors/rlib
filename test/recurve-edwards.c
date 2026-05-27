#include <rlib/rcrypto.h>

/* Encoded base points for round-trip validation. The Y bytes per RFC
 * 8032 §5.1.5 / §5.2.5; sign bit of x packed into the top of the
 * final byte. */
static const ruint8 ed25519_B_encoded[32] = {
  0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
  0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};
/* Canonical RFC 8032 §5.2 base point encoding: y_bytes (LE) || sign(x) bit.
 * Bx's LSB is 0 (LE byte 0 = 0x5e), so the sign bit is 0. */
static const ruint8 ed448_B_encoded[57] = {
  0x14, 0xfa, 0x30, 0xf2, 0x5b, 0x79, 0x08, 0x98,
  0xad, 0xc8, 0xd7, 0x4e, 0x2c, 0x13, 0xbd, 0xfd,
  0xc4, 0x39, 0x7c, 0xe6, 0x1c, 0xff, 0xd3, 0x3a,
  0xd7, 0xc2, 0xa0, 0x05, 0x1e, 0x9c, 0x78, 0x87,
  0x40, 0x98, 0xa3, 0x6c, 0x73, 0x73, 0xea, 0x4b,
  0x62, 0xc7, 0xc9, 0x56, 0x37, 0x20, 0x76, 0x88,
  0x24, 0xbc, 0xb6, 0x6e, 0x71, 0x46, 0x3f, 0x69,
  0x00,
};

/* L (subgroup order) as LE bytes. */
static const ruint8 ed25519_L_le[32] = {
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};
static const ruint8 ed448_L_le[56] = {
  0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23,
  0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
  0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4,
  0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
};

RTEST (recurve_edwards, ed25519_init_basepoint_on_curve, RTEST_FAST)
{
  REcurveEdwards curve;
  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X25519));
  r_assert_cmpuint (curve.coord_bytes, ==, 32);
  r_assert_cmpuint (curve.encoding_bytes, ==, 32);
  r_assert (curve.a_is_minus_one);
  r_assert (r_ecurve_edwards_point_is_on_curve (&curve.B, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed448_init_basepoint_on_curve, RTEST_FAST)
{
  REcurveEdwards curve;
  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X448));
  r_assert_cmpuint (curve.coord_bytes, ==, 56);
  r_assert_cmpuint (curve.encoding_bytes, ==, 57);
  r_assert (!curve.a_is_minus_one);
  r_assert (r_ecurve_edwards_point_is_on_curve (&curve.B, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed25519_dbl_equals_add_self, RTEST_FAST)
{
  REcurveEdwards curve;
  REcurveEdwardsPoint doubled, summed;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X25519));
  r_ecurve_edwards_point_dbl (&doubled, &curve.B, &curve);
  r_ecurve_edwards_point_add (&summed, &curve.B, &curve.B, &curve);
  r_assert (r_ecurve_edwards_point_equal (&doubled, &summed, &curve));
  r_assert (r_ecurve_edwards_point_is_on_curve (&doubled, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed448_dbl_equals_add_self, RTEST_FAST)
{
  REcurveEdwards curve;
  REcurveEdwardsPoint doubled, summed;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X448));
  r_ecurve_edwards_point_dbl (&doubled, &curve.B, &curve);
  r_ecurve_edwards_point_add (&summed, &curve.B, &curve.B, &curve);
  r_assert (r_ecurve_edwards_point_equal (&doubled, &summed, &curve));
  r_assert (r_ecurve_edwards_point_is_on_curve (&doubled, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed25519_add_neg_is_identity, RTEST_FAST)
{
  REcurveEdwards curve;
  REcurveEdwardsPoint neg_B, sum;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X25519));
  r_ecurve_edwards_point_neg (&neg_B, &curve.B, &curve);
  r_ecurve_edwards_point_add (&sum, &curve.B, &neg_B, &curve);
  r_assert (r_ecurve_edwards_point_is_identity (&sum, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed448_add_neg_is_identity, RTEST_FAST)
{
  REcurveEdwards curve;
  REcurveEdwardsPoint neg_B, sum;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X448));
  r_ecurve_edwards_point_neg (&neg_B, &curve.B, &curve);
  r_ecurve_edwards_point_add (&sum, &curve.B, &neg_B, &curve);
  r_assert (r_ecurve_edwards_point_is_identity (&sum, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed25519_scalar_mul_L_is_identity, RTEST_FAST)
{
  /* L * B = O because B has prime order L. */
  REcurveEdwards curve;
  REcurveEdwardsPoint LB;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X25519));
  r_ecurve_edwards_point_scalar_mul (&LB, ed25519_L_le, sizeof (ed25519_L_le),
      253, &curve.B, &curve);
  r_assert (r_ecurve_edwards_point_is_identity (&LB, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed448_scalar_mul_L_is_identity, RTEST_FAST)
{
  REcurveEdwards curve;
  REcurveEdwardsPoint LB;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X448));
  r_ecurve_edwards_point_scalar_mul (&LB, ed448_L_le, sizeof (ed448_L_le),
      446, &curve.B, &curve);
  r_assert (r_ecurve_edwards_point_is_identity (&LB, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed25519_scalar_mul_one_is_self, RTEST_FAST)
{
  REcurveEdwards curve;
  REcurveEdwardsPoint result;
  ruint8 one_scalar[32] = { 1 };

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X25519));
  r_ecurve_edwards_point_scalar_mul (&result, one_scalar, sizeof (one_scalar),
      1, &curve.B, &curve);
  r_assert (r_ecurve_edwards_point_equal (&result, &curve.B, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed25519_encode_decode_roundtrip, RTEST_FAST)
{
  REcurveEdwards curve;
  ruint8 encoded[32];
  REcurveEdwardsPoint decoded;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X25519));
  r_assert (r_ecurve_edwards_point_encode (encoded, &curve.B, &curve));
  r_assert_cmpmem (encoded, ==, ed25519_B_encoded, 32);

  r_assert (r_ecurve_edwards_point_decode (&decoded, encoded, &curve));
  r_assert (r_ecurve_edwards_point_equal (&decoded, &curve.B, &curve));
  r_assert (r_ecurve_edwards_point_is_on_curve (&decoded, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed448_encode_decode_roundtrip, RTEST_FAST)
{
  REcurveEdwards curve;
  ruint8 encoded[57];
  REcurveEdwardsPoint decoded;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X448));
  r_assert (r_ecurve_edwards_point_encode (encoded, &curve.B, &curve));
  r_assert_cmpmem (encoded, ==, ed448_B_encoded, 57);

  r_assert (r_ecurve_edwards_point_decode (&decoded, encoded, &curve));
  r_assert (r_ecurve_edwards_point_equal (&decoded, &curve.B, &curve));
  r_assert (r_ecurve_edwards_point_is_on_curve (&decoded, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, ed25519_decode_rejects_non_canonical_y, RTEST_FAST)
{
  /* y = p is non-canonical (>= p). Encode bytes for p in LE. */
  ruint8 bad_y[32] = {
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  };
  REcurveEdwards curve;
  REcurveEdwardsPoint out;

  r_assert (r_ecurve_edwards_init (&curve, R_ECURVE_ID_X25519));
  r_assert (!r_ecurve_edwards_point_decode (&out, bad_y, &curve));
  r_ecurve_edwards_clear (&curve);
}
RTEST_END;

RTEST (recurve_edwards, init_rejects_unsupported_curve, RTEST_FAST)
{
  REcurveEdwards curve;
  r_assert (!r_ecurve_edwards_init (&curve, R_ECURVE_ID_SECP256R1));
  r_assert (!r_ecurve_edwards_init (&curve, R_ECURVE_ID_NONE));
}
RTEST_END;
