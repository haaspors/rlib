#include <rlib/rcrypto.h>

/* RFC 7748 §6.1 X25519 Diffie-Hellman vectors. */
static const ruint8 x25519_alice_priv[32] = {
  0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72,
  0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
  0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};
static const ruint8 x25519_alice_pub[32] = {
  0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc,
  0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
  0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
};
static const ruint8 x25519_bob_priv[32] = {
  0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b,
  0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
  0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb
};
static const ruint8 x25519_bob_pub[32] = {
  0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2,
  0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
  0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};
static const ruint8 x25519_shared[32] = {
  0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4,
  0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
  0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42
};

/* RFC 7748 §6.2 X448 vectors. */
static const ruint8 x448_alice_priv[56] = {
  0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf, 0x46, 0xb0,
  0x4b, 0x58, 0x00, 0xd4, 0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
  0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5, 0x74, 0xa9, 0x41, 0x97,
  0x44, 0x89, 0x73, 0x91, 0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
  0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b
};
static const ruint8 x448_alice_pub[56] = {
  0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22, 0xd5, 0xae,
  0xa1, 0x21, 0x07, 0x4a, 0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
  0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb, 0xc8, 0x36, 0x64, 0x72,
  0x41, 0xd9, 0x53, 0xd4, 0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
  0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0
};
static const ruint8 x448_bob_priv[56] = {
  0x1c, 0x30, 0x6a, 0x7a, 0xc2, 0xa0, 0xe2, 0xe0, 0x99, 0x0b, 0x29, 0x44,
  0x70, 0xcb, 0xa3, 0x39, 0xe6, 0x45, 0x37, 0x72, 0xb0, 0x75, 0x81, 0x1d,
  0x8f, 0xad, 0x0d, 0x1d, 0x69, 0x27, 0xc1, 0x20, 0xbb, 0x5e, 0xe8, 0x97,
  0x2b, 0x0d, 0x3e, 0x21, 0x37, 0x4c, 0x9c, 0x92, 0x1b, 0x09, 0xd1, 0xb0,
  0x36, 0x6f, 0x10, 0xb6, 0x51, 0x73, 0x99, 0x2d
};
static const ruint8 x448_bob_pub[56] = {
  0x3e, 0xb7, 0xa8, 0x29, 0xb0, 0xcd, 0x20, 0xf5, 0xbc, 0xfc, 0x0b, 0x59,
  0x9b, 0x6f, 0xec, 0xcf, 0x6d, 0xa4, 0x62, 0x71, 0x07, 0xbd, 0xb0, 0xd4,
  0xf3, 0x45, 0xb4, 0x30, 0x27, 0xd8, 0xb9, 0x72, 0xfc, 0x3e, 0x34, 0xfb,
  0x42, 0x32, 0xa1, 0x3c, 0xa7, 0x06, 0xdc, 0xb5, 0x7a, 0xec, 0x3d, 0xae,
  0x07, 0xbd, 0xc1, 0xc6, 0x7b, 0xf3, 0x36, 0x09
};
static const ruint8 x448_shared[56] = {
  0x07, 0xff, 0xf4, 0x18, 0x1a, 0xc6, 0xcc, 0x95, 0xec, 0x1c, 0x16, 0xa9,
  0x4a, 0x0f, 0x74, 0xd1, 0x2d, 0xa2, 0x32, 0xce, 0x40, 0xa7, 0x75, 0x52,
  0x28, 0x1d, 0x28, 0x2b, 0xb6, 0x0c, 0x0b, 0x56, 0xfd, 0x24, 0x64, 0xc3,
  0x35, 0x54, 0x39, 0x36, 0x52, 0x1c, 0x24, 0x40, 0x30, 0x85, 0xd5, 0x9a,
  0x44, 0x9a, 0x50, 0x37, 0x51, 0x4a, 0x87, 0x9d
};

RTEST (rxdh, x25519_dh_rfc7748, RTEST_FAST)
{
  RCryptoKey * alice = r_xdh_priv_key_new (R_ECURVE_ID_X25519,
      x25519_alice_pub, sizeof (x25519_alice_pub),
      x25519_alice_priv, sizeof (x25519_alice_priv));
  RCryptoKey * bob = r_xdh_priv_key_new (R_ECURVE_ID_X25519,
      x25519_bob_pub, sizeof (x25519_bob_pub),
      x25519_bob_priv, sizeof (x25519_bob_priv));
  RCryptoKey * alice_pub = r_xdh_pub_key_new (R_ECURVE_ID_X25519,
      x25519_alice_pub, sizeof (x25519_alice_pub));
  RCryptoKey * bob_pub = r_xdh_pub_key_new (R_ECURVE_ID_X25519,
      x25519_bob_pub, sizeof (x25519_bob_pub));
  ruint8 shared_a[32], shared_b[32];
  rsize sa = sizeof (shared_a), sb = sizeof (shared_b);

  r_assert_cmpptr (alice, !=, NULL);
  r_assert_cmpptr (bob, !=, NULL);
  r_assert_cmpptr (alice_pub, !=, NULL);
  r_assert_cmpptr (bob_pub, !=, NULL);

  r_assert_cmpint (r_xdh_compute_shared (alice, bob_pub, shared_a, &sa),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (sa, ==, 32);
  r_assert_cmpmem (shared_a, ==, x25519_shared, 32);

  r_assert_cmpint (r_xdh_compute_shared (bob, alice_pub, shared_b, &sb),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (sb, ==, 32);
  r_assert_cmpmem (shared_b, ==, x25519_shared, 32);

  r_crypto_key_unref (alice);
  r_crypto_key_unref (bob);
  r_crypto_key_unref (alice_pub);
  r_crypto_key_unref (bob_pub);
}
RTEST_END;

RTEST (rxdh, x448_dh_rfc7748, RTEST_FAST)
{
  RCryptoKey * alice = r_xdh_priv_key_new (R_ECURVE_ID_X448,
      x448_alice_pub, sizeof (x448_alice_pub),
      x448_alice_priv, sizeof (x448_alice_priv));
  RCryptoKey * bob = r_xdh_priv_key_new (R_ECURVE_ID_X448,
      x448_bob_pub, sizeof (x448_bob_pub),
      x448_bob_priv, sizeof (x448_bob_priv));
  RCryptoKey * alice_pub = r_xdh_pub_key_new (R_ECURVE_ID_X448,
      x448_alice_pub, sizeof (x448_alice_pub));
  RCryptoKey * bob_pub = r_xdh_pub_key_new (R_ECURVE_ID_X448,
      x448_bob_pub, sizeof (x448_bob_pub));
  ruint8 shared_a[56], shared_b[56];
  rsize sa = sizeof (shared_a), sb = sizeof (shared_b);

  r_assert_cmpptr (alice, !=, NULL);
  r_assert_cmpptr (bob, !=, NULL);
  r_assert_cmpptr (alice_pub, !=, NULL);
  r_assert_cmpptr (bob_pub, !=, NULL);

  r_assert_cmpint (r_xdh_compute_shared (alice, bob_pub, shared_a, &sa),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (sa, ==, 56);
  r_assert_cmpmem (shared_a, ==, x448_shared, 56);

  r_assert_cmpint (r_xdh_compute_shared (bob, alice_pub, shared_b, &sb),
      ==, R_CRYPTO_OK);
  r_assert_cmpuint (sb, ==, 56);
  r_assert_cmpmem (shared_b, ==, x448_shared, 56);

  r_crypto_key_unref (alice);
  r_crypto_key_unref (bob);
  r_crypto_key_unref (alice_pub);
  r_crypto_key_unref (bob_pub);
}
RTEST_END;

RTEST (rxdh, key_metadata, RTEST_FAST)
{
  RCryptoKey * key = r_xdh_pub_key_new (R_ECURVE_ID_X25519,
      x25519_alice_pub, sizeof (x25519_alice_pub));
  const ruint8 * u = NULL;
  rsize usize = 0;

  r_assert_cmpptr (key, !=, NULL);
  r_assert_cmpint (r_xdh_key_get_curve (key), ==, R_ECURVE_ID_X25519);
  r_assert_cmpint (r_crypto_key_get_algo (key), ==, R_CRYPTO_ALGO_XDH);
  r_assert_cmpstr (r_crypto_key_get_strtype (key), ==, R_XDH_STR);
  r_assert_cmpint (r_crypto_key_get_type (key), ==, R_CRYPTO_PUBLIC_KEY);
  r_assert (r_xdh_key_get_pub_u (key, &u, &usize));
  r_assert_cmpuint (usize, ==, 32);
  r_assert_cmpmem (u, ==, x25519_alice_pub, 32);
  r_crypto_key_unref (key);
}
RTEST_END;

RTEST (rxdh, ctor_rejects_bad_inputs, RTEST_FAST)
{
  /* Bad curve id. */
  r_assert_cmpptr (r_xdh_pub_key_new (R_ECURVE_ID_SECP256R1,
        x25519_alice_pub, 32), ==, NULL);
  r_assert_cmpptr (r_xdh_priv_key_new_gen (R_ECURVE_ID_NONE, NULL), ==, NULL);

  /* Wrong size for the curve. */
  r_assert_cmpptr (r_xdh_pub_key_new (R_ECURVE_ID_X25519,
        x25519_alice_pub, 31), ==, NULL);
  r_assert_cmpptr (r_xdh_pub_key_new (R_ECURVE_ID_X448,
        x448_alice_pub, 32), ==, NULL);
  r_assert_cmpptr (r_xdh_priv_key_new (R_ECURVE_ID_X25519,
        x25519_alice_pub, 32, x25519_alice_priv, 31), ==, NULL);

  /* NULL pointers. */
  r_assert_cmpptr (r_xdh_pub_key_new (R_ECURVE_ID_X25519, NULL, 32), ==, NULL);
  r_assert_cmpptr (r_xdh_priv_key_new (R_ECURVE_ID_X25519,
        NULL, 32, x25519_alice_priv, 32), ==, NULL);
}
RTEST_END;

RTEST (rxdh, compute_shared_rejects_mismatched_curve, RTEST_FAST)
{
  RCryptoKey * priv25 = r_xdh_priv_key_new (R_ECURVE_ID_X25519,
      x25519_alice_pub, 32, x25519_alice_priv, 32);
  RCryptoKey * pub448 = r_xdh_pub_key_new (R_ECURVE_ID_X448,
      x448_bob_pub, 56);
  ruint8 out[56];
  rsize sn = sizeof (out);

  r_assert_cmpptr (priv25, !=, NULL);
  r_assert_cmpptr (pub448, !=, NULL);

  r_assert_cmpint (r_xdh_compute_shared (priv25, pub448, out, &sn),
      ==, R_CRYPTO_WRONG_TYPE);
  r_crypto_key_unref (priv25);
  r_crypto_key_unref (pub448);
}
RTEST_END;

RTEST (rxdh, compute_shared_rejects_low_order_peer, RTEST_FAST)
{
  /* Peer u = 0 is a low-order point; the ladder result is the
   * all-zero shared secret that RFC 7748 §6 forbids. The wrapper
   * surfaces that as R_CRYPTO_INVAL. */
  RCryptoKey * priv = r_xdh_priv_key_new (R_ECURVE_ID_X25519,
      x25519_alice_pub, 32, x25519_alice_priv, 32);
  ruint8 zero_u[32] = { 0 };
  RCryptoKey * peer = r_xdh_pub_key_new (R_ECURVE_ID_X25519, zero_u, 32);
  ruint8 out[32];
  rsize sn = sizeof (out);

  r_assert_cmpptr (priv, !=, NULL);
  r_assert_cmpptr (peer, !=, NULL);
  r_assert_cmpint (r_xdh_compute_shared (priv, peer, out, &sn),
      ==, R_CRYPTO_INVAL);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (peer);
}
RTEST_END;

RTEST (rxdh, compute_shared_rejects_wrong_key_types, RTEST_FAST)
{
  RCryptoKey * pub = r_xdh_pub_key_new (R_ECURVE_ID_X25519,
      x25519_alice_pub, 32);
  RCryptoKey * pub2 = r_xdh_pub_key_new (R_ECURVE_ID_X25519,
      x25519_bob_pub, 32);
  ruint8 out[32];
  rsize sn = sizeof (out);

  r_assert_cmpptr (pub, !=, NULL);
  r_assert_cmpptr (pub2, !=, NULL);

  /* Two public keys -> WRONG_TYPE (first arg must be private). */
  r_assert_cmpint (r_xdh_compute_shared (pub, pub2, out, &sn),
      ==, R_CRYPTO_WRONG_TYPE);

  r_crypto_key_unref (pub);
  r_crypto_key_unref (pub2);
}
RTEST_END;

RTEST (rxdh, compute_shared_rejects_undersized_buffer, RTEST_FAST)
{
  RCryptoKey * priv = r_xdh_priv_key_new (R_ECURVE_ID_X25519,
      x25519_alice_pub, 32, x25519_alice_priv, 32);
  RCryptoKey * peer = r_xdh_pub_key_new (R_ECURVE_ID_X25519,
      x25519_bob_pub, 32);
  ruint8 out[16];
  rsize sn = sizeof (out);

  r_assert_cmpptr (priv, !=, NULL);
  r_assert_cmpptr (peer, !=, NULL);

  r_assert_cmpint (r_xdh_compute_shared (priv, peer, out, &sn),
      ==, R_CRYPTO_BUFFER_TOO_SMALL);

  r_crypto_key_unref (priv);
  r_crypto_key_unref (peer);
}
RTEST_END;

RTEST (rxdh, x25519_keygen_roundtrip, RTEST_FAST)
{
  /* Generated key's public u must equal what the ladder computes
   * for ladder(scalar, basepoint) - the keygen path's own
   * postcondition. Easiest check: compute_shared with self produces
   * a non-zero value (and round-trips with a second peer). */
  RCryptoKey * alice = r_xdh_priv_key_new_gen (R_ECURVE_ID_X25519, NULL);
  RCryptoKey * bob = r_xdh_priv_key_new_gen (R_ECURVE_ID_X25519, NULL);
  const ruint8 * alice_u = NULL, * bob_u = NULL;
  rsize au_size, bu_size;
  RCryptoKey * alice_pub_view;
  RCryptoKey * bob_pub_view;
  ruint8 shared_a[32], shared_b[32];
  rsize sa = sizeof (shared_a), sb = sizeof (shared_b);

  r_assert_cmpptr (alice, !=, NULL);
  r_assert_cmpptr (bob, !=, NULL);

  r_assert (r_xdh_key_get_pub_u (alice, &alice_u, &au_size));
  r_assert (r_xdh_key_get_pub_u (bob, &bob_u, &bu_size));
  r_assert_cmpuint (au_size, ==, 32);
  r_assert_cmpuint (bu_size, ==, 32);

  alice_pub_view = r_xdh_pub_key_new (R_ECURVE_ID_X25519, alice_u, 32);
  bob_pub_view = r_xdh_pub_key_new (R_ECURVE_ID_X25519, bob_u, 32);
  r_assert_cmpptr (alice_pub_view, !=, NULL);
  r_assert_cmpptr (bob_pub_view, !=, NULL);

  r_assert_cmpint (r_xdh_compute_shared (alice, bob_pub_view, shared_a, &sa),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_xdh_compute_shared (bob, alice_pub_view, shared_b, &sb),
      ==, R_CRYPTO_OK);
  r_assert_cmpmem (shared_a, ==, shared_b, 32);

  r_crypto_key_unref (alice);
  r_crypto_key_unref (bob);
  r_crypto_key_unref (alice_pub_view);
  r_crypto_key_unref (bob_pub_view);
}
RTEST_END;
