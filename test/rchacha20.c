#include <rlib/rcrypto.h>
#include <rlib/rstr.h>

typedef struct {
  const rchar * key;
  ruint32       counter;
  const rchar * nonce;
  const rchar * keystream;
} RChaCha20BlockTestData;

/* Block-function known-answer vectors from RFC 8439 (sec 2.3.2 and
 * appendix A.1). */
static const RChaCha20BlockTestData block_test_data[] = {
  { /* RFC 8439 A.1 Test Vector #1 */
    "0000000000000000000000000000000000000000000000000000000000000000",
    0, "000000000000000000000000",
    "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
    "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586" },
  { /* RFC 8439 A.1 Test Vector #2 */
    "0000000000000000000000000000000000000000000000000000000000000000",
    1, "000000000000000000000000",
    "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
    "29b721769ce64e43d57133b074d839d531ed1f28510afb45ace10a1f4b794d6f" },
  { /* RFC 8439 sec 2.3.2 */
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    1, "000000090000004a00000000",
    "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
    "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e" },
};

RTEST_LOOP (rchacha20, block, RTEST_FAST, 0, R_N_ELEMENTS (block_test_data))
{
  const RChaCha20BlockTestData * data = &block_test_data[__i];
  ruint8 key[R_CHACHA20_KEY_SIZE];
  ruint8 nonce[R_CHACHA20_NONCE_SIZE];
  ruint8 expected[R_CHACHA20_BLOCK_SIZE];
  ruint8 out[R_CHACHA20_BLOCK_SIZE];

  r_assert_cmpuint (r_str_hex_to_binary (data->key, key, sizeof (key)),
      ==, sizeof (key));
  r_assert_cmpuint (r_str_hex_to_binary (data->nonce, nonce, sizeof (nonce)),
      ==, sizeof (nonce));
  r_assert_cmpuint (r_str_hex_to_binary (data->keystream, expected, sizeof (expected)),
      ==, sizeof (expected));

  r_chacha20_block (out, key, data->counter, nonce);
  r_assert_cmpmem (out, ==, expected, sizeof (expected));
}
RTEST_END;

RTEST (rchacha20, xor, RTEST_FAST)
{
  /* RFC 8439 sec 2.4.2 encryption test vector. */
  static const rchar plaintext[] =
      "Ladies and Gentlemen of the class of '99: If I could offer you "
      "only one tip for the future, sunscreen would be it.";
  static const rchar ciphertext_hex[] =
      "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
      "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
      "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
      "5af90bbf74a35be6b40b8eedf2785e42874d";
  ruint8 key[R_CHACHA20_KEY_SIZE];
  ruint8 nonce[R_CHACHA20_NONCE_SIZE];
  ruint8 expected[114];
  ruint8 out[114];
  rsize size = r_strlen (plaintext);

  r_assert_cmpuint (size, ==, sizeof (expected));
  r_assert_cmpuint (r_str_hex_to_binary (
      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      key, sizeof (key)), ==, sizeof (key));
  r_assert_cmpuint (r_str_hex_to_binary (
      "000000000000004a00000000", nonce, sizeof (nonce)), ==, sizeof (nonce));
  r_assert_cmpuint (r_str_hex_to_binary (ciphertext_hex, expected,
      sizeof (expected)), ==, sizeof (expected));

  /* Encrypt: keystream XOR plaintext == ciphertext. */
  r_chacha20_xor (out, (const ruint8 *) plaintext, size, key, 1, nonce);
  r_assert_cmpmem (out, ==, expected, size);

  /* Decrypt is the same operation, recovering the plaintext. */
  r_chacha20_xor (out, out, size, key, 1, nonce);
  r_assert_cmpmem (out, ==, plaintext, size);
}
RTEST_END;
