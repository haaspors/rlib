#include <rlib/rcrypto.h>
#include <rlib/rstr.h>

typedef struct {
  const rchar * key;
  const rchar * nonce;
  const rchar * aad;
  const rchar * plaintxt;
  const rchar * ciphertxt;
  const rchar * tag;
} RChaCha20Poly1305TestData;

/* AEAD known-answer vector from RFC 8439 sec 2.8.2. Values are hex;
 * plaintext and ciphertext lengths match. */
static const RChaCha20Poly1305TestData aead_test_data[] = {
  { /* RFC 8439 sec 2.8.2 */
    .key = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
    .nonce = "070000004041424344454647",
    .aad = "50515253c0c1c2c3c4c5c6c7",
    .plaintxt =
      "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
      "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
      "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
      "637265656e20776f756c642062652069742e",
    .ciphertxt =
      "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
      "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
      "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
      "3ff4def08e4b7a9de576d26586cec64b6116",
    .tag = "1ae10b594f09e26a7e902ecbd0600691" },
};

RTEST_LOOP (rchacha20poly1305, aead, RTEST_FAST, 0, R_N_ELEMENTS (aead_test_data))
{
  const RChaCha20Poly1305TestData * data = &aead_test_data[__i];
  RCryptoCipher * cipher;
  ruint8 key[R_CHACHA20POLY1305_KEY_SIZE];
  ruint8 nonce[R_CHACHA20POLY1305_NONCE_SIZE];
  ruint8 tag[R_CHACHA20POLY1305_TAG_SIZE];
  ruint8 outtag[R_CHACHA20POLY1305_TAG_SIZE];
  ruint8 * aad, * plaintxt, * ciphertxt, * out;
  rsize plainsize, aadsize;

  plainsize = r_strlen (data->plaintxt) / 2;
  aadsize   = r_strlen (data->aad) / 2;
  aad       = r_malloc (aadsize);
  plaintxt  = r_malloc (plainsize);
  ciphertxt = r_malloc (plainsize);
  out       = r_malloc (plainsize);

  r_assert_cmpuint (r_str_hex_to_binary (data->key, key, sizeof (key)),
      ==, sizeof (key));
  r_assert_cmpuint (r_str_hex_to_binary (data->nonce, nonce, sizeof (nonce)),
      ==, sizeof (nonce));
  r_assert_cmpuint (r_str_hex_to_binary (data->aad, aad, aadsize), ==, aadsize);
  r_assert_cmpuint (r_str_hex_to_binary (data->plaintxt, plaintxt, plainsize),
      ==, plainsize);
  r_assert_cmpuint (r_str_hex_to_binary (data->ciphertxt, ciphertxt, plainsize),
      ==, plainsize);
  r_assert_cmpuint (r_str_hex_to_binary (data->tag, tag, sizeof (tag)),
      ==, sizeof (tag));

  r_assert_cmpptr ((cipher = r_cipher_chacha20_poly1305_new (key)), !=, NULL);
  r_assert (r_crypto_cipher_is_aead (cipher));

  /* Encrypt: matches the RFC ciphertext and tag. */
  r_assert_cmpint (r_crypto_cipher_encrypt_aead (cipher, out, plainsize, plaintxt,
        aad, aadsize, nonce, sizeof (nonce), outtag, sizeof (outtag)),
      ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (out, ==, ciphertxt, plainsize);
  r_assert_cmpmem (outtag, ==, tag, sizeof (tag));

  /* Decrypt: recovers the plaintext and verifies the tag. */
  r_assert_cmpint (r_crypto_cipher_decrypt_aead (cipher, out, plainsize, ciphertxt,
        aad, aadsize, nonce, sizeof (nonce), tag, sizeof (tag)),
      ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpmem (out, ==, plaintxt, plainsize);

  /* A tampered tag fails with AUTH_FAILED and releases no plaintext. */
  {
    ruint8 badtag[R_CHACHA20POLY1305_TAG_SIZE];
    r_memcpy (badtag, tag, sizeof (badtag));
    badtag[0] ^= 0x01;
    r_assert_cmpint (r_crypto_cipher_decrypt_aead (cipher, out, plainsize, ciphertxt,
          aad, aadsize, nonce, sizeof (nonce), badtag, sizeof (badtag)),
        ==, R_CRYPTO_CIPHER_AUTH_FAILED);
  }

  /* Tampering with the AAD is likewise caught. */
  if (aadsize > 0) {
    aad[0] ^= 0x01;
    r_assert_cmpint (r_crypto_cipher_decrypt_aead (cipher, out, plainsize, ciphertxt,
          aad, aadsize, nonce, sizeof (nonce), tag, sizeof (tag)),
        ==, R_CRYPTO_CIPHER_AUTH_FAILED);
    aad[0] ^= 0x01;
  }

  /* The non-AEAD entry point is rejected on an AEAD cipher. */
  r_assert_cmpint (r_crypto_cipher_encrypt (cipher, out, plainsize, plaintxt,
        nonce, sizeof (nonce)), ==, R_CRYPTO_CIPHER_NEEDS_AEAD);

  r_crypto_cipher_unref (cipher);
  r_free (aad);
  r_free (plaintxt);
  r_free (ciphertxt);
  r_free (out);
}
RTEST_END;

/* Empty plaintext and empty AAD: the tag covers only the two zero length
 * words, and encrypt/decrypt must still round-trip (TLS can emit empty
 * application_data records). A flipped tag byte is rejected. */
RTEST (rchacha20poly1305, empty, RTEST_FAST)
{
  static const ruint8 key[R_CHACHA20POLY1305_KEY_SIZE] = {
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
  };
  static const ruint8 nonce[R_CHACHA20POLY1305_NONCE_SIZE] = {
    0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
  };
  RCryptoCipher * cipher;
  ruint8 tag[R_CHACHA20POLY1305_TAG_SIZE];
  ruint8 badtag[R_CHACHA20POLY1305_TAG_SIZE];

  r_assert_cmpptr ((cipher = r_cipher_chacha20_poly1305_new (key)), !=, NULL);

  r_assert_cmpint (r_crypto_cipher_encrypt_aead (cipher, NULL, 0, NULL,
        NULL, 0, (ruint8 *) nonce, sizeof (nonce), tag, sizeof (tag)),
      ==, R_CRYPTO_CIPHER_OK);
  r_assert_cmpint (r_crypto_cipher_decrypt_aead (cipher, NULL, 0, NULL,
        NULL, 0, (ruint8 *) nonce, sizeof (nonce), tag, sizeof (tag)),
      ==, R_CRYPTO_CIPHER_OK);

  r_memcpy (badtag, tag, sizeof (badtag));
  badtag[0] ^= 0x01;
  r_assert_cmpint (r_crypto_cipher_decrypt_aead (cipher, NULL, 0, NULL,
        NULL, 0, (ruint8 *) nonce, sizeof (nonce), badtag, sizeof (badtag)),
      ==, R_CRYPTO_CIPHER_AUTH_FAILED);

  r_crypto_cipher_unref (cipher);
}
RTEST_END;
