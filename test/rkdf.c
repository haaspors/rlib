#include <rlib/rcrypto.h>

RTEST (rkdf, pbkdf2_sha1_rfc6070, R_TEST_TYPE_FAST)
{
  ruint8 dk[32];

  /* RFC 6070 PBKDF2-HMAC-SHA1 test vectors. */
  r_assert (r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA1,
        (const ruint8 *) "password", 8, (const ruint8 *) "salt", 4, 1, dk, 20));
  r_assert_cmpmem (dk, ==,
      "\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06"
      "\x2f\xe0\x37\xa6", 20);

  r_assert (r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA1,
        (const ruint8 *) "password", 8, (const ruint8 *) "salt", 4, 2, dk, 20));
  r_assert_cmpmem (dk, ==,
      "\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0"
      "\xd8\xde\x89\x57", 20);

  r_assert (r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA1,
        (const ruint8 *) "password", 8, (const ruint8 *) "salt", 4, 4096, dk, 20));
  r_assert_cmpmem (dk, ==,
      "\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0"
      "\x65\xa4\x29\xc1", 20);

  /* dkLen 25 > SHA-1's 20: exercises multi-block output. */
  r_assert (r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA1,
        (const ruint8 *) "passwordPASSWORDpassword", 24,
        (const ruint8 *) "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36, 4096, dk, 25));
  r_assert_cmpmem (dk, ==,
      "\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a"
      "\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38", 25);

  /* Embedded NUL in both password and salt. */
  r_assert (r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA1,
        (const ruint8 *) "pass\0word", 9, (const ruint8 *) "sa\0lt", 5, 4096, dk, 16));
  r_assert_cmpmem (dk, ==,
      "\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3", 16);
}
RTEST_END;

RTEST (rkdf, pbkdf2_invalid_args, R_TEST_TYPE_FAST)
{
  ruint8 dk[16];

  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA256,
        NULL, 0, (const ruint8 *) "s", 1, 1, dk, 16));            /* NULL password */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA256,
        (const ruint8 *) "p", 1, NULL, 0, 1, dk, 16));            /* NULL salt */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA256,
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 0, dk, 16)); /* 0 iterations */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA256,
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 1, NULL, 16)); /* NULL out */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA256,
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 1, dk, 0));    /* 0 outlen */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHAKE256,
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 1, dk, 16));   /* XOF prf */
}
RTEST_END;

RTEST (rkdf, hkdf_sha256_rfc5869, R_TEST_TYPE_FAST)
{
  ruint8 ikm[22];
  ruint8 prk[32], okm[42];

  r_memset (ikm, 0x0b, sizeof (ikm));   /* RFC 5869 IKM = 0x0b x 22 */

  /* RFC 5869 A.1: basic case with salt + info. */
  r_assert (r_hkdf_extract (R_MSG_DIGEST_TYPE_SHA256,
        (const ruint8 *) "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c", 13,
        ikm, sizeof (ikm), prk));
  r_assert_cmpmem (prk, ==,
      "\x07\x77\x09\x36\x2c\x2e\x32\xdf\x0d\xdc\x3f\x0d\xc4\x7b\xba\x63"
      "\x90\xb6\xc7\x3b\xb5\x0f\x9c\x31\x22\xec\x84\x4a\xd7\xc2\xb3\xe5", 32);
  r_assert (r_hkdf_expand (R_MSG_DIGEST_TYPE_SHA256, prk, 32,
        (const ruint8 *) "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9", 10, okm, 42));
  r_assert_cmpmem (okm, ==,
      "\x3c\xb2\x5f\x25\xfa\xac\xd5\x7a\x90\x43\x4f\x64\xd0\x36\x2f\x2a"
      "\x2d\x2d\x0a\x90\xcf\x1a\x5a\x4c\x5d\xb0\x2d\x56\xec\xc4\xc5\xbf"
      "\x34\x00\x72\x08\xd5\xb8\x87\x18\x58\x65", 42);

  /* RFC 5869 A.3: zero-length salt and info (absent salt -> HashLen zeros). */
  r_assert (r_hkdf_extract (R_MSG_DIGEST_TYPE_SHA256, NULL, 0, ikm, sizeof (ikm), prk));
  r_assert_cmpmem (prk, ==,
      "\x19\xef\x24\xa3\x2c\x71\x7b\x16\x7f\x33\xa9\x1d\x6f\x64\x8b\xdf"
      "\x96\x59\x67\x76\xaf\xdb\x63\x77\xac\x43\x4c\x1c\x29\x3c\xcb\x04", 32);
  r_assert (r_hkdf_expand (R_MSG_DIGEST_TYPE_SHA256, prk, 32, NULL, 0, okm, 42));
  r_assert_cmpmem (okm, ==,
      "\x8d\xa4\xe7\x75\xa5\x63\xc1\x8f\x71\x5f\x80\x2a\x06\x3c\x5a\x31"
      "\xb8\xa1\x1f\x5c\x5e\xe1\x87\x9e\xc3\x45\x4e\x5f\x3c\x73\x8d\x2d"
      "\x9d\x20\x13\x95\xfa\xa4\xb6\x1a\x96\xc8", 42);

  /* Invalid args. */
  r_assert (!r_hkdf_extract (R_MSG_DIGEST_TYPE_SHA256, NULL, 0, NULL, 0, prk));        /* NULL ikm */
  r_assert (!r_hkdf_extract (R_MSG_DIGEST_TYPE_SHA256, ikm, sizeof (ikm),
        ikm, sizeof (ikm), NULL));                                                     /* NULL prk */
  r_assert (!r_hkdf_expand (R_MSG_DIGEST_TYPE_SHA256, prk, 32, NULL, 0, okm, 0));      /* 0 outlen */
  r_assert (!r_hkdf_expand (R_MSG_DIGEST_TYPE_SHA256, prk, 32, NULL, 0, okm, 255 * 32 + 1)); /* > 255*HashLen */
  r_assert (!r_hkdf_expand (R_MSG_DIGEST_TYPE_SHAKE256, prk, 32, NULL, 0, okm, 16));   /* XOF hash */
}
RTEST_END;
