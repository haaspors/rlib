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
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 0, dk, 16)); /* 0 iterations */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA256,
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 1, NULL, 16)); /* NULL out */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHA256,
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 1, dk, 0));    /* 0 outlen */
  r_assert (!r_kdf_pbkdf2 (R_MSG_DIGEST_TYPE_SHAKE256,
        (const ruint8 *) "p", 1, (const ruint8 *) "s", 1, 1, dk, 16));   /* XOF prf */
}
RTEST_END;
