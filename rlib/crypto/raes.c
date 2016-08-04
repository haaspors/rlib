/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/crypto/raes.h>
#include <rlib/crypto/raes-data.inc>

#include <rlib/rstr.h>

#define R_AES_MAX_KEY_BYTES   32

#define R_AES_FORWARD(X, Y)                                                    \
  X[0] = *rk++ ^                                                               \
      r_aes_ftbl[0][(Y[0]      ) & 0xff] ^ r_aes_ftbl[1][(Y[1] >>  8) & 0xff] ^\
      r_aes_ftbl[2][(Y[2] >> 16) & 0xff] ^ r_aes_ftbl[3][(Y[3] >> 24) & 0xff]; \
  X[1] = *rk++ ^                                                               \
      r_aes_ftbl[0][(Y[1]      ) & 0xff] ^ r_aes_ftbl[1][(Y[2] >>  8) & 0xff] ^\
      r_aes_ftbl[2][(Y[3] >> 16) & 0xff] ^ r_aes_ftbl[3][(Y[0] >> 24) & 0xff]; \
  X[2] = *rk++ ^                                                               \
      r_aes_ftbl[0][(Y[2]      ) & 0xff] ^ r_aes_ftbl[1][(Y[3] >>  8) & 0xff] ^\
      r_aes_ftbl[2][(Y[0] >> 16) & 0xff] ^ r_aes_ftbl[3][(Y[1] >> 24) & 0xff]; \
  X[3] = *rk++ ^                                                               \
      r_aes_ftbl[0][(Y[3]      ) & 0xff] ^ r_aes_ftbl[1][(Y[0] >>  8) & 0xff] ^\
      r_aes_ftbl[2][(Y[1] >> 16) & 0xff] ^ r_aes_ftbl[3][(Y[2] >> 24) & 0xff];

#define R_AES_REVERSE(X, Y)                                                    \
  X[0] = *rk++ ^                                                               \
      r_aes_rtbl[0][(Y[0]      ) & 0xff] ^ r_aes_rtbl[1][(Y[3] >>  8) & 0xff] ^\
      r_aes_rtbl[2][(Y[2] >> 16) & 0xff] ^ r_aes_rtbl[3][(Y[1] >> 24) & 0xff]; \
  X[1] = *rk++ ^                                                               \
      r_aes_rtbl[0][(Y[1]      ) & 0xff] ^ r_aes_rtbl[1][(Y[0] >>  8) & 0xff] ^\
      r_aes_rtbl[2][(Y[3] >> 16) & 0xff] ^ r_aes_rtbl[3][(Y[2] >> 24) & 0xff]; \
  X[2] = *rk++ ^                                                               \
      r_aes_rtbl[0][(Y[2]      ) & 0xff] ^ r_aes_rtbl[1][(Y[1] >>  8) & 0xff] ^\
      r_aes_rtbl[2][(Y[0] >> 16) & 0xff] ^ r_aes_rtbl[3][(Y[3] >> 24) & 0xff]; \
  X[3] = *rk++ ^                                                               \
      r_aes_rtbl[0][(Y[3]      ) & 0xff] ^ r_aes_rtbl[1][(Y[2] >>  8) & 0xff] ^\
      r_aes_rtbl[2][(Y[1] >> 16) & 0xff] ^ r_aes_rtbl[3][(Y[0] >> 24) & 0xff];

typedef struct {
  RCryptoCipher cipher;

  ruint8 key[R_AES_MAX_KEY_BYTES];
  ruint8 iv[R_AES_BLOCK_BYTES];

  ruint32 erk[R_AES_BLOCK_BYTES * sizeof (ruint32)];
  ruint32 drk[R_AES_BLOCK_BYTES * sizeof (ruint32)];
  ruint8 rounds;
} RAesCipher;

static void
r_cipher_aes_free (RAesCipher * cipher)
{
  r_free (cipher);
}

RCryptoCipher *
r_cipher_aes_new (ruint bits, const ruint8 * key)
{
  RAesCipher * ret;

  if (R_UNLIKELY (bits != 128 && bits != 192 && bits != 256)) return NULL;
  if (R_UNLIKELY (key == NULL)) return NULL;

  if ((ret = r_mem_new (RAesCipher)) != NULL) {
    ruint8 i;
    ruint32 * rk, * src;

    r_ref_init (ret, r_cipher_aes_free);
    ret->cipher.strtype = R_AES_STR;
    ret->cipher.algo = R_CRYPTO_CIPHER_ALGO_AES;
    ret->cipher.keybits = bits;
    ret->cipher.blockbits = R_AES_BLOCK_BYTES * 8;

    r_memcpy (ret->key, key, bits / 8);
    r_memset (ret->iv, 0, R_AES_BLOCK_BYTES);

    rk = ret->erk;
    for (i = 0; i < bits / 32; i++)
      rk[i] = RUINT32_FROM_LE (*((ruint32 *)&key[i * 4]));

    switch (bits) {
      case 128:
        ret->rounds = 10;

        for (i = 0; i < 10; i++, rk += 4) {
          rk[4]  = rk[0] ^ r_aes_round_data[i] ^
            ((ruint32) r_aes_fsbox[(rk[3] >>  8) & 0xff]      ) ^
            ((ruint32) r_aes_fsbox[(rk[3] >> 16) & 0xff] <<  8) ^
            ((ruint32) r_aes_fsbox[(rk[3] >> 24) & 0xff] << 16) ^
            ((ruint32) r_aes_fsbox[(rk[3]      ) & 0xff] << 24);

          rk[5]  = rk[1] ^ rk[4];
          rk[6]  = rk[2] ^ rk[5];
          rk[7]  = rk[3] ^ rk[6];
        }
        break;

      case 192:
        ret->rounds = 12;

        for (i = 0; i < 8; i++, rk += 6) {
          rk[6]  = rk[0] ^ r_aes_round_data[i] ^
            ((ruint32) r_aes_fsbox[(rk[5] >>  8) & 0xff]      ) ^
            ((ruint32) r_aes_fsbox[(rk[5] >> 16) & 0xff] <<  8) ^
            ((ruint32) r_aes_fsbox[(rk[5] >> 24) & 0xff] << 16) ^
            ((ruint32) r_aes_fsbox[(rk[5]      ) & 0xff] << 24);

          rk[7]  = rk[1] ^ rk[6];
          rk[8]  = rk[2] ^ rk[7];
          rk[9]  = rk[3] ^ rk[8];
          rk[10] = rk[4] ^ rk[9];
          rk[11] = rk[5] ^ rk[10];
        }
        break;

      case 256:
        ret->rounds = 14;

        for (i = 0; i < 7; i++, rk += 8) {
            rk[8]  = rk[0] ^ r_aes_round_data[i] ^
              ((ruint32) r_aes_fsbox[(rk[7] >>  8) & 0xff]      ) ^
              ((ruint32) r_aes_fsbox[(rk[7] >> 16) & 0xff] <<  8) ^
              ((ruint32) r_aes_fsbox[(rk[7] >> 24) & 0xff] << 16) ^
              ((ruint32) r_aes_fsbox[(rk[7]      ) & 0xff] << 24);

            rk[9]  = rk[1] ^ rk[8];
            rk[10] = rk[2] ^ rk[9];
            rk[11] = rk[3] ^ rk[10];

            rk[12] = rk[4] ^
              ((ruint32) r_aes_fsbox[(rk[11]      ) & 0xff]      ) ^
              ((ruint32) r_aes_fsbox[(rk[11] >>  8) & 0xff] <<  8) ^
              ((ruint32) r_aes_fsbox[(rk[11] >> 16) & 0xff] << 16) ^
              ((ruint32) r_aes_fsbox[(rk[11] >> 24) & 0xff] << 24);

            rk[13] = rk[5] ^ rk[12];
            rk[14] = rk[6] ^ rk[13];
            rk[15] = rk[7] ^ rk[14];
        }
        break;
    }

    src = ret->erk + ret->rounds * sizeof (ruint32);
    rk = ret->drk;

    *rk++ = src[0];
    *rk++ = src[1];
    *rk++ = src[2];
    *rk++ = src[3];

    for (i = ret->rounds - 1, src -= 4; i > 0; i--, src -= 4) {
      *rk++ = r_aes_rtbl[0][r_aes_fsbox[(src[0]      ) & 0xff]] ^
              r_aes_rtbl[1][r_aes_fsbox[(src[0] >>  8) & 0xff]] ^
              r_aes_rtbl[2][r_aes_fsbox[(src[0] >> 16) & 0xff]] ^
              r_aes_rtbl[3][r_aes_fsbox[(src[0] >> 24) & 0xff]];
      *rk++ = r_aes_rtbl[0][r_aes_fsbox[(src[1]      ) & 0xff]] ^
              r_aes_rtbl[1][r_aes_fsbox[(src[1] >>  8) & 0xff]] ^
              r_aes_rtbl[2][r_aes_fsbox[(src[1] >> 16) & 0xff]] ^
              r_aes_rtbl[3][r_aes_fsbox[(src[1] >> 24) & 0xff]];
      *rk++ = r_aes_rtbl[0][r_aes_fsbox[(src[2]      ) & 0xff]] ^
              r_aes_rtbl[1][r_aes_fsbox[(src[2] >>  8) & 0xff]] ^
              r_aes_rtbl[2][r_aes_fsbox[(src[2] >> 16) & 0xff]] ^
              r_aes_rtbl[3][r_aes_fsbox[(src[2] >> 24) & 0xff]];
      *rk++ = r_aes_rtbl[0][r_aes_fsbox[(src[3]      ) & 0xff]] ^
              r_aes_rtbl[1][r_aes_fsbox[(src[3] >>  8) & 0xff]] ^
              r_aes_rtbl[2][r_aes_fsbox[(src[3] >> 16) & 0xff]] ^
              r_aes_rtbl[3][r_aes_fsbox[(src[3] >> 24) & 0xff]];
    }

    *rk++ = *src++;
    *rk++ = *src++;
    *rk++ = *src++;
    *rk++ = *src++;
  }

  return &ret->cipher;
}

RCryptoCipher *
r_cipher_aes_new_from_hex (const rchar * hexkey)
{
  RCryptoCipher * ret;
  ruint8 * key;
  rsize size;

  if ((key = r_str_hex_mem (hexkey, &size)) != NULL) {
    ret = r_cipher_aes_new (size * 8, key);
    r_free (key);
  } else {
    ret = NULL;
  }

  return ret;
}

rboolean
r_cipher_aes_ecb_encrypt_block (const RCryptoCipher * cipher,
    const ruint8 plaintxt[R_AES_BLOCK_BYTES], ruint8 ciphertxt[R_AES_BLOCK_BYTES])
{
  ruint32 input[4], tmp[4]; /* 4 * 4 = 16 bytes */
  const ruint32 * rk;
  const RAesCipher * aes;
  ruint8 i;

  if (R_UNLIKELY (cipher == NULL)) return FALSE;

  aes = (const RAesCipher *)cipher;
  rk = aes->erk;

  input[0] = RUINT32_FROM_LE (*((ruint32 *)&plaintxt[0x0])) ^ *rk++;
  input[1] = RUINT32_FROM_LE (*((ruint32 *)&plaintxt[0x4])) ^ *rk++;
  input[2] = RUINT32_FROM_LE (*((ruint32 *)&plaintxt[0x8])) ^ *rk++;
  input[3] = RUINT32_FROM_LE (*((ruint32 *)&plaintxt[0xc])) ^ *rk++;

  for (i = aes->rounds / 2; i > 1; i--) {
    R_AES_FORWARD (tmp, input);
    R_AES_FORWARD (input, tmp);
  }

  R_AES_FORWARD (tmp, input);

  input[0] = *rk++ ^
          ((ruint32) r_aes_fsbox[(tmp[0]      ) & 0xff]      ) ^
          ((ruint32) r_aes_fsbox[(tmp[1] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_fsbox[(tmp[2] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_fsbox[(tmp[3] >> 24) & 0xff] << 24);
  input[1] = *rk++ ^
          ((ruint32) r_aes_fsbox[(tmp[1]      ) & 0xff]      ) ^
          ((ruint32) r_aes_fsbox[(tmp[2] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_fsbox[(tmp[3] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_fsbox[(tmp[0] >> 24) & 0xff] << 24);
  input[2] = *rk++ ^
          ((ruint32) r_aes_fsbox[(tmp[2]      ) & 0xff]      ) ^
          ((ruint32) r_aes_fsbox[(tmp[3] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_fsbox[(tmp[0] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_fsbox[(tmp[1] >> 24) & 0xff] << 24);
  input[3] = *rk++ ^
          ((ruint32) r_aes_fsbox[(tmp[3]      ) & 0xff]      ) ^
          ((ruint32) r_aes_fsbox[(tmp[0] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_fsbox[(tmp[1] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_fsbox[(tmp[2] >> 24) & 0xff] << 24);

  *((ruint32 *)&ciphertxt[0x0]) = RUINT32_TO_LE (input[0]);
  *((ruint32 *)&ciphertxt[0x4]) = RUINT32_TO_LE (input[1]);
  *((ruint32 *)&ciphertxt[0x8]) = RUINT32_TO_LE (input[2]);
  *((ruint32 *)&ciphertxt[0xc]) = RUINT32_TO_LE (input[3]);

  return TRUE;
}

rboolean
r_cipher_aes_ecb_decrypt_block (const RCryptoCipher * cipher,
    const ruint8 ciphertxt[R_AES_BLOCK_BYTES], ruint8 plaintxt[R_AES_BLOCK_BYTES])
{
  ruint32 input[4], tmp[4]; /* 4 * 4 = 16 bytes */
  const ruint32 * rk;
  const RAesCipher * aes;
  ruint8 i;

  if (R_UNLIKELY (cipher == NULL)) return FALSE;

  aes = (const RAesCipher *)cipher;
  rk = aes->drk;

  input[0] = RUINT32_FROM_LE (*((ruint32 *)&ciphertxt[0x0])) ^ *rk++;
  input[1] = RUINT32_FROM_LE (*((ruint32 *)&ciphertxt[0x4])) ^ *rk++;
  input[2] = RUINT32_FROM_LE (*((ruint32 *)&ciphertxt[0x8])) ^ *rk++;
  input[3] = RUINT32_FROM_LE (*((ruint32 *)&ciphertxt[0xc])) ^ *rk++;

  for (i = aes->rounds / 2; i > 1; i--) {
    R_AES_REVERSE (tmp, input);
    R_AES_REVERSE (input, tmp);
  }

  R_AES_REVERSE (tmp, input);

  input[0] = *rk++ ^
          ((ruint32) r_aes_rsbox[(tmp[0]      ) & 0xff]      ) ^
          ((ruint32) r_aes_rsbox[(tmp[3] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_rsbox[(tmp[2] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_rsbox[(tmp[1] >> 24) & 0xff] << 24);
  input[1] = *rk++ ^
          ((ruint32) r_aes_rsbox[(tmp[1]      ) & 0xff]      ) ^
          ((ruint32) r_aes_rsbox[(tmp[0] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_rsbox[(tmp[3] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_rsbox[(tmp[2] >> 24) & 0xff] << 24);
  input[2] = *rk++ ^
          ((ruint32) r_aes_rsbox[(tmp[2]      ) & 0xff]      ) ^
          ((ruint32) r_aes_rsbox[(tmp[1] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_rsbox[(tmp[0] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_rsbox[(tmp[3] >> 24) & 0xff] << 24);
  input[3] = *rk++ ^
          ((ruint32) r_aes_rsbox[(tmp[3]      ) & 0xff]      ) ^
          ((ruint32) r_aes_rsbox[(tmp[2] >>  8) & 0xff] <<  8) ^
          ((ruint32) r_aes_rsbox[(tmp[1] >> 16) & 0xff] << 16) ^
          ((ruint32) r_aes_rsbox[(tmp[0] >> 24) & 0xff] << 24);

  *((ruint32 *)&plaintxt[0x0]) = RUINT32_TO_LE (input[0]);
  *((ruint32 *)&plaintxt[0x4]) = RUINT32_TO_LE (input[1]);
  *((ruint32 *)&plaintxt[0x8]) = RUINT32_TO_LE (input[2]);
  *((ruint32 *)&plaintxt[0xc]) = RUINT32_TO_LE (input[3]);

  return TRUE;
}

RCryptoCipherResult
r_cipher_aes_ecb_encrypt (const RCryptoCipher * cipher,
    ruint8 * iv, rconstpointer data, rsize size, ruint8 * out)
{
  const ruint8 * ptr;

  (void) iv;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (out == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  for (ptr = data; ptr < ((ruint8 *)data) + size; ptr += R_AES_BLOCK_BYTES, out += R_AES_BLOCK_BYTES)
    r_cipher_aes_ecb_encrypt_block (cipher, ptr, out);

  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_ecb_decrypt (const RCryptoCipher * cipher,
    ruint8 * iv, rconstpointer data, rsize size, ruint8 * out)
{
  const ruint8 * ptr;

  (void) iv;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (out == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  for (ptr = data; ptr < ((ruint8 *)data) + size; ptr += R_AES_BLOCK_BYTES, out += R_AES_BLOCK_BYTES)
    r_cipher_aes_ecb_decrypt_block (cipher, ptr, out);

  return R_CRYPTO_CIPHER_OK;
}

