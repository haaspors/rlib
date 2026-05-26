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

#include <rlib/rcpufeatures.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#if defined(R_ARCH_X86_64) || defined(R_ARCH_X86)
# include <wmmintrin.h>           /* AES-NI */
#endif

#if defined(R_ARCH_AARCH64)
# include <arm_neon.h>            /* ARMv8 AES */
#endif

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

typedef struct _RAesCipher RAesCipher;
typedef rboolean (*RAesBlockFn) (const RAesCipher * aes,
    ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES]);

struct _RAesCipher {
  RCryptoCipher cipher;

  ruint8 key[R_AES_MAX_KEY_BYTES];

  ruint32 erk[R_AES_BLOCK_BYTES * sizeof (ruint32)];
  ruint32 drk[R_AES_BLOCK_BYTES * sizeof (ruint32)];
  ruint8 rounds;

  /* Per-block fast path picked once at construction in
   * r_cipher_aes_new_with_info based on r_cpu_has; saves the
   * feature check + extra branch on every block dispatch. */
  RAesBlockFn encrypt_block;
  RAesBlockFn decrypt_block;
};

#define R_AES_BLOCK_FN_DECL(name)                                              \
  static rboolean name (const RAesCipher * aes,                                \
      ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES])

R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_sw);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_sw);

#if defined(R_ARCH_X86_64) || defined(R_ARCH_X86)
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_aesni_128);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_aesni_192);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_aesni_256);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_aesni_128);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_aesni_192);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_aesni_256);
#endif

#if defined(R_ARCH_AARCH64)
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_armv8_128);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_armv8_192);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_armv8_256);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_armv8_128);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_armv8_192);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_armv8_256);
#endif

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ecb =  { "AES-128-ECB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_ECB, 128, 16, 16,
  r_cipher_aes_ecb_encrypt, r_cipher_aes_ecb_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ecb = { "AES-192-ECB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_ECB, 192, 16, 16,
  r_cipher_aes_ecb_encrypt, r_cipher_aes_ecb_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ecb = { "AES-256-ECB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_ECB, 256, 16, 16,
  r_cipher_aes_ecb_encrypt, r_cipher_aes_ecb_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_128_cbc = { "AES-128-CBC",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CBC, 128, 16, 16,
  r_cipher_aes_cbc_encrypt, r_cipher_aes_cbc_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_cbc = { "AES-192-CBC",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CBC, 192, 16, 16,
  r_cipher_aes_cbc_encrypt, r_cipher_aes_cbc_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_cbc = { "AES-256-CBC",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CBC, 256, 16, 16,
  r_cipher_aes_cbc_encrypt, r_cipher_aes_cbc_decrypt
};

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ctr = { "AES-128-CTR",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CTR, 128, 16, 16,
  r_cipher_aes_ctr_encrypt, r_cipher_aes_ctr_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ctr = { "AES-192-CTR",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CTR, 192, 16, 16,
  r_cipher_aes_ctr_encrypt, r_cipher_aes_ctr_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ctr = { "AES-256-CTR",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CTR, 256, 16, 16,
  r_cipher_aes_ctr_encrypt, r_cipher_aes_ctr_decrypt
};

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_cfb = { "AES-128-CFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CFB, 128, 16, 16,
  r_cipher_aes_cfb_encrypt, r_cipher_aes_cfb_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_cfb = { "AES-192-CFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CFB, 192, 16, 16,
  r_cipher_aes_cfb_encrypt, r_cipher_aes_cfb_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_cfb = { "AES-256-CFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CFB, 256, 16, 16,
  r_cipher_aes_cfb_encrypt, r_cipher_aes_cfb_decrypt
};

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ofb = { "AES-128-OFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_OFB, 128, 16, 16,
  r_cipher_aes_ofb_encrypt, r_cipher_aes_ofb_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ofb = { "AES-192-OFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_OFB, 192, 16, 16,
  r_cipher_aes_ofb_encrypt, r_cipher_aes_ofb_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ofb = { "AES-256-OFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_OFB, 256, 16, 16,
  r_cipher_aes_ofb_encrypt, r_cipher_aes_ofb_decrypt
};

static void
r_cipher_aes_free (RAesCipher * cipher)
{
  /* key + round-key schedules are key-equivalent; wipe before
   * release so heap reuse, swap, or core dumps don't expose them. */
  r_memclear_secure (cipher, sizeof (*cipher));
  r_free (cipher);
}

RCryptoCipher *
r_cipher_aes_new_with_info (const RCryptoCipherInfo * info, const ruint8 * key)
{
  RAesCipher * ret;

  if (R_UNLIKELY (key == NULL)) return NULL;

  if ((ret = r_mem_new (RAesCipher)) != NULL) {
    ruint8 i;
    ruint32 * rk, * src;

    r_ref_init (ret, r_cipher_aes_free);
    ret->cipher.info = info;
    r_memcpy (ret->key, key, info->keybits / 8);

    rk = ret->erk;
    for (i = 0; i < info->keybits / 32; i++)
      rk[i] = RUINT32_FROM_LE (*((ruint32 *)&key[i * 4]));

    switch (info->keybits) {
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

#if defined(R_ARCH_X86_64) || defined(R_ARCH_X86)
    if (r_cpu_has (R_CPU_FEATURE_AES_NI)) {
      switch (ret->rounds) {
        case 10:
          ret->encrypt_block = r_cipher_aes_ecb_encrypt_block_aesni_128;
          ret->decrypt_block = r_cipher_aes_ecb_decrypt_block_aesni_128;
          break;
        case 12:
          ret->encrypt_block = r_cipher_aes_ecb_encrypt_block_aesni_192;
          ret->decrypt_block = r_cipher_aes_ecb_decrypt_block_aesni_192;
          break;
        default: /* 14 = AES-256 */
          ret->encrypt_block = r_cipher_aes_ecb_encrypt_block_aesni_256;
          ret->decrypt_block = r_cipher_aes_ecb_decrypt_block_aesni_256;
          break;
      }
    } else
#elif defined(R_ARCH_AARCH64)
    if (r_cpu_has (R_CPU_FEATURE_ARM_AES)) {
      switch (ret->rounds) {
        case 10:
          ret->encrypt_block = r_cipher_aes_ecb_encrypt_block_armv8_128;
          ret->decrypt_block = r_cipher_aes_ecb_decrypt_block_armv8_128;
          break;
        case 12:
          ret->encrypt_block = r_cipher_aes_ecb_encrypt_block_armv8_192;
          ret->decrypt_block = r_cipher_aes_ecb_decrypt_block_armv8_192;
          break;
        default: /* 14 = AES-256 */
          ret->encrypt_block = r_cipher_aes_ecb_encrypt_block_armv8_256;
          ret->decrypt_block = r_cipher_aes_ecb_decrypt_block_armv8_256;
          break;
      }
    } else
#endif
    {
      ret->encrypt_block = r_cipher_aes_ecb_encrypt_block_sw;
      ret->decrypt_block = r_cipher_aes_ecb_decrypt_block_sw;
    }
  }

  return (RCryptoCipher *)ret;
}

RCryptoCipher *
r_cipher_aes_128_ecb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_128_ecb, key);
}

RCryptoCipher *
r_cipher_aes_192_ecb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_192_ecb, key);
}

RCryptoCipher *
r_cipher_aes_256_ecb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_256_ecb, key);
}

RCryptoCipher *
r_cipher_aes_128_cbc_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_128_cbc, key);
}

RCryptoCipher *
r_cipher_aes_192_cbc_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_192_cbc, key);
}

RCryptoCipher *
r_cipher_aes_256_cbc_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_256_cbc, key);
}

RCryptoCipher *
r_cipher_aes_128_ctr_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_128_ctr, key);
}

RCryptoCipher *
r_cipher_aes_192_ctr_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_192_ctr, key);
}

RCryptoCipher *
r_cipher_aes_256_ctr_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_256_ctr, key);
}

RCryptoCipher *
r_cipher_aes_128_cfb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_128_cfb, key);
}

RCryptoCipher *
r_cipher_aes_192_cfb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_192_cfb, key);
}

RCryptoCipher *
r_cipher_aes_256_cfb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_256_cfb, key);
}

RCryptoCipher *
r_cipher_aes_128_ofb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_128_ofb, key);
}

RCryptoCipher *
r_cipher_aes_192_ofb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_192_ofb, key);
}

RCryptoCipher *
r_cipher_aes_256_ofb_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_256_ofb, key);
}

RCryptoCipher *
r_cipher_aes_new (RCryptoCipherMode mode, ruint bits, const ruint8 * key)
{
  switch (bits) {
    case 128:
      switch (mode) {
        case R_CRYPTO_CIPHER_MODE_ECB:
          return r_cipher_aes_128_ecb_new (key);
        case R_CRYPTO_CIPHER_MODE_CBC:
          return r_cipher_aes_128_cbc_new (key);
        case R_CRYPTO_CIPHER_MODE_CTR:
          return r_cipher_aes_128_ctr_new (key);
        case R_CRYPTO_CIPHER_MODE_CFB:
          return r_cipher_aes_128_cfb_new (key);
        case R_CRYPTO_CIPHER_MODE_OFB:
          return r_cipher_aes_128_ofb_new (key);
        default:
          break;
      }
      break;
    case 192:
      switch (mode) {
        case R_CRYPTO_CIPHER_MODE_ECB:
          return r_cipher_aes_192_ecb_new (key);
        case R_CRYPTO_CIPHER_MODE_CBC:
          return r_cipher_aes_192_cbc_new (key);
        case R_CRYPTO_CIPHER_MODE_CTR:
          return r_cipher_aes_192_ctr_new (key);
        case R_CRYPTO_CIPHER_MODE_CFB:
          return r_cipher_aes_192_cfb_new (key);
        case R_CRYPTO_CIPHER_MODE_OFB:
          return r_cipher_aes_192_ofb_new (key);
        default:
          break;
      }
      break;
    case 256:
      switch (mode) {
        case R_CRYPTO_CIPHER_MODE_ECB:
          return r_cipher_aes_256_ecb_new (key);
        case R_CRYPTO_CIPHER_MODE_CBC:
          return r_cipher_aes_256_cbc_new (key);
        case R_CRYPTO_CIPHER_MODE_CTR:
          return r_cipher_aes_256_ctr_new (key);
        case R_CRYPTO_CIPHER_MODE_CFB:
          return r_cipher_aes_256_cfb_new (key);
        case R_CRYPTO_CIPHER_MODE_OFB:
          return r_cipher_aes_256_ofb_new (key);
        default:
          break;
      }
      break;
    default:
      break;
  }

  return NULL;
}

RCryptoCipher *
r_cipher_aes_new_from_hex (RCryptoCipherMode mode, const rchar * hexkey)
{
  RCryptoCipher * ret;
  ruint8 * key;
  rsize size;

  if ((key = r_str_hex_mem (hexkey, &size)) != NULL) {
    ret = r_cipher_aes_new (mode, (ruint)(size * 8), key);
    r_free (key);
  } else {
    ret = NULL;
  }

  return ret;
}

#if defined(R_ARCH_X86_64) || defined(R_ARCH_X86)
# if defined(__GNUC__) || defined(__clang__)
#  define R_AES_X86_TARGET __attribute__((target("aes,sse2")))
# else
#  define R_AES_X86_TARGET
# endif

/* AES-NI uses the same {LE u32} round-key layout the SW path
 * already produces - _mm_loadu_si128 sees the four LE u32s as a
 * 16-byte block with byte 0 in the low lane, matching the AES
 * state's column-major layout. Decrypt likewise consumes drk
 * directly since the SW key schedule pre-applies InvMixColumns
 * to the middle keys, which is what _mm_aesdec_si128 expects.
 *
 * The per-bits specialisation pins the round count as a compile-
 * time literal so the compiler fully unrolls the AESENC / AESDEC
 * sequence - on Zen3+ that lifts ECB-128 to ~5+ GiB/s vs ~2 GiB/s
 * for the generic loop where rounds is read from struct state. */
# define R_AES_AESNI_BLOCK(name, key_arr, op_round, op_last, rounds)         \
  R_AES_X86_TARGET                                                           \
  static rboolean                                                            \
  name (const RAesCipher * aes,                                              \
      ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES])    \
  {                                                                          \
    __m128i block = _mm_loadu_si128 ((const __m128i *)src);                  \
    const __m128i * rk = (const __m128i *)aes->key_arr;                      \
    ruint8 i;                                                                \
    block = _mm_xor_si128 (block, _mm_loadu_si128 (rk++));                   \
    for (i = 1; i < (rounds); i++, rk++)                                     \
      block = op_round (block, _mm_loadu_si128 (rk));                        \
    block = op_last (block, _mm_loadu_si128 (rk));                           \
    _mm_storeu_si128 ((__m128i *)dst, block);                                \
    return TRUE;                                                             \
  }

R_AES_AESNI_BLOCK (r_cipher_aes_ecb_encrypt_block_aesni_128, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 10)
R_AES_AESNI_BLOCK (r_cipher_aes_ecb_encrypt_block_aesni_192, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 12)
R_AES_AESNI_BLOCK (r_cipher_aes_ecb_encrypt_block_aesni_256, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 14)
R_AES_AESNI_BLOCK (r_cipher_aes_ecb_decrypt_block_aesni_128, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 10)
R_AES_AESNI_BLOCK (r_cipher_aes_ecb_decrypt_block_aesni_192, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 12)
R_AES_AESNI_BLOCK (r_cipher_aes_ecb_decrypt_block_aesni_256, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 14)
#endif

#if defined(R_ARCH_AARCH64)
# if defined(__GNUC__) || defined(__clang__)
#  define R_AES_ARM_TARGET __attribute__((target("+crypto")))
# else
#  define R_AES_ARM_TARGET
# endif

/* ARMv8 AESE/AESD do (AddRoundKey then SubBytes/ShiftRows) in a
 * single instruction, paired with AESMC/AESIMC for MixColumns.
 * Decrypt expects the encrypt round keys in reverse order - the
 * SW drk array (InvMixColumns pre-applied) doesn't match, so the
 * decrypt path walks erk backward instead.
 *
 * Per-bits specialisation matches the AES-NI rationale: literal
 * round count lets the compiler unroll the AESE/AESMC pairs. */
# define R_AES_ARMV8_ENCRYPT(name, rounds)                                   \
  R_AES_ARM_TARGET                                                           \
  static rboolean                                                            \
  name (const RAesCipher * aes,                                              \
      ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES])    \
  {                                                                          \
    uint8x16_t block = vld1q_u8 (src);                                       \
    const ruint8 * rk = (const ruint8 *)aes->erk;                            \
    ruint8 i;                                                                \
    for (i = 0; i < (rounds) - 1; i++, rk += 16) {                           \
      block = vaeseq_u8 (block, vld1q_u8 (rk));                              \
      block = vaesmcq_u8 (block);                                            \
    }                                                                        \
    block = vaeseq_u8 (block, vld1q_u8 (rk));                                \
    rk += 16;                                                                \
    block = veorq_u8 (block, vld1q_u8 (rk));                                 \
    vst1q_u8 (dst, block);                                                   \
    return TRUE;                                                             \
  }

# define R_AES_ARMV8_DECRYPT(name, rounds)                                   \
  R_AES_ARM_TARGET                                                           \
  static rboolean                                                            \
  name (const RAesCipher * aes,                                              \
      ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES])    \
  {                                                                          \
    uint8x16_t block = vld1q_u8 (src);                                       \
    const ruint8 * rk = (const ruint8 *)aes->erk + (rounds) * 16;            \
    ruint8 i;                                                                \
    for (i = 0; i < (rounds) - 1; i++, rk -= 16) {                           \
      block = vaesdq_u8 (block, vld1q_u8 (rk));                              \
      block = vaesimcq_u8 (block);                                           \
    }                                                                        \
    block = vaesdq_u8 (block, vld1q_u8 (rk));                                \
    rk -= 16;                                                                \
    block = veorq_u8 (block, vld1q_u8 (rk));                                 \
    vst1q_u8 (dst, block);                                                   \
    return TRUE;                                                             \
  }

R_AES_ARMV8_ENCRYPT (r_cipher_aes_ecb_encrypt_block_armv8_128, 10)
R_AES_ARMV8_ENCRYPT (r_cipher_aes_ecb_encrypt_block_armv8_192, 12)
R_AES_ARMV8_ENCRYPT (r_cipher_aes_ecb_encrypt_block_armv8_256, 14)
R_AES_ARMV8_DECRYPT (r_cipher_aes_ecb_decrypt_block_armv8_128, 10)
R_AES_ARMV8_DECRYPT (r_cipher_aes_ecb_decrypt_block_armv8_192, 12)
R_AES_ARMV8_DECRYPT (r_cipher_aes_ecb_decrypt_block_armv8_256, 14)

#endif

static rboolean
r_cipher_aes_ecb_encrypt_block_sw (const RAesCipher * aes,
    ruint8 ciphertxt[R_AES_BLOCK_BYTES], const ruint8 plaintxt[R_AES_BLOCK_BYTES])
{
  ruint32 input[4], tmp[4]; /* 4 * 4 = 16 bytes */
  const ruint32 * rk = aes->erk;
  ruint8 i;

  input[0] = r_load_le32 (&plaintxt[0x0]) ^ *rk++;
  input[1] = r_load_le32 (&plaintxt[0x4]) ^ *rk++;
  input[2] = r_load_le32 (&plaintxt[0x8]) ^ *rk++;
  input[3] = r_load_le32 (&plaintxt[0xc]) ^ *rk++;

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

  r_store_le32 (&ciphertxt[0x0], input[0]);
  r_store_le32 (&ciphertxt[0x4], input[1]);
  r_store_le32 (&ciphertxt[0x8], input[2]);
  r_store_le32 (&ciphertxt[0xc], input[3]);

  return TRUE;
}

rboolean
r_cipher_aes_ecb_encrypt_block (const RCryptoCipher * cipher,
    ruint8 ciphertxt[R_AES_BLOCK_BYTES], const ruint8 plaintxt[R_AES_BLOCK_BYTES])
{
  const RAesCipher * aes;
  if (R_UNLIKELY (cipher == NULL)) return FALSE;
  aes = (const RAesCipher *)cipher;
  return aes->encrypt_block (aes, ciphertxt, plaintxt);
}

static rboolean
r_cipher_aes_ecb_decrypt_block_sw (const RAesCipher * aes,
    ruint8 plaintxt[R_AES_BLOCK_BYTES], const ruint8 ciphertxt[R_AES_BLOCK_BYTES])
{
  ruint32 input[4], tmp[4]; /* 4 * 4 = 16 bytes */
  const ruint32 * rk = aes->drk;
  ruint8 i;

  input[0] = r_load_le32 (&ciphertxt[0x0]) ^ *rk++;
  input[1] = r_load_le32 (&ciphertxt[0x4]) ^ *rk++;
  input[2] = r_load_le32 (&ciphertxt[0x8]) ^ *rk++;
  input[3] = r_load_le32 (&ciphertxt[0xc]) ^ *rk++;

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

  r_store_le32 (&plaintxt[0x0], input[0]);
  r_store_le32 (&plaintxt[0x4], input[1]);
  r_store_le32 (&plaintxt[0x8], input[2]);
  r_store_le32 (&plaintxt[0xc], input[3]);

  return TRUE;
}

rboolean
r_cipher_aes_ecb_decrypt_block (const RCryptoCipher * cipher,
    ruint8 plaintxt[R_AES_BLOCK_BYTES], const ruint8 ciphertxt[R_AES_BLOCK_BYTES])
{
  const RAesCipher * aes;
  if (R_UNLIKELY (cipher == NULL)) return FALSE;
  aes = (const RAesCipher *)cipher;
  return aes->decrypt_block (aes, plaintxt, ciphertxt);
}

RCryptoCipherResult
r_cipher_aes_ecb_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;

  (void) iv;
  (void) ivsize;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  for (ptr = data; ptr < ((ruint8 *)data) + size; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES)
    r_cipher_aes_ecb_encrypt_block (cipher, dst, ptr);

  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_ecb_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;

  (void) iv;
  (void) ivsize;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  for (ptr = data; ptr < ((ruint8 *)data) + size; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES)
    r_cipher_aes_ecb_decrypt_block (cipher, dst, ptr);

  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_cbc_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;
  int i;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  for (ptr = data; ptr < ((ruint8 *)data) + size; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES) {
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
        dst[i] = ptr[i] ^ iv[i];
    r_cipher_aes_ecb_encrypt_block (cipher, dst, dst);
    r_memcpy (iv, dst, R_AES_BLOCK_BYTES);
  }

  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_cbc_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;
  ruint8 scratch[R_AES_BLOCK_BYTES];
  int i;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  for (ptr = data; ptr < ((ruint8 *)data) + size; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES) {
    /* Use scratch memory because decryption can be done inplace */
    r_memcpy (scratch, ptr, R_AES_BLOCK_BYTES);
    r_cipher_aes_ecb_decrypt_block (cipher, dst, ptr);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
        dst[i] ^= iv[i];
    r_memcpy (iv, scratch, R_AES_BLOCK_BYTES);
  }

  r_memclear_secure (scratch, sizeof (scratch));
  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_ctr_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;
  int i;
  rsize bsize = size;
  ruint8 scratch[R_AES_BLOCK_BYTES];

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  for (ptr = data; ptr < ((ruint8 *)data) + bsize; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES) {
    r_cipher_aes_ecb_encrypt_block (cipher, scratch, iv);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dst[i] = scratch[i] ^ ptr[i];
    for (i = R_AES_BLOCK_BYTES; i > 0; i--) {
      if (++iv[i - 1] != 0)
        break;
    }
  }

  if (size > 0) {
    r_cipher_aes_ecb_encrypt_block (cipher, scratch, iv);
    for (i = 0; i < (int)size; i++)
      dst[i] = scratch[i] ^ ptr[i];
    for (i = R_AES_BLOCK_BYTES; i > 0; i--) {
      if (++iv[i - 1] != 0)
        break;
    }
  }

  r_memclear_secure (scratch, sizeof (scratch));
  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_cfb_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;
  int i;
  rsize bsize = size;
  ruint8 scratch[R_AES_BLOCK_BYTES];

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  for (ptr = data; ptr < ((ruint8 *)data) + bsize; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES) {
    r_cipher_aes_ecb_encrypt_block (cipher, scratch, iv);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dst[i] = scratch[i] ^ ptr[i];
    /* CFB feedback: encrypt() input for the next block is the just-produced
     * ciphertext, not the plaintext. */
    r_memcpy (iv, dst, R_AES_BLOCK_BYTES);
  }

  if (size > 0) {
    r_cipher_aes_ecb_encrypt_block (cipher, scratch, iv);
    for (i = 0; i < (int)size; i++)
      dst[i] = scratch[i] ^ ptr[i];
  }

  r_memclear_secure (scratch, sizeof (scratch));
  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_cfb_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;
  int i;
  rsize bsize = size;
  ruint8 scratch[R_AES_BLOCK_BYTES];
  ruint8 ctsave[R_AES_BLOCK_BYTES];

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  for (ptr = data; ptr < ((ruint8 *)data) + bsize; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES) {
    /* Save the consumed ciphertext before XOR in case dst == ptr (in-place). */
    r_memcpy (ctsave, ptr, R_AES_BLOCK_BYTES);
    r_cipher_aes_ecb_encrypt_block (cipher, scratch, iv);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dst[i] = scratch[i] ^ ptr[i];
    /* CFB-decrypt feedback uses the consumed ciphertext. */
    r_memcpy (iv, ctsave, R_AES_BLOCK_BYTES);
  }

  if (size > 0) {
    r_cipher_aes_ecb_encrypt_block (cipher, scratch, iv);
    for (i = 0; i < (int)size; i++)
      dst[i] = scratch[i] ^ ptr[i];
  }

  r_memclear_secure (scratch, sizeof (scratch));
  r_memclear_secure (ctsave, sizeof (ctsave));
  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_ofb_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const ruint8 * ptr;
  int i;
  rsize bsize = size;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  for (ptr = data; ptr < ((ruint8 *)data) + bsize; ptr += R_AES_BLOCK_BYTES, dst += R_AES_BLOCK_BYTES) {
    /* OFB keystream: y_i = AES-encrypt(y_{i-1}), starting from IV.
     * Encrypt in-place into iv so it carries forward. */
    r_cipher_aes_ecb_encrypt_block (cipher, iv, iv);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dst[i] = iv[i] ^ ptr[i];
  }

  if (size > 0) {
    r_cipher_aes_ecb_encrypt_block (cipher, iv, iv);
    for (i = 0; i < (int)size; i++)
      dst[i] = iv[i] ^ ptr[i];
  }

  return R_CRYPTO_CIPHER_OK;
}

