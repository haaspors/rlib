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

#ifdef HAVE_WMMINTRIN_H
# include <wmmintrin.h>           /* AES-NI */
#endif

#ifdef HAVE_ARM_NEON_H
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

#define R_AES_PARALLEL_BLOCKS  4
#define R_AES_PARALLEL_BYTES   (R_AES_PARALLEL_BLOCKS * R_AES_BLOCK_BYTES)

typedef struct _RAesCipher RAesCipher;
typedef rboolean (*RAesBlockFn) (const RAesCipher * aes,
    ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES]);
typedef void (*RAesBlocksFn) (const RAesCipher * aes,
    ruint8 * dst, const ruint8 * src);

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

  /* 4-way parallel kernels used by the parallelizable mode loops
   * (ECB, CTR, CBC-decrypt, CFB-decrypt). NULL on the SW path -
   * mode loops fall back to encrypt_block / decrypt_block in
   * that case. */
  RAesBlocksFn encrypt_blocks_x4;
  RAesBlocksFn decrypt_blocks_x4;
};

#define R_AES_BLOCK_FN_DECL(name)                                              \
  static rboolean name (const RAesCipher * aes,                                \
      ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES])
#define R_AES_BLOCKS_FN_DECL(name)                                             \
  static void name (const RAesCipher * aes,                                    \
      ruint8 * dst, const ruint8 * src)

R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_sw);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_sw);

#ifdef HAVE_WMMINTRIN_H
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_encrypt_block_aesni_128);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_encrypt_block_aesni_192);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_encrypt_block_aesni_256);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_decrypt_block_aesni_128);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_decrypt_block_aesni_192);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_decrypt_block_aesni_256);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks_aesni_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks_aesni_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks_aesni_256);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks_aesni_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks_aesni_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks_aesni_256);
#endif

#ifdef HAVE_ARM_NEON_H
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_encrypt_block_armv8_128);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_encrypt_block_armv8_192);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_encrypt_block_armv8_256);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_decrypt_block_armv8_128);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_decrypt_block_armv8_192);
R_AES_BLOCK_FN_DECL  (r_cipher_aes_ecb_decrypt_block_armv8_256);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks_armv8_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks_armv8_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks_armv8_256);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks_armv8_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks_armv8_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks_armv8_256);
#endif

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ecb =  { "AES-128-ECB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_ECB, 128, 16, 16,
  r_cipher_aes_ecb_encrypt, r_cipher_aes_ecb_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ecb = { "AES-192-ECB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_ECB, 192, 16, 16,
  r_cipher_aes_ecb_encrypt, r_cipher_aes_ecb_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ecb = { "AES-256-ECB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_ECB, 256, 16, 16,
  r_cipher_aes_ecb_encrypt, r_cipher_aes_ecb_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_128_cbc = { "AES-128-CBC",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CBC, 128, 16, 16,
  r_cipher_aes_cbc_encrypt, r_cipher_aes_cbc_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_cbc = { "AES-192-CBC",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CBC, 192, 16, 16,
  r_cipher_aes_cbc_encrypt, r_cipher_aes_cbc_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_cbc = { "AES-256-CBC",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CBC, 256, 16, 16,
  r_cipher_aes_cbc_encrypt, r_cipher_aes_cbc_decrypt,
  NULL, NULL
};

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ctr = { "AES-128-CTR",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CTR, 128, 16, 16,
  r_cipher_aes_ctr_encrypt, r_cipher_aes_ctr_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ctr = { "AES-192-CTR",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CTR, 192, 16, 16,
  r_cipher_aes_ctr_encrypt, r_cipher_aes_ctr_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ctr = { "AES-256-CTR",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CTR, 256, 16, 16,
  r_cipher_aes_ctr_encrypt, r_cipher_aes_ctr_decrypt,
  NULL, NULL
};

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_cfb = { "AES-128-CFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CFB, 128, 16, 16,
  r_cipher_aes_cfb_encrypt, r_cipher_aes_cfb_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_cfb = { "AES-192-CFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CFB, 192, 16, 16,
  r_cipher_aes_cfb_encrypt, r_cipher_aes_cfb_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_cfb = { "AES-256-CFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CFB, 256, 16, 16,
  r_cipher_aes_cfb_encrypt, r_cipher_aes_cfb_decrypt,
  NULL, NULL
};

const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ofb = { "AES-128-OFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_OFB, 128, 16, 16,
  r_cipher_aes_ofb_encrypt, r_cipher_aes_ofb_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ofb = { "AES-192-OFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_OFB, 192, 16, 16,
  r_cipher_aes_ofb_encrypt, r_cipher_aes_ofb_decrypt,
  NULL, NULL
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_128_gcm = { "AES-128-GCM",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_GCM, 128, 12, 16,
  NULL, NULL,
  r_cipher_aes_gcm_encrypt, r_cipher_aes_gcm_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_gcm = { "AES-192-GCM",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_GCM, 192, 12, 16,
  NULL, NULL,
  r_cipher_aes_gcm_encrypt, r_cipher_aes_gcm_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_gcm = { "AES-256-GCM",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_GCM, 256, 12, 16,
  NULL, NULL,
  r_cipher_aes_gcm_encrypt, r_cipher_aes_gcm_decrypt
};

/* CCM advertises ivsize == 0 because the nonce length is caller-
 * chosen per call within 7..13; the AEAD ops validate it themselves. */
const RCryptoCipherInfo g__r_crypto_cipher_aes_128_ccm = { "AES-128-CCM",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CCM, 128, 0, 16,
  NULL, NULL,
  r_cipher_aes_ccm_encrypt, r_cipher_aes_ccm_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_192_ccm = { "AES-192-CCM",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CCM, 192, 0, 16,
  NULL, NULL,
  r_cipher_aes_ccm_encrypt, r_cipher_aes_ccm_decrypt
};
const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ccm = { "AES-256-CCM",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_CCM, 256, 0, 16,
  NULL, NULL,
  r_cipher_aes_ccm_encrypt, r_cipher_aes_ccm_decrypt
};

const RCryptoCipherInfo g__r_crypto_cipher_aes_256_ofb = { "AES-256-OFB",
  R_CRYPTO_CIPHER_ALGO_AES, R_CRYPTO_CIPHER_MODE_OFB, 256, 16, 16,
  r_cipher_aes_ofb_encrypt, r_cipher_aes_ofb_decrypt,
  NULL, NULL
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

#ifdef HAVE_WMMINTRIN_H
    if (r_cpu_has (R_CPU_FEATURE_AES_NI)) {
      switch (ret->rounds) {
        case 10:
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_aesni_128;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_aesni_128;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_aesni_128;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_aesni_128;
          break;
        case 12:
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_aesni_192;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_aesni_192;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_aesni_192;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_aesni_192;
          break;
        default: /* 14 = AES-256 */
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_aesni_256;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_aesni_256;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_aesni_256;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_aesni_256;
          break;
      }
    } else
#elif defined(HAVE_ARM_NEON_H)
    if (r_cpu_has (R_CPU_FEATURE_ARM_AES)) {
      switch (ret->rounds) {
        case 10:
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_armv8_128;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_armv8_128;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_armv8_128;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_armv8_128;
          break;
        case 12:
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_armv8_192;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_armv8_192;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_armv8_192;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_armv8_192;
          break;
        default: /* 14 = AES-256 */
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_armv8_256;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_armv8_256;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_armv8_256;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_armv8_256;
          break;
      }
    } else
#endif
    {
      ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_sw;
      ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_sw;
      ret->encrypt_blocks_x4  = NULL;  /* mode loops fall back to single-block */
      ret->decrypt_blocks_x4  = NULL;
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
r_cipher_aes_128_gcm_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_128_gcm, key);
}

RCryptoCipher *
r_cipher_aes_192_gcm_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_192_gcm, key);
}

RCryptoCipher *
r_cipher_aes_256_gcm_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_256_gcm, key);
}

RCryptoCipher *
r_cipher_aes_128_ccm_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_128_ccm, key);
}

RCryptoCipher *
r_cipher_aes_192_ccm_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_192_ccm, key);
}

RCryptoCipher *
r_cipher_aes_256_ccm_new (const ruint8 * key)
{
  return r_cipher_aes_new_with_info (&g__r_crypto_cipher_aes_256_ccm, key);
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
        case R_CRYPTO_CIPHER_MODE_GCM:
          return r_cipher_aes_128_gcm_new (key);
        case R_CRYPTO_CIPHER_MODE_CCM:
          return r_cipher_aes_128_ccm_new (key);
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
        case R_CRYPTO_CIPHER_MODE_GCM:
          return r_cipher_aes_192_gcm_new (key);
        case R_CRYPTO_CIPHER_MODE_CCM:
          return r_cipher_aes_192_ccm_new (key);
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
        case R_CRYPTO_CIPHER_MODE_GCM:
          return r_cipher_aes_256_gcm_new (key);
        case R_CRYPTO_CIPHER_MODE_CCM:
          return r_cipher_aes_256_ccm_new (key);
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

#ifdef HAVE_WMMINTRIN_H
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

/* 4-way parallel kernel: four independent blocks fed through the
 * round-key chain at every step. AESENC has 1-cycle throughput +
 * 4-cycle latency on Zen3 / Skylake+, so the 4-way interleave
 * lets the CPU schedule a new AESENC every cycle instead of
 * waiting for the prior round to retire - lifts ECB-128 above
 * 15 GiB/s vs the ~9 GiB/s single-block ceiling. */
# define R_AES_AESNI_BLOCKS_X4(name, key_arr, op_round, op_last, rounds)     \
  R_AES_X86_TARGET                                                           \
  static void                                                                \
  name (const RAesCipher * aes, ruint8 * dst, const ruint8 * src)            \
  {                                                                          \
    __m128i b0 = _mm_loadu_si128 ((const __m128i *)(src     ));              \
    __m128i b1 = _mm_loadu_si128 ((const __m128i *)(src + 16));              \
    __m128i b2 = _mm_loadu_si128 ((const __m128i *)(src + 32));              \
    __m128i b3 = _mm_loadu_si128 ((const __m128i *)(src + 48));              \
    const __m128i * rk = (const __m128i *)aes->key_arr;                      \
    __m128i k = _mm_loadu_si128 (rk++);                                      \
    ruint8 i;                                                                \
    b0 = _mm_xor_si128 (b0, k); b1 = _mm_xor_si128 (b1, k);                  \
    b2 = _mm_xor_si128 (b2, k); b3 = _mm_xor_si128 (b3, k);                  \
    for (i = 1; i < (rounds); i++, rk++) {                                   \
      k = _mm_loadu_si128 (rk);                                              \
      b0 = op_round (b0, k); b1 = op_round (b1, k);                          \
      b2 = op_round (b2, k); b3 = op_round (b3, k);                          \
    }                                                                        \
    k = _mm_loadu_si128 (rk);                                                \
    b0 = op_last (b0, k); b1 = op_last (b1, k);                              \
    b2 = op_last (b2, k); b3 = op_last (b3, k);                              \
    _mm_storeu_si128 ((__m128i *)(dst     ), b0);                            \
    _mm_storeu_si128 ((__m128i *)(dst + 16), b1);                            \
    _mm_storeu_si128 ((__m128i *)(dst + 32), b2);                            \
    _mm_storeu_si128 ((__m128i *)(dst + 48), b3);                            \
  }

R_AES_AESNI_BLOCKS_X4 (r_cipher_aes_ecb_encrypt_blocks_aesni_128, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 10)
R_AES_AESNI_BLOCKS_X4 (r_cipher_aes_ecb_encrypt_blocks_aesni_192, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 12)
R_AES_AESNI_BLOCKS_X4 (r_cipher_aes_ecb_encrypt_blocks_aesni_256, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 14)
R_AES_AESNI_BLOCKS_X4 (r_cipher_aes_ecb_decrypt_blocks_aesni_128, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 10)
R_AES_AESNI_BLOCKS_X4 (r_cipher_aes_ecb_decrypt_blocks_aesni_192, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 12)
R_AES_AESNI_BLOCKS_X4 (r_cipher_aes_ecb_decrypt_blocks_aesni_256, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 14)
#endif

#ifdef HAVE_ARM_NEON_H
# if defined(__GNUC__) || defined(__clang__)
#  define R_AES_ARM_TARGET __attribute__((target("+crypto")))
# else
#  define R_AES_ARM_TARGET
# endif

/* ARMv8 AESE/AESD do (AddRoundKey then SubBytes/ShiftRows) in a
 * single instruction, paired with AESMC/AESIMC for MixColumns.
 * Both directions consume the same {LE u32} round-key layout the
 * SW path uses - encrypt walks erk forward, decrypt walks the
 * IMC-pre-applied drk forward (same shape as the AES-NI side).
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
    const ruint8 * rk = (const ruint8 *)aes->drk;                            \
    ruint8 i;                                                                \
    for (i = 0; i < (rounds) - 1; i++, rk += 16) {                           \
      block = vaesdq_u8 (block, vld1q_u8 (rk));                              \
      block = vaesimcq_u8 (block);                                           \
    }                                                                        \
    block = vaesdq_u8 (block, vld1q_u8 (rk));                                \
    rk += 16;                                                                \
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

/* 4-way parallel kernels - same rationale as the AES-NI multi-
 * block path: ARMv8 AESE / AESD have 3-cycle latency / 1-cycle
 * throughput on Cortex / Apple Silicon, so interleaving 4
 * independent blocks keeps the pipeline full. */
# define R_AES_ARMV8_BLOCKS_X4_ENCRYPT(name, rounds)                          \
  R_AES_ARM_TARGET                                                            \
  static void                                                                 \
  name (const RAesCipher * aes, ruint8 * dst, const ruint8 * src)             \
  {                                                                           \
    uint8x16_t b0 = vld1q_u8 (src);                                           \
    uint8x16_t b1 = vld1q_u8 (src + 16);                                      \
    uint8x16_t b2 = vld1q_u8 (src + 32);                                      \
    uint8x16_t b3 = vld1q_u8 (src + 48);                                      \
    const ruint8 * rk = (const ruint8 *)aes->erk;                             \
    uint8x16_t k;                                                             \
    ruint8 i;                                                                 \
    for (i = 0; i < (rounds) - 1; i++, rk += 16) {                            \
      k = vld1q_u8 (rk);                                                      \
      b0 = vaeseq_u8 (b0, k); b0 = vaesmcq_u8 (b0);                           \
      b1 = vaeseq_u8 (b1, k); b1 = vaesmcq_u8 (b1);                           \
      b2 = vaeseq_u8 (b2, k); b2 = vaesmcq_u8 (b2);                           \
      b3 = vaeseq_u8 (b3, k); b3 = vaesmcq_u8 (b3);                           \
    }                                                                         \
    k = vld1q_u8 (rk); rk += 16;                                              \
    b0 = vaeseq_u8 (b0, k); b1 = vaeseq_u8 (b1, k);                           \
    b2 = vaeseq_u8 (b2, k); b3 = vaeseq_u8 (b3, k);                           \
    k = vld1q_u8 (rk);                                                        \
    b0 = veorq_u8 (b0, k); b1 = veorq_u8 (b1, k);                             \
    b2 = veorq_u8 (b2, k); b3 = veorq_u8 (b3, k);                             \
    vst1q_u8 (dst     , b0); vst1q_u8 (dst + 16, b1);                         \
    vst1q_u8 (dst + 32, b2); vst1q_u8 (dst + 48, b3);                         \
  }

# define R_AES_ARMV8_BLOCKS_X4_DECRYPT(name, rounds)                          \
  R_AES_ARM_TARGET                                                            \
  static void                                                                 \
  name (const RAesCipher * aes, ruint8 * dst, const ruint8 * src)             \
  {                                                                           \
    uint8x16_t b0 = vld1q_u8 (src);                                           \
    uint8x16_t b1 = vld1q_u8 (src + 16);                                      \
    uint8x16_t b2 = vld1q_u8 (src + 32);                                      \
    uint8x16_t b3 = vld1q_u8 (src + 48);                                      \
    const ruint8 * rk = (const ruint8 *)aes->drk;                             \
    uint8x16_t k;                                                             \
    ruint8 i;                                                                 \
    for (i = 0; i < (rounds) - 1; i++, rk += 16) {                            \
      k = vld1q_u8 (rk);                                                      \
      b0 = vaesdq_u8 (b0, k); b0 = vaesimcq_u8 (b0);                          \
      b1 = vaesdq_u8 (b1, k); b1 = vaesimcq_u8 (b1);                          \
      b2 = vaesdq_u8 (b2, k); b2 = vaesimcq_u8 (b2);                          \
      b3 = vaesdq_u8 (b3, k); b3 = vaesimcq_u8 (b3);                          \
    }                                                                         \
    k = vld1q_u8 (rk); rk += 16;                                              \
    b0 = vaesdq_u8 (b0, k); b1 = vaesdq_u8 (b1, k);                           \
    b2 = vaesdq_u8 (b2, k); b3 = vaesdq_u8 (b3, k);                           \
    k = vld1q_u8 (rk);                                                        \
    b0 = veorq_u8 (b0, k); b1 = veorq_u8 (b1, k);                             \
    b2 = veorq_u8 (b2, k); b3 = veorq_u8 (b3, k);                             \
    vst1q_u8 (dst     , b0); vst1q_u8 (dst + 16, b1);                         \
    vst1q_u8 (dst + 32, b2); vst1q_u8 (dst + 48, b3);                         \
  }

R_AES_ARMV8_BLOCKS_X4_ENCRYPT (r_cipher_aes_ecb_encrypt_blocks_armv8_128, 10)
R_AES_ARMV8_BLOCKS_X4_ENCRYPT (r_cipher_aes_ecb_encrypt_blocks_armv8_192, 12)
R_AES_ARMV8_BLOCKS_X4_ENCRYPT (r_cipher_aes_ecb_encrypt_blocks_armv8_256, 14)
R_AES_ARMV8_BLOCKS_X4_DECRYPT (r_cipher_aes_ecb_decrypt_blocks_armv8_128, 10)
R_AES_ARMV8_BLOCKS_X4_DECRYPT (r_cipher_aes_ecb_decrypt_blocks_armv8_192, 12)
R_AES_ARMV8_BLOCKS_X4_DECRYPT (r_cipher_aes_ecb_decrypt_blocks_armv8_256, 14)

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
  const RAesCipher * aes;
  const ruint8 * ptr;
  const ruint8 * end;

  (void) iv;
  (void) ivsize;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + size;
  if (aes->encrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      aes->encrypt_blocks_x4 (aes, dst, ptr);
      ptr += R_AES_PARALLEL_BYTES;
      dst += R_AES_PARALLEL_BYTES;
    }
  }
  while (ptr < end) {
    aes->encrypt_block (aes, dst, ptr);
    ptr += R_AES_BLOCK_BYTES;
    dst += R_AES_BLOCK_BYTES;
  }

  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_ecb_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const RAesCipher * aes;
  const ruint8 * ptr;
  const ruint8 * end;

  (void) iv;
  (void) ivsize;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + size;
  if (aes->decrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      aes->decrypt_blocks_x4 (aes, dst, ptr);
      ptr += R_AES_PARALLEL_BYTES;
      dst += R_AES_PARALLEL_BYTES;
    }
  }
  while (ptr < end) {
    aes->decrypt_block (aes, dst, ptr);
    ptr += R_AES_BLOCK_BYTES;
    dst += R_AES_BLOCK_BYTES;
  }

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
  const RAesCipher * aes;
  const ruint8 * ptr;
  const ruint8 * end;
  ruint8 scratch[R_AES_PARALLEL_BYTES];
  int i;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + size;

  /* 4-way path: snapshot the 4-block ciphertext window (decryption
   * can be in-place so the original ct must be saved before the
   * dst write), decrypt all 4 in parallel, then XOR each plaintext
   * with its chain predecessor (iv for the first, ct[i-1] for the
   * rest). iv is updated to the last ciphertext of the window. */
  if (aes->decrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      r_memcpy (scratch, ptr, R_AES_PARALLEL_BYTES);
      aes->decrypt_blocks_x4 (aes, dst, ptr);
      for (i = 0; i < R_AES_BLOCK_BYTES; i++) dst[i               ] ^= iv[i];
      for (i = 0; i < R_AES_BLOCK_BYTES; i++) dst[i + R_AES_BLOCK_BYTES    ] ^= scratch[i                          ];
      for (i = 0; i < R_AES_BLOCK_BYTES; i++) dst[i + R_AES_BLOCK_BYTES * 2] ^= scratch[i + R_AES_BLOCK_BYTES      ];
      for (i = 0; i < R_AES_BLOCK_BYTES; i++) dst[i + R_AES_BLOCK_BYTES * 3] ^= scratch[i + R_AES_BLOCK_BYTES * 2  ];
      r_memcpy (iv, scratch + R_AES_BLOCK_BYTES * 3, R_AES_BLOCK_BYTES);
      ptr += R_AES_PARALLEL_BYTES;
      dst += R_AES_PARALLEL_BYTES;
    }
  }

  while (ptr < end) {
    r_memcpy (scratch, ptr, R_AES_BLOCK_BYTES);
    aes->decrypt_block (aes, dst, ptr);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
        dst[i] ^= iv[i];
    r_memcpy (iv, scratch, R_AES_BLOCK_BYTES);
    ptr += R_AES_BLOCK_BYTES;
    dst += R_AES_BLOCK_BYTES;
  }

  r_memclear_secure (scratch, sizeof (scratch));
  return R_CRYPTO_CIPHER_OK;
}

/* Big-endian counter add-by-n on a 16-byte AES counter block.
 * n is small (1..R_AES_PARALLEL_BLOCKS) in our callers, so the
 * carry stops within a few bytes; the early-exit on no-carry
 * keeps the cost equivalent to the existing byte-by-byte ++iv. */
static void
r_aes_ctr_add (ruint8 iv[R_AES_BLOCK_BYTES], ruint32 n)
{
  int i;
  ruint32 carry = n;
  for (i = R_AES_BLOCK_BYTES; i > 0 && carry != 0; i--) {
    ruint32 sum = (ruint32) iv[i - 1] + (carry & 0xff);
    iv[i - 1] = (ruint8) sum;
    carry = (carry >> 8) + (sum >> 8);
  }
}

RCryptoCipherResult
r_cipher_aes_ctr_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const RAesCipher * aes;
  const ruint8 * ptr;
  const ruint8 * end;
  int i;
  rsize bsize = size;
  ruint8 scratch[R_AES_PARALLEL_BYTES];

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + bsize;

  /* 4-way path: build 4 consecutive counter blocks (iv, iv+1,
   * iv+2, iv+3) in scratch, encrypt all 4 in parallel, XOR with
   * the plaintext window, and advance iv by 4. */
  if (aes->encrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 0, iv, R_AES_BLOCK_BYTES);
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 1, iv, R_AES_BLOCK_BYTES);
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 2, iv, R_AES_BLOCK_BYTES);
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 3, iv, R_AES_BLOCK_BYTES);
      r_aes_ctr_add (scratch + R_AES_BLOCK_BYTES * 1, 1);
      r_aes_ctr_add (scratch + R_AES_BLOCK_BYTES * 2, 2);
      r_aes_ctr_add (scratch + R_AES_BLOCK_BYTES * 3, 3);
      aes->encrypt_blocks_x4 (aes, scratch, scratch);
      for (i = 0; i < R_AES_PARALLEL_BYTES; i++)
        dst[i] = scratch[i] ^ ptr[i];
      r_aes_ctr_add (iv, R_AES_PARALLEL_BLOCKS);
      ptr += R_AES_PARALLEL_BYTES;
      dst += R_AES_PARALLEL_BYTES;
    }
  }

  while (ptr < end) {
    aes->encrypt_block (aes, scratch, iv);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dst[i] = scratch[i] ^ ptr[i];
    r_aes_ctr_add (iv, 1);
    ptr += R_AES_BLOCK_BYTES;
    dst += R_AES_BLOCK_BYTES;
  }

  if (size > 0) {
    aes->encrypt_block (aes, scratch, iv);
    for (i = 0; i < (int)size; i++)
      dst[i] = scratch[i] ^ ptr[i];
    r_aes_ctr_add (iv, 1);
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
  const RAesCipher * aes;
  const ruint8 * ptr;
  const ruint8 * end;
  int i;
  rsize bsize = size;
  ruint8 scratch[R_AES_PARALLEL_BYTES];
  ruint8 ctsave[R_AES_PARALLEL_BYTES];

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + bsize;

  /* 4-way path: encrypt the 4 chain inputs (iv, ct[0], ct[1], ct[2])
   * in parallel into a keystream, then XOR with the ciphertext window.
   * iv is updated to ct[3] for the next iteration. */
  if (aes->encrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      r_memcpy (ctsave, ptr, R_AES_PARALLEL_BYTES);
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 0, iv, R_AES_BLOCK_BYTES);
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 1, ctsave + R_AES_BLOCK_BYTES * 0, R_AES_BLOCK_BYTES);
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 2, ctsave + R_AES_BLOCK_BYTES * 1, R_AES_BLOCK_BYTES);
      r_memcpy (scratch + R_AES_BLOCK_BYTES * 3, ctsave + R_AES_BLOCK_BYTES * 2, R_AES_BLOCK_BYTES);
      aes->encrypt_blocks_x4 (aes, scratch, scratch);
      for (i = 0; i < R_AES_PARALLEL_BYTES; i++)
        dst[i] = scratch[i] ^ ctsave[i];
      r_memcpy (iv, ctsave + R_AES_BLOCK_BYTES * 3, R_AES_BLOCK_BYTES);
      ptr += R_AES_PARALLEL_BYTES;
      dst += R_AES_PARALLEL_BYTES;
    }
  }

  while (ptr < end) {
    r_memcpy (ctsave, ptr, R_AES_BLOCK_BYTES);
    aes->encrypt_block (aes, scratch, iv);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dst[i] = scratch[i] ^ ptr[i];
    r_memcpy (iv, ctsave, R_AES_BLOCK_BYTES);
    ptr += R_AES_BLOCK_BYTES;
    dst += R_AES_BLOCK_BYTES;
  }

  if (size > 0) {
    aes->encrypt_block (aes, scratch, iv);
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

/******************************************************************************/
/*  AES-GCM (RFC 5288 / NIST SP 800-38D)                                      */
/******************************************************************************/

/* Multiply y by h in GF(2^128) with reducing polynomial
 * x^128 + x^7 + x^2 + x + 1, bit-reversed representation per NIST
 * SP 800-38D Section 6.3: byte[0] MSB carries the constant term x^0
 * and byte[15] LSB carries x^127. y is updated in place.
 *
 * Shift-and-XOR implementation: O(128) iterations per multiply,
 * not constant-time, slower than the 4-bit-table approach used in
 * production GHASH. Adequate for correctness and a baseline tests
 * can pin against; a faster implementation can land later without
 * changing this primitive's contract. */
static void
r_ghash_mul (ruint8 y[R_AES_BLOCK_BYTES], const ruint8 h[R_AES_BLOCK_BYTES])
{
  ruint8 z[R_AES_BLOCK_BYTES] = { 0 };
  ruint8 v[R_AES_BLOCK_BYTES];
  rsize i, j, k;

  r_memcpy (v, h, R_AES_BLOCK_BYTES);

  for (i = 0; i < R_AES_BLOCK_BYTES; i++) {
    for (j = 0; j < 8; j++) {
      if (y[i] & (0x80 >> j)) {
        for (k = 0; k < R_AES_BLOCK_BYTES; k++)
          z[k] ^= v[k];
      }
      /* v = v * x mod poly: right-shift, conditionally XOR 0xe1 into
       * v[0] (the bit-reversed reducing polynomial). */
      {
        ruint8 lsb = v[R_AES_BLOCK_BYTES - 1] & 1;
        for (k = R_AES_BLOCK_BYTES - 1; k > 0; k--)
          v[k] = (v[k] >> 1) | ((v[k - 1] & 1) << 7);
        v[0] >>= 1;
        if (lsb)
          v[0] ^= 0xe1;
      }
    }
  }

  r_memcpy (y, z, R_AES_BLOCK_BYTES);
}

/* GCM-specific counter increment: only the low 32 bits advance; the
 * high 96 bits stay fixed at the IV value. */
static void
r_gcm_ctr_inc32 (ruint8 ctr[R_AES_BLOCK_BYTES])
{
  ruint32 c = ((ruint32) ctr[12] << 24) | ((ruint32) ctr[13] << 16)
            | ((ruint32) ctr[14] <<  8) |  (ruint32) ctr[15];
  c++;
  ctr[12] = (c >> 24) & 0xff;
  ctr[13] = (c >> 16) & 0xff;
  ctr[14] = (c >>  8) & 0xff;
  ctr[15] =  c        & 0xff;
}

/* Fold @p data into the running GHASH state @p y, one 16-byte block
 * at a time. The trailing partial block (if any) is zero-padded out
 * to a full block before mixing. */
static void
r_gcm_ghash_update (ruint8 y[R_AES_BLOCK_BYTES],
    const ruint8 h[R_AES_BLOCK_BYTES],
    const ruint8 * data, rsize size)
{
  rsize k;

  while (size >= R_AES_BLOCK_BYTES) {
    for (k = 0; k < R_AES_BLOCK_BYTES; k++)
      y[k] ^= data[k];
    r_ghash_mul (y, h);
    data += R_AES_BLOCK_BYTES;
    size -= R_AES_BLOCK_BYTES;
  }
  if (size > 0) {
    ruint8 block[R_AES_BLOCK_BYTES] = { 0 };
    r_memcpy (block, data, size);
    for (k = 0; k < R_AES_BLOCK_BYTES; k++)
      y[k] ^= block[k];
    r_ghash_mul (y, h);
  }
}

/* Encode a 64-bit big-endian length-in-bits value into @p out. */
static void
r_gcm_be64 (ruint8 out[8], ruint64 v)
{
  rsize i;
  for (i = 0; i < 8; i++)
    out[i] = (ruint8) (v >> (56 - i * 8));
}

/* GHASH(H, AAD || pad || C || pad || [len(AAD)]_64 || [len(C)]_64),
 * then XOR with E_K(J0) to form the GCM tag. */
static void
r_gcm_compute_tag (const RAesCipher * aes,
    const ruint8 h[R_AES_BLOCK_BYTES],
    const ruint8 j0[R_AES_BLOCK_BYTES],
    rconstpointer aad, rsize aadsize,
    const ruint8 * ciphertxt, rsize ctsize,
    ruint8 tag[R_AES_BLOCK_BYTES])
{
  ruint8 y[R_AES_BLOCK_BYTES] = { 0 };
  ruint8 lenblock[R_AES_BLOCK_BYTES];
  ruint8 ek[R_AES_BLOCK_BYTES];
  rsize i;

  r_gcm_ghash_update (y, h, aad, aadsize);
  r_gcm_ghash_update (y, h, ciphertxt, ctsize);

  r_gcm_be64 (lenblock,     (ruint64) aadsize * 8);
  r_gcm_be64 (lenblock + 8, (ruint64) ctsize * 8);
  for (i = 0; i < R_AES_BLOCK_BYTES; i++)
    y[i] ^= lenblock[i];
  r_ghash_mul (y, h);

  aes->encrypt_block (aes, ek, j0);
  for (i = 0; i < R_AES_BLOCK_BYTES; i++)
    tag[i] = ek[i] ^ y[i];
}

/* Shared encrypt/decrypt body. @p generate_tag controls whether the
 * computed tag is written to @p tag (encrypt) or compared in constant
 * time against the supplied @p tag (decrypt). */
static RCryptoCipherResult
r_aes_gcm_op (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    const ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize,
    rboolean generate_tag)
{
  const RAesCipher * aes;
  ruint8 zero[R_AES_BLOCK_BYTES] = { 0 };
  ruint8 h[R_AES_BLOCK_BYTES];
  ruint8 j0[R_AES_BLOCK_BYTES];
  ruint8 ctr[R_AES_BLOCK_BYTES];
  ruint8 ksblock[R_AES_BLOCK_BYTES];
  ruint8 tagcomputed[R_AES_BLOCK_BYTES];
  const ruint8 * srcp;
  ruint8 * dstp;
  rsize remaining, i;

  if (R_UNLIKELY (cipher == NULL || iv == NULL || tag == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (size > 0 && (data == NULL || dst == NULL)))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (aadsize > 0 && aad == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  /* Only the recommended 96-bit IV is supported; longer / shorter IVs
   * need the alternate J0 construction (GHASH over IV). */
  if (R_UNLIKELY (ivsize != 12))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (tagsize == 0 || tagsize > R_AES_BLOCK_BYTES))
    return R_CRYPTO_CIPHER_INVAL;

  aes = (const RAesCipher *) cipher;

  /* H = E_K(0^128); J0 = IV || 0x00000001. */
  aes->encrypt_block (aes, h, zero);
  r_memcpy (j0, iv, 12);
  j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

  /* For decrypt, verify the tag against the ciphertext BEFORE
   * touching @p dst. This way an auth failure leaves any previous
   * @p dst contents intact; the caller never sees released plaintext
   * from a forged input. */
  if (!generate_tag) {
    r_gcm_compute_tag (aes, h, j0, aad, aadsize, data, size, tagcomputed);
    {
      ruint8 diff = 0;
      for (i = 0; i < tagsize; i++)
        diff |= tagcomputed[i] ^ tag[i];
      if (diff != 0) {
        r_memclear_secure (h, sizeof (h));
        r_memclear_secure (tagcomputed, sizeof (tagcomputed));
        return R_CRYPTO_CIPHER_AUTH_FAILED;
      }
    }
  }

  /* CTR-mode encrypt / decrypt starting at inc_32(J0). */
  r_memcpy (ctr, j0, R_AES_BLOCK_BYTES);
  r_gcm_ctr_inc32 (ctr);
  srcp = data;
  dstp = dst;
  remaining = size;
  while (remaining >= R_AES_BLOCK_BYTES) {
    aes->encrypt_block (aes, ksblock, ctr);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dstp[i] = ksblock[i] ^ srcp[i];
    r_gcm_ctr_inc32 (ctr);
    srcp += R_AES_BLOCK_BYTES;
    dstp += R_AES_BLOCK_BYTES;
    remaining -= R_AES_BLOCK_BYTES;
  }
  if (remaining > 0) {
    aes->encrypt_block (aes, ksblock, ctr);
    for (i = 0; i < remaining; i++)
      dstp[i] = ksblock[i] ^ srcp[i];
  }

  if (generate_tag) {
    r_gcm_compute_tag (aes, h, j0, aad, aadsize, dst, size, tagcomputed);
    r_memcpy (tag, tagcomputed, tagsize);
  }

  r_memclear_secure (h, sizeof (h));
  r_memclear_secure (ctr, sizeof (ctr));
  r_memclear_secure (ksblock, sizeof (ksblock));
  r_memclear_secure (tagcomputed, sizeof (tagcomputed));
  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_gcm_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize)
{
  return r_aes_gcm_op (cipher, dst, size, data, aad, aadsize,
      iv, ivsize, tag, tagsize, TRUE);
}

RCryptoCipherResult
r_cipher_aes_gcm_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize)
{
  return r_aes_gcm_op (cipher, dst, size, data, aad, aadsize,
      iv, ivsize, tag, tagsize, FALSE);
}

/******************************************************************************/
/*  AES-CCM (RFC 3610 / NIST SP 800-38C)                                      */
/******************************************************************************/

/* CBC-MAC: x = E_K(x XOR block). */
static inline void
r_ccm_mac_block (const RAesCipher * aes, ruint8 x[R_AES_BLOCK_BYTES],
    const ruint8 block[R_AES_BLOCK_BYTES])
{
  rsize i;
  for (i = 0; i < R_AES_BLOCK_BYTES; i++)
    x[i] ^= block[i];
  aes->encrypt_block (aes, x, x);
}

/* Feed @p size bytes through CBC-MAC, zero-padding the trailing
 * partial block (per RFC 3610 / SP 800-38C). */
static void
r_ccm_mac_feed (const RAesCipher * aes, ruint8 x[R_AES_BLOCK_BYTES],
    const ruint8 * data, rsize size)
{
  ruint8 block[R_AES_BLOCK_BYTES];
  while (size >= R_AES_BLOCK_BYTES) {
    r_ccm_mac_block (aes, x, data);
    data += R_AES_BLOCK_BYTES;
    size -= R_AES_BLOCK_BYTES;
  }
  if (size > 0) {
    r_memset (block, 0, R_AES_BLOCK_BYTES);
    r_memcpy (block, data, size);
    r_ccm_mac_block (aes, x, block);
  }
}

/* CCM counter increment: only the trailing L bytes carry the
 * counter; the leading flags + nonce stay fixed. */
static void
r_ccm_ctr_inc (ruint8 ctr[R_AES_BLOCK_BYTES], rsize L)
{
  rsize i;
  for (i = 0; i < L; i++) {
    if (++ctr[R_AES_BLOCK_BYTES - 1 - i] != 0)
      break;
  }
}

/* Build B0: flags || N || [size]_L. */
static void
r_ccm_build_b0 (ruint8 b0[R_AES_BLOCK_BYTES],
    const ruint8 * nonce, rsize nonce_len, rsize L,
    rboolean has_aad, rsize tag_len, rsize size)
{
  rsize i;
  b0[0] = (has_aad ? 0x40 : 0)
        | (ruint8) (((tag_len - 2) / 2) << 3)
        | (ruint8) (L - 1);
  r_memcpy (&b0[1], nonce, nonce_len);
  for (i = 0; i < L; i++) {
    rsize shift = 8 * (L - 1 - i);
    b0[1 + nonce_len + i] = (shift >= 8 * sizeof (rsize))
        ? 0
        : (ruint8) ((size >> shift) & 0xff);
  }
}

/* Build A0 (CTR starting block): flags = L-1, N, [0]_L. */
static void
r_ccm_build_a0 (ruint8 a0[R_AES_BLOCK_BYTES],
    const ruint8 * nonce, rsize nonce_len, rsize L)
{
  a0[0] = (ruint8) (L - 1);
  r_memcpy (&a0[1], nonce, nonce_len);
  r_memset (&a0[1 + nonce_len], 0, L);
}

/* CTR-encrypt or -decrypt @p src into @p dst using @p ctr, advancing
 * counter per block. The counter's L parameter is fixed by the
 * caller's nonce length. */
static void
r_ccm_ctr_xor (const RAesCipher * aes, ruint8 ctr[R_AES_BLOCK_BYTES], rsize L,
    ruint8 * dst, const ruint8 * src, rsize size)
{
  ruint8 ks[R_AES_BLOCK_BYTES];
  rsize i;
  while (size >= R_AES_BLOCK_BYTES) {
    aes->encrypt_block (aes, ks, ctr);
    for (i = 0; i < R_AES_BLOCK_BYTES; i++)
      dst[i] = ks[i] ^ src[i];
    r_ccm_ctr_inc (ctr, L);
    dst += R_AES_BLOCK_BYTES;
    src += R_AES_BLOCK_BYTES;
    size -= R_AES_BLOCK_BYTES;
  }
  if (size > 0) {
    aes->encrypt_block (aes, ks, ctr);
    for (i = 0; i < size; i++)
      dst[i] = ks[i] ^ src[i];
  }
  r_memclear_secure (ks, sizeof (ks));
}

/* Compute the CCM tag (full 16-byte CBC-MAC result, before truncation
 * and XOR with S_0). Operates on a plaintext buffer so it works for
 * both encrypt (input plaintext) and decrypt (recovered plaintext). */
static void
r_ccm_compute_mac (const RAesCipher * aes,
    const ruint8 * nonce, rsize nonce_len, rsize L,
    rconstpointer aad, rsize aadsize,
    const ruint8 * plain, rsize size, rsize tag_len,
    ruint8 x[R_AES_BLOCK_BYTES])
{
  ruint8 b0[R_AES_BLOCK_BYTES];

  r_ccm_build_b0 (b0, nonce, nonce_len, L, aadsize > 0, tag_len, size);
  aes->encrypt_block (aes, x, b0);

  if (aadsize > 0) {
    ruint8 block[R_AES_BLOCK_BYTES];
    rsize prefix_len, block_off, i;
    const ruint8 * aadp = aad;
    rsize aadrem = aadsize;

    /* Length-prefix the AAD per SP 800-38C A.2. */
    if (aadsize < (rsize) ((1u << 16) - (1u << 8))) {
      block[0] = (ruint8) ((aadsize >> 8) & 0xff);
      block[1] = (ruint8) (aadsize & 0xff);
      prefix_len = 2;
    } else if (sizeof (rsize) <= 4 || aadsize < ((ruint64) 1 << 32)) {
      block[0] = 0xff; block[1] = 0xfe;
      block[2] = (ruint8) ((aadsize >> 24) & 0xff);
      block[3] = (ruint8) ((aadsize >> 16) & 0xff);
      block[4] = (ruint8) ((aadsize >>  8) & 0xff);
      block[5] = (ruint8) (aadsize & 0xff);
      prefix_len = 6;
    } else {
      block[0] = 0xff; block[1] = 0xff;
      for (i = 0; i < 8; i++)
        block[2 + i] = (ruint8) ((((ruint64) aadsize) >> (56 - i * 8)) & 0xff);
      prefix_len = 10;
    }

    /* Fill the rest of the first block with AAD bytes, zero-pad if
     * the AAD is short. */
    block_off = prefix_len;
    while (block_off < R_AES_BLOCK_BYTES && aadrem > 0) {
      block[block_off++] = *aadp++;
      aadrem--;
    }
    while (block_off < R_AES_BLOCK_BYTES)
      block[block_off++] = 0;
    r_ccm_mac_block (aes, x, block);

    r_ccm_mac_feed (aes, x, aadp, aadrem);
  }

  r_ccm_mac_feed (aes, x, plain, size);
}

/* Shared encrypt/decrypt body, branched on @p generate_tag.
 * encrypt: MAC over plaintext, then CTR-encrypt to dst, then tag.
 * decrypt: CTR-decrypt into dst, then MAC over dst, then verify.
 * On auth failure the decrypted bytes remain in @p dst per CCM's
 * decrypt-then-verify shape; caller must discard. */
static RCryptoCipherResult
r_aes_ccm_op (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    const ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize,
    rboolean generate_tag)
{
  const RAesCipher * aes;
  ruint8 a0[R_AES_BLOCK_BYTES];
  ruint8 s0[R_AES_BLOCK_BYTES];
  ruint8 ctr[R_AES_BLOCK_BYTES];
  ruint8 x[R_AES_BLOCK_BYTES];
  rsize L;
  rsize i;

  if (R_UNLIKELY (cipher == NULL || iv == NULL || tag == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (size > 0 && (data == NULL || dst == NULL)))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (aadsize > 0 && aad == NULL))
    return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize < 7 || ivsize > 13))
    return R_CRYPTO_CIPHER_INVAL;
  /* CCM tag lengths: even, in [4, 16]. */
  if (R_UNLIKELY (tagsize < 4 || tagsize > R_AES_BLOCK_BYTES || (tagsize & 1) != 0))
    return R_CRYPTO_CIPHER_INVAL;

  L = 15 - ivsize;
  /* size < 2^(8L) when L < sizeof(rsize). */
  if (L < sizeof (rsize) && size >= ((rsize) 1 << (8 * L)))
    return R_CRYPTO_CIPHER_INVAL;

  aes = (const RAesCipher *) cipher;

  r_ccm_build_a0 (a0, iv, ivsize, L);
  aes->encrypt_block (aes, s0, a0);
  r_memcpy (ctr, a0, R_AES_BLOCK_BYTES);
  r_ccm_ctr_inc (ctr, L);

  if (generate_tag) {
    /* Encrypt: MAC over plaintext, then CTR-encrypt to dst, then
     * truncate-and-mask the tag. */
    r_ccm_compute_mac (aes, iv, ivsize, L, aad, aadsize, data, size, tagsize, x);
    r_ccm_ctr_xor (aes, ctr, L, dst, data, size);
    for (i = 0; i < tagsize; i++)
      tag[i] = x[i] ^ s0[i];
  } else {
    /* Decrypt: CTR into dst (recovers plaintext), MAC over dst,
     * truncate-and-mask, constant-time compare against received tag. */
    ruint8 tagcomputed[R_AES_BLOCK_BYTES];
    ruint8 diff = 0;
    r_ccm_ctr_xor (aes, ctr, L, dst, data, size);
    r_ccm_compute_mac (aes, iv, ivsize, L, aad, aadsize, dst, size, tagsize, x);
    for (i = 0; i < tagsize; i++)
      tagcomputed[i] = x[i] ^ s0[i];
    for (i = 0; i < tagsize; i++)
      diff |= tagcomputed[i] ^ tag[i];
    r_memclear_secure (tagcomputed, sizeof (tagcomputed));
    if (diff != 0) {
      r_memclear_secure (s0, sizeof (s0));
      r_memclear_secure (x, sizeof (x));
      return R_CRYPTO_CIPHER_AUTH_FAILED;
    }
  }

  r_memclear_secure (s0, sizeof (s0));
  r_memclear_secure (ctr, sizeof (ctr));
  r_memclear_secure (x, sizeof (x));
  return R_CRYPTO_CIPHER_OK;
}

RCryptoCipherResult
r_cipher_aes_ccm_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize)
{
  return r_aes_ccm_op (cipher, dst, size, data, aad, aadsize,
      iv, ivsize, tag, tagsize, TRUE);
}

RCryptoCipherResult
r_cipher_aes_ccm_decrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data,
    rconstpointer aad, rsize aadsize,
    ruint8 * iv, rsize ivsize,
    ruint8 * tag, rsize tagsize)
{
  return r_aes_ccm_op (cipher, dst, size, data, aad, aadsize,
      iv, ivsize, tag, tagsize, FALSE);
}

