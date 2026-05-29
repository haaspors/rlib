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
# include <wmmintrin.h>           /* AES-NI + PCLMULQDQ */
#endif
#ifdef HAVE_TMMINTRIN_H
# include <tmmintrin.h>           /* SSSE3 (PSHUFB - PCLMUL GHASH bit-reverse) */
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
#define R_AES_PARALLEL8_BLOCKS 8
#define R_AES_PARALLEL8_BYTES  (R_AES_PARALLEL8_BLOCKS * R_AES_BLOCK_BYTES)

typedef struct RAesCipher RAesCipher;
typedef rboolean (*RAesBlockFn) (const RAesCipher * aes,
    ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES]);
typedef void (*RAesBlocksFn) (const RAesCipher * aes,
    ruint8 * dst, const ruint8 * src);
typedef void (*RAesGhashMulFn) (ruint8 y[R_AES_BLOCK_BYTES],
    const RAesCipher * aes,
    const ruint8 * data, rsize nblocks);

/* 4-bit GHASH table (Shoup's method). Used by the SW kernel; HW
 * kernels (PCLMULQDQ / PMULL) work straight from ghash_h. */
typedef struct {
  ruint8 e[16][R_AES_BLOCK_BYTES];
} RGhashTable;

/* Big-endian counter add-by-n on a 16-byte AES counter block. Treat
 * the low 8 bytes as a 64-bit big-endian counter (the typical
 * working range for any sane CTR / GCM use): byte-swap to host, add,
 * byte-swap back - which the compiler folds to a BSWAP / ADD / BSWAP
 * sequence vs the prior byte-by-byte carry chain. The overflow into
 * the high 8 bytes is handled with a tail byte-by-byte chain but is
 * essentially unreachable in practice: NIST caps CTR / GCM at 2^48
 * blocks per IV, and our low half doesn't wrap until 2^64. */
static inline void
r_aes_ctr_add (ruint8 iv[R_AES_BLOCK_BYTES], ruint32 n)
{
  ruint64 lo = r_load_be64 (iv + 8);
  ruint64 new_lo = lo + n;
  if (R_UNLIKELY (new_lo < lo)) {
    int i;
    for (i = 7; i >= 0; i--) {
      iv[i]++;
      if (iv[i] != 0) break;
    }
  }
  r_store_be64 (iv + 8, new_lo);
}

struct RAesCipher {
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

  /* 4-way and 8-way parallel kernels used by the parallelizable mode
   * loops (ECB, CTR, CBC-decrypt, CFB-decrypt). NULL on the SW path -
   * mode loops fall back to a narrower kernel or single-block. The
   * 8-way kernel is preferred when the remaining run is >= 8 blocks;
   * it amortises load/store and key-schedule pressure better at the
   * cost of a larger register footprint. */
  RAesBlocksFn encrypt_blocks_x4;
  RAesBlocksFn decrypt_blocks_x4;
  RAesBlocksFn encrypt_blocks_x8;
  RAesBlocksFn decrypt_blocks_x8;

  /* GCM precomputed state - populated only when info->mode == GCM.
   * H = E_K(0^128), used by every GHASH multiplication; the 4-bit
   * table is built from H once when the SW kernel is in use. The
   * HW kernels (PCLMULQDQ / PMULL) read H directly. ghash_h_pow[i]
   * holds H^(i+2) in the same representation as ghash_h - H^2..H^8
   * fuel the HW kernels' 4-way / 8-way aggregated paths; unused
   * when the SW kernel is selected. */
  ruint8 ghash_h[R_AES_BLOCK_BYTES];
  ruint8 ghash_h_pow[7][R_AES_BLOCK_BYTES];
  RGhashTable ghash_t;
  RAesGhashMulFn ghash_mul;
};

#define R_AES_BLOCK_FN_DECL(name)                                              \
  static rboolean name (const RAesCipher * aes,                                \
      ruint8 dst[R_AES_BLOCK_BYTES], const ruint8 src[R_AES_BLOCK_BYTES])
#define R_AES_BLOCKS_FN_DECL(name)                                             \
  static void name (const RAesCipher * aes,                                    \
      ruint8 * dst, const ruint8 * src)

R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_encrypt_block_sw);
R_AES_BLOCK_FN_DECL (r_cipher_aes_ecb_decrypt_block_sw);

static void r_ghash_mul (ruint8 y[R_AES_BLOCK_BYTES],
    const ruint8 h[R_AES_BLOCK_BYTES]);
static void r_ghash_init_table (RGhashTable * t,
    const ruint8 h[R_AES_BLOCK_BYTES]);
static void r_ghash_mul_4bit (ruint8 y[R_AES_BLOCK_BYTES],
    const RAesCipher * aes,
    const ruint8 * data, rsize nblocks);
#if defined(HAVE_WMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
static void r_ghash_mul_pclmul (ruint8 y[R_AES_BLOCK_BYTES],
    const RAesCipher * aes,
    const ruint8 * data, rsize nblocks);
#endif
#ifdef HAVE_ARM_NEON_H
static void r_ghash_mul_pmull (ruint8 y[R_AES_BLOCK_BYTES],
    const RAesCipher * aes,
    const ruint8 * data, rsize nblocks);
#endif

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
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks8_aesni_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks8_aesni_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks8_aesni_256);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks8_aesni_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks8_aesni_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks8_aesni_256);
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
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks8_armv8_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks8_armv8_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_encrypt_blocks8_armv8_256);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks8_armv8_128);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks8_armv8_192);
R_AES_BLOCKS_FN_DECL (r_cipher_aes_ecb_decrypt_blocks8_armv8_256);
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
          ret->encrypt_blocks_x8  = r_cipher_aes_ecb_encrypt_blocks8_aesni_128;
          ret->decrypt_blocks_x8  = r_cipher_aes_ecb_decrypt_blocks8_aesni_128;
          break;
        case 12:
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_aesni_192;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_aesni_192;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_aesni_192;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_aesni_192;
          ret->encrypt_blocks_x8  = r_cipher_aes_ecb_encrypt_blocks8_aesni_192;
          ret->decrypt_blocks_x8  = r_cipher_aes_ecb_decrypt_blocks8_aesni_192;
          break;
        default: /* 14 = AES-256 */
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_aesni_256;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_aesni_256;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_aesni_256;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_aesni_256;
          ret->encrypt_blocks_x8  = r_cipher_aes_ecb_encrypt_blocks8_aesni_256;
          ret->decrypt_blocks_x8  = r_cipher_aes_ecb_decrypt_blocks8_aesni_256;
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
          ret->encrypt_blocks_x8  = r_cipher_aes_ecb_encrypt_blocks8_armv8_128;
          ret->decrypt_blocks_x8  = r_cipher_aes_ecb_decrypt_blocks8_armv8_128;
          break;
        case 12:
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_armv8_192;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_armv8_192;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_armv8_192;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_armv8_192;
          ret->encrypt_blocks_x8  = r_cipher_aes_ecb_encrypt_blocks8_armv8_192;
          ret->decrypt_blocks_x8  = r_cipher_aes_ecb_decrypt_blocks8_armv8_192;
          break;
        default: /* 14 = AES-256 */
          ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_armv8_256;
          ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_armv8_256;
          ret->encrypt_blocks_x4  = r_cipher_aes_ecb_encrypt_blocks_armv8_256;
          ret->decrypt_blocks_x4  = r_cipher_aes_ecb_decrypt_blocks_armv8_256;
          ret->encrypt_blocks_x8  = r_cipher_aes_ecb_encrypt_blocks8_armv8_256;
          ret->decrypt_blocks_x8  = r_cipher_aes_ecb_decrypt_blocks8_armv8_256;
          break;
      }
    } else
#endif
    {
      ret->encrypt_block      = r_cipher_aes_ecb_encrypt_block_sw;
      ret->decrypt_block      = r_cipher_aes_ecb_decrypt_block_sw;
      ret->encrypt_blocks_x4  = NULL;  /* mode loops fall back to single-block */
      ret->decrypt_blocks_x4  = NULL;
      ret->encrypt_blocks_x8  = NULL;
      ret->decrypt_blocks_x8  = NULL;
    }
  }

  /* GCM-specific setup: derive H = E_K(0^128) and pick a GHASH kernel.
   * Done once per cipher so the per-op fast path is just a function-
   * pointer dispatch. */
  if (ret != NULL && info->mode == R_CRYPTO_CIPHER_MODE_GCM) {
    ruint8 zero[R_AES_BLOCK_BYTES] = { 0 };
    ret->encrypt_block (ret, ret->ghash_h, zero);
    ret->ghash_mul = NULL;
#if defined(HAVE_WMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
    if (r_cpu_has (R_CPU_FEATURE_PCLMUL))
      ret->ghash_mul = r_ghash_mul_pclmul;
#elif defined(HAVE_ARM_NEON_H)
    if (r_cpu_has (R_CPU_FEATURE_ARM_PMULL))
      ret->ghash_mul = r_ghash_mul_pmull;
#endif
    if (ret->ghash_mul != NULL) {
      /* HW kernels (PCLMULQDQ / PMULL) operate on the natural-LE
       * polynomial representation (bit i = x^i). rlib's NIST-style
       * H has byte-internal MSB = x^0, so per-byte bit-reverse H
       * once here; the kernel only has to bit-reverse y on entry
       * and the result on exit. The 4-way / 8-way aggregated paths
       * also need H^2..H^8 in the same representation - compute
       * them via the SW reference (which expects NIST form) BEFORE
       * the in-place bit-reverse of H. ghash_h_pow[i] = H^(i+2). */
      rsize idx, p;
      r_memcpy (ret->ghash_h_pow[0], ret->ghash_h, R_AES_BLOCK_BYTES);
      r_ghash_mul (ret->ghash_h_pow[0], ret->ghash_h);          /* H^2 */
      for (p = 1; p < 7; p++) {
        r_memcpy (ret->ghash_h_pow[p], ret->ghash_h_pow[p - 1], R_AES_BLOCK_BYTES);
        r_ghash_mul (ret->ghash_h_pow[p], ret->ghash_h);        /* H^(p+2) */
      }
      for (p = 0; p < 7; p++) {
        for (idx = 0; idx < R_AES_BLOCK_BYTES; idx++) {
          ruint8 b = ret->ghash_h_pow[p][idx];
          b = (ruint8) (((b & 0xf0) >> 4) | ((b & 0x0f) << 4));
          b = (ruint8) (((b & 0xcc) >> 2) | ((b & 0x33) << 2));
          b = (ruint8) (((b & 0xaa) >> 1) | ((b & 0x55) << 1));
          ret->ghash_h_pow[p][idx] = b;
        }
      }
      for (idx = 0; idx < R_AES_BLOCK_BYTES; idx++) {
        ruint8 b = ret->ghash_h[idx];
        b = (ruint8) (((b & 0xf0) >> 4) | ((b & 0x0f) << 4));
        b = (ruint8) (((b & 0xcc) >> 2) | ((b & 0x33) << 2));
        b = (ruint8) (((b & 0xaa) >> 1) | ((b & 0x55) << 1));
        ret->ghash_h[idx] = b;
      }
    } else {
      ret->ghash_mul = r_ghash_mul_4bit;
      r_ghash_init_table (&ret->ghash_t, ret->ghash_h);
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

/* 8-way variant: doubles the block count to better hide the AES
 * round chain on cores where AESENC is dual-issue (Zen+ has 0.5-
 * cycle throughput, so 4-way already saturates - but the wider
 * window gives the compiler more scheduling room and amortises the
 * load/store and key-broadcast pressure across more bytes per
 * loop iteration. On older Intel (Westmere-Haswell, single-issue
 * AESENC) it's a more direct ~2x. */
# define R_AES_AESNI_BLOCKS_X8(name, key_arr, op_round, op_last, rounds)     \
  R_AES_X86_TARGET                                                           \
  static void                                                                \
  name (const RAesCipher * aes, ruint8 * dst, const ruint8 * src)            \
  {                                                                          \
    __m128i b0 = _mm_loadu_si128 ((const __m128i *)(src      ));             \
    __m128i b1 = _mm_loadu_si128 ((const __m128i *)(src +  16));             \
    __m128i b2 = _mm_loadu_si128 ((const __m128i *)(src +  32));             \
    __m128i b3 = _mm_loadu_si128 ((const __m128i *)(src +  48));             \
    __m128i b4 = _mm_loadu_si128 ((const __m128i *)(src +  64));             \
    __m128i b5 = _mm_loadu_si128 ((const __m128i *)(src +  80));             \
    __m128i b6 = _mm_loadu_si128 ((const __m128i *)(src +  96));             \
    __m128i b7 = _mm_loadu_si128 ((const __m128i *)(src + 112));             \
    const __m128i * rk = (const __m128i *)aes->key_arr;                      \
    __m128i k = _mm_loadu_si128 (rk++);                                      \
    ruint8 i;                                                                \
    b0 = _mm_xor_si128 (b0, k); b1 = _mm_xor_si128 (b1, k);                  \
    b2 = _mm_xor_si128 (b2, k); b3 = _mm_xor_si128 (b3, k);                  \
    b4 = _mm_xor_si128 (b4, k); b5 = _mm_xor_si128 (b5, k);                  \
    b6 = _mm_xor_si128 (b6, k); b7 = _mm_xor_si128 (b7, k);                  \
    for (i = 1; i < (rounds); i++, rk++) {                                   \
      k = _mm_loadu_si128 (rk);                                              \
      b0 = op_round (b0, k); b1 = op_round (b1, k);                          \
      b2 = op_round (b2, k); b3 = op_round (b3, k);                          \
      b4 = op_round (b4, k); b5 = op_round (b5, k);                          \
      b6 = op_round (b6, k); b7 = op_round (b7, k);                          \
    }                                                                        \
    k = _mm_loadu_si128 (rk);                                                \
    b0 = op_last (b0, k); b1 = op_last (b1, k);                              \
    b2 = op_last (b2, k); b3 = op_last (b3, k);                              \
    b4 = op_last (b4, k); b5 = op_last (b5, k);                              \
    b6 = op_last (b6, k); b7 = op_last (b7, k);                              \
    _mm_storeu_si128 ((__m128i *)(dst      ), b0);                           \
    _mm_storeu_si128 ((__m128i *)(dst +  16), b1);                           \
    _mm_storeu_si128 ((__m128i *)(dst +  32), b2);                           \
    _mm_storeu_si128 ((__m128i *)(dst +  48), b3);                           \
    _mm_storeu_si128 ((__m128i *)(dst +  64), b4);                           \
    _mm_storeu_si128 ((__m128i *)(dst +  80), b5);                           \
    _mm_storeu_si128 ((__m128i *)(dst +  96), b6);                           \
    _mm_storeu_si128 ((__m128i *)(dst + 112), b7);                           \
  }

R_AES_AESNI_BLOCKS_X8 (r_cipher_aes_ecb_encrypt_blocks8_aesni_128, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 10)
R_AES_AESNI_BLOCKS_X8 (r_cipher_aes_ecb_encrypt_blocks8_aesni_192, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 12)
R_AES_AESNI_BLOCKS_X8 (r_cipher_aes_ecb_encrypt_blocks8_aesni_256, erk,
    _mm_aesenc_si128, _mm_aesenclast_si128, 14)
R_AES_AESNI_BLOCKS_X8 (r_cipher_aes_ecb_decrypt_blocks8_aesni_128, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 10)
R_AES_AESNI_BLOCKS_X8 (r_cipher_aes_ecb_decrypt_blocks8_aesni_192, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 12)
R_AES_AESNI_BLOCKS_X8 (r_cipher_aes_ecb_decrypt_blocks8_aesni_256, drk,
    _mm_aesdec_si128, _mm_aesdeclast_si128, 14)
#endif /* HAVE_WMMINTRIN_H (AES-NI block kernels) */

/* PCLMUL GHASH kernel: needs PCLMULQDQ (wmmintrin.h) for the
 * polynomial mul AND PSHUFB (tmmintrin.h, SSSE3) for the per-byte
 * bit-reverse. Both header probes are independent so a (hypothetical)
 * system with one but not the other falls back to SW. */
#if defined(HAVE_WMMINTRIN_H) && defined(HAVE_TMMINTRIN_H)
# if defined(__GNUC__) || defined(__clang__)
#  define R_GHASH_X86_TARGET __attribute__((target("pclmul,ssse3")))
# else
#  define R_GHASH_X86_TARGET
# endif

/* Per-byte bit-reverse via two PSHUFB lookups on the nibble-rev
 * table. Converts between rlib's "byte-internal MSB = x^0" GHASH
 * representation and the natural-LE polynomial representation
 * (bit i = x^i) that PCLMULQDQ operates on. */
R_GHASH_X86_TARGET
static inline __m128i
r_ghash_byte_bitrev (__m128i v)
{
  const __m128i lo_mask = _mm_set1_epi8 ((char) 0x0f);
  /* rev_nibble[n] = bit-reverse of the 4-bit value n. */
  const __m128i lut = _mm_setr_epi8 (
      0x0, 0x8, 0x4, 0xc, 0x2, 0xa, 0x6, 0xe,
      0x1, 0x9, 0x5, 0xd, 0x3, 0xb, 0x7, 0xf);
  __m128i lo_nib = _mm_and_si128 (v, lo_mask);
  __m128i hi_nib = _mm_and_si128 (_mm_srli_epi16 (v, 4), lo_mask);
  /* Bit-reverse of the original low nibble lands in the result's
   * high nibble, and vice versa. */
  __m128i lo_rev = _mm_shuffle_epi8 (lut, lo_nib);
  __m128i hi_rev = _mm_shuffle_epi8 (lut, hi_nib);
  return _mm_or_si128 (_mm_slli_epi16 (lo_rev, 4), hi_rev);
}

/* a * b in GF(2)[x] (no reduction) XOR-accumulated into the 256-bit
 * register pair (@c *lo, @c *hi). Four PCLMULQDQ per call; the cross-
 * term pair is XORed before splitting across the 128-bit boundary. */
R_GHASH_X86_TARGET
static inline void
r_ghash_poly_mul_acc (__m128i * lo, __m128i * hi, __m128i a, __m128i b)
{
  __m128i t0 = _mm_clmulepi64_si128 (a, b, 0x00);
  __m128i t3 = _mm_clmulepi64_si128 (a, b, 0x11);
  __m128i tm = _mm_xor_si128 (
      _mm_clmulepi64_si128 (a, b, 0x10),
      _mm_clmulepi64_si128 (a, b, 0x01));
  *lo = _mm_xor_si128 (*lo, _mm_xor_si128 (t0, _mm_slli_si128 (tm, 8)));
  *hi = _mm_xor_si128 (*hi, _mm_xor_si128 (t3, _mm_srli_si128 (tm, 8)));
}

/* Reduce a 256-bit polynomial (@c lo low, @c hi high) mod NIST g(z)
 * = z^128 + z^7 + z^2 + z + 1. Fold the high half through the
 * low-order tap polynomial 0x87 = z^7 + z^2 + z + 1, expressed as
 * three 128-bit left shifts (by 1, 2 and 7) plus the unshifted
 * value. A second pass folds the tiny overflow (the topmost 7 bits
 * of @c hi that Phase 1's shifts pushed past bit 127) back through
 * the same tap polynomial. */
R_GHASH_X86_TARGET
static inline __m128i
r_ghash_reduce_pclmul (__m128i lo, __m128i hi)
{
  __m128i s1, s2, s7, c1, c2, c7, over;

# define SHL128(out, src, n)                                                  \
  do {                                                                        \
    __m128i shifted = _mm_slli_epi32 ((src), (n));                            \
    __m128i carry = _mm_srli_epi32 ((src), 32 - (n));                         \
    carry = _mm_slli_si128 (carry, 4);                                        \
    (out) = _mm_or_si128 (shifted, carry);                                    \
  } while (0)

  SHL128 (s1, hi, 1);
  SHL128 (s2, hi, 2);
  SHL128 (s7, hi, 7);
  lo = _mm_xor_si128 (lo, hi);
  lo = _mm_xor_si128 (lo, s1);
  lo = _mm_xor_si128 (lo, s2);
  lo = _mm_xor_si128 (lo, s7);

  c1 = _mm_srli_epi32 (hi, 31);
  c2 = _mm_srli_epi32 (hi, 30);
  c7 = _mm_srli_epi32 (hi, 25);
  over = _mm_xor_si128 (_mm_xor_si128 (c1, c2), c7);
  over = _mm_srli_si128 (over, 12);

  SHL128 (s1, over, 1);
  SHL128 (s2, over, 2);
  SHL128 (s7, over, 7);
  lo = _mm_xor_si128 (lo, over);
  lo = _mm_xor_si128 (lo, s1);
  lo = _mm_xor_si128 (lo, s2);
  lo = _mm_xor_si128 (lo, s7);
# undef SHL128

  return lo;
}

/* GHASH multi-block update via PCLMULQDQ.
 *
 * Bridges rlib's "byte-internal MSB = x^0" representation to PCLMUL's
 * natural-LE polynomial form via per-byte bit-reverse. H and its
 * powers are pre-reversed once at cipher construction; @p y stays in
 * the reversed form across iterations so we only bit-reverse on
 * entry and exit, not per-block.
 *
 * For nblocks >= 4 the 4-way aggregated path runs: four polynomial
 * multiplies feed one 256-bit accumulator, and a single reduction
 * collapses it - amortising the reduction cost across 4 blocks. The
 * formula (y_new = (y XOR b0)*H^4 + b1*H^3 + b2*H^2 + b3*H) makes
 * the four mults independent, which the CPU schedules at PCLMULQDQ's
 * 1-cycle throughput. Trailing blocks (< 4) fall through to the
 * single-block path. */
R_GHASH_X86_TARGET
static void
r_ghash_mul_pclmul (ruint8 y[R_AES_BLOCK_BYTES], const RAesCipher * aes,
    const ruint8 * data, rsize nblocks)
{
  __m128i y_br = r_ghash_byte_bitrev (_mm_loadu_si128 ((const __m128i *) y));
  __m128i h1 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h);
  __m128i lo, hi;

  /* 8-way aggregated path: matches the 4-way shape but stretches the
   * formula to eight blocks per reduction:
   *   y_new = (y XOR b0)*H^8 + b1*H^7 + b2*H^6 + b3*H^5
   *         + b4*H^4 + b5*H^3 + b6*H^2 + b7*H
   * All eight polynomial multiplies are independent, which PCLMULQDQ
   * issues at 1/cycle. */
  if (nblocks >= 8) {
    __m128i h2 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[0]);
    __m128i h3 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[1]);
    __m128i h4 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[2]);
    __m128i h5 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[3]);
    __m128i h6 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[4]);
    __m128i h7 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[5]);
    __m128i h8 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[6]);

    while (nblocks >= 8) {
      __m128i b0 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data +   0)));
      __m128i b1 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data +  16)));
      __m128i b2 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data +  32)));
      __m128i b3 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data +  48)));
      __m128i b4 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data +  64)));
      __m128i b5 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data +  80)));
      __m128i b6 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data +  96)));
      __m128i b7 = r_ghash_byte_bitrev (
          _mm_loadu_si128 ((const __m128i *) (data + 112)));
      __m128i a0 = _mm_xor_si128 (y_br, b0);

      lo = _mm_setzero_si128 ();
      hi = _mm_setzero_si128 ();
      r_ghash_poly_mul_acc (&lo, &hi, a0, h8);
      r_ghash_poly_mul_acc (&lo, &hi, b1, h7);
      r_ghash_poly_mul_acc (&lo, &hi, b2, h6);
      r_ghash_poly_mul_acc (&lo, &hi, b3, h5);
      r_ghash_poly_mul_acc (&lo, &hi, b4, h4);
      r_ghash_poly_mul_acc (&lo, &hi, b5, h3);
      r_ghash_poly_mul_acc (&lo, &hi, b6, h2);
      r_ghash_poly_mul_acc (&lo, &hi, b7, h1);
      y_br = r_ghash_reduce_pclmul (lo, hi);

      data += 128;
      nblocks -= 8;
    }
  }

  if (nblocks >= 4) {
    __m128i h2 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[0]);
    __m128i h3 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[1]);
    __m128i h4 = _mm_loadu_si128 ((const __m128i *) aes->ghash_h_pow[2]);

    __m128i b0 = r_ghash_byte_bitrev (
        _mm_loadu_si128 ((const __m128i *) (data +  0)));
    __m128i b1 = r_ghash_byte_bitrev (
        _mm_loadu_si128 ((const __m128i *) (data + 16)));
    __m128i b2 = r_ghash_byte_bitrev (
        _mm_loadu_si128 ((const __m128i *) (data + 32)));
    __m128i b3 = r_ghash_byte_bitrev (
        _mm_loadu_si128 ((const __m128i *) (data + 48)));
    __m128i a0 = _mm_xor_si128 (y_br, b0);

    lo = _mm_setzero_si128 ();
    hi = _mm_setzero_si128 ();
    r_ghash_poly_mul_acc (&lo, &hi, a0, h4);
    r_ghash_poly_mul_acc (&lo, &hi, b1, h3);
    r_ghash_poly_mul_acc (&lo, &hi, b2, h2);
    r_ghash_poly_mul_acc (&lo, &hi, b3, h1);
    y_br = r_ghash_reduce_pclmul (lo, hi);

    data += 64;
    nblocks -= 4;
  }

  while (nblocks > 0) {
    __m128i b = r_ghash_byte_bitrev (
        _mm_loadu_si128 ((const __m128i *) data));
    __m128i a = _mm_xor_si128 (y_br, b);
    lo = _mm_setzero_si128 ();
    hi = _mm_setzero_si128 ();
    r_ghash_poly_mul_acc (&lo, &hi, a, h1);
    y_br = r_ghash_reduce_pclmul (lo, hi);
    data += R_AES_BLOCK_BYTES;
    nblocks--;
  }

  _mm_storeu_si128 ((__m128i *) y, r_ghash_byte_bitrev (y_br));
}
#endif /* HAVE_WMMINTRIN_H && HAVE_TMMINTRIN_H (PCLMUL GHASH kernel) */

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

/* 8-way variant: same rationale as the AES-NI x8 - more independent
 * blocks in flight to hide AESE/AESMC latency (Cortex-A class chips
 * tend to have 1-cycle throughput / 3-cycle latency on AESE+AESMC
 * pairs, so the wider window is meaningful here). */
# define R_AES_ARMV8_BLOCKS_X8_ENCRYPT(name, rounds)                          \
  R_AES_ARM_TARGET                                                            \
  static void                                                                 \
  name (const RAesCipher * aes, ruint8 * dst, const ruint8 * src)             \
  {                                                                           \
    uint8x16_t b0 = vld1q_u8 (src       );                                    \
    uint8x16_t b1 = vld1q_u8 (src +  16);                                     \
    uint8x16_t b2 = vld1q_u8 (src +  32);                                     \
    uint8x16_t b3 = vld1q_u8 (src +  48);                                     \
    uint8x16_t b4 = vld1q_u8 (src +  64);                                     \
    uint8x16_t b5 = vld1q_u8 (src +  80);                                     \
    uint8x16_t b6 = vld1q_u8 (src +  96);                                     \
    uint8x16_t b7 = vld1q_u8 (src + 112);                                     \
    const ruint8 * rk = (const ruint8 *)aes->erk;                             \
    uint8x16_t k;                                                             \
    ruint8 i;                                                                 \
    for (i = 0; i < (rounds) - 1; i++, rk += 16) {                            \
      k = vld1q_u8 (rk);                                                      \
      b0 = vaeseq_u8 (b0, k); b0 = vaesmcq_u8 (b0);                           \
      b1 = vaeseq_u8 (b1, k); b1 = vaesmcq_u8 (b1);                           \
      b2 = vaeseq_u8 (b2, k); b2 = vaesmcq_u8 (b2);                           \
      b3 = vaeseq_u8 (b3, k); b3 = vaesmcq_u8 (b3);                           \
      b4 = vaeseq_u8 (b4, k); b4 = vaesmcq_u8 (b4);                           \
      b5 = vaeseq_u8 (b5, k); b5 = vaesmcq_u8 (b5);                           \
      b6 = vaeseq_u8 (b6, k); b6 = vaesmcq_u8 (b6);                           \
      b7 = vaeseq_u8 (b7, k); b7 = vaesmcq_u8 (b7);                           \
    }                                                                         \
    k = vld1q_u8 (rk); rk += 16;                                              \
    b0 = vaeseq_u8 (b0, k); b1 = vaeseq_u8 (b1, k);                           \
    b2 = vaeseq_u8 (b2, k); b3 = vaeseq_u8 (b3, k);                           \
    b4 = vaeseq_u8 (b4, k); b5 = vaeseq_u8 (b5, k);                           \
    b6 = vaeseq_u8 (b6, k); b7 = vaeseq_u8 (b7, k);                           \
    k = vld1q_u8 (rk);                                                        \
    b0 = veorq_u8 (b0, k); b1 = veorq_u8 (b1, k);                             \
    b2 = veorq_u8 (b2, k); b3 = veorq_u8 (b3, k);                             \
    b4 = veorq_u8 (b4, k); b5 = veorq_u8 (b5, k);                             \
    b6 = veorq_u8 (b6, k); b7 = veorq_u8 (b7, k);                             \
    vst1q_u8 (dst       , b0); vst1q_u8 (dst +  16, b1);                      \
    vst1q_u8 (dst +  32, b2); vst1q_u8 (dst +  48, b3);                       \
    vst1q_u8 (dst +  64, b4); vst1q_u8 (dst +  80, b5);                       \
    vst1q_u8 (dst +  96, b6); vst1q_u8 (dst + 112, b7);                       \
  }

# define R_AES_ARMV8_BLOCKS_X8_DECRYPT(name, rounds)                          \
  R_AES_ARM_TARGET                                                            \
  static void                                                                 \
  name (const RAesCipher * aes, ruint8 * dst, const ruint8 * src)             \
  {                                                                           \
    uint8x16_t b0 = vld1q_u8 (src       );                                    \
    uint8x16_t b1 = vld1q_u8 (src +  16);                                     \
    uint8x16_t b2 = vld1q_u8 (src +  32);                                     \
    uint8x16_t b3 = vld1q_u8 (src +  48);                                     \
    uint8x16_t b4 = vld1q_u8 (src +  64);                                     \
    uint8x16_t b5 = vld1q_u8 (src +  80);                                     \
    uint8x16_t b6 = vld1q_u8 (src +  96);                                     \
    uint8x16_t b7 = vld1q_u8 (src + 112);                                     \
    const ruint8 * rk = (const ruint8 *)aes->drk;                             \
    uint8x16_t k;                                                             \
    ruint8 i;                                                                 \
    for (i = 0; i < (rounds) - 1; i++, rk += 16) {                            \
      k = vld1q_u8 (rk);                                                      \
      b0 = vaesdq_u8 (b0, k); b0 = vaesimcq_u8 (b0);                          \
      b1 = vaesdq_u8 (b1, k); b1 = vaesimcq_u8 (b1);                          \
      b2 = vaesdq_u8 (b2, k); b2 = vaesimcq_u8 (b2);                          \
      b3 = vaesdq_u8 (b3, k); b3 = vaesimcq_u8 (b3);                          \
      b4 = vaesdq_u8 (b4, k); b4 = vaesimcq_u8 (b4);                          \
      b5 = vaesdq_u8 (b5, k); b5 = vaesimcq_u8 (b5);                          \
      b6 = vaesdq_u8 (b6, k); b6 = vaesimcq_u8 (b6);                          \
      b7 = vaesdq_u8 (b7, k); b7 = vaesimcq_u8 (b7);                          \
    }                                                                         \
    k = vld1q_u8 (rk); rk += 16;                                              \
    b0 = vaesdq_u8 (b0, k); b1 = vaesdq_u8 (b1, k);                           \
    b2 = vaesdq_u8 (b2, k); b3 = vaesdq_u8 (b3, k);                           \
    b4 = vaesdq_u8 (b4, k); b5 = vaesdq_u8 (b5, k);                           \
    b6 = vaesdq_u8 (b6, k); b7 = vaesdq_u8 (b7, k);                           \
    k = vld1q_u8 (rk);                                                        \
    b0 = veorq_u8 (b0, k); b1 = veorq_u8 (b1, k);                             \
    b2 = veorq_u8 (b2, k); b3 = veorq_u8 (b3, k);                             \
    b4 = veorq_u8 (b4, k); b5 = veorq_u8 (b5, k);                             \
    b6 = veorq_u8 (b6, k); b7 = veorq_u8 (b7, k);                             \
    vst1q_u8 (dst       , b0); vst1q_u8 (dst +  16, b1);                      \
    vst1q_u8 (dst +  32, b2); vst1q_u8 (dst +  48, b3);                       \
    vst1q_u8 (dst +  64, b4); vst1q_u8 (dst +  80, b5);                       \
    vst1q_u8 (dst +  96, b6); vst1q_u8 (dst + 112, b7);                       \
  }

R_AES_ARMV8_BLOCKS_X8_ENCRYPT (r_cipher_aes_ecb_encrypt_blocks8_armv8_128, 10)
R_AES_ARMV8_BLOCKS_X8_ENCRYPT (r_cipher_aes_ecb_encrypt_blocks8_armv8_192, 12)
R_AES_ARMV8_BLOCKS_X8_ENCRYPT (r_cipher_aes_ecb_encrypt_blocks8_armv8_256, 14)
R_AES_ARMV8_BLOCKS_X8_DECRYPT (r_cipher_aes_ecb_decrypt_blocks8_armv8_128, 10)
R_AES_ARMV8_BLOCKS_X8_DECRYPT (r_cipher_aes_ecb_decrypt_blocks8_armv8_192, 12)
R_AES_ARMV8_BLOCKS_X8_DECRYPT (r_cipher_aes_ecb_decrypt_blocks8_armv8_256, 14)

/* MSVC ARM64 declares vmull_p64 as taking __n64 (not poly64_t) and
 * returning __n128 (no poly128_t typedef), so a straight ACLE call
 * doesn't compile. Wrap the intrinsic once and return uint8x16_t -
 * on MSVC that's the same underlying type as __n128, on GCC / clang
 * we reinterpret from poly128_t. The rest of the kernel can stay in
 * standard ACLE types. */
#if defined(_MSC_VER) && !defined(__clang__)
R_AES_ARM_TARGET
static __forceinline uint8x16_t
r_pmull_p64 (uint64_t a, uint64_t b)
{
  __n64 _a, _b;
  /* Plain memcpy as the portable type-pun. __n64 and uint64_t are
   * both 8 bytes; MSVC optimises the copy away. */
  memcpy (&_a, &a, sizeof (_a));
  memcpy (&_b, &b, sizeof (_b));
  return vmull_p64 (_a, _b);
}
#else
R_AES_ARM_TARGET
static inline uint8x16_t
r_pmull_p64 (uint64_t a, uint64_t b)
{
  return vreinterpretq_u8_p128 (vmull_p64 ((poly64_t) a, (poly64_t) b));
}
#endif

/* a * b in GF(2)[x] (no reduction) XOR-accumulated into the 256-bit
 * register pair (@c *lo, @c *hi). Mirrors r_ghash_poly_mul_acc on
 * the x86 side. */
R_AES_ARM_TARGET
static inline void
r_ghash_poly_mul_acc_pmull (uint8x16_t * lo, uint8x16_t * hi,
    uint8x16_t a, uint8x16_t b)
{
  uint64_t alo = vgetq_lane_u64 (vreinterpretq_u64_u8 (a), 0);
  uint64_t ahi = vgetq_lane_u64 (vreinterpretq_u64_u8 (a), 1);
  uint64_t blo = vgetq_lane_u64 (vreinterpretq_u64_u8 (b), 0);
  uint64_t bhi = vgetq_lane_u64 (vreinterpretq_u64_u8 (b), 1);
  uint8x16_t t0 = r_pmull_p64 (alo, blo);
  uint8x16_t t3 = r_pmull_p64 (ahi, bhi);
  uint8x16_t tm = veorq_u8 (r_pmull_p64 (ahi, blo),
                            r_pmull_p64 (alo, bhi));
  *lo = veorq_u8 (*lo,
      veorq_u8 (t0, vextq_u8 (vdupq_n_u8 (0), tm, 8)));
  *hi = veorq_u8 (*hi,
      veorq_u8 (t3, vextq_u8 (tm, vdupq_n_u8 (0), 8)));
}

/* Reduce a 256-bit polynomial (@c lo low, @c hi high) mod NIST g(z)
 * = z^128 + z^7 + z^2 + z + 1. Mirrors r_ghash_reduce_pclmul. */
R_AES_ARM_TARGET
static inline uint8x16_t
r_ghash_reduce_pmull (uint8x16_t lo, uint8x16_t hi)
{
  uint8x16_t s1, s2, s7, c1, c2, c7, over;

# define SHL128(out, src, n)                                                  \
  do {                                                                        \
    uint32x4_t _sh = vshlq_n_u32 (vreinterpretq_u32_u8 (src), (n));           \
    uint32x4_t _ca = vshrq_n_u32 (vreinterpretq_u32_u8 (src), 32 - (n));      \
    uint8x16_t _cab = vextq_u8 (vdupq_n_u8 (0),                               \
        vreinterpretq_u8_u32 (_ca), 12);                                      \
    (out) = veorq_u8 (vreinterpretq_u8_u32 (_sh), _cab);                      \
  } while (0)

  SHL128 (s1, hi, 1);
  SHL128 (s2, hi, 2);
  SHL128 (s7, hi, 7);
  lo = veorq_u8 (lo, hi);
  lo = veorq_u8 (lo, s1);
  lo = veorq_u8 (lo, s2);
  lo = veorq_u8 (lo, s7);

  c1 = vreinterpretq_u8_u32 (
        vshrq_n_u32 (vreinterpretq_u32_u8 (hi), 31));
  c2 = vreinterpretq_u8_u32 (
        vshrq_n_u32 (vreinterpretq_u32_u8 (hi), 30));
  c7 = vreinterpretq_u8_u32 (
        vshrq_n_u32 (vreinterpretq_u32_u8 (hi), 25));
  over = veorq_u8 (veorq_u8 (c1, c2), c7);
  over = vextq_u8 (over, vdupq_n_u8 (0), 12);

  SHL128 (s1, over, 1);
  SHL128 (s2, over, 2);
  SHL128 (s7, over, 7);
  lo = veorq_u8 (lo, over);
  lo = veorq_u8 (lo, s1);
  lo = veorq_u8 (lo, s2);
  lo = veorq_u8 (lo, s7);
# undef SHL128

  return lo;
}

/* GHASH multi-block update via ARMv8 PMULL. Structurally identical
 * to r_ghash_mul_pclmul: 4-way aggregated path for nblocks >= 4
 * (four polynomial multiplies into one accumulator + one reduction),
 * single-block fallback for the trailing remainder. */
R_AES_ARM_TARGET
static void
r_ghash_mul_pmull (ruint8 y[R_AES_BLOCK_BYTES], const RAesCipher * aes,
    const ruint8 * data, rsize nblocks)
{
  uint8x16_t y_br = vrbitq_u8 (vld1q_u8 (y));
  uint8x16_t h1 = vld1q_u8 (aes->ghash_h);
  uint8x16_t lo, hi;

  /* 8-way aggregated path: same formula and instruction shape as
   * the PCLMUL kernel - eight independent vmull_p64 streams feed
   * one accumulator, single reduction at the end. */
  if (nblocks >= 8) {
    uint8x16_t h2 = vld1q_u8 (aes->ghash_h_pow[0]);
    uint8x16_t h3 = vld1q_u8 (aes->ghash_h_pow[1]);
    uint8x16_t h4 = vld1q_u8 (aes->ghash_h_pow[2]);
    uint8x16_t h5 = vld1q_u8 (aes->ghash_h_pow[3]);
    uint8x16_t h6 = vld1q_u8 (aes->ghash_h_pow[4]);
    uint8x16_t h7 = vld1q_u8 (aes->ghash_h_pow[5]);
    uint8x16_t h8 = vld1q_u8 (aes->ghash_h_pow[6]);

    while (nblocks >= 8) {
      uint8x16_t b0 = vrbitq_u8 (vld1q_u8 (data +   0));
      uint8x16_t b1 = vrbitq_u8 (vld1q_u8 (data +  16));
      uint8x16_t b2 = vrbitq_u8 (vld1q_u8 (data +  32));
      uint8x16_t b3 = vrbitq_u8 (vld1q_u8 (data +  48));
      uint8x16_t b4 = vrbitq_u8 (vld1q_u8 (data +  64));
      uint8x16_t b5 = vrbitq_u8 (vld1q_u8 (data +  80));
      uint8x16_t b6 = vrbitq_u8 (vld1q_u8 (data +  96));
      uint8x16_t b7 = vrbitq_u8 (vld1q_u8 (data + 112));
      uint8x16_t a0 = veorq_u8 (y_br, b0);

      lo = vdupq_n_u8 (0);
      hi = vdupq_n_u8 (0);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, a0, h8);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, b1, h7);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, b2, h6);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, b3, h5);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, b4, h4);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, b5, h3);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, b6, h2);
      r_ghash_poly_mul_acc_pmull (&lo, &hi, b7, h1);
      y_br = r_ghash_reduce_pmull (lo, hi);

      data += 128;
      nblocks -= 8;
    }
  }

  if (nblocks >= 4) {
    uint8x16_t h2 = vld1q_u8 (aes->ghash_h_pow[0]);
    uint8x16_t h3 = vld1q_u8 (aes->ghash_h_pow[1]);
    uint8x16_t h4 = vld1q_u8 (aes->ghash_h_pow[2]);

    uint8x16_t b0 = vrbitq_u8 (vld1q_u8 (data +  0));
    uint8x16_t b1 = vrbitq_u8 (vld1q_u8 (data + 16));
    uint8x16_t b2 = vrbitq_u8 (vld1q_u8 (data + 32));
    uint8x16_t b3 = vrbitq_u8 (vld1q_u8 (data + 48));
    uint8x16_t a0 = veorq_u8 (y_br, b0);

    lo = vdupq_n_u8 (0);
    hi = vdupq_n_u8 (0);
    r_ghash_poly_mul_acc_pmull (&lo, &hi, a0, h4);
    r_ghash_poly_mul_acc_pmull (&lo, &hi, b1, h3);
    r_ghash_poly_mul_acc_pmull (&lo, &hi, b2, h2);
    r_ghash_poly_mul_acc_pmull (&lo, &hi, b3, h1);
    y_br = r_ghash_reduce_pmull (lo, hi);

    data += 64;
    nblocks -= 4;
  }

  while (nblocks > 0) {
    uint8x16_t b = vrbitq_u8 (vld1q_u8 (data));
    uint8x16_t a = veorq_u8 (y_br, b);
    lo = vdupq_n_u8 (0);
    hi = vdupq_n_u8 (0);
    r_ghash_poly_mul_acc_pmull (&lo, &hi, a, h1);
    y_br = r_ghash_reduce_pmull (lo, hi);
    data += R_AES_BLOCK_BYTES;
    nblocks--;
  }

  vst1q_u8 (y, vrbitq_u8 (y_br));
}

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
  if (aes->encrypt_blocks_x8 != NULL) {
    while (ptr + R_AES_PARALLEL8_BYTES <= end) {
      aes->encrypt_blocks_x8 (aes, dst, ptr);
      ptr += R_AES_PARALLEL8_BYTES;
      dst += R_AES_PARALLEL8_BYTES;
    }
  }
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
  if (aes->decrypt_blocks_x8 != NULL) {
    while (ptr + R_AES_PARALLEL8_BYTES <= end) {
      aes->decrypt_blocks_x8 (aes, dst, ptr);
      ptr += R_AES_PARALLEL8_BYTES;
      dst += R_AES_PARALLEL8_BYTES;
    }
  }
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
  ruint8 scratch[R_AES_PARALLEL8_BYTES];
  int i;
  rsize w;

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY ((size % R_AES_BLOCK_BYTES) > 0)) return R_CRYPTO_CIPHER_WRONG_BLOCK_SIZE;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + size;

  /* 8-way / 4-way path: snapshot the window's ciphertext (decryption
   * can be in-place so the original ct must be saved before the dst
   * write), decrypt N blocks in parallel, then XOR each plaintext
   * with its chain predecessor (iv for the first, ct[i-1] for the
   * rest). iv is updated to the last ciphertext of the window. */
  if (aes->decrypt_blocks_x8 != NULL) {
    while (ptr + R_AES_PARALLEL8_BYTES <= end) {
      r_memcpy (scratch, ptr, R_AES_PARALLEL8_BYTES);
      aes->decrypt_blocks_x8 (aes, dst, ptr);
      for (i = 0; i < R_AES_BLOCK_BYTES; i++) dst[i] ^= iv[i];
      for (w = 1; w < R_AES_PARALLEL8_BLOCKS; w++) {
        for (i = 0; i < R_AES_BLOCK_BYTES; i++)
          dst[i + R_AES_BLOCK_BYTES * w] ^= scratch[i + R_AES_BLOCK_BYTES * (w - 1)];
      }
      r_memcpy (iv, scratch + R_AES_BLOCK_BYTES * (R_AES_PARALLEL8_BLOCKS - 1), R_AES_BLOCK_BYTES);
      ptr += R_AES_PARALLEL8_BYTES;
      dst += R_AES_PARALLEL8_BYTES;
    }
  }
  if (aes->decrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      r_memcpy (scratch, ptr, R_AES_PARALLEL_BYTES);
      aes->decrypt_blocks_x4 (aes, dst, ptr);
      for (i = 0; i < R_AES_BLOCK_BYTES; i++) dst[i] ^= iv[i];
      for (w = 1; w < R_AES_PARALLEL_BLOCKS; w++) {
        for (i = 0; i < R_AES_BLOCK_BYTES; i++)
          dst[i + R_AES_BLOCK_BYTES * w] ^= scratch[i + R_AES_BLOCK_BYTES * (w - 1)];
      }
      r_memcpy (iv, scratch + R_AES_BLOCK_BYTES * (R_AES_PARALLEL_BLOCKS - 1), R_AES_BLOCK_BYTES);
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


RCryptoCipherResult
r_cipher_aes_ctr_encrypt (const RCryptoCipher * cipher,
    ruint8 * dst, rsize size, rconstpointer data, ruint8 * iv, rsize ivsize)
{
  const RAesCipher * aes;
  const ruint8 * ptr;
  const ruint8 * end;
  int i;
  rsize bsize = size;
  rsize w;
  ruint8 scratch[R_AES_PARALLEL8_BYTES];

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + bsize;

  /* 8-way / 4-way path: build N consecutive counter blocks (iv, iv+1,
   * ..., iv+N-1) in scratch, encrypt all N in parallel, XOR with the
   * plaintext window, and advance iv by N. */
  if (aes->encrypt_blocks_x8 != NULL) {
    while (ptr + R_AES_PARALLEL8_BYTES <= end) {
      for (w = 0; w < R_AES_PARALLEL8_BLOCKS; w++)
        r_memcpy (scratch + R_AES_BLOCK_BYTES * w, iv, R_AES_BLOCK_BYTES);
      for (w = 1; w < R_AES_PARALLEL8_BLOCKS; w++)
        r_aes_ctr_add (scratch + R_AES_BLOCK_BYTES * w, (ruint32) w);
      aes->encrypt_blocks_x8 (aes, scratch, scratch);
      for (i = 0; i < R_AES_PARALLEL8_BYTES; i++)
        dst[i] = scratch[i] ^ ptr[i];
      r_aes_ctr_add (iv, R_AES_PARALLEL8_BLOCKS);
      ptr += R_AES_PARALLEL8_BYTES;
      dst += R_AES_PARALLEL8_BYTES;
    }
  }
  if (aes->encrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      for (w = 0; w < R_AES_PARALLEL_BLOCKS; w++)
        r_memcpy (scratch + R_AES_BLOCK_BYTES * w, iv, R_AES_BLOCK_BYTES);
      for (w = 1; w < R_AES_PARALLEL_BLOCKS; w++)
        r_aes_ctr_add (scratch + R_AES_BLOCK_BYTES * w, (ruint32) w);
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
  rsize w;
  ruint8 scratch[R_AES_PARALLEL8_BYTES];
  ruint8 ctsave[R_AES_PARALLEL8_BYTES];

  if (R_UNLIKELY (cipher == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (data == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (dst == NULL)) return R_CRYPTO_CIPHER_INVAL;
  if (R_UNLIKELY (ivsize != R_AES_BLOCK_BYTES)) return R_CRYPTO_CIPHER_INVAL;

  size %= R_AES_BLOCK_BYTES;
  bsize -= size;

  aes = (const RAesCipher *)cipher;
  ptr = data;
  end = ptr + bsize;

  /* 8-way / 4-way path: encrypt the N chain inputs (iv, ct[0],
   * ..., ct[N-2]) in parallel into a keystream, XOR with the
   * ciphertext window. iv is updated to ct[N-1] for next iteration. */
  if (aes->encrypt_blocks_x8 != NULL) {
    while (ptr + R_AES_PARALLEL8_BYTES <= end) {
      r_memcpy (ctsave, ptr, R_AES_PARALLEL8_BYTES);
      r_memcpy (scratch, iv, R_AES_BLOCK_BYTES);
      for (w = 1; w < R_AES_PARALLEL8_BLOCKS; w++)
        r_memcpy (scratch + R_AES_BLOCK_BYTES * w,
            ctsave + R_AES_BLOCK_BYTES * (w - 1), R_AES_BLOCK_BYTES);
      aes->encrypt_blocks_x8 (aes, scratch, scratch);
      for (i = 0; i < R_AES_PARALLEL8_BYTES; i++)
        dst[i] = scratch[i] ^ ctsave[i];
      r_memcpy (iv, ctsave + R_AES_BLOCK_BYTES * (R_AES_PARALLEL8_BLOCKS - 1), R_AES_BLOCK_BYTES);
      ptr += R_AES_PARALLEL8_BYTES;
      dst += R_AES_PARALLEL8_BYTES;
    }
  }
  if (aes->encrypt_blocks_x4 != NULL) {
    while (ptr + R_AES_PARALLEL_BYTES <= end) {
      r_memcpy (ctsave, ptr, R_AES_PARALLEL_BYTES);
      r_memcpy (scratch, iv, R_AES_BLOCK_BYTES);
      for (w = 1; w < R_AES_PARALLEL_BLOCKS; w++)
        r_memcpy (scratch + R_AES_BLOCK_BYTES * w,
            ctsave + R_AES_BLOCK_BYTES * (w - 1), R_AES_BLOCK_BYTES);
      aes->encrypt_blocks_x4 (aes, scratch, scratch);
      for (i = 0; i < R_AES_PARALLEL_BYTES; i++)
        dst[i] = scratch[i] ^ ctsave[i];
      r_memcpy (iv, ctsave + R_AES_BLOCK_BYTES * (R_AES_PARALLEL_BLOCKS - 1), R_AES_BLOCK_BYTES);
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
 * Bit-by-bit shift-and-XOR implementation. Used only to populate
 * the 4-bit table once per GCM op; the hot path runs through
 * r_ghash_mul_4bit. */
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

/* Build the 4-bit GHASH table (Shoup's method) into @p t. e[n] holds
 * (n * H) where the 4-bit value @c n encodes the polynomial chunk for
 * x^0..x^3 in bit-reversed form (bit 3 of @c n = coefficient of
 * x^0). */
static void
r_ghash_init_table (RGhashTable * t, const ruint8 h[R_AES_BLOCK_BYTES])
{
  rsize n;
  r_memset (t->e[0], 0, R_AES_BLOCK_BYTES);
  for (n = 1; n < 16; n++) {
    r_memset (t->e[n], 0, R_AES_BLOCK_BYTES);
    t->e[n][0] = (ruint8) (n << 4);
    r_ghash_mul (t->e[n], h);
  }
}

/* Reduction lookup for the four low-order bits that shift off the
 * end during each nibble step of r_ghash_mul_4bit. R[rem] stores the
 * bit-reversed reduction polynomial contributions for those four
 * positions, spread across the new high-order bytes (z[0], z[1]). */
static const ruint8 r_ghash_reduce_4bit[16][2] = {
  { 0x00, 0x00 }, { 0x1c, 0x20 }, { 0x38, 0x40 }, { 0x24, 0x60 },
  { 0x70, 0x80 }, { 0x6c, 0xa0 }, { 0x48, 0xc0 }, { 0x54, 0xe0 },
  { 0xe1, 0x00 }, { 0xfd, 0x20 }, { 0xd9, 0x40 }, { 0xc5, 0x60 },
  { 0x91, 0x80 }, { 0x8d, 0xa0 }, { 0xa9, 0xc0 }, { 0xb5, 0xe0 }
};

static void
r_ghash_mul_4bit (ruint8 y[R_AES_BLOCK_BYTES], const RAesCipher * aes,
    const ruint8 * data, rsize nblocks)
{
  const RGhashTable * t = &aes->ghash_t;
  ruint8 z[R_AES_BLOCK_BYTES];
  rssize byte_idx;
  rsize k;
  ruint8 n, rem;

  while (nblocks > 0) {
    for (k = 0; k < R_AES_BLOCK_BYTES; k++)
      y[k] ^= data[k];

    r_memset (z, 0, R_AES_BLOCK_BYTES);
    for (byte_idx = R_AES_BLOCK_BYTES - 1; byte_idx >= 0; byte_idx--) {
      /* Process the low nibble first (higher x position), then high.
       * Each step is z = (z * x^4) XOR T[n], with z * x^4 done as a
       * 4-bit right-shift plus the precomputed reduction for the
       * four bits that fell off. */
      n = y[byte_idx] & 0xf;
      rem = z[R_AES_BLOCK_BYTES - 1] & 0xf;
      for (k = R_AES_BLOCK_BYTES - 1; k > 0; k--)
        z[k] = (ruint8) ((z[k] >> 4) | (z[k - 1] << 4));
      z[0] >>= 4;
      z[0] ^= r_ghash_reduce_4bit[rem][0];
      z[1] ^= r_ghash_reduce_4bit[rem][1];
      for (k = 0; k < R_AES_BLOCK_BYTES; k++)
        z[k] ^= t->e[n][k];

      n = y[byte_idx] >> 4;
      rem = z[R_AES_BLOCK_BYTES - 1] & 0xf;
      for (k = R_AES_BLOCK_BYTES - 1; k > 0; k--)
        z[k] = (ruint8) ((z[k] >> 4) | (z[k - 1] << 4));
      z[0] >>= 4;
      z[0] ^= r_ghash_reduce_4bit[rem][0];
      z[1] ^= r_ghash_reduce_4bit[rem][1];
      for (k = 0; k < R_AES_BLOCK_BYTES; k++)
        z[k] ^= t->e[n][k];
    }
    r_memcpy (y, z, R_AES_BLOCK_BYTES);

    data += R_AES_BLOCK_BYTES;
    nblocks--;
  }
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

/* As r_gcm_ctr_inc32 but advances by @p n. ruint32 wraparound matches
 * the GCM inc_32 spec naturally. */
static void
r_gcm_ctr_inc32_n (ruint8 ctr[R_AES_BLOCK_BYTES], ruint32 n)
{
  ruint32 c = ((ruint32) ctr[12] << 24) | ((ruint32) ctr[13] << 16)
            | ((ruint32) ctr[14] <<  8) |  (ruint32) ctr[15];
  c += n;
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
    const RAesCipher * aes,
    const ruint8 * data, rsize size)
{
  rsize nblocks = size / R_AES_BLOCK_BYTES;
  rsize tail = size % R_AES_BLOCK_BYTES;

  if (nblocks > 0)
    aes->ghash_mul (y, aes, data, nblocks);
  if (tail > 0) {
    ruint8 block[R_AES_BLOCK_BYTES] = { 0 };
    r_memcpy (block, data + nblocks * R_AES_BLOCK_BYTES, tail);
    aes->ghash_mul (y, aes, block, 1);
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
    const ruint8 j0[R_AES_BLOCK_BYTES],
    rconstpointer aad, rsize aadsize,
    const ruint8 * ciphertxt, rsize ctsize,
    ruint8 tag[R_AES_BLOCK_BYTES])
{
  ruint8 y[R_AES_BLOCK_BYTES] = { 0 };
  ruint8 lenblock[R_AES_BLOCK_BYTES];
  ruint8 ek[R_AES_BLOCK_BYTES];
  rsize i;

  r_gcm_ghash_update (y, aes, aad, aadsize);
  r_gcm_ghash_update (y, aes, ciphertxt, ctsize);

  r_gcm_be64 (lenblock,     (ruint64) aadsize * 8);
  r_gcm_be64 (lenblock + 8, (ruint64) ctsize * 8);
  aes->ghash_mul (y, aes, lenblock, 1);

  aes->encrypt_block (aes, ek, j0);
  for (i = 0; i < R_AES_BLOCK_BYTES; i++)
    tag[i] = ek[i] ^ y[i];

  /* ek is the tag-encryption mask and y the GHASH accumulator; wipe
   * both, matching the secret-scrubbing the mode ops do. */
  r_memclear_secure (ek, sizeof (ek));
  r_memclear_secure (y, sizeof (y));
  r_memclear_secure (lenblock, sizeof (lenblock));
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

  /* J0 = IV || 0x00000001. H and the GHASH kernel are precomputed on
   * the cipher at construction time. */
  r_memcpy (j0, iv, 12);
  j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

  /* For decrypt, verify the tag against the ciphertext BEFORE
   * touching @p dst. This way an auth failure leaves any previous
   * @p dst contents intact; the caller never sees released plaintext
   * from a forged input. */
  if (!generate_tag) {
    r_gcm_compute_tag (aes, j0, aad, aadsize, data, size, tagcomputed);
    {
      ruint8 diff = 0;
      for (i = 0; i < tagsize; i++)
        diff |= tagcomputed[i] ^ tag[i];
      if (diff != 0) {
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

  /* 8-way / 4-way path: stage N consecutive GCM counter blocks
   * (ctr, ctr+1, ..., ctr+N-1) in scratch, encrypt all N in parallel
   * via the SIMD-interleaved kernel, XOR with the source window, and
   * advance ctr by N. Mirrors the shape of r_cipher_aes_ctr_encrypt;
   * the only twist is GCM's inc_32 wrap behaviour. */
  if (aes->encrypt_blocks_x8 != NULL) {
    ruint8 ks8[R_AES_PARALLEL8_BYTES];
    rsize w;
    while (remaining >= R_AES_PARALLEL8_BYTES) {
      for (w = 0; w < R_AES_PARALLEL8_BLOCKS; w++)
        r_memcpy (ks8 + R_AES_BLOCK_BYTES * w, ctr, R_AES_BLOCK_BYTES);
      for (w = 1; w < R_AES_PARALLEL8_BLOCKS; w++)
        r_gcm_ctr_inc32_n (ks8 + R_AES_BLOCK_BYTES * w, (ruint32) w);
      aes->encrypt_blocks_x8 (aes, ks8, ks8);
      for (i = 0; i < R_AES_PARALLEL8_BYTES; i++)
        dstp[i] = ks8[i] ^ srcp[i];
      r_gcm_ctr_inc32_n (ctr, R_AES_PARALLEL8_BLOCKS);
      srcp += R_AES_PARALLEL8_BYTES;
      dstp += R_AES_PARALLEL8_BYTES;
      remaining -= R_AES_PARALLEL8_BYTES;
    }
    r_memclear_secure (ks8, sizeof (ks8));
  }
  if (aes->encrypt_blocks_x4 != NULL) {
    ruint8 ks4[R_AES_PARALLEL_BYTES];
    rsize w;
    while (remaining >= R_AES_PARALLEL_BYTES) {
      for (w = 0; w < R_AES_PARALLEL_BLOCKS; w++)
        r_memcpy (ks4 + R_AES_BLOCK_BYTES * w, ctr, R_AES_BLOCK_BYTES);
      for (w = 1; w < R_AES_PARALLEL_BLOCKS; w++)
        r_gcm_ctr_inc32_n (ks4 + R_AES_BLOCK_BYTES * w, (ruint32) w);
      aes->encrypt_blocks_x4 (aes, ks4, ks4);
      for (i = 0; i < R_AES_PARALLEL_BYTES; i++)
        dstp[i] = ks4[i] ^ srcp[i];
      r_gcm_ctr_inc32_n (ctr, R_AES_PARALLEL_BLOCKS);
      srcp += R_AES_PARALLEL_BYTES;
      dstp += R_AES_PARALLEL_BYTES;
      remaining -= R_AES_PARALLEL_BYTES;
    }
    r_memclear_secure (ks4, sizeof (ks4));
  }

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
    r_gcm_compute_tag (aes, j0, aad, aadsize, dst, size, tagcomputed);
    r_memcpy (tag, tagcomputed, tagsize);
  }

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

