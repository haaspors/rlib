/* RLIB - Convenience library for useful things
 * Copyright (C) 2026  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/crypto/rchacha20.h>

#include <rlib/rmem.h>

/* ChaCha20 per RFC 8439. State is 16 32-bit words: 4 constant, 8 key,
 * 1 counter, 3 nonce. */

#define R_CHACHA20_ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

static inline ruint32
r_chacha20_load_le32 (const ruint8 * p)
{
  return (ruint32)p[0] | ((ruint32)p[1] << 8) |
      ((ruint32)p[2] << 16) | ((ruint32)p[3] << 24);
}

static inline void
r_chacha20_store_le32 (ruint8 * p, ruint32 v)
{
  p[0] = (ruint8)(v);
  p[1] = (ruint8)(v >> 8);
  p[2] = (ruint8)(v >> 16);
  p[3] = (ruint8)(v >> 24);
}

#define R_CHACHA20_QUARTERROUND(s, a, b, c, d)                                \
  R_STMT_START {                                                              \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = R_CHACHA20_ROTL32 (s[d], 16);          \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = R_CHACHA20_ROTL32 (s[b], 12);          \
    s[a] += s[b]; s[d] ^= s[a]; s[d] = R_CHACHA20_ROTL32 (s[d], 8);           \
    s[c] += s[d]; s[b] ^= s[c]; s[b] = R_CHACHA20_ROTL32 (s[b], 7);           \
  } R_STMT_END

void
r_chacha20_block (ruint8 * out,
    const ruint8 * key, ruint32 counter, const ruint8 * nonce)
{
  ruint32 state[16];
  ruint32 work[16];
  int i;

  /* "expand 32-byte k" */
  state[0] = 0x61707865; state[1] = 0x3320646e;
  state[2] = 0x79622d32; state[3] = 0x6b206574;
  for (i = 0; i < 8; i++)
    state[4 + i] = r_chacha20_load_le32 (key + 4 * i);
  state[12] = counter;
  for (i = 0; i < 3; i++)
    state[13 + i] = r_chacha20_load_le32 (nonce + 4 * i);

  r_memcpy (work, state, sizeof (state));
  for (i = 0; i < 10; i++) {
    /* Column rounds */
    R_CHACHA20_QUARTERROUND (work, 0, 4,  8, 12);
    R_CHACHA20_QUARTERROUND (work, 1, 5,  9, 13);
    R_CHACHA20_QUARTERROUND (work, 2, 6, 10, 14);
    R_CHACHA20_QUARTERROUND (work, 3, 7, 11, 15);
    /* Diagonal rounds */
    R_CHACHA20_QUARTERROUND (work, 0, 5, 10, 15);
    R_CHACHA20_QUARTERROUND (work, 1, 6, 11, 12);
    R_CHACHA20_QUARTERROUND (work, 2, 7,  8, 13);
    R_CHACHA20_QUARTERROUND (work, 3, 4,  9, 14);
  }

  for (i = 0; i < 16; i++)
    r_chacha20_store_le32 (out + 4 * i, work[i] + state[i]);

  /* state[] holds the key, work[] a keystream block - wipe both so no
   * secret material lingers in this frame after we return. */
  r_memclear_secure (state, sizeof (state));
  r_memclear_secure (work, sizeof (work));
}

void
r_chacha20_xor (ruint8 * dst, const ruint8 * src, rsize size,
    const ruint8 * key, ruint32 counter, const ruint8 * nonce)
{
  ruint8 block[R_CHACHA20_BLOCK_SIZE];

  while (size > 0) {
    rsize i, n = size < R_CHACHA20_BLOCK_SIZE ? size : R_CHACHA20_BLOCK_SIZE;

    r_chacha20_block (block, key, counter++, nonce);
    for (i = 0; i < n; i++)
      dst[i] = src[i] ^ block[i];

    dst += n;
    src += n;
    size -= n;
  }

  r_memclear_secure (block, sizeof (block));
}
