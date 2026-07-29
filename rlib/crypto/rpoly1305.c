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
#include <rlib/crypto/rpoly1305.h>

#include "rcrypto-private.h"

#include <rlib/rmem.h>

/* Poly1305 per RFC 8439 §2.5, evaluated in radix 2^26: the 130-bit
 * accumulator is spread across five 26-bit limbs so every partial
 * product stays inside a 64-bit multiply. This is the portable
 * software approach; the clamp masks, carry chain and final freeze
 * follow the reference implementation. */

void
r_poly1305_init (RPoly1305Ctx * ctx, const ruint8 key[32])
{
  /* r &= 0x0ffffffc0ffffffc0ffffffc0fffffff - the clamp zeroes the
   * high 4 bits of the top three bytes and the low 2 bits of the top
   * three limb-boundary bytes, split here across the 26-bit limbs. */
  ctx->r[0] = (r_load_le32 (&key[ 0])     ) & 0x03ffffff;
  ctx->r[1] = (r_load_le32 (&key[ 3]) >> 2) & 0x03ffff03;
  ctx->r[2] = (r_load_le32 (&key[ 6]) >> 4) & 0x03ffc0ff;
  ctx->r[3] = (r_load_le32 (&key[ 9]) >> 6) & 0x03f03fff;
  ctx->r[4] = (r_load_le32 (&key[12]) >> 8) & 0x000fffff;

  ctx->h[0] = ctx->h[1] = ctx->h[2] = ctx->h[3] = ctx->h[4] = 0;

  /* "s" - the second half of the key, added in after the freeze. */
  ctx->pad[0] = r_load_le32 (&key[16]);
  ctx->pad[1] = r_load_le32 (&key[20]);
  ctx->pad[2] = r_load_le32 (&key[24]);
  ctx->pad[3] = r_load_le32 (&key[28]);

  ctx->leftover = 0;
  ctx->final = 0;
}

/* Absorb a run of whole 16-byte blocks: h = (h + m) * r mod (2^130 - 5). */
static void
r_poly1305_blocks (RPoly1305Ctx * ctx, const ruint8 * m, rsize bytes)
{
  const ruint32 hibit = ctx->final ? 0 : (1UL << 24);
  ruint32 r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2],
          r3 = ctx->r[3], r4 = ctx->r[4];
  /* s_i = 5 * r_i, folding the 2^130 == 5 reduction into the product. */
  ruint32 s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
  ruint32 h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2],
          h3 = ctx->h[3], h4 = ctx->h[4];

  while (bytes >= R_POLY1305_BLOCK_SIZE) {
    ruint64 d0, d1, d2, d3, d4;
    ruint32 c;

    /* h += m, spread across the 26-bit limbs, with the high bit set
     * for a full (non-final) block. */
    h0 += (r_load_le32 (&m[ 0])     ) & 0x03ffffff;
    h1 += (r_load_le32 (&m[ 3]) >> 2) & 0x03ffffff;
    h2 += (r_load_le32 (&m[ 6]) >> 4) & 0x03ffffff;
    h3 += (r_load_le32 (&m[ 9]) >> 6) & 0x03ffffff;
    h4 += (r_load_le32 (&m[12]) >> 8) | hibit;

    /* h *= r, with the 5*r terms wrapping the overflow back down. */
    d0 = (ruint64)h0*r0 + (ruint64)h1*s4 + (ruint64)h2*s3 + (ruint64)h3*s2 + (ruint64)h4*s1;
    d1 = (ruint64)h0*r1 + (ruint64)h1*r0 + (ruint64)h2*s4 + (ruint64)h3*s3 + (ruint64)h4*s2;
    d2 = (ruint64)h0*r2 + (ruint64)h1*r1 + (ruint64)h2*r0 + (ruint64)h3*s4 + (ruint64)h4*s3;
    d3 = (ruint64)h0*r3 + (ruint64)h1*r2 + (ruint64)h2*r1 + (ruint64)h3*r0 + (ruint64)h4*s4;
    d4 = (ruint64)h0*r4 + (ruint64)h1*r3 + (ruint64)h2*r2 + (ruint64)h3*r1 + (ruint64)h4*r0;

    /* Partial carry propagation back into 26-bit limbs. */
    c = (ruint32)(d0 >> 26); h0 = (ruint32)d0 & 0x3ffffff; d1 += c;
    c = (ruint32)(d1 >> 26); h1 = (ruint32)d1 & 0x3ffffff; d2 += c;
    c = (ruint32)(d2 >> 26); h2 = (ruint32)d2 & 0x3ffffff; d3 += c;
    c = (ruint32)(d3 >> 26); h3 = (ruint32)d3 & 0x3ffffff; d4 += c;
    c = (ruint32)(d4 >> 26); h4 = (ruint32)d4 & 0x3ffffff; h0 += c * 5;
    c = h0 >> 26;            h0 = h0 & 0x3ffffff;           h1 += c;

    m += R_POLY1305_BLOCK_SIZE;
    bytes -= R_POLY1305_BLOCK_SIZE;
  }

  ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
  ctx->h[3] = h3; ctx->h[4] = h4;
}

void
r_poly1305_update (RPoly1305Ctx * ctx, const ruint8 * m, rsize bytes)
{
  rsize i;

  /* Top up a partially filled block first. */
  if (ctx->leftover > 0) {
    rsize want = R_POLY1305_BLOCK_SIZE - ctx->leftover;
    if (want > bytes)
      want = bytes;
    for (i = 0; i < want; i++)
      ctx->buffer[ctx->leftover + i] = m[i];
    bytes -= want;
    m += want;
    ctx->leftover += want;
    if (ctx->leftover < R_POLY1305_BLOCK_SIZE)
      return;
    r_poly1305_blocks (ctx, ctx->buffer, R_POLY1305_BLOCK_SIZE);
    ctx->leftover = 0;
  }

  /* Bulk of whole blocks. */
  if (bytes >= R_POLY1305_BLOCK_SIZE) {
    rsize want = bytes & ~((rsize)R_POLY1305_BLOCK_SIZE - 1);
    r_poly1305_blocks (ctx, m, want);
    m += want;
    bytes -= want;
  }

  /* Stash the remainder. */
  for (i = 0; i < bytes; i++)
    ctx->buffer[ctx->leftover + i] = m[i];
  ctx->leftover += bytes;
}

void
r_poly1305_finish (RPoly1305Ctx * ctx, ruint8 mac[16])
{
  ruint32 h0, h1, h2, h3, h4, c;
  ruint32 g0, g1, g2, g3, g4;
  ruint32 mask;
  ruint64 f;

  /* Pad and process the trailing partial block: append 0x01, zero-fill,
   * clear the implicit high bit (final flag). */
  if (ctx->leftover > 0) {
    rsize i = ctx->leftover;
    ctx->buffer[i++] = 1;
    for (; i < R_POLY1305_BLOCK_SIZE; i++)
      ctx->buffer[i] = 0;
    ctx->final = 1;
    r_poly1305_blocks (ctx, ctx->buffer, R_POLY1305_BLOCK_SIZE);
  }

  /* Fully carry h. */
  h0 = ctx->h[0]; h1 = ctx->h[1]; h2 = ctx->h[2]; h3 = ctx->h[3]; h4 = ctx->h[4];

  c = h1 >> 26; h1 &= 0x3ffffff;
  h2 += c;      c = h2 >> 26; h2 &= 0x3ffffff;
  h3 += c;      c = h3 >> 26; h3 &= 0x3ffffff;
  h4 += c;      c = h4 >> 26; h4 &= 0x3ffffff;
  h0 += c * 5;  c = h0 >> 26; h0 &= 0x3ffffff;
  h1 += c;

  /* Compute h + -p (i.e. h - (2^130 - 5)) and keep it iff there was no borrow. */
  g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
  g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
  g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
  g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
  g4 = h4 + c - (1UL << 26);

  /* Select h if h < p (g underflowed, top bit set) else g, in constant time. */
  mask = (g4 >> ((sizeof (ruint32) * 8) - 1)) - 1;
  g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  /* Collapse the 26-bit limbs back into four 32-bit words. */
  h0 = ((h0      ) | (h1 << 26)) & 0xffffffff;
  h1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffff;
  h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
  h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

  /* mac = (h + s) mod 2^128. */
  f = (ruint64)h0 + ctx->pad[0];             h0 = (ruint32)f;
  f = (ruint64)h1 + ctx->pad[1] + (f >> 32); h1 = (ruint32)f;
  f = (ruint64)h2 + ctx->pad[2] + (f >> 32); h2 = (ruint32)f;
  f = (ruint64)h3 + ctx->pad[3] + (f >> 32); h3 = (ruint32)f;

  r_store_le32 (&mac[ 0], h0);
  r_store_le32 (&mac[ 4], h1);
  r_store_le32 (&mac[ 8], h2);
  r_store_le32 (&mac[12], h3);

  /* Wipe the accumulator and key-derived state. */
  r_memclear_secure (ctx, sizeof (*ctx));
}

void
r_poly1305_mac (ruint8 tag[R_POLY1305_TAG_SIZE],
    const ruint8 * msg, rsize size, const ruint8 key[R_POLY1305_KEY_SIZE])
{
  RPoly1305Ctx ctx;

  r_poly1305_init (&ctx, key);
  r_poly1305_update (&ctx, msg, size);
  r_poly1305_finish (&ctx, tag);
}
