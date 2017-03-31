/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/rbase64.h>
#include <rlib/rstr.h>
#include <rlib/rtty.h>

static const rchar base64_enc_table[] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#define R_BASE64_BYTE_INVALID    255
#define R_BASE64_BYTE_PADDING    214
#define R_BASE64_BYTE_SPACE      111

static const ruint8 base64_dec_table[256] = {
  255,255,255,255,255,255,255,255,255,111,111,255,111,111,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  111,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
   52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,214,255,255,
  255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
   15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

rboolean
r_base64_is_valid_char (rchar ch)
{
  return base64_dec_table[(ruint8)ch] < 64;
}

rsize
r_base64_encode (rchar * dst, rsize dsize, rconstpointer data, rsize size)
{
  const ruint8 * src;
  rchar * ptr;

  if (R_UNLIKELY (dst == NULL)) return 0;
  if (R_UNLIKELY (data == NULL)) return 0;

  for (ptr = dst, src = data; size >= 3 && dsize >= 4; dsize -= 4, size -= 3, src += 3) {
    *ptr++ = base64_enc_table[(src[0] & 0xfc) >> 2];
    *ptr++ = base64_enc_table[((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4)];
    *ptr++ = base64_enc_table[((src[1] & 0x0F) << 2) | ((src[2] & 0xc0) >> 6)];
    *ptr++ = base64_enc_table[(src[2] & 0x3f)];
  }

  if (dsize >= 4) {
    if (size == 2) {
      *ptr++ = base64_enc_table[(src[0] & 0xfc) >> 2];
      *ptr++ = base64_enc_table[((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4)];
      *ptr++ = base64_enc_table[((src[1] & 0x0F) << 2)];
      *ptr++ = '=';
    } else if (size == 1) {
      *ptr++ = base64_enc_table[(src[0] & 0xfc) >> 2];
      *ptr++ = base64_enc_table[((src[0] & 0x03) << 4)];
      *ptr++ = '=';
      *ptr++ = '=';
    }
  }

  return RPOINTER_TO_SIZE (ptr - dst);
}

rsize
r_base64_decode (ruint8 * dst, rsize dsize, const rchar * data, rssize size)
{
  ruint8 c, scratch[4] = { 0, 0, 0, 0 };
  const rchar * src = data, * srcend;
  ruint8 * ptr = dst;
  int i;

  if (size < 0) size = r_strlen (data);
  srcend = src + size;

  while (src < srcend) {
    /* fill scratch */
    for (i = 0; i < 4;) {
      if (R_UNLIKELY (src >= srcend))
        goto tail;
      else if ((c = base64_dec_table[(ruint8)*src++]) < 64)
        scratch[i++] = c;
      else if (c == R_BASE64_BYTE_SPACE)
        continue;
      else /* c == 214 (-42) (special for '=') or invalid */
        goto tail;
    }

    if (ptr + 3 > dst + dsize)
      break;
    *ptr++ = ((scratch[0] << 2) & 0xfc) | ((scratch[1] >> 4) & 0x03);
    *ptr++ = ((scratch[1] << 4) & 0xf0) | ((scratch[2] >> 2) & 0x0f);
    *ptr++ = ((scratch[2] << 6) & 0xc0) | ((scratch[3] >> 0) & 0x3f);
  }

  goto beach;

tail:
  if (i == 3) {
    if (ptr < dst + dsize)
      *ptr++ = ((scratch[0] << 2) & 0xfc) | ((scratch[1] >> 4) & 0x03);
    if (ptr < dst + dsize)
      *ptr++ = ((scratch[1] << 4) & 0xf0) | ((scratch[2] >> 2) & 0x0f);
  } else if (i == 2) {
    if (ptr < dst + dsize)
      *ptr++ = ((scratch[0] << 2) & 0xfc) | ((scratch[1] >> 4) & 0x03);
  }

beach:
  return RPOINTER_TO_SIZE (ptr - dst);
}

rchar *
r_base64_encode_dup (rconstpointer data, rsize size, rsize * outsize)
{
  if (data != NULL && size != 0) {
    rsize s = ((size + 2) / 3) * 4 + 1;
    if (s > size) {
      rchar * ret;

      if ((ret = r_malloc (s)) != NULL) {
        if (r_base64_encode (ret, s, data, size) == s - 1) {
          ret[--s] = 0;
          if (outsize != NULL)
            *outsize = s;
          return ret;
        }

        r_free (ret);
      }
    }
  }

  return NULL;
}

rchar *
r_base64_encode_dup_full (rconstpointer data, rsize size, rsize linesize, rsize * outsize)
{
  if (linesize == 0)
    return r_base64_encode_dup (data, size, outsize);

  if (data != NULL && size != 0) {
    rchar * ret;
    rsize s = ((size + 2) / 3) * 4;

    s += s / ((linesize + 3) & ~3);
    s++;

    if ((ret = r_malloc (s)) != NULL) {
      const ruint8 * src = data;
      rchar * dst = ret;
      rsize lpos;

      for (lpos = 0; size >= 3; size -= 3, src += 3) {
        *dst++ = base64_enc_table[(src[0] & 0xfc) >> 2];
        *dst++ = base64_enc_table[((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4)];
        *dst++ = base64_enc_table[((src[1] & 0x0F) << 2) | ((src[2] & 0xc0) >> 6)];
        *dst++ = base64_enc_table[(src[2] & 0x3f)];

        lpos += 4;
        if (lpos >= linesize) {
          if (size > 3)
            *dst++ = '\n';
          lpos = 0;
        }
      }

      if (size == 2) {
        *dst++ = base64_enc_table[(src[0] & 0xfc) >> 2];
        *dst++ = base64_enc_table[((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4)];
        *dst++ = base64_enc_table[((src[1] & 0x0F) << 2)];
        *dst++ = '=';
      } else if (size == 1) {
        *dst++ = base64_enc_table[(src[0] & 0xfc) >> 2];
        *dst++ = base64_enc_table[((src[0] & 0x03) << 4)];
        *dst++ = '=';
        *dst++ = '=';
      }

      *dst = 0;
      if (outsize != NULL)
        *outsize = RPOINTER_TO_SIZE (dst) - RPOINTER_TO_SIZE (ret);
      return ret;
    }
  }

  return NULL;
}

ruint8 *
r_base64_decode_dup (const rchar * data, rssize size, rsize * outsize)
{
  ruint8 * ret;
  rsize dsize;

  if (R_UNLIKELY (data == NULL)) return NULL;
  if (size < 0) size = r_strlen (data);
  if (R_UNLIKELY (size == 0)) return NULL;

  dsize = ((size / 4) + 1) * 3;

  if ((ret = r_malloc (dsize)) != NULL) {
    dsize = r_base64_decode (ret, dsize, data, size);
    ret[dsize] = 0;
    if (outsize != NULL)
      *outsize = dsize;
  }

  return ret;
}

