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

static const ruint8 base64_dec_table[256] = {
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
  255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
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

rchar *
r_base64_encode (rconstpointer data, rsize size, rsize * outsize)
{
  if (data != NULL && size != 0) {
    rsize s = ((size + 2) / 3) * 4 + 1;
    if (s > size) {
      rchar * ret;

      if ((ret = r_malloc (s)) != NULL) {
        const ruint8 * src = data;
        rchar * dst = ret;
        for (; size >= 3; size -= 3, src += 3) {
          *dst++ = base64_enc_table[(src[0] & 0xfc) >> 2];
          *dst++ = base64_enc_table[((src[0] & 0x03) << 4) | ((src[1] & 0xf0) >> 4)];
          *dst++ = base64_enc_table[((src[1] & 0x0F) << 2) | ((src[2] & 0xc0) >> 6)];
          *dst++ = base64_enc_table[(src[2] & 0x3f)];
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

        ret[--s] = 0;
        if (outsize != NULL)
          *outsize = s;
        return ret;
      }
    }
  }

  return NULL;
}

ruint8 *
r_base64_decode (const rchar * data, rssize size, rsize * outsize)
{
  if (data != NULL && size != 0) {
    ruint8 * ret;

    if (size < 0)
      size = r_strlen (data);

    if ((ret = r_malloc (((size / 4) + 1) * 3)) != NULL) {
      const rchar * src = data, * end = data + size;
      ruint8 * dst = ret;
      int i;

      do {
        /* fill scratch */
        ruint8 c, scratch[4] = { 0, 0, 0, 0 };
        for (i = 0; src < end && i < 4;) {
          if ((c = base64_dec_table[(ruint8)*src++]) != 255) {
            if (c < 64) {
              scratch[i] = c;
              i++;
            } else { /* c == -42 (special for '=') */
              src = end;
              break;
            }
          }
        }

        *dst++ = ((scratch[0] << 2) & 0xfc) | ((scratch[1] >> 4) & 0x03);
        *dst++ = ((scratch[1] << 4) & 0xf0) | ((scratch[2] >> 2) & 0x0f);
        *dst++ = ((scratch[2] << 6) & 0xc0) | ((scratch[3] >> 0) & 0x3f);
      } while (src < end);

      /* adjust dst if some bits from src/scratch not used */
      dst -= ((24 - i * 6) + 7) / 8;
      if (outsize != NULL)
        *outsize = dst - ret;
      return ret;
    }
  }

  return NULL;
}

