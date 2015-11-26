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
#include "rlib-private.h"
#include <rlib/runicode.h>
#include <rlib/rmem.h>
#include <string.h>

/* FIXME: Implement BOM validation ByteOrderMark */

static inline ruint
r_unichar_to_utf8 (runichar c, rchar * str)
{
  if (c < 0x80) {
    str[0] = c;
    return 1;
  } else if (c < 0x800) {
    str[1] = ((c      ) & 0x3f) | 0x80;
    str[0] = ((c >>  6)         | 0xc0);
    return 2;
  } else if (c < 0x10000) {
    str[2] = ((c      ) & 0x3f) | 0x80;
    str[1] = ((c >>  6) & 0x3f) | 0x80;
    str[0] = ((c >> 12)         | 0xe0);
    return 3;
  } else if (c < 0x200000) {
    str[3] = ((c      ) & 0x3f) | 0x80;
    str[2] = ((c >>  6) & 0x3f) | 0x80;
    str[1] = ((c >> 12) & 0x3f) | 0x80;
    str[0] = ((c >> 18)         | 0xf0);
    return 4;
  } else if (c < 0x4000000) {
    str[4] = ((c      ) & 0x3f) | 0x80;
    str[3] = ((c >>  6) & 0x3f) | 0x80;
    str[2] = ((c >> 12) & 0x3f) | 0x80;
    str[1] = ((c >> 18) & 0x3f) | 0x80;
    str[0] = ((c >> 24)         | 0xf8);
    return 5;
  }

  str[5] = ((c      ) & 0x3f) | 0x80;
  str[4] = ((c >>  6) & 0x3f) | 0x80;
  str[3] = ((c >> 12) & 0x3f) | 0x80;
  str[2] = ((c >> 18) & 0x3f) | 0x80;
  str[1] = ((c >> 24) & 0x3f) | 0x80;
  str[0] = ((c >> 30)         | 0xfc);
  return 6;
}

static inline ruint
r_utf8_to_unichar (const rchar * utf8, rsize len, runichar * uc)
{
  if (len == 0)
    return 0;

  if (utf8[0] > 0) {
    *uc = (runichar)(utf8[0] & 0x7f);
    return 1;
  } else if ((utf8[0] & 0xe0) == 0xc0) {
    if (len < 2 || (utf8[1] & 0xc0) != 0x80)
      return 0;
    *uc  = (utf8[0] & 0x1f) << 6;
    *uc |= (utf8[1] & 0x3f);
    return 2;
  } else if ((utf8[0] & 0xf0) == 0xe0) {
    if (len < 3 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80)
      return 0;
    *uc  = (utf8[0] & 0x0f) << 12;
    *uc |= (utf8[1] & 0x3f) <<  6;
    *uc |= (utf8[2] & 0x3f);
    return 3;
  } else if ((utf8[0] & 0xf8) == 0xf0) {
    if (len < 4 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80 ||
        (utf8[3] & 0xc0) != 0x80)
      return 0;
    *uc  = (utf8[0] & 0x07) << 18;
    *uc |= (utf8[1] & 0x3f) << 12;
    *uc |= (utf8[2] & 0x3f) <<  6;
    *uc |= (utf8[3] & 0x3f);
    return 4;
  } else if ((utf8[0] & 0xfc) == 0xf8) {
    if (len < 5 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80 ||
        (utf8[3] & 0xc0) != 0x80 || (utf8[4] & 0xc0) != 0x80)
      return 0;
    *uc  = (utf8[0] & 0x03) << 24;
    *uc |= (utf8[1] & 0x3f) << 18;
    *uc |= (utf8[2] & 0x3f) << 12;
    *uc |= (utf8[3] & 0x3f) <<  6;
    *uc |= (utf8[4] & 0x3f);
    return 5;
  }

  if (len < 6 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80 ||
      (utf8[3] & 0xc0) != 0x80 || (utf8[4] & 0xc0) != 0x80 ||
      (utf8[5] & 0xc0) != 0x80)
    return 0;
  *uc  = (utf8[0] & 0x01) << 30;
  *uc |= (utf8[1] & 0x3f) << 24;
  *uc |= (utf8[2] & 0x3f) << 18;
  *uc |= (utf8[3] & 0x3f) << 12;
  *uc |= (utf8[4] & 0x3f) <<  6;
  *uc |= (utf8[5] & 0x3f);
  return 5;
}

rchar *
r_utf16_to_utf8 (const runichar2 * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen)
{
  rchar * pos, * ret;
  rlong i;

  if (retlen != NULL) *retlen = 0;
  if (inlen != NULL) *inlen = 0;
  if (len < 0) return NULL; /* FIXME */

  /* Converting from UTF16 limits to 0x0 - 0x10ffff meaning max 4byte UTF-8 */
  /* This is mpst likely over allocating, but then we don't need two loops   */
  if (R_UNLIKELY ((ret = r_malloc ((len+1) * 2)) == NULL))
    return NULL;

  for (i = 0, pos = ret; i < len; i++) {
    runichar2 c = str[i];

    if (c >= 0xd800 && c < 0xdc00) {
      runichar2 hc = c - 0xd800;
      if (R_UNLIKELY (++i >= len))
        goto utf16_error;

      c = str[i];
      if (c >= 0xdc00 && c < 0xe000) {
        pos += r_unichar_to_utf8 ((runichar)c-0xdc00 + 0x10000 + hc*0x400, pos);
      } else {
        goto utf16_error;
      }
    } else if (c == 0) {
      break;
    } else if (c >= 0xdc00 && c < 0xe000) {
      goto utf16_error;
    } else {
      pos += r_unichar_to_utf8 ((runichar)c, pos);
    }
  }

  if (error != NULL) *error = FALSE;
done:
  pos[0] = 0;
  if (retlen != NULL) *retlen = pos - ret;
  if (inlen != NULL) *inlen = i;
  return ret;

utf16_error:
  if (error != NULL) *error = TRUE;
  goto done;
}

runichar2 *
r_utf8_to_utf16 (const rchar * str, rlong len,
    rboolean * error, rlong * inlen, rlong * retlen)
{
  runichar2 * ret, * pos;
  rlong i, r;

  if (len < 0) len = strlen (str);
  if (retlen != NULL) *retlen = 0;
  if (inlen != NULL) *inlen = 0;

  if (R_UNLIKELY ((ret = r_mem_new_n (runichar2, len+1)) == NULL))
    return NULL;

  for (i = 0, pos = ret; i < len && str[i] != 0; i+=r) {
    runichar uc;

    if ((r = r_utf8_to_unichar (&str[i], len-i, &uc)) == 0)
      goto utf8_error;

    if (uc < 0x10000) {
      *pos++ = (runichar2)uc & 0xffff;
    } else if (uc < 0x110000) {
      *pos++ = ((uc - 0x10000) / 0x400) | 0xd800;
      *pos++ = ((uc - 0x10000) % 0x400) | 0xdc00;
    } else {
      goto utf8_error;
    }
  }

  if (error != NULL) *error = FALSE;
done:
  pos[0] = 0;
  if (retlen != NULL) *retlen = pos - ret;
  if (inlen != NULL) *inlen = i;
  return ret;

utf8_error:
  if (error != NULL) *error = TRUE;
  goto done;
}

