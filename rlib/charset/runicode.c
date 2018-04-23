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
#include <rlib/charset/runicode.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

/* FIXME: Implement BOM validation ByteOrderMark */

static inline rssize
r_unichar_to_utf8 (runichar c, rchar * str, rsize size)
{
  if (c < 0x80) {
    if (size < 1)
      return -1;
    str[0] = c;
    return 1;
  } else if (c < 0x800) {
    if (size < 2)
      return -1;
    str[1] = ((c      ) & 0x3f) | 0x80;
    str[0] = ((c >>  6)         | 0xc0);
    return 2;
  } else if (c < 0x10000) {
    if (size < 3)
      return -1;
    str[2] = ((c      ) & 0x3f) | 0x80;
    str[1] = ((c >>  6) & 0x3f) | 0x80;
    str[0] = ((c >> 12)         | 0xe0);
    return 3;
  } else if (c < 0x200000) {
    if (size < 4)
      return -1;
    str[3] = ((c      ) & 0x3f) | 0x80;
    str[2] = ((c >>  6) & 0x3f) | 0x80;
    str[1] = ((c >> 12) & 0x3f) | 0x80;
    str[0] = ((c >> 18)         | 0xf0);
    return 4;
  } else if (c < 0x4000000) {
    if (size < 5)
      return -1;
    str[4] = ((c      ) & 0x3f) | 0x80;
    str[3] = ((c >>  6) & 0x3f) | 0x80;
    str[2] = ((c >> 12) & 0x3f) | 0x80;
    str[1] = ((c >> 18) & 0x3f) | 0x80;
    str[0] = ((c >> 24)         | 0xf8);
    return 5;
  }

  if (size < 6)
    return -1;
  str[5] = ((c      ) & 0x3f) | 0x80;
  str[4] = ((c >>  6) & 0x3f) | 0x80;
  str[3] = ((c >> 12) & 0x3f) | 0x80;
  str[2] = ((c >> 18) & 0x3f) | 0x80;
  str[1] = ((c >> 24) & 0x3f) | 0x80;
  str[0] = ((c >> 30)         | 0xfc);
  return 6;
}

static inline rssize
r_utf8_to_unichar (const rchar * utf8, rsize size, runichar * uc)
{
  if (size == 0)
    return 0;

  if (utf8[0] > 0) {
    *uc = (runichar)(utf8[0] & 0x7f);
    return 1;
  } else if ((utf8[0] & 0xe0) == 0xc0) {
    if (size < 2 || (utf8[1] & 0xc0) != 0x80)
      return -1;
    *uc  = (utf8[0] & 0x1f) << 6;
    *uc |= (utf8[1] & 0x3f);
    return 2;
  } else if ((utf8[0] & 0xf0) == 0xe0) {
    if (size < 3 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80)
      return -1;
    *uc  = (utf8[0] & 0x0f) << 12;
    *uc |= (utf8[1] & 0x3f) <<  6;
    *uc |= (utf8[2] & 0x3f);
    return 3;
  } else if ((utf8[0] & 0xf8) == 0xf0) {
    if (size < 4 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80 ||
        (utf8[3] & 0xc0) != 0x80)
      return -1;
    *uc  = (utf8[0] & 0x07) << 18;
    *uc |= (utf8[1] & 0x3f) << 12;
    *uc |= (utf8[2] & 0x3f) <<  6;
    *uc |= (utf8[3] & 0x3f);
    return 4;
  } else if ((utf8[0] & 0xfc) == 0xf8) {
    if (size < 5 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80 ||
        (utf8[3] & 0xc0) != 0x80 || (utf8[4] & 0xc0) != 0x80)
      return -1;
    *uc  = (utf8[0] & 0x03) << 24;
    *uc |= (utf8[1] & 0x3f) << 18;
    *uc |= (utf8[2] & 0x3f) << 12;
    *uc |= (utf8[3] & 0x3f) <<  6;
    *uc |= (utf8[4] & 0x3f);
    return 5;
  }

  if (size < 6 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80 ||
      (utf8[3] & 0xc0) != 0x80 || (utf8[4] & 0xc0) != 0x80 ||
      (utf8[5] & 0xc0) != 0x80)
    return -1;
  *uc  = (utf8[0] & 0x01) << 30;
  *uc |= (utf8[1] & 0x3f) << 24;
  *uc |= (utf8[2] & 0x3f) << 18;
  *uc |= (utf8[3] & 0x3f) << 12;
  *uc |= (utf8[4] & 0x3f) <<  6;
  *uc |= (utf8[5] & 0x3f);
  return 5;
}


RUnicodeResult
r_utf8_to_utf16 (runichar2 * dst, rsize dstsize, const rchar * src, rssize srcsize,
    rsize * dstoutsize, rchar ** srcendptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  runichar2 * dstptr, * dstend;
  rssize i, r;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  if (srcsize < 0)
    srcsize = r_strlen (src);

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] != 0;
      i += r) {
    runichar uc;

    if ((r = r_utf8_to_unichar (&src[i], srcsize - i, &uc)) > 0) {
      if (uc <= 0xffff) {
        if (dstptr + 1 > dstend) {
          ret = R_UNICODE_OVERFLOW;
          break;
        }
        *dstptr++ = (runichar2)uc & 0xffff;
      } else if (uc < 0x110000) {
        if (dstptr + 2 > dstend) {
          ret = R_UNICODE_OVERFLOW;
          break;
        }
        *dstptr++ = ((uc - 0x10000) / 0x400) | 0xd800;
        *dstptr++ = ((uc - 0x10000) % 0x400) | 0xdc00;
      } else {
        ret = R_UNICODE_INVALID_CODE_POINT;
        break;
      }
    } else if (r == 0) {
      break;
    } else {
      ret = R_UNICODE_INCOMPLETE_CODE_POINT;
      break;
    }
  }

  *dstptr = 0;

  if (dstoutsize != NULL)
    *dstoutsize = dstptr - dst;
  if (srcendptr != NULL)
    *srcendptr = (rchar *)&src[i];

  return ret;
}

RUnicodeResult
r_utf16_to_utf8 (rchar * dst, rsize dstsize, const runichar2 * src, rsize srcsize,
    rsize * dstoutsize, runichar2 ** srcendptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  rchar * dstptr, * dstend;
  rssize i, r;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] > 0;
      i++, dstptr += r) {
    if (src[i] < 0xd800) {
      r = r_unichar_to_utf8 ((runichar)src[i], dstptr, dstend - dstptr);
    } else if (src[i] < 0xdc00) {
      runichar2 hc = src[i] - 0xd800;

      if (++i < srcsize && src[i] >= 0xdc00 && src[i] < 0xe000) {
        runichar uc = (runichar)src[i] - 0xdc00 + 0x10000 + (hc << 10);
        r = r_unichar_to_utf8 (uc, dstptr, dstend - dstptr);
      } else {
        ret = R_UNICODE_INCOMPLETE_CODE_POINT;
        break;
      }
    } else if (src[i] < 0xe000) {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    } else {
      r = r_unichar_to_utf8 ((runichar)src[i], dstptr, dstend - dstptr);
    }

    if (r <= 0) {
      ret = R_UNICODE_OVERFLOW;
      break;
    }
  }

  *dstptr = 0;

  if (dstoutsize != NULL)
    *dstoutsize = dstptr - dst;
  if (srcendptr != NULL)
    *srcendptr = (runichar2 *)&src[i];

  return ret;
}

runichar2
* r_utf8_to_utf16_dup (const rchar * src, rssize srcsize,
    RUnicodeResult * res, rsize * retsize, rchar ** endptr)
{
  runichar2 * ret;
  RUnicodeResult r;

  if (srcsize < 0)
    srcsize = r_strlen (src);

  if ((ret = r_mem_new_n (runichar2, srcsize + 1)) != NULL) {
    if ((r = r_utf8_to_utf16 (ret, srcsize + 1, src, srcsize, retsize, endptr)) != R_UNICODE_OK) {
      r_free (ret);
      ret = NULL;
    }
  } else {
    r = R_UNICODE_OOM;
  }

  if (res != NULL)
    *res = r;
  return ret;
}

rchar *
r_utf16_to_utf8_dup (const runichar2 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar2 ** endptr)
{
  rchar * ret;
  RUnicodeResult r;
  rsize dstsize;

  if (R_UNLIKELY (src == NULL || srcsize == 0)) {
    if (res != NULL) *res = R_UNICODE_INVAL;
    return NULL;
  }

  dstsize = (srcsize + 1) * 4;

  /* Converting from UTF16 limits to 0x0 - 0x10ffff meaning max 4byte UTF-8 */
  if ((ret = r_mem_new_n (rchar, dstsize)) != NULL) {
    if ((r = r_utf16_to_utf8 (ret, dstsize, src, srcsize, retsize, endptr)) != R_UNICODE_OK) {
      r_free (ret);
      ret = NULL;
    }
  } else {
    r = R_UNICODE_OOM;
  }

  if (res != NULL)
    *res = r;
  return ret;
}

