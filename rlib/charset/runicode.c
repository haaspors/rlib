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

/* Optional Byte Order Marks (Unicode TR #38).  rlib's UTF-16 API takes
 * a typed runichar2 (native ruint16) array, so the byte order is fixed by
 * the type and the BOM exists only to convey "this is text" / strip
 * convention.  We silently consume a leading native-order BOM (U+FEFF)
 * and refuse the byte-swapped form (0xFFFE) since it signals input the
 * caller fed us in the wrong endianness.  For UTF-8 the BOM is the
 * three-byte sequence EF BB BF -- also silently stripped if leading. */
#define R_UTF16_BOM       0xFEFFu
#define R_UTF16_BOM_SWAP  0xFFFEu

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

/* Sentinel returned by r_utf8_to_unichar for sequences that decode
 * to a valid bit pattern but whose canonical form would be shorter
 * (RFC 3629 §3 overlong forms). Caller flags as
 * R_UNICODE_INVALID_CODE_POINT. */
#define R_UTF8_OVERLONG  (-2)

static inline rssize
r_utf8_to_unichar (const rchar * utf8, rsize size, runichar * uc)
{
  if (size == 0)
    return 0;

  /* High-bit-clear means single-byte ASCII; testing against 0x80
   * directly avoids depending on whether `char` is signed (AArch64
   * defaults to unsigned, x86 to signed). */
  if ((utf8[0] & 0x80) == 0) {
    *uc = (runichar)(utf8[0] & 0x7f);
    return 1;
  } else if ((utf8[0] & 0xe0) == 0xc0) {
    if (size < 2 || (utf8[1] & 0xc0) != 0x80)
      return -1;
    *uc  = (utf8[0] & 0x1f) << 6;
    *uc |= (utf8[1] & 0x3f);
    /* Overlong: a 2-byte encoding of U+0000..U+007F (RFC 3629 §3). */
    if (*uc < 0x80)
      return R_UTF8_OVERLONG;
    return 2;
  } else if ((utf8[0] & 0xf0) == 0xe0) {
    if (size < 3 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80)
      return -1;
    *uc  = (utf8[0] & 0x0f) << 12;
    *uc |= (utf8[1] & 0x3f) <<  6;
    *uc |= (utf8[2] & 0x3f);
    if (*uc < 0x800)
      return R_UTF8_OVERLONG;
    return 3;
  } else if ((utf8[0] & 0xf8) == 0xf0) {
    if (size < 4 || (utf8[1] & 0xc0) != 0x80 || (utf8[2] & 0xc0) != 0x80 ||
        (utf8[3] & 0xc0) != 0x80)
      return -1;
    *uc  = (utf8[0] & 0x07) << 18;
    *uc |= (utf8[1] & 0x3f) << 12;
    *uc |= (utf8[2] & 0x3f) <<  6;
    *uc |= (utf8[3] & 0x3f);
    if (*uc < 0x10000)
      return R_UTF8_OVERLONG;
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
    if (*uc < 0x200000)
      return R_UTF8_OVERLONG;
    return 5;
  }

  /* Pre-RFC-3629 legacy 6-byte sequence. RFC 3629 forbids these,
   * but the rest of the decoder accepts them and lets the caller
   * reject via the canonical >= 0x110000 check. Stay backwards-
   * compatible here; the overlong-vs-canonical distinction still
   * applies. */
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
  if (*uc < 0x4000000)
    return R_UTF8_OVERLONG;
  return 6;
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

  /* Strip a leading UTF-8 BOM (EF BB BF). */
  if (srcsize >= 3 &&
      (ruint8) src[0] == 0xef &&
      (ruint8) src[1] == 0xbb &&
      (ruint8) src[2] == 0xbf) {
    src += 3;
    srcsize -= 3;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] != 0;
      i += r) {
    runichar uc;

    if ((r = r_utf8_to_unichar (&src[i], srcsize - i, &uc)) > 0) {
      /* Reject UTF-8-encoded UTF-16 surrogates and non-Unicode
       * codepoints (RFC 3629 §3 / Unicode Standard §3.9). */
      if ((uc >= 0xd800 && uc < 0xe000) || uc >= 0x110000) {
        ret = R_UNICODE_INVALID_CODE_POINT;
        break;
      }
      if (uc <= 0xffff) {
        if (dstptr + 1 > dstend) {
          ret = R_UNICODE_OVERFLOW;
          break;
        }
        *dstptr++ = (runichar2)uc & 0xffff;
      } else {
        if (dstptr + 2 > dstend) {
          ret = R_UNICODE_OVERFLOW;
          break;
        }
        *dstptr++ = ((uc - 0x10000) / 0x400) | 0xd800;
        *dstptr++ = ((uc - 0x10000) % 0x400) | 0xdc00;
      }
    } else if (r == 0) {
      break;
    } else if (r == R_UTF8_OVERLONG) {
      ret = R_UNICODE_INVALID_CODE_POINT;
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
  rsize i;
  rssize r;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  if (srcsize > 0) {
    if (src[0] == R_UTF16_BOM_SWAP)
      return R_UNICODE_INVAL;
    if (src[0] == R_UTF16_BOM) {
      src++;
      srcsize--;
    }
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


/* ---- UTF-32 conversions -------------------------------------------- */

/* UTF-32 is one codepoint per code unit, so the conversions are
 * straightforward: pair (decode-from-N, encode-as-32) or (decode-
 * from-32, encode-as-N). The only validation specific to the UTF-32
 * side is rejecting out-of-range (>= 0x110000) and surrogate-half
 * (0xD800..0xDFFF) values - both flagged as
 * R_UNICODE_INVALID_CODE_POINT. */

RUnicodeResult
r_utf8_to_utf32 (runichar4 * dst, rsize dstsize, const rchar * src,
    rssize srcsize, rsize * dstoutsize, rchar ** srcendptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  runichar4 * dstptr, * dstend;
  rssize i, r;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  if (srcsize < 0)
    srcsize = r_strlen (src);

  /* Strip a leading UTF-8 BOM (EF BB BF). */
  if (srcsize >= 3 &&
      (ruint8) src[0] == 0xef &&
      (ruint8) src[1] == 0xbb &&
      (ruint8) src[2] == 0xbf) {
    src += 3;
    srcsize -= 3;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] != 0;
      i += r) {
    runichar uc;

    if ((r = r_utf8_to_unichar (&src[i], srcsize - i, &uc)) > 0) {
      if (uc >= 0x110000 || (uc >= 0xd800 && uc < 0xe000)) {
        ret = R_UNICODE_INVALID_CODE_POINT;
        break;
      }
      if (dstptr >= dstend) {
        ret = R_UNICODE_OVERFLOW;
        break;
      }
      *dstptr++ = (runichar4)uc;
    } else if (r == 0) {
      break;
    } else if (r == R_UTF8_OVERLONG) {
      ret = R_UNICODE_INVALID_CODE_POINT;
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
r_utf32_to_utf8 (rchar * dst, rsize dstsize, const runichar4 * src,
    rsize srcsize, rsize * dstoutsize, runichar4 ** srcendptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  rchar * dstptr, * dstend;
  rsize i;
  rssize r = 0;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  /* Optional UTF-32 BOM at the start (single 0xFEFF code unit). */
  if (srcsize > 0 && src[0] == R_UTF16_BOM) {
    src++;
    srcsize--;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] != 0;
      i++, dstptr += r) {
    runichar uc = (runichar)src[i];

    if (uc >= 0x110000 || (uc >= 0xd800 && uc < 0xe000)) {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }
    r = r_unichar_to_utf8 (uc, dstptr, dstend - dstptr);
    if (r <= 0) {
      ret = R_UNICODE_OVERFLOW;
      break;
    }
  }

  *dstptr = 0;

  if (dstoutsize != NULL)
    *dstoutsize = dstptr - dst;
  if (srcendptr != NULL)
    *srcendptr = (runichar4 *)&src[i];

  return ret;
}

RUnicodeResult
r_utf16_to_utf32 (runichar4 * dst, rsize dstsize, const runichar2 * src,
    rsize srcsize, rsize * dstoutsize, runichar2 ** srcendptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  runichar4 * dstptr, * dstend;
  rsize i;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  if (srcsize > 0) {
    if (src[0] == R_UTF16_BOM_SWAP)
      return R_UNICODE_INVAL;
    if (src[0] == R_UTF16_BOM) {
      src++;
      srcsize--;
    }
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] > 0;
      ) {
    runichar uc;

    if (src[i] < 0xd800 || src[i] >= 0xe000) {
      uc = (runichar)src[i];
      i++;
    } else if (src[i] < 0xdc00) {
      runichar2 hc = src[i] - 0xd800;
      if (i + 1 < srcsize && src[i + 1] >= 0xdc00 && src[i + 1] < 0xe000) {
        uc = (runichar)src[i + 1] - 0xdc00 + 0x10000 + ((runichar)hc << 10);
        i += 2;
      } else {
        ret = R_UNICODE_INCOMPLETE_CODE_POINT;
        break;
      }
    } else {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }

    if (dstptr >= dstend) {
      ret = R_UNICODE_OVERFLOW;
      break;
    }
    *dstptr++ = (runichar4)uc;
  }

  *dstptr = 0;

  if (dstoutsize != NULL)
    *dstoutsize = dstptr - dst;
  if (srcendptr != NULL)
    *srcendptr = (runichar2 *)&src[i];

  return ret;
}

RUnicodeResult
r_utf32_to_utf16 (runichar2 * dst, rsize dstsize, const runichar4 * src,
    rsize srcsize, rsize * dstoutsize, runichar4 ** srcendptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  runichar2 * dstptr, * dstend;
  rsize i;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  if (srcsize > 0 && src[0] == R_UTF16_BOM) {
    src++;
    srcsize--;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] != 0;
      i++) {
    runichar uc = (runichar)src[i];

    if (uc >= 0x110000 || (uc >= 0xd800 && uc < 0xe000)) {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }

    if (uc < 0x10000) {
      if (dstptr >= dstend) {
        ret = R_UNICODE_OVERFLOW;
        break;
      }
      *dstptr++ = (runichar2)uc;
    } else {
      if (dstptr + 1 >= dstend) {
        ret = R_UNICODE_OVERFLOW;
        break;
      }
      *dstptr++ = ((uc - 0x10000) / 0x400) | 0xd800;
      *dstptr++ = ((uc - 0x10000) % 0x400) | 0xdc00;
    }
  }

  *dstptr = 0;

  if (dstoutsize != NULL)
    *dstoutsize = dstptr - dst;
  if (srcendptr != NULL)
    *srcendptr = (runichar4 *)&src[i];

  return ret;
}

runichar4 *
r_utf8_to_utf32_dup (const rchar * src, rssize srcsize, RUnicodeResult * res,
    rsize * retsize, rchar ** endptr)
{
  runichar4 * ret;
  RUnicodeResult r;

  if (srcsize < 0)
    srcsize = r_strlen (src);

  /* Worst case: one UTF-32 unit per source byte (ASCII fast path),
   * plus the NUL terminator. */
  if ((ret = r_mem_new_n (runichar4, srcsize + 1)) != NULL) {
    if ((r = r_utf8_to_utf32 (ret, srcsize + 1, src, srcsize, retsize, endptr))
        != R_UNICODE_OK) {
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
r_utf32_to_utf8_dup (const runichar4 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar4 ** endptr)
{
  rchar * ret;
  RUnicodeResult r;
  rsize dstsize;

  if (R_UNLIKELY (src == NULL || srcsize == 0)) {
    if (res != NULL) *res = R_UNICODE_INVAL;
    return NULL;
  }

  /* Codepoints in [0, 0x10FFFF] encode to at most 4 UTF-8 bytes,
   * plus the trailing NUL. */
  dstsize = srcsize * 4 + 1;

  if ((ret = r_mem_new_n (rchar, dstsize)) != NULL) {
    if ((r = r_utf32_to_utf8 (ret, dstsize, src, srcsize, retsize, endptr))
        != R_UNICODE_OK) {
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

runichar4 *
r_utf16_to_utf32_dup (const runichar2 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar2 ** endptr)
{
  runichar4 * ret;
  RUnicodeResult r;

  if (R_UNLIKELY (src == NULL || srcsize == 0)) {
    if (res != NULL) *res = R_UNICODE_INVAL;
    return NULL;
  }

  /* Worst case: one UTF-32 unit per UTF-16 unit (no surrogate
   * pairs), plus the NUL terminator. */
  if ((ret = r_mem_new_n (runichar4, srcsize + 1)) != NULL) {
    if ((r = r_utf16_to_utf32 (ret, srcsize + 1, src, srcsize, retsize, endptr))
        != R_UNICODE_OK) {
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

runichar2 *
r_utf32_to_utf16_dup (const runichar4 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar4 ** endptr)
{
  runichar2 * ret;
  RUnicodeResult r;
  rsize dstsize;

  if (R_UNLIKELY (src == NULL || srcsize == 0)) {
    if (res != NULL) *res = R_UNICODE_INVAL;
    return NULL;
  }

  /* Codepoints outside the BMP encode to a surrogate pair (2 units),
   * plus the trailing NUL. */
  dstsize = srcsize * 2 + 1;

  if ((ret = r_mem_new_n (runichar2, dstsize)) != NULL) {
    if ((r = r_utf32_to_utf16 (ret, dstsize, src, srcsize, retsize, endptr))
        != R_UNICODE_OK) {
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
