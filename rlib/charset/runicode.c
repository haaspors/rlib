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

/* RFC 3629 caps Unicode codepoints at U+10FFFF, which encodes in
 * at most 4 UTF-8 bytes. All callers in this file pass codepoints
 * they have already validated against that bound; an out-of-range
 * value here returns -1 rather than falling back to pre-RFC-3629
 * 5- or 6-byte encodings. */
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
  } else if (c < 0x110000) {
    if (size < 4)
      return -1;
    str[3] = ((c      ) & 0x3f) | 0x80;
    str[2] = ((c >>  6) & 0x3f) | 0x80;
    str[1] = ((c >> 12) & 0x3f) | 0x80;
    str[0] = ((c >> 18)         | 0xf0);
    return 4;
  }

  return -1;
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
  }

  /* Lead bytes 0xF8..0xFF are forbidden by RFC 3629 §3: 5- and
   * 6-byte sequences only existed in pre-3629 UTF-8 and can only
   * encode codepoints >= U+200000, well outside the Unicode range.
   * Reject up-front. */
  return -1;
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
      /* High surrogate. Peek at the next unit without consuming - if
       * the pair is incomplete we want srcendptr to point at this
       * high surrogate so the caller can resume from here once more
       * UTF-16 units arrive. */
      if (i + 1 < srcsize && src[i + 1] >= 0xdc00 && src[i + 1] < 0xe000) {
        runichar2 hc = src[i] - 0xd800;
        runichar uc = (runichar)src[i + 1] - 0xdc00 + 0x10000 + (hc << 10);
        r = r_unichar_to_utf8 (uc, dstptr, dstend - dstptr);
        i++;            /* consume the low surrogate; outer loop bumps for the high */
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

/* ---- Validation entry points ---------------------------------------
 * Scan-only counterparts to the conversion functions. The byte- /
 * code-unit-level scan is the same in either case; the converters
 * have an extra "encode into destination" step that the validators
 * skip. Implemented standalone here (rather than calling the
 * conversion functions with a sink destination) to avoid the
 * destination-buffer threading and to make the streaming srcendptr
 * semantics explicit. */

RUnicodeResult
r_utf8_validate (const rchar * src, rssize size, rchar ** endptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  rssize i, r;
  runichar uc;

  if (R_UNLIKELY (src == NULL))
    return R_UNICODE_INVAL;
  if (size < 0)
    size = r_strlen (src);

  /* Strip a leading UTF-8 BOM (matches r_utf8_to_utf16's behaviour). */
  if (size >= 3 &&
      (ruint8) src[0] == 0xef &&
      (ruint8) src[1] == 0xbb &&
      (ruint8) src[2] == 0xbf) {
    src += 3;
    size -= 3;
  }

  for (i = 0; i < size && src[i] != 0; i += r) {
    r = r_utf8_to_unichar (&src[i], size - i, &uc);
    if (r > 0) {
      if ((uc >= 0xd800 && uc < 0xe000) || uc >= 0x110000) {
        ret = R_UNICODE_INVALID_CODE_POINT;
        break;
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

  if (endptr != NULL)
    *endptr = (rchar *)&src[i];
  return ret;
}

RUnicodeResult
r_utf16_validate (const runichar2 * src, rsize size, runichar2 ** endptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  rsize i = 0;

  if (R_UNLIKELY (src == NULL))
    return R_UNICODE_INVAL;

  if (size > 0) {
    if (src[0] == R_UTF16_BOM_SWAP)
      return R_UNICODE_INVAL;
    if (src[0] == R_UTF16_BOM) {
      src++;
      size--;
    }
  }

  while (i < size && src[i] != 0) {
    if (src[i] < 0xd800 || src[i] >= 0xe000) {
      i++;
    } else if (src[i] < 0xdc00) {
      if (i + 1 < size && src[i + 1] >= 0xdc00 && src[i + 1] < 0xe000) {
        i += 2;
      } else {
        ret = R_UNICODE_INCOMPLETE_CODE_POINT;
        break;
      }
    } else {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }
  }

  if (endptr != NULL)
    *endptr = (runichar2 *)&src[i];
  return ret;
}

RUnicodeResult
r_utf32_validate (const runichar4 * src, rsize size, runichar4 ** endptr)
{
  RUnicodeResult ret = R_UNICODE_OK;
  rsize i = 0;

  if (R_UNLIKELY (src == NULL))
    return R_UNICODE_INVAL;

  /* UTF-32 BOM is a single 0xFEFF code unit at the start. */
  if (size > 0 && src[0] == R_UTF16_BOM) {
    src++;
    size--;
  }

  for (; i < size && src[i] != 0; i++) {
    if (src[i] >= 0x110000 || (src[i] >= 0xd800 && src[i] < 0xe000)) {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }
  }

  if (endptr != NULL)
    *endptr = (runichar4 *)&src[i];
  return ret;
}

/* ---- Single-codepoint encode / decode ------------------------------
 * Public wrappers around the file-private r_utf8_to_unichar /
 * r_unichar_to_utf8. The wrappers translate the int32 -1 / -2
 * sentinels into RUnicodeResult, validate the codepoint against the
 * surrogate / range exclusions on the encode side, and provide UTF-16
 * pair-aware siblings so callers can drive their own iteration. */

RUnicodeResult
r_utf8_decode_codepoint (const rchar * src, rsize size, runichar4 * uc,
    rsize * consumed)
{
  rssize r;
  runichar tmp;

  if (R_UNLIKELY (src == NULL || uc == NULL || size == 0))
    return R_UNICODE_INVAL;

  r = r_utf8_to_unichar (src, size, &tmp);
  if (r > 0) {
    if ((tmp >= 0xd800 && tmp < 0xe000) || tmp >= 0x110000) {
      if (consumed != NULL) *consumed = 0;
      return R_UNICODE_INVALID_CODE_POINT;
    }
    *uc = tmp;
    if (consumed != NULL) *consumed = (rsize)r;
    return R_UNICODE_OK;
  }

  if (consumed != NULL) *consumed = 0;
  if (r == R_UTF8_OVERLONG)
    return R_UNICODE_INVALID_CODE_POINT;
  return R_UNICODE_INCOMPLETE_CODE_POINT;
}

RUnicodeResult
r_utf8_encode_codepoint (runichar4 uc, rchar * dst, rsize size,
    rsize * written)
{
  rssize r;

  if (R_UNLIKELY (dst == NULL || size == 0))
    return R_UNICODE_INVAL;
  if ((uc >= 0xd800 && uc < 0xe000) || uc >= 0x110000) {
    if (written != NULL) *written = 0;
    return R_UNICODE_INVALID_CODE_POINT;
  }

  r = r_unichar_to_utf8 ((runichar)uc, dst, size);
  if (r > 0) {
    if (written != NULL) *written = (rsize)r;
    return R_UNICODE_OK;
  }
  if (written != NULL) *written = 0;
  return R_UNICODE_OVERFLOW;
}

RUnicodeResult
r_utf16_decode_codepoint (const runichar2 * src, rsize size, runichar4 * uc,
    rsize * consumed)
{
  if (R_UNLIKELY (src == NULL || uc == NULL || size == 0))
    return R_UNICODE_INVAL;

  if (src[0] < 0xd800 || src[0] >= 0xe000) {
    *uc = (runichar4)src[0];
    if (consumed != NULL) *consumed = 1;
    return R_UNICODE_OK;
  }
  if (src[0] >= 0xdc00) {
    /* Lone low surrogate. */
    if (consumed != NULL) *consumed = 0;
    return R_UNICODE_INVALID_CODE_POINT;
  }
  /* High surrogate; need a low surrogate to follow. */
  if (size < 2) {
    if (consumed != NULL) *consumed = 0;
    return R_UNICODE_INCOMPLETE_CODE_POINT;
  }
  if (src[1] < 0xdc00 || src[1] >= 0xe000) {
    if (consumed != NULL) *consumed = 0;
    return R_UNICODE_INVALID_CODE_POINT;
  }
  *uc = 0x10000 + (((runichar4)(src[0] - 0xd800)) << 10) +
      ((runichar4)(src[1] - 0xdc00));
  if (consumed != NULL) *consumed = 2;
  return R_UNICODE_OK;
}

RUnicodeResult
r_utf16_encode_codepoint (runichar4 uc, runichar2 * dst, rsize size,
    rsize * written)
{
  if (R_UNLIKELY (dst == NULL || size == 0))
    return R_UNICODE_INVAL;
  if ((uc >= 0xd800 && uc < 0xe000) || uc >= 0x110000) {
    if (written != NULL) *written = 0;
    return R_UNICODE_INVALID_CODE_POINT;
  }

  if (uc < 0x10000) {
    dst[0] = (runichar2)uc;
    if (written != NULL) *written = 1;
    return R_UNICODE_OK;
  }
  if (size < 2) {
    if (written != NULL) *written = 0;
    return R_UNICODE_OVERFLOW;
  }
  dst[0] = ((uc - 0x10000) / 0x400) | 0xd800;
  dst[1] = ((uc - 0x10000) % 0x400) | 0xdc00;
  if (written != NULL) *written = 2;
  return R_UNICODE_OK;
}

/* ---- Codepoint counting and advance --------------------------------
 * Single-pass decoders that walk one codepoint at a time. The
 * counter stops on error and reports the partial count; the
 * advance helper stops either when it has skipped @n codepoints
 * or when it runs out of input / hits a bad sequence. */

rsize
r_utf8_strlen_codepoints (const rchar * src, rssize size,
    RUnicodeResult * result)
{
  rsize count = 0;
  rssize i, r;
  runichar uc;
  RUnicodeResult ret = R_UNICODE_OK;

  if (R_UNLIKELY (src == NULL)) {
    if (result != NULL) *result = R_UNICODE_INVAL;
    return 0;
  }
  if (size < 0) size = r_strlen (src);

  for (i = 0; i < size && src[i] != 0; i += r) {
    r = r_utf8_to_unichar (&src[i], size - i, &uc);
    if (r > 0) {
      if ((uc >= 0xd800 && uc < 0xe000) || uc >= 0x110000) {
        ret = R_UNICODE_INVALID_CODE_POINT;
        break;
      }
      count++;
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

  if (result != NULL) *result = ret;
  return count;
}

const rchar *
r_utf8_advance (const rchar * src, rssize size, rsize n,
    RUnicodeResult * result)
{
  rssize i, r;
  rsize skipped = 0;
  runichar uc;
  RUnicodeResult ret = R_UNICODE_OK;

  if (R_UNLIKELY (src == NULL)) {
    if (result != NULL) *result = R_UNICODE_INVAL;
    return NULL;
  }
  if (size < 0) size = r_strlen (src);

  for (i = 0; skipped < n && i < size && src[i] != 0; i += r) {
    r = r_utf8_to_unichar (&src[i], size - i, &uc);
    if (r > 0) {
      if ((uc >= 0xd800 && uc < 0xe000) || uc >= 0x110000) {
        ret = R_UNICODE_INVALID_CODE_POINT;
        break;
      }
      skipped++;
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

  if (skipped < n && ret == R_UNICODE_OK)
    ret = R_UNICODE_OVERFLOW;
  if (result != NULL) *result = ret;
  return &src[i];
}

rsize
r_utf16_strlen_codepoints (const runichar2 * src, rsize size,
    RUnicodeResult * result)
{
  rsize count = 0, i = 0;
  RUnicodeResult ret = R_UNICODE_OK;

  if (R_UNLIKELY (src == NULL)) {
    if (result != NULL) *result = R_UNICODE_INVAL;
    return 0;
  }

  while (i < size && src[i] != 0) {
    if (src[i] < 0xd800 || src[i] >= 0xe000) {
      i++;
      count++;
    } else if (src[i] < 0xdc00) {
      if (i + 1 < size && src[i + 1] >= 0xdc00 && src[i + 1] < 0xe000) {
        i += 2;
        count++;
      } else {
        ret = R_UNICODE_INCOMPLETE_CODE_POINT;
        break;
      }
    } else {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }
  }

  if (result != NULL) *result = ret;
  return count;
}

/* ---- Explicit-endianness UTF-16/32 -> UTF-8 ----------------------
 * Internal: load a UTF-16 code unit from the source buffer at byte
 * offset @i in the given endianness. The helpers below decode unit-
 * by-unit into the host-order surrogate-pair logic. */

static inline runichar2
r_load_utf16_be (const ruint8 * p)
{
  return ((runichar2)p[0] << 8) | (runichar2)p[1];
}

static inline runichar2
r_load_utf16_le (const ruint8 * p)
{
  return ((runichar2)p[1] << 8) | (runichar2)p[0];
}

static inline runichar4
r_load_utf32_be (const ruint8 * p)
{
  return ((runichar4)p[0] << 24) | ((runichar4)p[1] << 16) |
         ((runichar4)p[2] <<  8) |  (runichar4)p[3];
}

static inline runichar4
r_load_utf32_le (const ruint8 * p)
{
  return ((runichar4)p[3] << 24) | ((runichar4)p[2] << 16) |
         ((runichar4)p[1] <<  8) |  (runichar4)p[0];
}

typedef runichar2 (*RUtf16LoadFn) (const ruint8 *);
typedef runichar4 (*RUtf32LoadFn) (const ruint8 *);

/* UTF-16 wire-format decode: srcsize is bytes; reject odd-length
 * input; dispatch through @load to get host-order code units. */
static RUnicodeResult
r_utf16_wire_to_utf8 (rchar * dst, rsize dstsize, const ruint8 * src,
    rsize srcsize, rsize * dstoutsize, ruint8 ** srcendptr,
    RUtf16LoadFn load)
{
  RUnicodeResult ret = R_UNICODE_OK;
  rchar * dstptr, * dstend;
  rsize i;
  rssize r;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY ((srcsize & 1u) != 0))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1; i + 1 < srcsize; ) {
    runichar2 u = load (&src[i]);
    if (u == 0) break;
    if (u < 0xd800 || u >= 0xe000) {
      r = r_unichar_to_utf8 ((runichar)u, dstptr, dstend - dstptr);
      i += 2;
    } else if (u < 0xdc00) {
      /* High surrogate; peek at next unit without consuming. */
      if (i + 3 < srcsize) {
        runichar2 u2 = load (&src[i + 2]);
        if (u2 >= 0xdc00 && u2 < 0xe000) {
          runichar uc = 0x10000 +
              (((runichar)(u - 0xd800)) << 10) +
              ((runichar)(u2 - 0xdc00));
          r = r_unichar_to_utf8 (uc, dstptr, dstend - dstptr);
          i += 4;
        } else {
          ret = R_UNICODE_INCOMPLETE_CODE_POINT;
          break;
        }
      } else {
        ret = R_UNICODE_INCOMPLETE_CODE_POINT;
        break;
      }
    } else {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }
    if (r <= 0) {
      ret = R_UNICODE_OVERFLOW;
      break;
    }
    dstptr += r;
  }

  *dstptr = 0;
  if (dstoutsize != NULL) *dstoutsize = dstptr - dst;
  if (srcendptr != NULL) *srcendptr = (ruint8 *)&src[i];
  return ret;
}

static RUnicodeResult
r_utf32_wire_to_utf8 (rchar * dst, rsize dstsize, const ruint8 * src,
    rsize srcsize, rsize * dstoutsize, ruint8 ** srcendptr,
    RUtf32LoadFn load)
{
  RUnicodeResult ret = R_UNICODE_OK;
  rchar * dstptr, * dstend;
  rsize i;
  rssize r = 0;

  if (R_UNLIKELY (dst == NULL || dstsize == 0 || src == NULL))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY ((srcsize & 3u) != 0))
    return R_UNICODE_INVAL;
  if (R_UNLIKELY (dstsize == 1)) {
    dst[0] = 0;
    return R_UNICODE_OVERFLOW;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1; i + 3 < srcsize;
      i += 4, dstptr += r) {
    runichar4 cp = load (&src[i]);
    if (cp == 0) break;
    if (cp >= 0x110000 || (cp >= 0xd800 && cp < 0xe000)) {
      ret = R_UNICODE_INVALID_CODE_POINT;
      break;
    }
    r = r_unichar_to_utf8 ((runichar)cp, dstptr, dstend - dstptr);
    if (r <= 0) {
      ret = R_UNICODE_OVERFLOW;
      break;
    }
  }

  *dstptr = 0;
  if (dstoutsize != NULL) *dstoutsize = dstptr - dst;
  if (srcendptr != NULL) *srcendptr = (ruint8 *)&src[i];
  return ret;
}

RUnicodeResult
r_utf16be_to_utf8 (rchar * dst, rsize dstsize, const ruint8 * src,
    rsize srcsize, rsize * dstoutsize, ruint8 ** srcendptr)
{
  return r_utf16_wire_to_utf8 (dst, dstsize, src, srcsize, dstoutsize,
      srcendptr, r_load_utf16_be);
}

RUnicodeResult
r_utf16le_to_utf8 (rchar * dst, rsize dstsize, const ruint8 * src,
    rsize srcsize, rsize * dstoutsize, ruint8 ** srcendptr)
{
  return r_utf16_wire_to_utf8 (dst, dstsize, src, srcsize, dstoutsize,
      srcendptr, r_load_utf16_le);
}

RUnicodeResult
r_utf32be_to_utf8 (rchar * dst, rsize dstsize, const ruint8 * src,
    rsize srcsize, rsize * dstoutsize, ruint8 ** srcendptr)
{
  return r_utf32_wire_to_utf8 (dst, dstsize, src, srcsize, dstoutsize,
      srcendptr, r_load_utf32_be);
}

RUnicodeResult
r_utf32le_to_utf8 (rchar * dst, rsize dstsize, const ruint8 * src,
    rsize srcsize, rsize * dstoutsize, ruint8 ** srcendptr)
{
  return r_utf32_wire_to_utf8 (dst, dstsize, src, srcsize, dstoutsize,
      srcendptr, r_load_utf32_le);
}

/* _dup variants: allocate worst-case output and run the in-buffer
 * conversion. Worst case for UTF-16 -> UTF-8 is 3 bytes per BMP code
 * unit (since a surrogate pair encodes one 4-byte UTF-8 codepoint
 * from 4 input bytes, so 2 input bytes per output byte is the
 * worst-case ratio). For UTF-32 -> UTF-8 it's 1 byte UTF-8 per 4
 * bytes UTF-32 minimum to 4:4 maximum. */

static rchar *
r_utfXX_to_utf8_dup_common (const ruint8 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, ruint8 ** endptr,
    rsize per_unit_bytes, rsize worst_utf8_per_unit,
    RUnicodeResult (*conv) (rchar *, rsize, const ruint8 *, rsize,
        rsize *, ruint8 **))
{
  rchar * ret;
  RUnicodeResult r;
  rsize dstsize;
  rsize units;

  if (R_UNLIKELY (src == NULL || srcsize == 0)) {
    if (res != NULL) *res = R_UNICODE_INVAL;
    return NULL;
  }
  if (R_UNLIKELY ((srcsize % per_unit_bytes) != 0)) {
    if (res != NULL) *res = R_UNICODE_INVAL;
    return NULL;
  }

  units = srcsize / per_unit_bytes;
  dstsize = units * worst_utf8_per_unit + 1;

  if ((ret = r_mem_new_n (rchar, dstsize)) != NULL) {
    if ((r = conv (ret, dstsize, src, srcsize, retsize, endptr))
        != R_UNICODE_OK) {
      r_free (ret);
      ret = NULL;
    }
  } else {
    r = R_UNICODE_OOM;
  }

  if (res != NULL) *res = r;
  return ret;
}

rchar *
r_utf16be_to_utf8_dup (const ruint8 * src, rsize srcsize, RUnicodeResult * res,
    rsize * retsize, ruint8 ** endptr)
{
  return r_utfXX_to_utf8_dup_common (src, srcsize, res, retsize, endptr,
      2, 3, r_utf16be_to_utf8);
}

rchar *
r_utf16le_to_utf8_dup (const ruint8 * src, rsize srcsize, RUnicodeResult * res,
    rsize * retsize, ruint8 ** endptr)
{
  return r_utfXX_to_utf8_dup_common (src, srcsize, res, retsize, endptr,
      2, 3, r_utf16le_to_utf8);
}

rchar *
r_utf32be_to_utf8_dup (const ruint8 * src, rsize srcsize, RUnicodeResult * res,
    rsize * retsize, ruint8 ** endptr)
{
  return r_utfXX_to_utf8_dup_common (src, srcsize, res, retsize, endptr,
      4, 4, r_utf32be_to_utf8);
}

rchar *
r_utf32le_to_utf8_dup (const ruint8 * src, rsize srcsize, RUnicodeResult * res,
    rsize * retsize, ruint8 ** endptr)
{
  return r_utfXX_to_utf8_dup_common (src, srcsize, res, retsize, endptr,
      4, 4, r_utf32le_to_utf8);
}

/* ---- WTF-8 (UTF-8 + unpaired surrogates) ---------------------------
 * Same byte / surrogate plumbing as the strict converters, just
 * with the "is this a surrogate codepoint?" rejection lifted on
 * both decode (UTF-8 byte pattern -> surrogate code unit) and
 * encode (lone surrogate -> 3-byte UTF-8). Overlong sequences and
 * codepoints >= 0x110000 stay rejected. */

RUnicodeResult
r_utf16_to_wtf8 (rchar * dst, rsize dstsize, const runichar2 * src,
    rsize srcsize, rsize * dstoutsize, runichar2 ** srcendptr)
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
    runichar uc;

    if (src[i] < 0xd800 || src[i] >= 0xe000) {
      uc = (runichar)src[i];
    } else if (src[i] < 0xdc00) {
      /* High surrogate; try to pair. WTF-8 only emits the surrogate
       * directly if the pair is malformed - paired surrogates still
       * produce the canonical 4-byte UTF-8. */
      if (i + 1 < srcsize && src[i + 1] >= 0xdc00 && src[i + 1] < 0xe000) {
        uc = 0x10000 + (((runichar)(src[i] - 0xd800)) << 10) +
            ((runichar)(src[i + 1] - 0xdc00));
        i++;
      } else {
        /* Lone high surrogate -> emit as 3-byte WTF-8. */
        uc = (runichar)src[i];
      }
    } else {
      /* Lone low surrogate -> emit as 3-byte WTF-8. */
      uc = (runichar)src[i];
    }

    /* The strict r_unichar_to_utf8 emits the canonical 3-byte
     * sequence for any codepoint in [0x800, 0x10000) - which
     * includes the surrogate range. WTF-8 wants exactly those
     * bytes for a lone surrogate, so we can call it directly. */
    r = r_unichar_to_utf8 (uc, dstptr, dstend - dstptr);
    if (r <= 0) {
      ret = R_UNICODE_OVERFLOW;
      break;
    }
  }

  *dstptr = 0;
  if (dstoutsize != NULL) *dstoutsize = dstptr - dst;
  if (srcendptr != NULL) *srcendptr = (runichar2 *)&src[i];
  return ret;
}

RUnicodeResult
r_wtf8_to_utf16 (runichar2 * dst, rsize dstsize, const rchar * src,
    rssize srcsize, rsize * dstoutsize, rchar ** srcendptr)
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

  if (srcsize < 0) srcsize = r_strlen (src);

  /* Strip leading UTF-8 BOM. */
  if (srcsize >= 3 &&
      (ruint8)src[0] == 0xef && (ruint8)src[1] == 0xbb &&
      (ruint8)src[2] == 0xbf) {
    src += 3; srcsize -= 3;
  }

  for (i = 0, dstptr = dst, dstend = dst + dstsize - 1;
      i < srcsize && src[i] != 0;
      i += r) {
    runichar uc;

    r = r_utf8_to_unichar (&src[i], srcsize - i, &uc);
    if (r > 0) {
      /* Reject only out-of-range codepoints. Surrogates are
       * *allowed* in WTF-8. */
      if (uc >= 0x110000) {
        ret = R_UNICODE_INVALID_CODE_POINT;
        break;
      }
      if (uc <= 0xffff) {
        if (dstptr + 1 > dstend) {
          ret = R_UNICODE_OVERFLOW;
          break;
        }
        *dstptr++ = (runichar2)uc;
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
  if (dstoutsize != NULL) *dstoutsize = dstptr - dst;
  if (srcendptr != NULL) *srcendptr = (rchar *)&src[i];
  return ret;
}

rchar *
r_utf16_to_wtf8_dup (const runichar2 * src, rsize srcsize,
    RUnicodeResult * res, rsize * retsize, runichar2 ** endptr)
{
  rchar * ret;
  RUnicodeResult r;
  rsize dstsize;

  if (R_UNLIKELY (src == NULL || srcsize == 0)) {
    if (res != NULL) *res = R_UNICODE_INVAL;
    return NULL;
  }
  dstsize = srcsize * 3 + 1;
  if ((ret = r_mem_new_n (rchar, dstsize)) != NULL) {
    if ((r = r_utf16_to_wtf8 (ret, dstsize, src, srcsize, retsize, endptr))
        != R_UNICODE_OK) {
      r_free (ret);
      ret = NULL;
    }
  } else {
    r = R_UNICODE_OOM;
  }
  if (res != NULL) *res = r;
  return ret;
}

runichar2 *
r_wtf8_to_utf16_dup (const rchar * src, rssize srcsize,
    RUnicodeResult * res, rsize * retsize, rchar ** endptr)
{
  runichar2 * ret;
  RUnicodeResult r;

  if (srcsize < 0) srcsize = r_strlen (src);
  if ((ret = r_mem_new_n (runichar2, srcsize + 1)) != NULL) {
    if ((r = r_wtf8_to_utf16 (ret, srcsize + 1, src, srcsize, retsize, endptr))
        != R_UNICODE_OK) {
      r_free (ret);
      ret = NULL;
    }
  } else {
    r = R_UNICODE_OOM;
  }
  if (res != NULL) *res = r;
  return ret;
}
