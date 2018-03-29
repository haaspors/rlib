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
#include <rlib/rstr.h>
#include <rlib/charset/rascii.h>

#include <rlib/rmem.h>

#include <string.h>
#include <errno.h>
#include <ctype.h>

const ruint16 r_ascii_table[256] = {
  0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
  0x0004, 0x0104, 0x0104, 0x0004, 0x0104, 0x0104, 0x0004, 0x0004,
  0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
  0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004, 0x0004,
  0x0140, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0,
  0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0,
  0x0459, 0x0459, 0x0459, 0x0459, 0x0459, 0x0459, 0x0459, 0x0459,
  0x0459, 0x0459, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0,
  0x00d0, 0x0653, 0x0653, 0x0653, 0x0653, 0x0653, 0x0653, 0x0253,
  0x0253, 0x0253, 0x0253, 0x0253, 0x0253, 0x0253, 0x0253, 0x0253,
  0x0253, 0x0253, 0x0253, 0x0253, 0x0253, 0x0253, 0x0253, 0x0253,
  0x0253, 0x0253, 0x0253, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0,
  0x00d0, 0x0473, 0x0473, 0x0473, 0x0473, 0x0473, 0x0473, 0x0073,
  0x0073, 0x0073, 0x0073, 0x0073, 0x0073, 0x0073, 0x0073, 0x0073,
  0x0073, 0x0073, 0x0073, 0x0073, 0x0073, 0x0073, 0x0073, 0x0073,
  0x0073, 0x0073, 0x0073, 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x0004
  /* rest is 0x0000 */
};

static const ruint16 r_ascii_digit_table[256] = {
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x0000, 0x0101, 0x0202, 0x0303, 0x0404, 0x0505, 0x0606, 0x0707, 0x0808, 0x0909, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x0a80, 0x0b80, 0x0c80, 0x0d80, 0x0e80, 0x0f80, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x0a80, 0x0b80, 0x0c80, 0x0d80, 0x0e80, 0x0f80, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
  0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080,
};

rint8
r_ascii_digit_value (rchar c)
{
  return (rint8)(r_ascii_digit_table[(ruint8)c] & 0xff);
}

rint8
r_ascii_xdigit_value (rchar c)
{
  return (rint8)((r_ascii_digit_table[(ruint8)c] >> 8) & 0xff);
}

rchar *
r_ascii_make_upper (rchar * str, rssize len)
{
  rsize size;

  if (str != NULL && (size = len < 0 ? (rssize)r_strlen (str) : len) > 0) {
    rchar * it;
    for (it = str; *it != 0 && size > 0; it++, size--) {
      if (r_ascii_islower (*it))
        *it -= 0x20;
    }
  }

  return str;
}

rchar *
r_ascii_make_lower (rchar * str, rssize len)
{
  rsize size;

  if (str != NULL && (size = len < 0 ? (rssize)r_strlen (str) : len) > 0) {
    rchar * it;
    for (it = str; *it != 0 && size > 0; it++, size--) {
      if (r_ascii_isupper (*it))
        *it += 0x20;
    }
  }

  return str;
}

rsize
r_strlen (const rchar * str)
{
  if (R_UNLIKELY (str == NULL)) return 0;
  return strlen (str);
}

int
r_strcmp (const rchar * a, const rchar * b)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  return strcmp (a, b);
}

int
r_strcasecmp (const rchar * a, const rchar * b)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
#if defined (HAVE__STRICMP)
  return _stricmp (a, b);
#elif defined (HAVE_STRCASECMP)
  return strcasecmp (a, b);
#else
#error "no case insensitive string compare function"
#endif
}

int
r_strncmp (const rchar * a, const rchar * b, rsize len)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  return strncmp (a, b, len);
}

int
r_strncasecmp (const rchar * a, const rchar * b, rsize len)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
#if defined (HAVE__STRNICMP)
  return _strnicmp (a, b, len);
#elif defined (HAVE_STRNCASECMP)
  return strncasecmp (a, b, len);
#else
#error "no case insensitive string compare function"
#endif
}

int
r_strcmp_size (const rchar * a, rssize asize, const rchar * b, rssize bsize)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  if (asize < 0) asize = r_strlen (a);
  if (bsize < 0) bsize = r_strlen (b);
  if (asize - bsize != 0) return (int)(asize - bsize);
  return strncmp (a, b, asize);
}

int
r_strcasecmp_size (const rchar * a, rssize asize, const rchar * b, rssize bsize)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  if (asize < 0) asize = r_strlen (a);
  if (bsize < 0) bsize = r_strlen (b);
  if (asize - bsize != 0) return (int)(asize - bsize);
#if defined (HAVE__STRNICMP)
  return _strnicmp (a, b, asize);
#elif defined (HAVE_STRNCASECMP)
  return strncasecmp (a, b, asize);
#else
#error "no case insensitive string compare function"
#endif
}

rboolean
r_str_has_prefix (const rchar * str, const rchar * prefix)
{
  if (str == NULL || prefix == NULL)
    return FALSE;

  return strncmp (str, prefix, strlen (prefix)) == 0;
}

rboolean
r_str_has_suffix (const rchar * str, const rchar * suffix)
{
  rsize len, suffixlen;

  if (str == NULL || suffix == NULL)
    return FALSE;

  len = strlen (str);
  suffixlen = strlen (suffix);

  if (len < suffixlen)
    return FALSE;
  return strcmp (str + len - suffixlen, suffix) == 0;
}

rsize
r_strspn (const rchar * str, const rchar * set)
{
  if (R_UNLIKELY (str == NULL)) return 0;
  if (R_UNLIKELY (set == NULL)) return strlen (str);
  return strspn (str, set);
}

rsize
r_strcspn (const rchar * str, const rchar * cset)
{
  if (R_UNLIKELY (str == NULL)) return 0;
  if (R_UNLIKELY (cset == NULL)) return 0;
  return strcspn (str, cset);
}

rchar *
r_strchr (const rchar * str, int c)
{
  if (R_UNLIKELY (str == NULL)) return NULL;
  return strchr (str, c);
}

rchar *
r_strnchr (const rchar * str, int c, rsize size)
{
  if (R_UNLIKELY (str == NULL)) return NULL;
  return memchr (str, c, size);
}

rchar *
r_strrchr (const rchar * str, int c)
{
  if (R_UNLIKELY (str == NULL)) return NULL;
  return strrchr (str, c);
}

rchar *
r_strnrchr (const rchar * str, int c, rsize size)
{
#ifndef HAVE_MEMRCHR
  const rchar * r;

  if (R_UNLIKELY (str == NULL)) return NULL;

  for (r = str + size; r > str; ) {
    if (*(--r) == (rchar)c)
      return (rchar *)r;
  }

  return NULL;
#else
  return memrchr (str, c, size);
#endif
}

rchar *
r_strstr (const rchar * str, const rchar * sub)
{
  if (R_UNLIKELY (str == NULL)) return NULL;
  if (R_UNLIKELY (sub == NULL)) return NULL;
  return strstr (str, sub);
}

rchar *
r_strnstr (const rchar * str, const rchar * sub, rsize size)
{
#ifndef HAVE_STRNSTR
  rchar * ret;
  rsize s, ss;

  if (R_UNLIKELY (sub == NULL)) return NULL;

  ret = (rchar *)str;
  s = size;
  ss = strlen (sub);
  do {
    if ((ret = memchr (ret, (int)*sub, s)) != NULL) {
      if ((s = size - (ret - str)) < ss) {
        ret = NULL;
      } else {
        if (r_strncmp (ret, sub, ss) == 0)
          break;
        ret++;
      }
    }
  } while (ret != NULL);

  return ret;
#else
  if (R_UNLIKELY (str == NULL)) return NULL;
  if (R_UNLIKELY (sub == NULL)) return NULL;

  return strnstr (str, sub, size);
#endif
}

rchar *
r_strpbrk (const rchar * str, const rchar * set)
{
  if (R_UNLIKELY (str == NULL)) return NULL;
  if (R_UNLIKELY (set == NULL)) return NULL;
  return strpbrk (str, set);
}

rchar *
r_str_ptr_of_c (const rchar * str, rssize strsize, rchar c)
{
  rssize idx;

  if ((idx = r_str_idx_of_c (str, strsize, c)) >= 0)
    return (rchar *)str + idx;

  return NULL;
}

rchar *
r_str_ptr_of_c_any (const rchar * str, rssize strsize,
    const rchar * c, rssize chars)
{
  rssize idx;

  if ((idx = r_str_idx_of_c_any (str, strsize, c, chars)) >= 0)
    return (rchar *)str + idx;

  return NULL;
}

rchar *
r_str_ptr_of_str (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize)
{
  rssize idx;

  if ((idx = r_str_idx_of_str (str, strsize, sub, subsize)) >= 0)
    return (rchar *)str + idx;

  return NULL;
}

rchar *
r_str_ptr_of_str_case (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize)
{
  rssize idx;

  if ((idx = r_str_idx_of_str_case (str, strsize, sub, subsize)) >= 0)
    return (rchar *)str + idx;

  return NULL;
}

rssize
r_str_idx_of_c (const rchar * str, rssize strsize, rchar c)
{
  rsize i, size;

  if (R_UNLIKELY (str == NULL || strsize == 0))
    return -1;

  size = strsize > 0 ? (rsize)strsize : r_strlen (str);
  for (i = 0; i < size; i++) {
    if (str[i] == c)
      return (rssize)i;
  }

  return -1;
}

rssize
r_str_idx_of_c_case (const rchar * str, rssize strsize, rchar c)
{
  rchar ch[2] = { c, c };

  if (r_ascii_islower (c))
    ch[1] -= 0x20;
  else if (r_ascii_isupper (c))
    ch[1] += 0x20;
  else
    return r_str_idx_of_c (str, strsize, c);

  return r_str_idx_of_c_any (str, strsize, ch, 2);
}

rssize
r_str_idx_of_c_any (const rchar * str, rssize strsize,
    const rchar * c, rssize chars)
{
  rsize i, size;

  if (R_UNLIKELY (str == NULL || strsize == 0 ||
      c == NULL || chars == 0))
    return -1;

  if (chars == 1)
    return r_str_idx_of_c (str, strsize, *c);

  size = strsize > 0 ? (rsize)strsize : r_strlen (str);
  for (i = 0; i < size; i++) {
    if (r_str_idx_of_c (c, chars, str[i]) >= 0)
      return (rssize)i;
  }

  return -1;
}

rssize
r_str_idx_of_str (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize)
{
  rssize ret, idx;

  if (strsize < 0) strsize = (rssize) r_strlen (str);
  if (subsize < 0) subsize = (rssize) r_strlen (sub);

  if (R_UNLIKELY (subsize <= 0))
    return -1;
  if (subsize == 1)
    return r_str_idx_of_c (str, strsize, *sub);

  ret = 0;
  while ((idx = r_str_idx_of_c (str+ret, strsize-ret, *sub)) >= 0) {
    ret += idx;
    if (strsize - ret < subsize) break;

    if (r_strncmp (&str[ret+1], &sub[1], subsize - 1) == 0)
      return ret;
    ret++;
  }

  return -1;
}

rssize
r_str_idx_of_str_case (const rchar * str, rssize strsize,
    const rchar * sub, rssize subsize)
{
  rssize ret, idx;

  if (strsize < 0) strsize = (rssize) r_strlen (str);
  if (subsize < 0) subsize = (rssize) r_strlen (sub);

  if (R_UNLIKELY (subsize <= 0))
    return -1;
  if (subsize == 1)
    return r_str_idx_of_c_case (str, strsize, *sub);

  ret = 0;
  while ((idx = r_str_idx_of_c_case (str+ret, strsize-ret, *sub)) >= 0) {
    ret += idx;
    if (strsize - ret < subsize) break;

    if (r_strncasecmp (&str[ret+1], &sub[1], subsize - 1) == 0)
      return ret;
    ret++;
  }

  return -1;
}

rchar *
r_strcpy (rchar * dst, const rchar * src)
{
  if (R_UNLIKELY (dst == NULL)) return NULL;
  if (R_UNLIKELY (src == NULL)) return dst;
  return strcpy (dst, src);
}

rchar *
r_strncpy (rchar * dst, const rchar * src, rsize len)
{
  if (R_UNLIKELY (dst == NULL)) return NULL;
  if (R_UNLIKELY (src == NULL)) {
    memset (dst, 0, len);
    return dst;
  }
  return strncpy (dst, src, len);
}

rchar *
r_strcat (rchar * dst, const rchar * src)
{
  if (R_UNLIKELY (dst == NULL)) return NULL;
  if (R_UNLIKELY (src == NULL)) return dst;
  return strcat (dst, src);
}

rchar *
r_strncat (rchar * dst, const rchar * src, rsize len)
{
  if (R_UNLIKELY (dst == NULL)) return NULL;
  if (R_UNLIKELY (src == NULL)) {
    memset (dst, 0, len);
    return dst;
  }
  return strncat (dst, src, len);
}

rchar *
r_stpcpy (rchar * dst, const rchar * src)
{
  if (R_UNLIKELY (dst == NULL))
    return NULL;
  if (R_UNLIKELY (src == NULL))
    return dst;
#ifdef HAVE_STPCPY
  return stpcpy (dst, src);
#else
  do {
    *dst++ = *src;
  } while (*src++ != '\0');

  return dst - 1;
#endif
}

rchar *
r_stpncpy (rchar * dst, const rchar * src, rsize len)
{
  if (R_UNLIKELY (dst == NULL))
    return NULL;
  if (R_UNLIKELY (src == NULL)) {
    memset (dst, 0, len);
    return dst;
  }
#ifdef HAVE_STPNCPY
  return stpncpy (dst, src, len);
#else
  do {
    if (len > 0) {
      len--;
      *dst++ = *src;
    } else {
      dst++;
      break;
    }
  } while (*src++ != '\0');

  if (len > 0)
    memset (dst, 0, len);

  return dst - 1;
#endif
}

static inline RStrParse
r_str_to_int_parse (const rchar * str, const rchar ** endptr, ruint base,
    ruint bits, rint64 * val)
{
  RStrParse ret = R_STR_PARSE_INVAL;
  const rchar * ptr, * start;
  rboolean neg = FALSE;
  ruint64 v = 0, m = RUINT64_MAX >> (sizeof (ruint64) * 8 - (bits - 1));

  *val = 0;
  if (endptr != NULL)
    *endptr = str;

  if (R_UNLIKELY (str == NULL || *str == 0))
    return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (base == 1 || base > 36))
    return R_STR_PARSE_INVAL;

  ptr = r_str_lwstrip (str);
  if (R_UNLIKELY (*ptr == 0))
    goto beach;

  ret = R_STR_PARSE_OK;
  if ((neg = (*ptr == '-'))) {
    ptr++;
    m++;
  } else if (*ptr == '+') {
    ptr++;
  }

  if (base == 0) {
    base = 10;
    if (ptr[0] == '0') {
      if (ptr[1] == 'X' || ptr[1] == 'x') {
        if (r_ascii_isxdigit (ptr[2])) {
          base = 16;
          ptr += 2;
        }
      } else if (ptr[1] >= '0' && ptr[1] <= '7') {
        base = 8;
        ptr++;
      }
    }
  } else if (base == 16) {
    if (ptr[0] == '0' && (ptr[1] == 'X' || ptr[1] == 'x') &&
        r_ascii_isxdigit (ptr[2])) {
      ptr += 2;
    }
  }

  for (start = ptr; *ptr != 0;) {
    rchar c;
    ruint64 nv;

    if (r_ascii_isdigit (*ptr))       c = *ptr - '0';
    else if (r_ascii_islower (*ptr))  c = 10 + *ptr - 'a';
    else if (r_ascii_isupper (*ptr))  c = 10 + *ptr - 'A';
    else break;

    if ((ruint)c >= base)
      break;

    ptr++;
    nv = v * base + c;
    if (nv <= m && nv >= v) {
      v = nv;
    } else {
      v = m;
      ret = R_STR_PARSE_RANGE;
      break;
    }
  }

  if (start != ptr)
    *val = !neg ? (rint64)v : -(rint64)v;
  else
    ret = R_STR_PARSE_INVAL;

beach:
  if (endptr != NULL)
    *endptr = ptr;

  return ret;
}

static inline RStrParse
r_str_to_uint_parse (const rchar * str, const rchar ** endptr, ruint base,
    ruint bits, ruint64 * val)
{
  RStrParse ret = R_STR_PARSE_INVAL;
  const rchar * ptr, * start;
  ruint64 v = 0, m = RUINT64_MAX >> (sizeof (ruint64) * 8 - bits);

  *val = 0;
  if (endptr != NULL)
    *endptr = str;

  if (R_UNLIKELY (str == NULL || *str == 0))
    return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (base == 1 || base > 36))
    return R_STR_PARSE_INVAL;

  ptr = r_str_lwstrip (str);
  if (R_UNLIKELY (*ptr == 0))
    goto beach;

  ret = R_STR_PARSE_OK;
  if (*ptr == '0') {
    ptr++;
    if ((base == 0 || base == 16) && (*ptr == 'X' || *ptr == 'x')) {
      if (!r_ascii_isxdigit (ptr[1]))
        goto beach;
      base = 16;
      ptr++;
    } else if (base == 0) {
      if (*ptr < '0' || *ptr > '7')
        goto beach;
      base = 8;
    }
  } else if (base == 0) {
    base = 10;
  }

  for (start = ptr; *ptr != 0;) {
    rchar c;
    ruint64 nv;

    if (r_ascii_isdigit (*ptr))       c = *ptr - '0';
    else if (r_ascii_islower (*ptr))  c = 10 + *ptr - 'a';
    else if (r_ascii_isupper (*ptr))  c = 10 + *ptr - 'A';
    else break;

    if ((ruint)c >= base)
      break;

    ptr++;
    nv = v * base + c;
    if (nv <= m && nv > v) {
      v = nv;
    } else {
      v = m;
      ret = R_STR_PARSE_RANGE;
      break;
    }
  }

  if (start != ptr)
    *val = v;
  else
    ret = R_STR_PARSE_INVAL;

beach:
  if (endptr != NULL)
    *endptr = ptr;

  return ret;
}

rint8
r_str_to_int8 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  rint64 ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 8, &ret);
  if (res != NULL)
    *res = r;
  return (rint8)ret;
}

ruint8
r_str_to_uint8 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruint64 ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 8, &ret);
  if (res != NULL)
    *res = r;
  return (ruint8)ret;
}

rint16
r_str_to_int16 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  rint64 ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 16, &ret);
  if (res != NULL)
    *res = r;
  return (rint16)ret;
}

ruint16
r_str_to_uint16 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruint64 ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 16, &ret);
  if (res != NULL)
    *res = r;
  return (ruint16)ret;
}

rint32
r_str_to_int32 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  rint64 ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 32, &ret);
  if (res != NULL)
    *res = r;
  return (rint32)ret;
}

ruint32
r_str_to_uint32 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruint64 ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 32, &ret);
  if (res != NULL)
    *res = r;
  return (ruint32)ret;
}

rint64
r_str_to_int64 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  rint64 ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 64, &ret);
  if (res != NULL)
    *res = r;
  return ret;
}

ruint64
r_str_to_uint64 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruint64 ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 64, &ret);
  if (res != NULL)
    *res = r;
  return ret;
}

rfloat
r_str_to_float (const rchar * str, const rchar ** endptr, RStrParse * res)
{
  rfloat ret;
  errno = 0;
  if (str != NULL) {
    ret = strtof (str, (rchar **)endptr);
    if (res != NULL)
      *res = errno == 0 ? R_STR_PARSE_OK : R_STR_PARSE_INVAL;
  } else {
    errno = EINVAL;
    ret = 0.0f;
    if (res)
      *res = R_STR_PARSE_INVAL;
  }

  return ret;
}

rdouble
r_str_to_double (const rchar * str, const rchar ** endptr, RStrParse * res)
{
  rdouble ret;
  errno = 0;
  if (str != NULL) {
    ret = strtod (str, (rchar **)endptr);
    if (res != NULL)
      *res = errno == 0 ? R_STR_PARSE_OK : R_STR_PARSE_INVAL;
  } else {
    errno = EINVAL;
    ret = 0.0;
    if (res)
      *res = R_STR_PARSE_INVAL;
  }

  return ret;
}

rchar *
r_strdup (const rchar * str)
{
  rchar * ret;

  if (R_LIKELY (str != NULL)) {
    rsize size = strlen (str) + 1;
    ret = r_malloc (size);
    memcpy (ret, str, size);
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_strndup (const rchar * str, rsize size)
{
  rchar * ret;

  if (R_LIKELY (str != NULL)) {
    const rchar * end;

    if ((end = r_strnchr (str, 0, size)) != NULL)
      size = RPOINTER_TO_SIZE (end - str);

    ret = r_malloc (size + 1);
    memcpy (ret, str, size);
    ret[size] = 0;
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_strdup_size (const rchar * str, rssize size)
{
  rchar * ret;

  if (str != NULL) {
    if (size < 0)
      ret = r_strdup (str);
    else
      ret = r_strndup (str, (rsize)size);
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_strdup_wstrip (const rchar * str)
{
  rchar * ret;

  if (R_LIKELY (str != NULL)) {
    rsize size;
    str = r_str_lwstrip (str);
    size = strlen (str);
    while (size > 0 && r_ascii_isspace (str[size - 1])) size--;
    ret = r_malloc (size + 1);
    memcpy (ret, str, size);
    ret[size] = 0;
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_strdup_strip (const rchar * str, const rchar * chars)
{
  rchar * ret;

  if (R_LIKELY (str != NULL)) {
    rsize size;
    str = r_str_lstrip (str, chars);
    size = strlen (str);
    while (size > 0 && strchr (chars, str[size - 1])) size--;
    ret = r_malloc (size + 1);
    memcpy (ret, str, size);
    ret[size] = 0;
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_str_wstrip (rchar * str)
{
  if (R_LIKELY (str != NULL)) {
    rsize size;
    while (r_ascii_isspace (*str)) str++;
    size = strlen (str);
    while (size > 0 && r_ascii_isspace (str[size - 1])) size--;
    str[size] = 0;
  }
  return str;
}

const rchar *
r_str_lwstrip (const rchar * str)
{
  if (R_LIKELY (str != NULL))
    while (r_ascii_isspace (*str)) str++;
  return str;
}

rchar *
r_str_twstrip (rchar * str)
{
  if (R_LIKELY (str != NULL)) {
    rsize size = strlen (str);
    while (size > 0 && r_ascii_isspace (str[size - 1])) size--;
    str[size] = 0;
  }

  return str;
}

rchar *
r_str_strip (rchar * str, const rchar * chars)
{
  if (R_LIKELY (str != NULL)) {
    rsize size;
    while (strchr (chars, *str)) str++;
    size = strlen (str);
    while (size > 0 && strchr (chars, str[size - 1])) size--;
    str[size] = 0;
  }
  return str;
}

const rchar *
r_str_lstrip (const rchar * str, const rchar * chars)
{
  if (R_LIKELY (str != NULL))
    while (strchr (chars, *str) != NULL) str++;
  return str;
}

rchar *
r_str_tstrip (rchar * str, const rchar * chars)
{
  if (R_LIKELY (str != NULL)) {
    rsize size = strlen (str);
    while (size > 0 && strchr (chars, str[size - 1])) size--;
    str[size] = 0;
  }

  return str;
}

int
r_asprintf (rchar ** str, const rchar * fmt, ...)
{
  int ret;
  va_list args;
  va_start (args, fmt);
  ret = r_vasprintf (str, fmt, args);
  va_end (args);
  return ret;
}

int
r_vasprintf (rchar ** str, const rchar * fmt, va_list args)
{
  int ret;

  if (R_UNLIKELY (str == NULL))
    return 0;
  if (R_UNLIKELY (fmt == NULL)) {
    *str = NULL;
    return 0;
  }

#if defined (HAVE_VASPRINTF)
  ret = vasprintf (str, fmt, args);
#elif defined (HAVE_VSPRINTF)
  va_list args_copy;
  va_copy (args_copy, args);
#if defined (HAVE__VSCPRINTF)
  ret = _vscprintf (fmt, args_copy);
#elif defined (HAVE_VSNPRINTF)
  ret = vsnprintf (NULL, 0, fmt, args_copy);
#else
#error vsprintf cant calculate size...
#endif
  va_end (args_copy);
  if (R_LIKELY (ret >= 0)) {
    *str = r_malloc (ret + 1);
    if (R_LIKELY (*str != NULL)) {
      ret = vsprintf (*str, fmt, args);
      if (R_UNLIKELY (ret < 0)) {
        r_free (*str);
        *str = NULL;
      }
    }
  }
#else
#pragma message ("r_vasprintf not implemented")
  (void) fmt;
  (void) args;
  *str = NULL;
  ret = 0;
#endif
  return ret;
}

rchar *
r_strprintf (const rchar * fmt, ...)
{
  rchar * ret;
  va_list args;
  va_start (args, fmt);
  r_vasprintf (&ret, fmt, args);
  va_end (args);
  return ret;
}

rchar *
r_strvprintf (const rchar * fmt, va_list args)
{
  rchar * ret;
  r_vasprintf (&ret, fmt, args);
  return ret;
}

int
r_strscanf (const rchar * str, const rchar * fmt, ...)
{
  int ret;
  va_list args;
  va_start (args, fmt);
  ret = r_strvscanf (str, fmt, args);
  va_end (args);
  return ret;
}

int
r_strvscanf (const rchar * str, const rchar * fmt, va_list args)
{
  if (R_UNLIKELY (str == NULL)) return -1;
  if (R_UNLIKELY (fmt == NULL)) return -1;
  return vsscanf (str, fmt, args);
}

RSList *
r_str_list_new (const rchar * str0, ...)
{
  RSList * ret;
  va_list args;

  va_start (args, str0);
  ret = r_str_list_newv (str0, args);
  va_end (args);

  return ret;
}

RSList *
r_str_list_newv (const rchar * str0, va_list args)
{
  RSList * cur, * ret;
  const rchar * arg;

  if (R_UNLIKELY (str0 == NULL))
    return NULL;

  ret = cur = r_slist_alloc (r_strdup (str0));
  for (arg = va_arg (args, const rchar *); arg != NULL;
      arg = va_arg (args, const rchar *), cur = cur->next) {
    cur->next = r_slist_alloc (r_strdup (arg));
  }

  return ret;
}

rchar **
r_strv_new (const rchar * str0, ...)
{
  rchar ** ret;
  va_list args;

  va_start (args, str0);
  ret = r_strv_newv (str0, args);
  va_end (args);

  return ret;
}

rchar **
r_strv_newv (const rchar * str0, va_list args)
{
  RSList * cur, * lst;
  rchar ** ret;
  rsize i = 0;

  if (R_UNLIKELY ((lst = r_str_list_newv (str0, args)) == NULL))
    return NULL;

  ret = r_mem_new_n (rchar *, r_slist_len (lst) + 1);
  while (lst) {
    cur = lst;
    lst = r_slist_next (cur);

    ret[i++] = r_slist_data (cur);
    r_slist_free1 (cur);
  }

  ret[i] = NULL;

  return ret;
}

rchar **
r_strv_copy (rchar * const * strv)
{
  rchar ** ret;

  if (R_LIKELY ((ret = r_mem_new_n (rchar *, r_strv_len (strv) + 1)) != NULL)) {
    rsize i;
    for (i = 0; strv[i] != NULL; i++)
      ret[i] = r_strdup (strv[i]);

    ret[i] = NULL;
  }

  return ret;
}

void
r_strv_free (rchar ** strv)
{
  rsize i;

  if (R_UNLIKELY (strv == NULL))
    return;

  for (i = 0; strv[i] != NULL; i++)
    r_free (strv[i]);

  r_free (strv);
}

rsize
r_strv_len (rchar * const * strv)
{
  rsize i;
  for (i = 0; strv[i] != NULL; i++);
  return i;
}

void
r_strv_foreach (rchar ** strv, RFunc func, rpointer user)
{
  if (strv != NULL) {
    rsize i;
    for (i = 0; strv[i] != NULL; i++)
      func (strv[i], user);
  }
}

rboolean
r_strv_contains (rchar * const * strv, const rchar * str)
{
  rsize i;
  for (i = 0; strv[i] != NULL; i++) {
    if (r_str_equals (strv[i], str))
      return TRUE;
  }
  return FALSE;
}

rchar *
r_strv_join (rchar * const * strv, const rchar * delim)
{
  rchar * ret, * ptr;
  rsize len, dlen;
  int i;

  if (R_UNLIKELY (strv == NULL))
    return NULL;
  else if (R_UNLIKELY (*strv == NULL))
    return r_strdup ("");

  /* compute total length len */
  dlen = strlen (delim);
  for (i = 1, len = strlen (*strv); strv[i] != NULL; i++)
    len += dlen + strlen(strv[i]);

  /* join strings */
  ret = r_malloc (len + 1);
  for (i = 1, ptr = r_stpcpy (ret, *strv); strv[i] != NULL; i++)
    ptr = r_stpcpy (r_stpcpy (ptr, delim), strv[i]);

  return ret;
}

rchar **
r_strsplit (const rchar * str, const rchar * delim, rsize max)
{
  rchar ** ret = NULL;

  if (str != NULL && delim != NULL && *delim != 0 && max > 0) {
    rsize dlen = strlen (delim);
    const rchar * prev, * ptr = str - dlen;
    rsize i, count = 1;

    while ((ptr = strstr (ptr + dlen, delim)) != NULL && count < max) count++;

    ret = r_mem_new_n (rchar *, count + 1);
    for (i = 0, prev = str; i < count - 1; i++, prev = ptr + dlen) {
      ptr = strstr (prev, delim);
      ret[i] = r_strndup (prev, ptr - prev);
    }
    ret[i] = r_strdup (prev);
    ret[count] = NULL;
  }

  return ret;
}

int
r_str_chunk_cmp (const RStrChunk * buf, const rchar * str, rssize size)
{
  int ret;
  if (size < 0) size = (rssize)r_strlen (str);
  if ((ret = (int)(size - buf->size)) == 0)
    ret = r_memcmp (buf->str, str, size);
  return ret;
}

int
r_str_chunk_casecmp (const RStrChunk * buf, const rchar * str, rssize size)
{
  int ret;
  if (size < 0) size = (rssize)r_strlen (str);
  if ((ret = (int)(size - buf->size)) == 0)
    ret = r_strncasecmp (buf->str, str, size);
  return ret;
}

rboolean
r_str_chunk_has_prefix (const RStrChunk * buf, const rchar * str, rssize size)
{
  if (size < 0) size = (rssize)r_strlen (str);
  return ((rsize)size <= buf->size) ? (r_memcmp (buf->str, str, size) == 0) : FALSE;
}

RStrParse
r_str_chunk_next_line (const RStrChunk * buf, RStrChunk * line)
{
  rssize offset;
  rsize max;

  if (R_UNLIKELY (buf == NULL)) return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (line == NULL)) return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (buf->str == NULL || buf->size == 0)) return R_STR_PARSE_INVAL;

  if (line->str != NULL) {
    if (R_UNLIKELY (line->str < buf->str)) return R_STR_PARSE_INVAL;
    line->str += line->size;
    if (line->str >= buf->str + buf->size)
      return R_STR_PARSE_RANGE;
    line->size = buf->size - RPOINTER_TO_SIZE (line->str - buf->str);
  } else {
    *line = *buf;
  }

  r_str_chunk_wstrip (line);

  max = buf->size - RPOINTER_TO_SIZE (line->str - buf->str);
  offset = r_str_idx_of_c (line->str, max, '\n');
  line->size = offset >= 0 ? (rsize)offset : max;

  while (line->size > 0 && r_ascii_isspace (line->str[line->size - 1]))
    line->size--;

  return line->size > 0 ? R_STR_PARSE_OK : R_STR_PARSE_RANGE;
}

ruint
r_str_chunk_split (RStrChunk * buf, const rchar * delim, ...)
{
  ruint ret;
  va_list args;

  va_start (args, delim);
  ret = r_str_chunk_splitv (buf, delim, args);
  va_end (args);

  return ret;
}

ruint
r_str_chunk_splitv (RStrChunk * buf, const rchar * delim, va_list args)
{
  ruint ret = 0;
  RStrChunk * cur;
  rssize s;

  if (R_UNLIKELY (buf == NULL)) return 0;
  if (R_UNLIKELY (delim == NULL)) return 0;

  while (buf->size > 0 && (cur = va_arg (args, RStrChunk *)) != NULL) {
    ret++;

    if ((s = r_str_idx_of_str (buf->str, buf->size, delim, -1)) < 0) {
      r_memcpy (cur, buf, sizeof (RStrChunk));
      buf->str += buf->size;
      buf->size = 0;
    } else {
      cur->str = buf->str;
      cur->size = s++;
      buf->str += s;
      buf->size -= s;
    }
  }

  return ret;
}

void
r_str_chunk_wstrip (RStrChunk * buf)
{
  while (buf->size > 0 && r_ascii_isspace (buf->str[0])) {
    buf->str++;
    buf->size--;
  }
  while (buf->size > 0 && (buf->str[buf->size - 1] == 0 ||
        r_ascii_isspace (buf->str[buf->size - 1]))) {
    buf->size--;
  }
}

RStrParse
r_str_kv_parse (RStrKV * kv, const rchar * str, rssize size,
    const rchar * delim, const rchar ** endptr)
{
  rchar * ptr;
  rsize dsize;

  if (R_UNLIKELY (kv == NULL)) return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (str == NULL)) return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (delim == NULL)) return R_STR_PARSE_INVAL;

  dsize = r_strlen (delim);
  if ((ptr = r_str_ptr_of_str (str, size, delim, dsize)) != NULL) {
    const rchar * end = str + ((size < 0) ? r_strlen (str) : (rsize)size);

    kv->key.str = (rchar *)r_str_lwstrip (str);
    kv->key.size = ptr - kv->key.str;
    kv->val.str = (rchar *)r_str_lwstrip (ptr + dsize);
    kv->val.size = end - kv->val.str;

    if (endptr != NULL)
      *endptr = end;
    return R_STR_PARSE_OK;
  }

  return R_STR_PARSE_RANGE;
}

RStrParse
r_str_kv_parse_multiple (RStrKV * kv, const rchar * str, rssize size,
    const rchar * kvdelim, rssize kvdsize, const rchar * delim, rssize dsize,
    const rchar ** endptr)
{
  rchar * ptr;

  if (R_UNLIKELY (kv == NULL)) return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (str == NULL)) return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (kvdelim == NULL)) return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (delim == NULL)) return R_STR_PARSE_INVAL;

  if (size < 0) size = r_strlen (str);
  if (kvdsize < 0) kvdsize = r_strlen (kvdelim);
  if (dsize < 0) dsize = r_strlen (delim);

  if ((ptr = r_str_ptr_of_str (str, size, kvdelim, kvdsize)) != NULL) {
    const rchar * end;

    kv->key.str = (rchar *)r_str_lwstrip (str);
    kv->key.size = ptr - kv->key.str;
    kv->val.str = (rchar *)r_str_lwstrip (ptr + dsize);

    if ((end = r_str_ptr_of_str (kv->val.str, RPOINTER_TO_SIZE (str + size - kv->val.str),
            delim, dsize)) != NULL) {
      kv->val.size = end - kv->val.str;
      end += dsize;
    } else {
      end = str + size;
      kv->val.size = end - kv->val.str;
    }

    if (endptr != NULL)
      *endptr = end;
    return R_STR_PARSE_OK;
  }

  return R_STR_PARSE_RANGE;
}

rboolean
r_str_kv_is_key (const RStrKV * kv, const rchar * key, rssize size)
{
  rsize len;

  if (R_UNLIKELY (kv == NULL)) return FALSE;
  if (R_UNLIKELY (key == NULL)) return FALSE;

  if ((len = size < 0 ? r_strlen (key) : (rsize)size) != kv->key.size)
    return FALSE;
  return r_strncmp (kv->key.str, key, len) == 0;
}

rboolean
r_str_kv_is_value (const RStrKV * kv, const rchar * val, rssize size)
{
  rsize len;

  if (R_UNLIKELY (kv == NULL)) return FALSE;
  if (R_UNLIKELY (val == NULL)) return FALSE;

  if ((len = size < 0 ? r_strlen (val) : (rsize)size) != kv->val.size)
    return FALSE;
  return r_strncmp (kv->val.str, val, len) == 0;
}

rchar *
r_strjoin (const rchar * delim, ...)
{
  rchar * ret;
  va_list args;

  va_start (args, delim);
  ret = r_strjoinv (delim, args);
  va_end (args);

  return ret;
}

rchar *
r_strjoinv (const rchar * delim, va_list args)
{
  rchar * ret, * ptr;
  const rchar * cur;
  rsize len, dlen;
  va_list args_dup;

  if (R_UNLIKELY (delim == NULL))
    return NULL;

  va_copy (args_dup, args);

  cur = va_arg (args_dup, const rchar *);
  if (R_LIKELY (cur != NULL)) {
    /* compute total length len */
    dlen = strlen (delim);
    len = strlen (cur);
    while ((cur = va_arg (args_dup, const rchar *)) != NULL)
      len += dlen + strlen(cur);

    /* join strings */
    ret = r_malloc (len + 1);
    ptr = r_stpcpy (ret, va_arg (args, const rchar *));
    while ((cur = va_arg (args, const rchar *)) != NULL)
      ptr = r_stpcpy (r_stpcpy (ptr, delim), cur);
  } else {
    ret = r_strdup ("");
  }

  va_end (args_dup);
  return ret;
}

rchar *
r_strnjoin (rchar * str, rsize size, const rchar * delim, ...)
{
  rchar * ret;
  va_list args;

  va_start (args, delim);
  ret = r_strnjoinv (str, size, delim, args);
  va_end (args);

  return ret;
}

rchar *
r_strnjoinv (rchar * str, rsize size, const rchar * delim, va_list args)
{
  rchar * ptr;
  const rchar * cur;
  rsize len, dlen;
  va_list args_dup;

  if (R_UNLIKELY (str == NULL)) return NULL;
  if (R_UNLIKELY (size == 0)) return NULL;
  if (R_UNLIKELY (delim == NULL)) return NULL;

  va_copy (args_dup, args);

  cur = va_arg (args_dup, const rchar *);
  ptr = str;
  if (R_LIKELY (cur != NULL)) {
    /* compute total length len */
    dlen = strlen (delim);
    len = strlen (cur);
    while ((cur = va_arg (args_dup, const rchar *)) != NULL)
      len += dlen + strlen (cur);

    if (len >= size)
      return NULL;

    /* join strings */
    ptr = r_stpcpy (ptr, va_arg (args, const rchar *));
    while ((cur = va_arg (args, const rchar *)) != NULL)
      ptr = r_stpcpy (r_stpcpy (ptr, delim), cur);
  } else {
    *str = 0;
  }

  va_end (args_dup);
  return str;
}

#if RLIB_SIZEOF_VOID_P == 8
#define _PTR_FMT  "%16p: "
#else
#define _PTR_FMT  "%8p: "
#endif

void
r_str_dump (rchar * dst, const rchar * src, rsize size)
{
  dst += r_sprintf (dst, _PTR_FMT, src);
  while (size-- > 0) {
    *dst++ = r_ascii_isprint (*src) ? *src : '.';
    src++;
  }
  *dst = 0;
}

rboolean
r_str_mem_dump (rchar * str, const ruint8 * ptr, rsize size, rsize align)
{
  rsize i, itsize, pad, pad_extra;

  if (R_UNLIKELY (size == 0 || align == 0))
    return FALSE;
  if (R_UNLIKELY (str == NULL))
    return FALSE;
  if (R_UNLIKELY (ptr == NULL))
    return FALSE;

  for (; size > 0; size -= itsize, ptr += itsize) {
    itsize = size > align ? align : size;
    pad = (align - itsize);
    pad_extra = (align - itsize) / 8;

    str += r_sprintf (str, _PTR_FMT, ptr);
    for (i = 0; i < itsize; i++) {
      str += r_sprintf (str, "%02x ", ptr[i]);
    }

    memset (str, (int)' ', pad * 3 + 1);
    str += pad * 3 + 1;

    *str++ = '"';
    for (i = 0; i < itsize; i++) {
      *str++ = r_ascii_isprint (ptr[i]) ? ptr[i] : '.';
      if ((i+1) % 8 == 0 && (i+1) < itsize) *str++ = ' ';
    }
    memset (str, (int)' ', pad + pad_extra);
    str += pad + pad_extra;
    *str++ = '"';
    if (size > align)
      *str++ = '\n';
  }

#undef _PTR_FMT

  *str = 0;
  return TRUE;
}

rchar *
r_str_mem_dump_dup (const ruint8 * ptr, rsize size, rsize align)
{
  rchar * ret;
  rsize memsize;

  if (R_UNLIKELY (size == 0 || align == 0))
    return NULL;

  memsize = R_STR_MEM_DUMP_SIZE (align) * ((size / align) + 1);

  if ((ret = r_malloc (memsize)) != NULL) {
    if (R_UNLIKELY (!r_str_mem_dump (ret, ptr, size, align))) {
      r_free (ret);
      ret = NULL;
    }
  }

  return ret;
}

rchar *
r_str_mem_hex (const ruint8 * ptr, rsize size)
{
  rchar * ret;

  if (ptr != NULL && size > 0 && (ret = r_malloc (size * 2 + 1)) != NULL) {
    static const rchar hex[] = "0123456789abcdef";
    rchar * dst = ret;
    rsize i;

    for (i = 0; i < size; i++, ptr++) {
      *(dst++) = hex[*ptr >> 4];
      *(dst++) = hex[*ptr & 0xf];
    }

    *dst = 0;
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_str_mem_hex_full (const ruint8 * ptr, rsize size,
    const rchar * divider, rsize interval)
{
  rchar * ret;
  rsize asize, dlen;

  if (interval == 0 || (dlen = r_strlen (divider)) == 0)
    return r_str_mem_hex (ptr, size);

  asize = size * 2 + ((size - 1) / interval) * dlen + 1;
  if (ptr != NULL && size > 0 && (ret = r_malloc (asize)) != NULL) {
    static const rchar hex[] = "0123456789abcdef";
    rchar * dst = ret;
    rsize i;

    for (i = 0; TRUE; ) {
      *(dst++) = hex[ptr[i] >> 4];
      *(dst++) = hex[ptr[i] & 0xf];

      if (++i >= size)
        break;

      if ((i % interval) == 0) {
        r_memcpy (dst, divider, dlen);
        dst += dlen;
      }
    }

    *dst = 0;
  } else {
    ret = NULL;
  }

  return ret;
}

rsize
r_str_hex_to_binary (const rchar * hex, ruint8 * bin, rsize size)
{
  rsize ret;

  if (R_UNLIKELY (hex == NULL)) return 0;
  if (R_UNLIKELY (bin == NULL)) return 0;
  if (R_UNLIKELY (size == 0)) return 0;

  hex = r_str_lwstrip (hex);
  if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X'))
    hex += 2;

  for (ret = 0; *hex != 0 && !r_ascii_isspace (*hex); ret++, hex += 2) {
    if (ret > size) return 0;
    if (!r_ascii_isxdigit (hex[0])) return 0;
    if (hex[1] == 0 || !r_ascii_isxdigit (hex[1])) return 0;

    *bin++ =  (r_ascii_xdigit_value (hex[0]) << 4) |
              (r_ascii_xdigit_value (hex[1])     );
  }

  return ret;
}

ruint8 *
r_str_hex_mem (const rchar * hex, rsize * outsize)
{
  ruint8 * ret;
  rsize size;

  if (R_UNLIKELY (hex == NULL)) return NULL;
  if ((size = strlen (hex) / 2) == 0) return NULL;

  if ((ret = r_malloc (size)) != NULL) {
    if ((size = r_str_hex_to_binary (hex, ret, size)) == 0) {
      r_free (ret);
      ret = NULL;
    }

    if (outsize != NULL)
      *outsize = size;
  }

  return ret;
}

