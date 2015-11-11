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
#include <rlib/ralloc.h>
#include <rlib/rascii.h>
#include <string.h>
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
r_strncmp (const rchar * a, const rchar * b, rsize len)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  return strncmp (a, b, len);
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

rchar *
r_strcpy (rchar * dst, const rchar * src)
{
  if (R_UNLIKELY (dst == NULL))
    return NULL;
  if (R_UNLIKELY (src == NULL))
    return dst;
  return strcpy (dst, src);
}

rchar *
r_strncpy (rchar * dst, const rchar * src, rsize len)
{
  if (R_UNLIKELY (dst == NULL))
    return NULL;
  if (R_UNLIKELY (src == NULL)) {
    memset (dst, 0, len);
    return dst;
  }
  return strncpy (dst, src, len);
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
    ruint bits, rintmax * val)
{
  RStrParse ret = R_STR_PARSE_INVAL;
  const rchar * ptr, * start;
  rboolean neg = FALSE;
  ruintmax v = 0, m = RUINTMAX_MAX >> (RLIB_SIZEOF_INTMAX * 8 - (bits - 1));

  *val = 0;
  if (endptr != NULL)
    *endptr = str;

  if (R_UNLIKELY (str == NULL || *str == 0))
    return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (base == 1 || base > 36))
    return R_STR_PARSE_INVAL;

  ptr = r_strlwstrip (str);
  if (R_UNLIKELY (*ptr == 0))
    goto beach;

  ret = R_STR_PARSE_OK;
  if ((neg = (*ptr == '-')) || *ptr == '+') {
    ptr++;
    m++;
  }

  if (*ptr == '0') {
    ptr++;
    if ((base == 0 || base == 16) && (*ptr == 'X' || *ptr == 'x')) {
      if (!r_ascii_isxdigit (ptr[1]))
        goto beach;
      base = 16;
      ptr++;
    } else if (base == 0) {
      base = 8;
    }
  } else if (base == 0) {
    base = 10;
  }

  for (start = ptr; *ptr != 0;) {
    rchar c;
    ruintmax nv;

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
    *val = !neg ? v : -v;
  else
    ret = R_STR_PARSE_INVAL;

beach:
  if (endptr != NULL)
    *endptr = ptr;

  return ret;
}

static inline RStrParse
r_str_to_uint_parse (const rchar * str, const rchar ** endptr, ruint base,
    ruint bits, ruintmax * val)
{
  RStrParse ret = R_STR_PARSE_INVAL;
  const rchar * ptr, * start;
  ruintmax v = 0, m = RUINTMAX_MAX >> (RLIB_SIZEOF_INTMAX * 8 - bits);

  *val = 0;
  if (endptr != NULL)
    *endptr = str;

  if (R_UNLIKELY (str == NULL || *str == 0))
    return R_STR_PARSE_INVAL;
  if (R_UNLIKELY (base == 1 || base > 36))
    return R_STR_PARSE_INVAL;

  ptr = r_strlwstrip (str);
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
      base = 8;
    }
  } else if (base == 0) {
    base = 10;
  }

  for (start = ptr; *ptr != 0;) {
    rchar c;
    ruintmax nv;

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
  rintmax ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 8, &ret);
  if (res != NULL)
    *res = r;
  return (rint8)ret;
}

ruint8
r_str_to_uint8 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruintmax ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 8, &ret);
  if (res != NULL)
    *res = r;
  return (ruint8)ret;
}

rint16
r_str_to_int16 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  rintmax ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 16, &ret);
  if (res != NULL)
    *res = r;
  return (rint16)ret;
}

ruint16
r_str_to_uint16 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruintmax ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 16, &ret);
  if (res != NULL)
    *res = r;
  return (ruint16)ret;
}

rint32
r_str_to_int32 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  rintmax ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 32, &ret);
  if (res != NULL)
    *res = r;
  return (rint32)ret;
}

ruint32
r_str_to_uint32 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruintmax ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 32, &ret);
  if (res != NULL)
    *res = r;
  return (ruint32)ret;
}

rint64
r_str_to_int64 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  rintmax ret;
  RStrParse r = r_str_to_int_parse (str, endptr, base, 64, &ret);
  if (res != NULL)
    *res = r;
  return (rint64)ret;
}

ruint64
r_str_to_uint64 (const rchar * str, const rchar ** endptr, ruint base, RStrParse * res)
{
  ruintmax ret;
  RStrParse r = r_str_to_uint_parse (str, endptr, base, 64, &ret);
  if (res != NULL)
    *res = r;
  return (ruint64)ret;
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
r_strndup (const rchar * str, rsize n)
{
  rchar * ret;

  if (R_LIKELY (str != NULL)) {
    rsize size = strlen (str);
    if (n < size)
      size = n;

    ret = r_malloc (size + 1);
    memcpy (ret, str, size);
    ret[size] = 0;
  } else {
    ret = NULL;
  }

  return ret;
}

rchar *
r_strdup_strip (const rchar * str)
{
  rchar * ret;

  if (R_LIKELY (str != NULL)) {
    rsize size;
    str = r_strlwstrip (str);
    size = strlen (str);
    while (size > 0 && isspace (str[size - 1])) size--;
    ret = r_malloc (size + 1);
    memcpy (ret, str, size);
    ret[size] = 0;
  } else {
    ret = NULL;
  }

  return ret;
}

const rchar *
r_strlwstrip (const rchar * str)
{
  if (R_LIKELY (str != NULL))
    while (isspace (*str)) str++;
  return str;
}

rchar *
r_strtwstrip (rchar * str)
{
  if (R_LIKELY (str != NULL)) {
    rsize size = strlen (str);
    while (size > 0 && isspace (str[size - 1])) size--;
    str[size] = 0;
  }

  return str;
}

rchar *
r_strstrip (rchar * str)
{
  if (R_LIKELY (str != NULL)) {
    rsize size;
    while (isspace (*str)) str++;
    size = strlen (str);
    while (size > 0 && isspace (str[size - 1])) size--;
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

#if defined(HAVE_VASPRINTF)
  ret = vasprintf (str, fmt, args);
#elif defined(HAVE_VSPRINTF)
  va_list args_copy;
  va_copy (args_copy, args);
#if defined(HAVE__VSCPRINTF)
  ret = _vscprintf (fmt, args_copy);
#elif defined(HAVE_VSNPRINTF)
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
#error r_str_vprintf not implemented
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

  ret = r_malloc (sizeof (rchar *) * (r_slist_len (lst) + 1));
  while (lst) {
    cur = lst;
    lst = r_slist_next (cur);

    ret[i++] = r_slist_data (cur);
    r_slist_free1 (cur);
  }

  ret[i] = NULL;

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

    ret = r_malloc (sizeof (rchar *) * (count + 1));
    for (i = 0, prev = str; i < count - 1; i++, prev = ptr + dlen) {
      ptr = strstr (prev, delim);
      ret[i] = r_strndup (prev, ptr - prev);
    }
    ret[i] = r_strdup (prev);
    ret[count] = NULL;
  }

  return ret;
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

rboolean
r_str_mem_dump (rchar * str, const ruint8 * ptr, rsize size, rsize align)
{
  rsize i;

  if (R_UNLIKELY (size == 0 || size > align))
    return FALSE;
  if (R_UNLIKELY (str == NULL))
    return FALSE;
  if (R_UNLIKELY (ptr == NULL))
    return FALSE;

#if RLIB_SIZEOF_VOID_P == 8
#define _PTR_FMT  "%14p: "
#else
#define _PTR_FMT  "%8p: "
#endif

  if (size > 0) {
    rsize pad = (align - size);
    rsize pad_extra = (align - size) / 8;

    str += r_sprintf (str, _PTR_FMT, ptr);
    for (i = 0; i < size; i++) {
      str += r_sprintf (str, "%02x ", ptr[i]);
    }

    memset (str, (int)' ', pad * 3 + 1);
    str += pad * 3 + 1;

    *str++ = '"';
    for (i = 0; i < size; i++) {
      *str++ = r_ascii_isprint (ptr[i]) ? ptr[i] : '.';
      if ((i+1) % 8 == 0 && (i+1) < size) *str++ = ' ';
    }
    memset (str, (int)' ', pad + pad_extra);
    str += pad + pad_extra;
    *str++ = '"';
  }

#undef _PTR_FMT

  *str = 0;
  return TRUE;
}

rchar *
r_str_mem_dump_dup (const ruint8 * ptr, rsize size, rsize align)
{
  rchar * ret;

  if (R_UNLIKELY (size == 0 || size > align))
    return NULL;

  if ((ret = r_malloc (R_STR_MEM_DUMP_SIZE (align))) != NULL) {
    if (R_UNLIKELY (!r_str_mem_dump (ret, ptr, size, align))) {
      r_free (ret);
      ret = NULL;
    }
  }

  return ret;
}

