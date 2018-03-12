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
#include <rlib/data/rstring.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

#define R_STRING_ALLOC_MASK           0x3F

struct RString
{
  rchar * cstr;
  rsize size;
  rsize len;
};

RString *
r_string_new (const rchar * cstr)
{
  RString * str;
  rsize len;

  if (R_UNLIKELY (cstr == NULL))
    return r_string_new_sized (0);

  len = r_strlen (cstr);
  str = r_string_new_sized (len + 1);
  r_memcpy (str->cstr, cstr, len + 1);
  str->len = len;

  return str;
}

RString *
r_string_new_sized (rsize size)
{
  RString * str = r_mem_new (RString);
  str->len = 0;
  str->size = size | R_STRING_ALLOC_MASK;
  str->cstr = r_malloc (str->size);
  str->cstr[0] = 0;

  return str;
}

void
r_string_free (RString * str)
{
  r_free (r_string_free_keep (str));
}

rchar *
r_string_free_keep (RString * str)
{
  rchar * ret = str->cstr;
  r_free (str);
  return ret;
}

rsize
r_string_length (RString * str)
{
  return str->len;
}

rsize
r_string_alloc_size (RString * str)
{
  return str->size;
}

int
r_string_cmp (RString * str1, RString * str2)
{
  return r_strcmp (str1->cstr, str2->cstr);
}

int
r_string_cmp_cstr (RString * str, const rchar * cstr)
{
  return r_strcmp (str->cstr, cstr);
}

#define r_string_ensure_additional_size(str, size) \
  r_string_ensure_size (str, str->len + 1 + (size))
static rboolean
r_string_ensure_size (RString * str, rsize size)
{
  if (size > str->size) {
    str->size += (size - str->size) | R_STRING_ALLOC_MASK;
    if ((str->cstr = r_realloc (str->cstr, str->size)) == NULL) {
      str->len = str->size = 0;
      return FALSE;
    }
  }
  return TRUE;
}

rsize
r_string_reset (RString * str, const rchar * cstr)
{
  rsize ret;

  if (R_UNLIKELY (cstr == NULL))
    return 0;
  ret = r_strlen (cstr);
  if (R_UNLIKELY (!r_string_ensure_size (str, ret)))
    return 0;

  r_memcpy (str->cstr, cstr, ret + 1);

  return ret;
}

rsize
r_string_append (RString * str, const rchar * cstr)
{
  if (R_UNLIKELY (cstr == NULL))
    return 0;

  return r_string_append_len (str, cstr, r_strlen (cstr));
}

rsize
r_string_append_len (RString * str, const rchar * cstr, rsize len)
{
  if (R_UNLIKELY (cstr == NULL || len == 0))
    return 0;
  if (R_UNLIKELY (!r_string_ensure_additional_size (str, len)))
    return 0;

  r_memcpy (str->cstr + str->len, cstr, len);
  str->len += len;
  str->cstr[str->len] = 0;

  return len;
}

rsize
r_string_append_printf (RString * str, const rchar * fmt, ...)
{
  rsize ret;
  va_list args;
  va_start (args, fmt);
  ret = r_string_append_vprintf (str, fmt, args);
  va_end (args);
  return ret;
}

rsize
r_string_append_vprintf (RString * str, const rchar * fmt, va_list ap)
{
  rchar * cstr = r_strvprintf (fmt, ap);
  rsize ret = r_string_append (str, cstr);
  r_free (cstr);

  return ret;
}

rsize
r_string_prepend (RString * str, const rchar * cstr)
{
  if (R_UNLIKELY (cstr == NULL))
    return 0;

  return r_string_prepend_len (str, cstr, r_strlen (cstr));
}

rsize
r_string_prepend_len (RString * str, const rchar * cstr, rsize len)
{
  if (R_UNLIKELY (cstr == NULL || len == 0))
    return 0;
  if (R_UNLIKELY (!r_string_ensure_additional_size (str, len)))
    return 0;

  r_memmove (str->cstr + len, str->cstr, str->len + 1);
  r_memcpy (str->cstr, cstr, len);
  str->len += len;

  return len;
}

rsize
r_string_prepend_printf (RString * str, const rchar * fmt, ...)
{
  rsize ret;
  va_list args;
  va_start (args, fmt);
  ret = r_string_prepend_vprintf (str, fmt, args);
  va_end (args);
  return ret;
}

rsize
r_string_prepend_vprintf (RString * str, const rchar * fmt, va_list ap)
{
  rchar * cstr;
  rsize ret;

  if ((cstr = r_strvprintf (fmt, ap)) != NULL) {
    rsize len = r_strlen (cstr);
    if ((ret = r_string_prepend_len (str, cstr, len)) == len)
      ret++;
    r_free (cstr);
  } else {
    ret = 0;
  }

  return ret;
}

rsize
r_string_insert (RString * str, rsize pos, const rchar * cstr)
{
  if (R_UNLIKELY (cstr == NULL))
    return 0;

  return r_string_insert_len (str, pos, cstr, r_strlen (cstr));
}

rsize
r_string_insert_len (RString * str, rsize pos, const rchar * cstr, rsize len)
{
  if (R_UNLIKELY (cstr == NULL))
    return 0;

  if (R_UNLIKELY (pos >= str->len))
    return r_string_append (str, cstr);

  if (R_UNLIKELY (!r_string_ensure_additional_size (str, len)))
    return 0;
  r_memmove (str->cstr + pos + len, str->cstr + pos, str->len - pos + 1);
  r_memcpy (str->cstr + pos, cstr, len);
  str->len += len;

  return len;
}

rsize
r_string_overwrite (RString * str, rsize pos, const rchar * cstr)
{
  if (R_UNLIKELY (cstr == NULL))
    return 0;

  return r_string_overwrite_len (str, pos, cstr, r_strlen (cstr));
}

rsize
r_string_overwrite_len (RString * str, rsize pos, const rchar * cstr, rsize len)
{
  if (R_UNLIKELY (cstr == NULL))
    return 0;

  if (R_UNLIKELY (pos >= str->len))
    return r_string_append (str, cstr);

  if (pos + len > str->len) {
    if (R_UNLIKELY (!r_string_ensure_additional_size (str, pos + len - str->len)))
      return 0;
    r_memcpy (str->cstr + pos, cstr, len);
    str->len = pos + len;
    str->cstr[str->len] = 0;
  } else {
    r_memcpy (str->cstr + pos, cstr, len);
  }

  return len;
}

rsize
r_string_truncate (RString * str, rsize len)
{
  rsize ret;
  if (R_UNLIKELY (len > str->len))
    return 0;

  ret = str->len - len;
  str->len = len;
  str->cstr[len] = 0;
  return ret;
}

rsize
r_string_erase (RString * str, rsize pos, rsize len)
{
  if (pos > str->len)
    return 0;
  else if (pos + len >= str->len)
    return r_string_truncate (str, pos);

  str->len -= len;
  r_memmove (str->cstr + pos, str->cstr + pos + len, str->len - pos + 1);

  return str->len;
}

