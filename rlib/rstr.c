/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include <rlib/rstr.h>
#include <rlib/ralloc.h>
#include <string.h>
#include <ctype.h>

int
r_strcmp (const rchar * a, const rchar * b)
{
  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  return strcmp (a, b);
}

rchar *
r_stpcpy (rchar * dst, const rchar * src)
{
#ifdef HAVE_STPCPY
  return stpcpy (dst, src);
#else
  do {
    *dst++ = *src;
  } while (*src++ != '\0');

  return dst - 1;
#endif
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
    while (isspace (str[size]) && size > 0) size--;
    ret = r_malloc (size + 1);
    memcpy (ret, str, size);
    ret[size] = 0;
  } else {
    ret = NULL;
  }

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
  RSList * cur, * lst = r_str_list_newv (str0, args);
  rchar ** ret = r_malloc (sizeof (rchar *) * r_slist_len (lst));
  rsize i = 0;

  while (lst) {
    cur = lst;
    lst = r_slist_next (cur);

    ret[i++] = r_slist_data (cur);
    r_slist_free1 (cur);
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

rboolean
r_strv_contains (rchar * const * strv, const rchar * str)
{
  rsize i;
  for (i = 0; strv[i] != NULL; i++) {
    if (r_str_equals (*strv, str))
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
    rsize len = strlen (str);
    while (isspace (str[len]) && len > 0) len--;
    str[len] = 0;
  }

  return str;
}

