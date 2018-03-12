/* RLIB - Convenience library for useful things
 * Copyright (C) 2016  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/asn1/roid.h>

#include <rlib/charset/rascii.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

rchar *
r_asn1_oid_to_dot (const ruint32 * oid, rsize oidlen)
{
  rchar * ret;

  if (R_UNLIKELY (oid == NULL || oidlen == 0))
    return NULL;

  /* FIXME: Is this enough mem??? */
  if ((ret = r_malloc (oidlen * 8)) != NULL) {
    rchar * ptr;
    rsize i;

    ptr = ret + r_sprintf (ret, "%u", oid[0]);
    for (i = 1; i < oidlen; i++)
      ptr += r_sprintf (ptr, ".%u", oid[i]);
  } else {
    ret = NULL;
  }

  return ret;
}

ruint32 *
r_asn1_oid_from_dot (const rchar * oid, rssize oidsize, rsize * outlen)
{
  const rchar * ptr, * end;
  ruint32 * ret;
  rsize len;

  if (R_UNLIKELY (oid == NULL || (oidsize >= 0 && oidsize <= 2)))
    return NULL;

  if (oidsize < 0)
    oidsize = r_strlen (oid);

  if ((ret = r_mem_new_n (ruint32, (oidsize + 1) / 2)) != NULL) {
    for (ptr = oid, len = 0; ptr < oid+oidsize && *ptr; ptr = end+1) {
      RStrParse res;
      ret[len++] = r_str_to_uint32 (ptr, &end, 10, &res);

      if (res == R_STR_PARSE_OK && end <= oid+oidsize) {
        while (end < oid+oidsize && r_ascii_isspace (*end))
          end++;
        if (end == oid+oidsize)
          break;
        if (*end == '.' && end+1 < oid+oidsize)
          continue;
      }

      r_free (ret);
      return NULL;
    }

    if (outlen != NULL)
      *outlen = len;
  }

  return ret;
}

rboolean
r_asn1_oid_is_dot (const ruint32 * oid, rsize oidlen,
    const rchar * dot, rssize dotsize)
{
  rboolean ret;
  rchar * oiddot;

  if (dotsize < 0)
    dotsize = r_strlen (dot);
  if (R_UNLIKELY (dot == NULL || dotsize == 0))
    return FALSE;

  if ((oiddot = r_asn1_oid_to_dot (oid, oidlen)) != NULL) {
    ret = r_strcmp (oiddot, dot) == 0;
    r_free (oiddot);
  } else {
    ret = FALSE;
  }

  return ret;
}

rboolean
r_asn1_oid_has_dot_prefix (const ruint32 * oid, rsize oidlen,
    const rchar * dot, rssize dotsize)
{
  rboolean ret;
  rchar * oiddot;

  if (dotsize < 0)
    dotsize = r_strlen (dot);
  if (R_UNLIKELY (dot == NULL || dotsize == 0))
    return FALSE;

  if ((oiddot = r_asn1_oid_to_dot (oid, oidlen)) != NULL) {
    ret = r_strncmp (oiddot, dot, dotsize) == 0;
    r_free (oiddot);
  } else {
    ret = FALSE;
  }

  return ret;
}

