/* RLIB - Convenience library for useful things
 * Copyright (C) 2016 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/net/rsocketaddress.h>
#include "rsocket-private.h"
#include "net/rnet-private.h"

#include <rlib/charset/rascii.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#define R_SOCKET_ADDRESS_FAMILY(a)         (a)->addr.ss_family
#define R_SOCKET_ADDRESS_IPV4_ADDR(a)      ((struct sockaddr_in *)&(a)->addr)->sin_addr.s_addr
#define R_SOCKET_ADDRESS_IPV4_PORT(a)      ((struct sockaddr_in *)&(a)->addr)->sin_port
#define R_SOCKET_ADDRESS_IPV4_SIZE          sizeof (struct sockaddr_in)

#define R_SOCKET_ADDRESS_IPV6_ADDR(a)      ((struct sockaddr_in6 *)&(a)->addr)->sin6_addr.s6_addr
#define R_SOCKET_ADDRESS_IPV6_PORT(a)      ((struct sockaddr_in6 *)&(a)->addr)->sin6_port
#define R_SOCKET_ADDRESS_IPV6_FLOWINFO(a)  ((struct sockaddr_in6 *)&(a)->addr)->sin6_flowinfo
#define R_SOCKET_ADDRESS_IPV6_SCOPE_ID(a)  ((struct sockaddr_in6 *)&(a)->addr)->sin6_scope_id
#define R_SOCKET_ADDRESS_IPV6_SIZE          sizeof (struct sockaddr_in6)

RSocketAddress *
r_socket_address_new (void)
{
  RSocketAddress * ret;

  if ((ret = r_mem_new0 (RSocketAddress)) != NULL) {
    r_ref_init (ret, r_free);
    ret->addrlen = sizeof (ret->addr);
  }

  return ret;
}

RSocketAddress *
r_socket_address_new_from_native (rconstpointer addr, rsize addrsize)
{
  RSocketAddress * ret;

  if (R_UNLIKELY (addr == NULL)) return NULL;
  if (R_UNLIKELY (addrsize == 0 || addrsize > sizeof (ret->addr))) return NULL;

  if ((ret = r_mem_new0 (RSocketAddress)) != NULL) {
    r_ref_init (ret, r_free);
    ret->addrlen = (socklen_t) MIN (sizeof (ret->addr), addrsize);
    r_memcpy (&ret->addr, addr, ret->addrlen);
  }

  return ret;
}

RSocketAddress *
r_socket_address_copy (const RSocketAddress * addr)
{
  RSocketAddress * ret;

  if (R_UNLIKELY (addr == NULL)) return NULL;

  if ((ret = r_mem_new (RSocketAddress)) != NULL) {
    r_ref_init (ret, r_free);
    ret->addrlen = addr->addrlen;
    r_memcpy (&ret->addr, &addr->addr, sizeof (ret->addr));
  }

  return ret;
}

RSocketAddress *
r_socket_address_ipv4_new_uint32 (ruint32 addr, ruint16 port)
{
  RSocketAddress * ret;

  if ((ret = r_mem_new0 (RSocketAddress)) != NULL) {
    r_ref_init (ret, r_free);

    ret->addrlen = R_SOCKET_ADDRESS_IPV4_SIZE;
    R_SOCKET_ADDRESS_FAMILY (ret) = R_SOCKET_FAMILY_IPV4;
    R_SOCKET_ADDRESS_IPV4_PORT (ret) = r_htons (port);
    R_SOCKET_ADDRESS_IPV4_ADDR (ret) = r_htonl (addr);
  }

  return ret;
}

RSocketAddress *
r_socket_address_ipv6_new_from_bytes (const ruint8 ip[16], ruint16 port)
{
  RSocketAddress * ret;

  if (R_UNLIKELY (ip == NULL)) return NULL;

  if ((ret = r_mem_new0 (RSocketAddress)) != NULL) {
    r_ref_init (ret, r_free);

    ret->addrlen = R_SOCKET_ADDRESS_IPV6_SIZE;
    R_SOCKET_ADDRESS_FAMILY (ret) = R_SOCKET_FAMILY_IPV6;
    R_SOCKET_ADDRESS_IPV6_PORT (ret) = r_htons (port);
    r_memcpy (R_SOCKET_ADDRESS_IPV6_ADDR (ret), ip, 16);
  }

  return ret;
}

/* Parse a strict dotted-quad "d.d.d.d" (decimal octets 0-255, no leading
 * zeros), as accepted by inet_pton(AF_INET); @p src is NUL-terminated. */
static rboolean
r_socket_address_parse_ipv4 (const rchar * src, ruint8 out[4])
{
  ruint8 tmp[4];
  ruint8 * tp = tmp;
  ruint octets = 0;
  rboolean saw_digit = FALSE;
  rchar ch;

  *tp = 0;
  while ((ch = *src++) != 0) {
    if (r_ascii_isdigit (ch)) {
      ruint nw = (ruint) *tp * 10 + (ruint) (ch - '0');
      if (saw_digit && *tp == 0)        /* reject a leading zero */
        return FALSE;
      if (nw > 255)
        return FALSE;
      *tp = (ruint8) nw;
      if (!saw_digit) {
        if (++octets > 4)
          return FALSE;
        saw_digit = TRUE;
      }
    } else if (ch == '.' && saw_digit) {
      if (octets == 4)
        return FALSE;
      *++tp = 0;
      saw_digit = FALSE;
    } else {
      return FALSE;
    }
  }
  if (octets != 4)
    return FALSE;

  r_memcpy (out, tmp, sizeof (tmp));
  return TRUE;
}

/* Parse an RFC 4291 IPv6 text address — "::" zero-compression and an
 * optional trailing embedded IPv4 included — into 16 network-order
 * bytes. Mirrors the classic inet_pton6 state machine. */
static rboolean
r_socket_address_parse_ipv6 (const rchar * src, ruint8 out[16])
{
  ruint8 tmp[16], * tp, * endp, * colonp;
  const rchar * curtok;
  ruint val = 0;
  ruint xdigits = 0;
  rchar ch;

  r_memset (tmp, 0, sizeof (tmp));
  tp = tmp;
  endp = tmp + sizeof (tmp);
  colonp = NULL;

  /* A leading ':' is only valid as part of "::". */
  if (*src == ':') {
    if (*++src != ':')
      return FALSE;
  }
  curtok = src;

  while ((ch = *src++) != 0) {
    if (r_ascii_isxdigit (ch)) {
      val = (val << 4) | (ruint) r_ascii_xdigit_value (ch);
      if (++xdigits > 4)
        return FALSE;
      continue;
    }
    if (ch == ':') {
      curtok = src;
      if (xdigits == 0) {
        if (colonp != NULL)             /* only one "::" permitted */
          return FALSE;
        colonp = tp;
        continue;
      }
      if (*src == 0)                    /* a trailing single ':' is invalid */
        return FALSE;
      if (tp + 2 > endp)
        return FALSE;
      *tp++ = (ruint8) (val >> 8);
      *tp++ = (ruint8) val;
      xdigits = 0;
      val = 0;
      continue;
    }
    if (ch == '.' && tp + 4 <= endp &&
        r_socket_address_parse_ipv4 (curtok, tp)) {
      tp += 4;                          /* embedded trailing IPv4 */
      xdigits = 0;
      break;                            /* parse_ipv4 consumed up to the NUL */
    }
    return FALSE;
  }

  if (xdigits > 0) {
    if (tp + 2 > endp)
      return FALSE;
    *tp++ = (ruint8) (val >> 8);
    *tp++ = (ruint8) val;
  }

  if (colonp != NULL) {
    /* Slide the groups after "::" to the end, zero-filling the gap. */
    rsize n = (rsize) (tp - colonp);
    rsize i;
    if (tp == endp)                     /* "::" with no room to expand */
      return FALSE;
    for (i = 1; i <= n; i++) {
      *(endp - i) = colonp[n - i];
      colonp[n - i] = 0;
    }
    tp = endp;
  }
  if (tp != endp)
    return FALSE;

  r_memcpy (out, tmp, sizeof (tmp));
  return TRUE;
}

RSocketAddress *
r_socket_address_ipv6_new_from_string (const rchar * ip, ruint16 port)
{
  ruint8 buf[16];

  if (R_UNLIKELY (ip == NULL)) return NULL;
  if (!r_socket_address_parse_ipv6 (ip, buf))
    return NULL;

  return r_socket_address_ipv6_new_from_bytes (buf, port);
}

RSocketAddress *
r_socket_address_ipv4_new_uint8 (ruint8 a, ruint8 b, ruint8 c, ruint8 d, ruint16 port)
{
  RSocketAddress * ret;

  if ((ret = r_mem_new0 (RSocketAddress)) != NULL) {
    r_ref_init (ret, r_free);

    ret->addrlen = R_SOCKET_ADDRESS_IPV4_SIZE;
    R_SOCKET_ADDRESS_FAMILY (ret) = R_SOCKET_FAMILY_IPV4;
    R_SOCKET_ADDRESS_IPV4_PORT (ret) = r_htons (port);
    R_SOCKET_ADDRESS_IPV4_ADDR (ret) = ((ruint32)d << 24) | ((ruint32)c << 16) |
      ((ruint32)b << 8) | (ruint32)a;
  }

  return ret;
}

RSocketAddress *
r_socket_address_ipv4_new_from_string (const rchar * ip, ruint16 port)
{
  ruint8 b[4];

  if (R_UNLIKELY (ip == NULL)) return NULL;
  if (!r_socket_address_parse_ipv4 (ip, b))
    return NULL;

  return r_socket_address_ipv4_new_uint8 (b[0], b[1], b[2], b[3], port);
}

RSocketFamily
r_socket_address_get_family (const RSocketAddress * addr)
{
  return (RSocketFamily)R_SOCKET_ADDRESS_FAMILY (addr);
}

int
r_socket_address_cmp (const RSocketAddress * a, const RSocketAddress * b)
{
  int ret;

  if (R_UNLIKELY (a == NULL)) return -(a != b);
  if (R_UNLIKELY (b == NULL)) return a != b;
  if (R_UNLIKELY (a->addrlen != b->addrlen)) return b->addrlen - a->addrlen;

  /* We can't do memcmp on the storage structure */

  if ((ret = (int)R_SOCKET_ADDRESS_FAMILY (b) - (int)R_SOCKET_ADDRESS_FAMILY (a)) == 0) {
    switch (R_SOCKET_ADDRESS_FAMILY (a)) {
      case R_SOCKET_FAMILY_IPV4:
        {
          if ((ret = ((int)R_SOCKET_ADDRESS_IPV4_PORT (b) - (int)R_SOCKET_ADDRESS_IPV4_PORT (a))) == 0)
            ret = (int)R_SOCKET_ADDRESS_IPV4_ADDR (b) - (int)R_SOCKET_ADDRESS_IPV4_ADDR (a);
        }
        break;
      case R_SOCKET_FAMILY_IPV6:
        {
          if ((ret = ((int)R_SOCKET_ADDRESS_IPV6_PORT (b) - (int)R_SOCKET_ADDRESS_IPV6_PORT (a))) == 0)
            if ((ret = ((int)R_SOCKET_ADDRESS_IPV6_FLOWINFO (b) - (int)R_SOCKET_ADDRESS_IPV6_FLOWINFO (a))) == 0)
              if ((ret = ((int)R_SOCKET_ADDRESS_IPV6_SCOPE_ID (b) - (int)R_SOCKET_ADDRESS_IPV6_SCOPE_ID (a))) == 0)
                ret = r_memcmp (R_SOCKET_ADDRESS_IPV6_ADDR (b), R_SOCKET_ADDRESS_IPV6_ADDR (a), 16);
        }
        break;
      default:
        ret = r_memcmp (&a->addr, &b->addr, sizeof (a->addr));
    }
  }

  return ret;
}

ruint16
r_socket_address_ipv4_get_port (const RSocketAddress * addr)
{
  if (R_UNLIKELY (addr == NULL)) return RUINT16_MAX;
  if (r_socket_address_get_family (addr) != R_SOCKET_FAMILY_IPV4)
    return RUINT16_MAX;
  return r_ntohs (R_SOCKET_ADDRESS_IPV4_PORT (addr));
}

ruint32
r_socket_address_ipv4_get_ip (const RSocketAddress * addr)
{
  if (R_UNLIKELY (addr == NULL)) return RUINT32_MAX; /* INADDR_NONE */
  if (r_socket_address_get_family (addr) != R_SOCKET_FAMILY_IPV4)
    return RUINT32_MAX;
  return r_ntohl (R_SOCKET_ADDRESS_IPV4_ADDR (addr));
}

ruint16
r_socket_address_ipv6_get_port (const RSocketAddress * addr)
{
  if (R_UNLIKELY (addr == NULL)) return RUINT16_MAX;
  if (r_socket_address_get_family (addr) != R_SOCKET_FAMILY_IPV6)
    return RUINT16_MAX;
  return r_ntohs (R_SOCKET_ADDRESS_IPV6_PORT (addr));
}

rboolean
r_socket_address_ipv6_get_ip_bytes (const RSocketAddress * addr, ruint8 ip[16])
{
  if (R_UNLIKELY (addr == NULL || ip == NULL)) return FALSE;
  if (r_socket_address_get_family (addr) != R_SOCKET_FAMILY_IPV6)
    return FALSE;
  r_memcpy (ip, R_SOCKET_ADDRESS_IPV6_ADDR (addr), 16);
  return TRUE;
}

/* Longest text forms incl. NUL: "255.255.255.255" and
 * "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255". */
#define R_SOCKET_ADDRESS_IPV4_STRLEN  16
#define R_SOCKET_ADDRESS_IPV6_STRLEN  46

/* Write the dotted-quad for four network-order octets; returns length. */
static rsize
r_socket_address_format_ipv4 (const ruint8 ip[4], rchar * dst)
{
  return (rsize) r_sprintf (dst, "%"RUINT8_FMT".%"RUINT8_FMT".%"RUINT8_FMT".%"RUINT8_FMT,
      ip[0], ip[1], ip[2], ip[3]);
}

/* Format 16 network-order bytes as a canonical RFC 5952 IPv6 address:
 * lowercase, the longest run of zero groups (leftmost on ties) collapsed
 * to "::", and a trailing embedded IPv4 for the v4-mapped / v4-compatible
 * forms — matching inet_ntop. @p dst must hold R_SOCKET_ADDRESS_IPV6_STRLEN. */
static void
r_socket_address_format_ipv6 (const ruint8 ip[16], rchar * dst)
{
  ruint words[8];
  int best_base = -1, best_len = 0, cur_base = -1, cur_len = 0, i;
  rchar * tp = dst;

  for (i = 0; i < 8; i++)
    words[i] = ((ruint) ip[i * 2] << 8) | (ruint) ip[i * 2 + 1];

  /* Longest run of consecutive zero groups, leftmost winning on a tie. */
  for (i = 0; i < 8; i++) {
    if (words[i] == 0) {
      if (cur_base == -1) { cur_base = i; cur_len = 1; }
      else cur_len++;
      if (cur_len > best_len) { best_base = cur_base; best_len = cur_len; }
    } else {
      cur_base = -1;
    }
  }
  if (best_len < 2)             /* "::" only collapses two or more groups */
    best_base = -1;

  for (i = 0; i < 8; i++) {
    if (best_base != -1 && i >= best_base && i < best_base + best_len) {
      if (i == best_base)
        *tp++ = ':';
      continue;
    }
    if (i != 0)
      *tp++ = ':';
    if (i == 6 && best_base == 0 &&
        (best_len == 6 || (best_len == 5 && words[5] == 0xffff))) {
      tp += r_socket_address_format_ipv4 (ip + 12, tp);
      break;
    }
    tp += (rsize) r_sprintf (tp, "%x", words[i]);
  }
  if (best_base != -1 && best_base + best_len == 8)
    *tp++ = ':';
  *tp = 0;
}

rboolean
r_socket_address_ipv4_build_str (const RSocketAddress * addr, rboolean port,
    rchar * str, rsize size)
{
  rchar tmp[R_SOCKET_ADDRESS_IPV4_STRLEN + 8];
  rsize n;

  if (R_UNLIKELY (addr == NULL || str == NULL)) return FALSE;

  n = r_socket_address_format_ipv4 (
      (const ruint8 *) &R_SOCKET_ADDRESS_IPV4_ADDR (addr), tmp);
  if (port)
    n += (rsize) r_sprintf (tmp + n, ":%"RUINT16_FMT,
        r_ntohs (R_SOCKET_ADDRESS_IPV4_PORT (addr)));

  if (n + 1 > size)
    return FALSE;
  r_memcpy (str, tmp, n + 1);
  return TRUE;
}

rchar *
r_socket_address_ipv4_to_str (const RSocketAddress * addr, rboolean port)
{
  rchar str[32];
  return r_socket_address_ipv4_build_str (addr, port, str, sizeof (str)) ?
    r_strndup (str, sizeof (str)) : NULL;
}

rboolean
r_socket_address_ipv6_build_str (const RSocketAddress * addr, rboolean port,
    rchar * str, rsize size)
{
  rchar tmp[R_SOCKET_ADDRESS_IPV6_STRLEN + 10];   /* "[" + addr + "]:65535" */
  rsize n;

  if (R_UNLIKELY (addr == NULL || str == NULL)) return FALSE;
  if (r_socket_address_get_family (addr) != R_SOCKET_FAMILY_IPV6) return FALSE;

  if (port) {
    /* RFC 3986 / 2732: bracket the address and append :port. */
    tmp[0] = '[';
    r_socket_address_format_ipv6 (R_SOCKET_ADDRESS_IPV6_ADDR (addr), tmp + 1);
    n = r_strlen (tmp);
    n += (rsize) r_sprintf (tmp + n, "]:%"RUINT16_FMT,
        r_ntohs (R_SOCKET_ADDRESS_IPV6_PORT (addr)));
  } else {
    r_socket_address_format_ipv6 (R_SOCKET_ADDRESS_IPV6_ADDR (addr), tmp);
    n = r_strlen (tmp);
  }

  if (n + 1 > size)
    return FALSE;
  r_memcpy (str, tmp, n + 1);
  return TRUE;
}

rchar *
r_socket_address_ipv6_to_str (const RSocketAddress * addr, rboolean port)
{
  /* Max IPv6 string: "[ffff:...:ffff]:65535" -> 39 + brackets/port = ~48. */
  rchar str[64];
  if (!r_socket_address_ipv6_build_str (addr, port, str, sizeof (str)))
    return NULL;
  return r_strdup (str);
}

rchar *
r_socket_address_to_str (const RSocketAddress * addr)
{
  switch (R_SOCKET_ADDRESS_FAMILY (addr)) {
    case R_SOCKET_FAMILY_IPV4:
      return r_socket_address_ipv4_to_str (addr, TRUE);
    case R_SOCKET_FAMILY_IPV6:
      return r_socket_address_ipv6_to_str (addr, TRUE);
    default:
      break;
  }

  return r_strdup ("<UNKNOWN>");
}

