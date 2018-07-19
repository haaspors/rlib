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
#include <rlib/rsocketaddress.h>
#include "rsocket-private.h"
#include "net/rnet-private.h"

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
    ret->addrlen = MIN (sizeof (ret->addr), addrsize);
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
  RSocketAddress * ret;
  ruint32 a;

  if (R_UNLIKELY (ip == NULL)) return NULL;

  {
#if defined (HAVE_INET_PTON)
    struct in_addr in;
    if (inet_pton (R_AF_INET, ip, &in) < 1)
      return NULL;
    a = in.s_addr;
#elif defined (R_OS_WIN32)
    struct in_addr in;
    if (r_win32_inet_pton (R_AF_INET, ip, &in) < 1)
      return NULL;
    a = in.s_addr;
#elif defined (HAVE_INET_ATON)
    struct in_addr in;
    if (inet_aton (ip, &in) < 1)
      return NULL;
    a = in.s_addr;
#else
    /* FIXME: Implement parsing and remove inet_pton/inet_aton */
    return NULL;
#endif
  }

  if ((ret = r_mem_new0 (RSocketAddress)) != NULL) {
    r_ref_init (ret, r_free);

    ret->addrlen = R_SOCKET_ADDRESS_IPV4_SIZE;
    R_SOCKET_ADDRESS_FAMILY (ret) = R_SOCKET_FAMILY_IPV4;
    R_SOCKET_ADDRESS_IPV4_PORT (ret) = r_htons (port);
    R_SOCKET_ADDRESS_IPV4_ADDR (ret) = a;
  }

  return ret;
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

  return r_ntohs (R_SOCKET_ADDRESS_IPV4_PORT (addr));
}

ruint32
r_socket_address_ipv4_get_ip (const RSocketAddress * addr)
{
  if (R_UNLIKELY (addr == NULL)) return RUINT32_MAX; /* INADDR_NONE */

  return r_ntohl (R_SOCKET_ADDRESS_IPV4_ADDR (addr));
}

rboolean
r_socket_address_ipv4_build_str (const RSocketAddress * addr, rboolean port,
    rchar * str, rsize size)
{
  if (R_UNLIKELY (addr == NULL)) return FALSE;

#if defined (HAVE_INET_PTON)
  if (inet_ntop (R_AF_INET, &((struct sockaddr_in *)&addr->addr)->sin_addr, str, size) == NULL)
    return FALSE;
  if (port) {
    rchar p[8];
    r_sprintf (p, ":%"RUINT16_FMT, r_ntohs (R_SOCKET_ADDRESS_IPV4_PORT (addr)));
    if (size <= r_strlen (str) + r_strlen (p))
      return FALSE;

    r_strcat (str, p);
  }
#elif defined (R_OS_WIN32)
  if (r_win32_inet_ntop (R_AF_INET, &((struct sockaddr_in *)&addr->addr)->sin_addr, str, size) == NULL)
    return FALSE;
  if (port) {
    rchar p[8];
    r_sprintf (p, ":%"RUINT16_FMT, r_ntohs (R_SOCKET_ADDRESS_IPV4_PORT (addr)));
    if (size <= r_strlen (str) + r_strlen (p))
      return FALSE;

    r_strcat (str, p);
  }
#else
  if (port) {
    return r_snprintf (str, size,
        "%"RUINT8_FMT".%"RUINT8_FMT".%"RUINT8_FMT".%"RUINT8_FMT":%"RUINT16_FMT,
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr)      ) & 0xff),
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr) >>  8) & 0xff),
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr) >> 16) & 0xff),
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr) >> 24) & 0xff),
        r_ntohs (R_SOCKET_ADDRESS_IPV4_PORT (addr))) < (int)size;
  } else {
    return r_snprintf (str, size,
        "%"RUINT8_FMT".%"RUINT8_FMT".%"RUINT8_FMT".%"RUINT8_FMT,
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr)      ) & 0xff),
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr) >>  8) & 0xff),
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr) >> 16) & 0xff),
        (ruint8)((R_SOCKET_ADDRESS_IPV4_ADDR (addr) >> 24) & 0xff)) < (int)size;
  }
#endif

  return TRUE;
}

rchar *
r_socket_address_ipv4_to_str (const RSocketAddress * addr, rboolean port)
{
  rchar str[32];
  return r_socket_address_ipv4_build_str (addr, port, str, sizeof (str)) ?
    r_strndup (str, sizeof (str)) : NULL;
}

rchar *
r_socket_address_to_str (const RSocketAddress * addr)
{
  switch (R_SOCKET_ADDRESS_FAMILY (addr)) {
    case R_SOCKET_FAMILY_IPV4:
      return r_socket_address_ipv4_to_str (addr, TRUE);
    /*FIXME case R_SOCKET_FAMILY_IPV6:*/
    default:
      break;
  }

  return r_strdup ("<UNKNOWN>");
}

