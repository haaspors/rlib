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
#ifndef __R_SOCKET_ADDRESS_H__
#define __R_SOCKET_ADDRESS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

#define R_SOCKET_ADDRESS_IPV4_ANY             0x00000000 /* 0.0.0.0 */
#define R_SOCKET_ADDRESS_IPV4_BROADCAST       0xffffffff /* 255.255.255.255 */
#define R_SOCKET_ADDRESS_IPV4_NONE            0xffffffff /* 255.255.255.255 */
#define R_SOCKET_ADDRESS_IPV4_LOOPBACK        0x7f000001 /* 127.0.0.1 */
#define R_SOCKET_ADDRESS_IPV4_UNSPEC_GROUP    0xe0000000 /* 224.0.0.0 */
#define R_SOCKET_ADDRESS_IPV4_ALLHOSTS_GROUP  0xe0000001 /* 224.0.0.1 */
#define R_SOCKET_ADDRESS_IPV4_ALLRTRS_GROUP   0xe0000002 /* 224.0.0.2 */
#define R_SOCKET_ADDRESS_IPV4_MAX_LOCAL_GROUP 0xe00000ff /* 224.0.0.255 */
#define R_SOCKET_ADDRESS_IPV6_ANY_INIT        { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
#define R_SOCKET_ADDRESS_IPV6_LOOPBACK_INIT   { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

typedef enum {
  R_SOCKET_FAMILY_NONE = 0,
  R_SOCKET_FAMILY_UNSPEC = R_SOCKET_FAMILY_NONE,
  R_SOCKET_FAMILY_UNIX = R_AF_UNIX,
  R_SOCKET_FAMILY_IPV4 = R_AF_INET,
  R_SOCKET_FAMILY_IPV6 = R_AF_INET6,
  R_SOCKET_FAMILY_IRDA = R_AF_IRDA,
  R_SOCKET_FAMILY_BLUETOOTH = R_AF_BLUETOOTH,
} RSocketFamily;

typedef struct _RSocketAddress  RSocketAddress;

R_API RSocketAddress * r_socket_address_new (void) R_ATTR_MALLOC;
R_API RSocketAddress * r_socket_address_new_from_native (rconstpointer addr, rsize addrsize) R_ATTR_MALLOC;
R_API RSocketAddress * r_socket_address_copy (const RSocketAddress * addr);
R_API RSocketAddress * r_socket_address_ipv4_new_uint32 (ruint32 addr, ruint16 port) R_ATTR_MALLOC;
R_API RSocketAddress * r_socket_address_ipv4_new_uint8 (ruint8 a, ruint8 b, ruint8 c, ruint8 d, ruint16 port) R_ATTR_MALLOC;
R_API RSocketAddress * r_socket_address_ipv4_new_from_string (const rchar * ip, ruint16 port) R_ATTR_MALLOC;
#define r_socket_address_ref    r_ref_ref
#define r_socket_address_unref  r_ref_unref

R_API RSocketFamily r_socket_address_get_family (const RSocketAddress * addr);
R_API int r_socket_address_cmp (const RSocketAddress * a, const RSocketAddress * b);
#define r_socket_address_is_equal(a, b) (r_socket_address_cmp (a, b) == 0)

R_API ruint16 r_socket_address_ipv4_get_port (const RSocketAddress * addr);
R_API ruint32 r_socket_address_ipv4_get_ip (const RSocketAddress * addr);
R_API rboolean r_socket_address_ipv4_build_str (const RSocketAddress * addr, rboolean port, rchar * str, rsize size);
R_API rchar * r_socket_address_ipv4_to_str (const RSocketAddress * addr, rboolean port);

R_API rchar * r_socket_address_to_str (const RSocketAddress * addr) R_ATTR_MALLOC;

R_END_DECLS

#endif /* __R_SOCKET_ADDRESS_H__ */

