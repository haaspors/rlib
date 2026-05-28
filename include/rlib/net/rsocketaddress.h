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

/**
 * @file rlib/net/rsocketaddress.h
 * @brief Family-tagged socket address (IPv4 / IPv6 / Unix / Bluetooth)
 * with constructors, accessors and string formatting.
 */

#include <rlib/rtypes.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

/**
 * @defgroup r_socketaddress Socket addresses (RSocketAddress)
 * @ingroup r_net
 *
 * @brief Refcounted, family-tagged wrapper around a native socket
 * address (@c sockaddr_in / @c sockaddr_in6 / etc.).
 *
 * Constructors come in three shapes: build from native bytes
 * (@ref r_socket_address_new_from_native), build from family-specific
 * components (e.g. @ref r_socket_address_ipv4_new_uint32 /
 * @ref r_socket_address_ipv6_new_from_bytes), or parse from a
 * textual representation (@c _new_from_string).
 *
 * The family-specific getters (@c _ipv4_get_port, @c _ipv6_get_ip_bytes,
 * etc.) only return meaningful data when @ref r_socket_address_get_family
 * matches; calling them on the wrong family is a programmer error.
 *
 * @{
 */

/** @brief IPv4 @c INADDR_ANY (0.0.0.0). */
#define R_SOCKET_ADDRESS_IPV4_ANY             0x00000000
/** @brief IPv4 broadcast (255.255.255.255). */
#define R_SOCKET_ADDRESS_IPV4_BROADCAST       0xffffffff
/** @brief Sentinel "no address" (255.255.255.255). */
#define R_SOCKET_ADDRESS_IPV4_NONE            0xffffffff
/** @brief IPv4 loopback (127.0.0.1). */
#define R_SOCKET_ADDRESS_IPV4_LOOPBACK        0x7f000001
/** @brief IPv4 multicast base (224.0.0.0). */
#define R_SOCKET_ADDRESS_IPV4_UNSPEC_GROUP    0xe0000000
/** @brief IPv4 all-hosts multicast (224.0.0.1). */
#define R_SOCKET_ADDRESS_IPV4_ALLHOSTS_GROUP  0xe0000001
/** @brief IPv4 all-routers multicast (224.0.0.2). */
#define R_SOCKET_ADDRESS_IPV4_ALLRTRS_GROUP   0xe0000002
/** @brief Top of the link-local IPv4 multicast range (224.0.0.255). */
#define R_SOCKET_ADDRESS_IPV4_MAX_LOCAL_GROUP 0xe00000ff
/** @brief Static initialiser for IPv6 @c in6addr_any. */
#define R_SOCKET_ADDRESS_IPV6_ANY_INIT        { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
/** @brief Static initialiser for IPv6 @c in6addr_loopback (::1). */
#define R_SOCKET_ADDRESS_IPV6_LOOPBACK_INIT   { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

/** @brief Address family discriminator. */
typedef enum {
  R_SOCKET_FAMILY_NONE = 0,                       /**< Uninitialised / unknown. */
  R_SOCKET_FAMILY_UNSPEC = R_SOCKET_FAMILY_NONE,  /**< Alias for @c NONE. */
  R_SOCKET_FAMILY_UNIX = R_AF_UNIX,               /**< Unix-domain (AF_UNIX). */
  R_SOCKET_FAMILY_IPV4 = R_AF_INET,               /**< IPv4 (AF_INET). */
  R_SOCKET_FAMILY_IPV6 = R_AF_INET6,              /**< IPv6 (AF_INET6). */
  R_SOCKET_FAMILY_IRDA = R_AF_IRDA,               /**< IrDA (AF_IRDA). */
  R_SOCKET_FAMILY_BLUETOOTH = R_AF_BLUETOOTH,     /**< Bluetooth (AF_BLUETOOTH). */
} RSocketFamily;

/** @brief Opaque, refcounted socket-address handle. */
typedef struct RSocketAddress  RSocketAddress;

/** @brief Allocate an empty address (family @c NONE). */
R_API RSocketAddress * r_socket_address_new (void) R_ATTR_MALLOC;
/**
 * @brief Wrap a native OS @c sockaddr blob.
 * @param addr     Pointer to a @c sockaddr_storage / @c sockaddr_in* / etc.
 * @param addrsize Size in bytes (use the corresponding @c sa_len-style value).
 */
R_API RSocketAddress * r_socket_address_new_from_native (rconstpointer addr, rsize addrsize) R_ATTR_MALLOC;
/** @brief Return a new refcounted copy of @p addr. */
R_API RSocketAddress * r_socket_address_copy (const RSocketAddress * addr);
/**
 * @brief Build an IPv4 address from a host-order 32-bit IP and port.
 * @param addr 32-bit IPv4 address in host byte order.
 * @param port Port in host byte order (0 means "any").
 */
R_API RSocketAddress * r_socket_address_ipv4_new_uint32 (ruint32 addr, ruint16 port) R_ATTR_MALLOC;
/** @brief Build an IPv4 address from dotted-quad octets and a port. */
R_API RSocketAddress * r_socket_address_ipv4_new_uint8 (ruint8 a, ruint8 b, ruint8 c, ruint8 d, ruint16 port) R_ATTR_MALLOC;
/**
 * @brief Parse a textual IPv4 address (@c "a.b.c.d") and attach @p port.
 * @return New address, or @c NULL if parsing fails.
 */
R_API RSocketAddress * r_socket_address_ipv4_new_from_string (const rchar * ip, ruint16 port) R_ATTR_MALLOC;
/**
 * @brief Build an IPv6 address from 16 raw bytes and a port.
 * @param ip   16-byte IPv6 address in network order.
 * @param port Port in host byte order.
 */
R_API RSocketAddress * r_socket_address_ipv6_new_from_bytes (const ruint8 ip[16],
    ruint16 port) R_ATTR_MALLOC;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_socket_address_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_socket_address_unref  r_ref_unref

/** @brief Return @p addr's family tag. */
R_API RSocketFamily r_socket_address_get_family (const RSocketAddress * addr);
/**
 * @brief Compare two addresses (family, IP, port).
 * @return @c <0 / @c 0 / @c >0 as in @c strcmp.
 */
R_API int r_socket_address_cmp (const RSocketAddress * a, const RSocketAddress * b);
/** @brief Convenience macro: @c TRUE iff @p a and @p b compare equal. */
#define r_socket_address_is_equal(a, b) (r_socket_address_cmp (a, b) == 0)

/** @brief IPv4 port accessor. */
R_API ruint16 r_socket_address_ipv4_get_port (const RSocketAddress * addr);
/** @brief IPv4 address accessor (host byte order). */
R_API ruint32 r_socket_address_ipv4_get_ip (const RSocketAddress * addr);
/**
 * @brief Render an IPv4 address into a caller-provided buffer.
 * @param addr Address to render.
 * @param port @c TRUE to append @c ":port", @c FALSE to omit.
 * @param str  Output buffer.
 * @param size Buffer size in bytes.
 * @return @c TRUE on success, @c FALSE if the buffer is too small.
 */
R_API rboolean r_socket_address_ipv4_build_str (const RSocketAddress * addr, rboolean port, rchar * str, rsize size);
/**
 * @brief Render an IPv4 address into a newly-allocated string.
 * @param addr Address to render.
 * @param port @c TRUE to append @c ":port", @c FALSE to omit.
 */
R_API rchar * r_socket_address_ipv4_to_str (const RSocketAddress * addr, rboolean port);

/**
 * @brief Parse a textual IPv6 address (@c "::1", @c "fe80::1", ...) and
 * attach @p port.
 */
R_API RSocketAddress * r_socket_address_ipv6_new_from_string (const rchar * ip,
    ruint16 port) R_ATTR_MALLOC;
/** @brief IPv6 port accessor. */
R_API ruint16 r_socket_address_ipv6_get_port (const RSocketAddress * addr);
/**
 * @brief Copy the IPv6 address bytes into @p ip.
 * @return @c TRUE on success, @c FALSE if @p addr is not IPv6.
 */
R_API rboolean r_socket_address_ipv6_get_ip_bytes (const RSocketAddress * addr,
    ruint8 ip[16]);
/**
 * @brief Render an IPv6 address into a caller-provided buffer.
 * @param addr Address to render.
 * @param port @c TRUE to append @c ":port", @c FALSE to omit.
 * @param str  Output buffer.
 * @param size Buffer size in bytes.
 */
R_API rboolean r_socket_address_ipv6_build_str (const RSocketAddress * addr,
    rboolean port, rchar * str, rsize size);
/**
 * @brief Render an IPv6 address into a newly-allocated string.
 * @param addr Address to render.
 * @param port @c TRUE to append @c ":port" (wrapped in brackets), @c FALSE to omit.
 */
R_API rchar * r_socket_address_ipv6_to_str (const RSocketAddress * addr,
    rboolean port);

/**
 * @brief Render any-family address into a newly-allocated string;
 * picks the appropriate per-family formatter.
 */
R_API rchar * r_socket_address_to_str (const RSocketAddress * addr) R_ATTR_MALLOC;

R_END_DECLS

/** @} */

#endif /* __R_SOCKET_ADDRESS_H__ */

