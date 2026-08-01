/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_NET_INTERFACE_H__
#define __R_NET_INTERFACE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/rnetif.h
 * @brief Enumerate the host's network interfaces and their addresses.
 */

#include <rlib/rtypes.h>

#include <rlib/data/rptrarray.h>
#include <rlib/net/rsocketaddress.h>

/**
 * @defgroup r_netif Network interfaces
 * @ingroup r_net
 *
 * @brief Enumerate the host's network interfaces — their addresses, link
 * status, media type, MTU and hardware address. The source of ICE host
 * candidates and any other "what are my local interfaces" query.
 *
 * @ref r_net_query_interfaces returns an array of @ref RNetInterface, each
 * grouping the @ref RNetInterfaceAddr addresses configured on it. The
 * @c find helpers locate an interface in that array by name or index.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Largest hardware (link-layer) address stored, in bytes. */
#define R_NET_IFACE_HWADDR_MAXLEN   8

/** @brief Status flags for a network interface (bitmask). */
typedef enum {
  R_NET_IFACE_UP           = (1 << 0),  /**< Administratively up. */
  R_NET_IFACE_RUNNING      = (1 << 1),  /**< Link is active / operational. */
  R_NET_IFACE_LOOPBACK     = (1 << 2),  /**< Loopback interface. */
  R_NET_IFACE_POINTOPOINT  = (1 << 3),  /**< Point-to-point link. */
  R_NET_IFACE_BROADCAST    = (1 << 4),  /**< Supports broadcast. */
  R_NET_IFACE_MULTICAST    = (1 << 5),  /**< Supports multicast. */
} RNetInterfaceFlags;

/** @brief Media type of a network interface (best effort). */
typedef enum {
  R_NET_IFACE_TYPE_UNKNOWN = 0,  /**< Not determined. */
  R_NET_IFACE_TYPE_ETHERNET,     /**< Wired Ethernet. */
  R_NET_IFACE_TYPE_WIFI,         /**< IEEE 802.11 wireless. */
  R_NET_IFACE_TYPE_LOOPBACK,     /**< Loopback. */
  R_NET_IFACE_TYPE_PPP,          /**< Point-to-point protocol. */
  R_NET_IFACE_TYPE_TUNNEL,       /**< Tunnel (e.g. VPN). */
  R_NET_IFACE_TYPE_OTHER,        /**< Known but none of the above. */
} RNetInterfaceType;

/**
 * @brief One address configured on a network interface.
 */
typedef struct {
  RSocketAddress *  addr;       /**< @brief The address (port 0). */
  ruint             prefixlen;  /**< @brief Netmask length in bits. */
  RSocketAddress *  broadcast;  /**< @brief Broadcast / point-to-point peer address, or @c NULL. */
} RNetInterfaceAddr;

/**
 * @brief A local network interface and the addresses bound to it.
 */
typedef struct {
  rchar *             name;       /**< @brief Interface name (or adapter id). */
  ruint               index;      /**< @brief Interface index (0 if unknown). */
  RNetInterfaceFlags  flags;      /**< @brief Status flags (@ref RNetInterfaceFlags). */
  RNetInterfaceType   type;       /**< @brief Media type (@ref RNetInterfaceType). */
  ruint               mtu;        /**< @brief Link MTU in bytes (0 if unknown). */
  ruint8              hwaddr[R_NET_IFACE_HWADDR_MAXLEN]; /**< @brief Hardware (MAC) address. */
  rsize               hwaddrlen;  /**< @brief Hardware address length in bytes (0 if none). */
  RPtrArray *         addrs;      /**< @brief Addresses (@ref RNetInterfaceAddr). */
} RNetInterface;

/**
 * @brief Enumerate the host's network interfaces.
 *
 * Returns a (possibly empty) array of @ref RNetInterface, each grouping the
 * IPv4 / IPv6 addresses on one interface together with its status, type,
 * MTU and hardware address; unref it with @ref r_ptr_array_unref. Never
 * returns @c NULL. Fields that a platform does not report are left zero /
 * @ref R_NET_IFACE_TYPE_UNKNOWN.
 */
R_API RPtrArray * r_net_query_interfaces (void) R_ATTR_MALLOC;

/** @brief Find the interface named @p name in @p ifaces, or @c NULL. */
R_API const RNetInterface * r_net_interfaces_find_by_name (const RPtrArray * ifaces,
    const rchar * name);
/** @brief Find the interface with index @p index in @p ifaces, or @c NULL. */
R_API const RNetInterface * r_net_interfaces_find_by_index (const RPtrArray * ifaces,
    ruint index);

/**
 * @brief Format an interface's hardware address as @c "aa:bb:cc:dd:ee:ff".
 *
 * Returns a newly allocated colon-separated hex string, or @c NULL when the
 * interface has no hardware address. Free it with @ref r_free.
 */
R_API rchar * r_net_interface_hwaddr_to_str (const RNetInterface * iface) R_ATTR_MALLOC;

R_END_DECLS

/** @} */

#endif /* __R_NET_INTERFACE_H__ */
