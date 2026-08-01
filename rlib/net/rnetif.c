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

#include "config.h"

/* iphlpapi's richer per-address fields (OnLinkPrefixLength, ...) need a
 * Vista+ SDK target; request it before any Windows header is pulled in. */
#if defined (R_OS_WIN32) && (!defined (_WIN32_WINNT) || _WIN32_WINNT < 0x0600)
#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include "rsocket-private.h"
#include "rnet-private.h"
#include <rlib/net/rnetif.h>

#include <rlib/rmem.h>
#include <rlib/rstr.h>

#if defined (HAVE_POSIX_SOCKETS) && defined (HAVE_IFADDRS_H)
#include <ifaddrs.h>
#include <net/if.h>
#define R_NETIF_GETIFADDRS  1
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_NETPACKET_PACKET_H
#include <netpacket/packet.h>       /* Linux: struct sockaddr_ll */
#endif
#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>             /* Linux: ARPHRD_* */
#endif
#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>             /* BSD / macOS: struct sockaddr_dl */
#endif
#ifdef HAVE_NET_IF_TYPES_H
#include <net/if_types.h>          /* BSD / macOS: IFT_* */
#endif
#ifdef HAVE_NET_IF_MEDIA_H
#include <net/if_media.h>          /* BSD / macOS: SIOCGIFMEDIA, IFM_IEEE80211 */
#endif
#elif defined (HAVE_WINSOCK2)
#include <iphlpapi.h>
#define R_NETIF_WINDOWS     1
#endif


static void
r_net_interface_addr_free (rpointer data)
{
  RNetInterfaceAddr * ia = data;

  if (ia->addr != NULL)
    r_socket_address_unref (ia->addr);
  if (ia->broadcast != NULL)
    r_socket_address_unref (ia->broadcast);
  r_free (ia);
}

static void
r_net_interface_free (rpointer data)
{
  RNetInterface * iface = data;

  r_free (iface->name);
  r_ptr_array_unref (iface->addrs);
  r_free (iface);
}

/* Return the interface named @name from @array, creating and appending it
 * if it is not there yet, so addresses and link metadata group per
 * interface regardless of how the platform reports them. */
static RNetInterface *
r_net_interface_get (RPtrArray * array, const rchar * name)
{
  RNetInterface * iface;
  rsize i, c;

  for (i = 0, c = r_ptr_array_size (array); i < c; i++) {
    iface = r_ptr_array_get (array, i);
    if (r_str_equals (iface->name, name))
      return iface;
  }

  iface = r_mem_new0 (RNetInterface);
  iface->name = r_strdup (name);
  iface->addrs = r_ptr_array_new ();
  r_ptr_array_add (array, iface, r_net_interface_free);
  return iface;
}

const RNetInterface *
r_net_interfaces_find_by_name (const RPtrArray * ifaces, const rchar * name)
{
  rsize i, c;

  if (R_UNLIKELY (ifaces == NULL || name == NULL)) return NULL;

  for (i = 0, c = r_ptr_array_size ((RPtrArray *) ifaces); i < c; i++) {
    RNetInterface * iface = r_ptr_array_get ((RPtrArray *) ifaces, i);
    if (r_str_equals (iface->name, name))
      return iface;
  }
  return NULL;
}

const RNetInterface *
r_net_interfaces_find_by_index (const RPtrArray * ifaces, ruint index)
{
  rsize i, c;

  if (R_UNLIKELY (ifaces == NULL)) return NULL;

  for (i = 0, c = r_ptr_array_size ((RPtrArray *) ifaces); i < c; i++) {
    RNetInterface * iface = r_ptr_array_get ((RPtrArray *) ifaces, i);
    if (iface->index == index)
      return iface;
  }
  return NULL;
}

rchar *
r_net_interface_hwaddr_to_str (const RNetInterface * iface)
{
  rchar * ret, * p;
  rsize i;

  if (R_UNLIKELY (iface == NULL) || iface->hwaddrlen == 0)
    return NULL;

  /* "xx:" per byte, NUL for the last separator's slot. */
  p = ret = r_malloc (iface->hwaddrlen * 3);
  for (i = 0; i < iface->hwaddrlen; i++)
    p += r_sprintf (p, "%s%.2x", i > 0 ? ":" : "", iface->hwaddr[i]);

  return ret;
}


#if defined (R_NETIF_GETIFADDRS)
static ruint
r_net_prefixlen (const struct sockaddr * mask)
{
  const ruint8 * p;
  rsize i, n;
  ruint bits = 0;

  if (mask == NULL)
    return 0;
  if (mask->sa_family == AF_INET) {
    p = (const ruint8 *) &((const struct sockaddr_in *) mask)->sin_addr;
    n = 4;
  } else if (mask->sa_family == AF_INET6) {
    p = (const ruint8 *) &((const struct sockaddr_in6 *) mask)->sin6_addr;
    n = 16;
  } else {
    return 0;
  }

  for (i = 0; i < n; i++) {
    ruint8 b = p[i];
    while (b) { bits += b & 1; b >>= 1; }
  }
  return bits;
}

static RNetInterfaceFlags
r_net_flags_from_ifflags (unsigned int f)
{
  RNetInterfaceFlags flags = 0;

  if (f & IFF_UP)          flags |= R_NET_IFACE_UP;
  if (f & IFF_RUNNING)     flags |= R_NET_IFACE_RUNNING;
  if (f & IFF_LOOPBACK)    flags |= R_NET_IFACE_LOOPBACK;
  if (f & IFF_POINTOPOINT) flags |= R_NET_IFACE_POINTOPOINT;
  if (f & IFF_BROADCAST)   flags |= R_NET_IFACE_BROADCAST;
  if (f & IFF_MULTICAST)   flags |= R_NET_IFACE_MULTICAST;
  return flags;
}

#if defined (HAVE_SYS_IOCTL_H) && defined (SIOCGIFMTU)
static ruint
r_net_query_mtu (int fd, const rchar * name)
{
  struct ifreq ifr;

  if (fd < 0)
    return 0;
  r_memset (&ifr, 0, sizeof (ifr));
  r_strncpy (ifr.ifr_name, name, sizeof (ifr.ifr_name) - 1);
  if (ioctl (fd, SIOCGIFMTU, &ifr) != 0)
    return 0;
  return (ruint) ifr.ifr_mtu;
}
#else
#define r_net_query_mtu(fd, name)   0
#endif

#if defined (HAVE_NETPACKET_PACKET_H) && defined (HAVE_NET_IF_ARP_H)
/* Linux: hardware address and type live in an AF_PACKET pseudo-address. */
static void
r_net_fill_link (RNetInterface * iface, const struct sockaddr * sa)
{
  const struct sockaddr_ll * ll = (const struct sockaddr_ll *) sa;
  rsize len = ll->sll_halen;

  if (len > R_NET_IFACE_HWADDR_MAXLEN)
    len = R_NET_IFACE_HWADDR_MAXLEN;
  r_memcpy (iface->hwaddr, ll->sll_addr, len);
  iface->hwaddrlen = len;

  switch (ll->sll_hatype) {
    case ARPHRD_ETHER:     iface->type = R_NET_IFACE_TYPE_ETHERNET; break;
    case ARPHRD_LOOPBACK:  iface->type = R_NET_IFACE_TYPE_LOOPBACK; break;
    case ARPHRD_PPP:       iface->type = R_NET_IFACE_TYPE_PPP; break;
#ifdef ARPHRD_IEEE80211
    case ARPHRD_IEEE80211: iface->type = R_NET_IFACE_TYPE_WIFI; break;
#endif
#ifdef ARPHRD_TUNNEL
    case ARPHRD_TUNNEL:    iface->type = R_NET_IFACE_TYPE_TUNNEL; break;
#endif
#ifdef ARPHRD_SIT
    case ARPHRD_SIT:       iface->type = R_NET_IFACE_TYPE_TUNNEL; break;
#endif
    default:               iface->type = R_NET_IFACE_TYPE_OTHER; break;
  }
}
#define R_NETIF_LINK_FAMILY   AF_PACKET
#elif defined (HAVE_NET_IF_DL_H)
/* BSD / macOS: hardware address and type live in an AF_LINK pseudo-address. */
static void
r_net_fill_link (RNetInterface * iface, const struct sockaddr * sa)
{
  const struct sockaddr_dl * dl = (const struct sockaddr_dl *) sa;
  rsize len = dl->sdl_alen;

  if (len > R_NET_IFACE_HWADDR_MAXLEN)
    len = R_NET_IFACE_HWADDR_MAXLEN;
  r_memcpy (iface->hwaddr, LLADDR (dl), len);
  iface->hwaddrlen = len;

#ifdef HAVE_NET_IF_TYPES_H
  switch (dl->sdl_type) {
    case IFT_ETHER:      iface->type = R_NET_IFACE_TYPE_ETHERNET; break;
    case IFT_LOOP:       iface->type = R_NET_IFACE_TYPE_LOOPBACK; break;
    case IFT_PPP:        iface->type = R_NET_IFACE_TYPE_PPP; break;
#ifdef IFT_IEEE80211
    case IFT_IEEE80211:  iface->type = R_NET_IFACE_TYPE_WIFI; break;
#endif
#ifdef IFT_GIF
    case IFT_GIF:        iface->type = R_NET_IFACE_TYPE_TUNNEL; break;
#endif
#ifdef IFT_STF
    case IFT_STF:        iface->type = R_NET_IFACE_TYPE_TUNNEL; break;
#endif
    default:             iface->type = R_NET_IFACE_TYPE_OTHER; break;
  }
#endif
}
#define R_NETIF_LINK_FAMILY   AF_LINK
#endif

/* Managed-mode Wi-Fi presents as ARPHRD_ETHER / IFT_ETHER, so getifaddrs
 * (like `ip link`) reports it as Ethernet. Recover the real media type:
 * Linux / Android expose a phy80211 link under sysfs; BSD / macOS answer
 * SIOCGIFMEDIA with an IFM_IEEE80211 media type. */
#if defined (R_OS_LINUX)
static rboolean
r_net_iface_is_wifi (int fd, const rchar * name)
{
  rchar path[64];

  (void) fd;
  r_snprintf (path, sizeof (path), "/sys/class/net/%s/phy80211", name);
  return access (path, F_OK) == 0;
}
#elif defined (HAVE_NET_IF_MEDIA_H) && defined (SIOCGIFMEDIA) && defined (IFM_IEEE80211)
static rboolean
r_net_iface_is_wifi (int fd, const rchar * name)
{
  struct ifmediareq ifmr;

  if (fd < 0)
    return FALSE;
  r_memset (&ifmr, 0, sizeof (ifmr));
  r_strncpy (ifmr.ifm_name, name, sizeof (ifmr.ifm_name) - 1);
  if (ioctl (fd, SIOCGIFMEDIA, &ifmr) != 0)
    return FALSE;
  return IFM_TYPE (ifmr.ifm_current) == IFM_IEEE80211;
}
#else
#define r_net_iface_is_wifi(fd, name)   FALSE
#endif

RPtrArray *
r_net_query_interfaces (void)
{
  RPtrArray * ret = r_ptr_array_new ();
  struct ifaddrs * ifa, * it;
  rsize i, c;
  int fd = -1;

  if (getifaddrs (&ifa) != 0)
    return ret;

#if defined (HAVE_SYS_IOCTL_H) && defined (SIOCGIFMTU)
  fd = socket (AF_INET, SOCK_DGRAM, 0);
#endif

  for (it = ifa; it != NULL; it = it->ifa_next) {
    RNetInterface * iface;
    rsize salen;

    if (it->ifa_addr == NULL)
      continue;

    iface = r_net_interface_get (ret, it->ifa_name);
    iface->flags = r_net_flags_from_ifflags (it->ifa_flags);
    if (iface->index == 0)
      iface->index = if_nametoindex (it->ifa_name);
    if (iface->mtu == 0)
      iface->mtu = r_net_query_mtu (fd, it->ifa_name);
    if (iface->flags & R_NET_IFACE_LOOPBACK)
      iface->type = R_NET_IFACE_TYPE_LOOPBACK;

    if (it->ifa_addr->sa_family == AF_INET)
      salen = sizeof (struct sockaddr_in);
    else if (it->ifa_addr->sa_family == AF_INET6)
      salen = sizeof (struct sockaddr_in6);
#if defined (R_NETIF_LINK_FAMILY)
    else if (it->ifa_addr->sa_family == R_NETIF_LINK_FAMILY) {
      r_net_fill_link (iface, it->ifa_addr);
      continue;
    }
#endif
    else
      continue;

    {
      RNetInterfaceAddr * ia = r_mem_new0 (RNetInterfaceAddr);
      ia->addr = r_socket_address_new_from_native (it->ifa_addr, salen);
      ia->prefixlen = r_net_prefixlen (it->ifa_netmask);
      if (it->ifa_broadaddr != NULL &&
          it->ifa_broadaddr->sa_family == it->ifa_addr->sa_family)
        ia->broadcast = r_socket_address_new_from_native (it->ifa_broadaddr, salen);
      if (ia->addr != NULL)
        r_ptr_array_add (iface->addrs, ia, r_net_interface_addr_free);
      else
        r_net_interface_addr_free (ia);
    }
  }

  /* Upgrade Ethernet-looking interfaces that are really Wi-Fi. */
  for (i = 0, c = r_ptr_array_size (ret); i < c; i++) {
    RNetInterface * iface = r_ptr_array_get (ret, i);
    if (iface->type == R_NET_IFACE_TYPE_ETHERNET &&
        r_net_iface_is_wifi (fd, iface->name))
      iface->type = R_NET_IFACE_TYPE_WIFI;
  }

  if (fd >= 0)
    close (fd);
  freeifaddrs (ifa);
  return ret;
}
#elif defined (R_NETIF_WINDOWS)
static RNetInterfaceType
r_net_type_from_iftype (DWORD iftype)
{
  switch (iftype) {
    case IF_TYPE_ETHERNET_CSMACD:   return R_NET_IFACE_TYPE_ETHERNET;
    case IF_TYPE_IEEE80211:         return R_NET_IFACE_TYPE_WIFI;
    case IF_TYPE_SOFTWARE_LOOPBACK: return R_NET_IFACE_TYPE_LOOPBACK;
    case IF_TYPE_PPP:               return R_NET_IFACE_TYPE_PPP;
    case IF_TYPE_TUNNEL:            return R_NET_IFACE_TYPE_TUNNEL;
    default:                        return R_NET_IFACE_TYPE_OTHER;
  }
}

RPtrArray *
r_net_query_interfaces (void)
{
  RPtrArray * ret = r_ptr_array_new ();
  IP_ADAPTER_ADDRESSES * adapters = NULL, * ad;
  ULONG size = 15 * 1024;
  ULONG gaaflags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
      GAA_FLAG_SKIP_DNS_SERVER;
  DWORD rv;
  ruint tries;

  for (tries = 0; tries < 3; tries++) {
    if ((adapters = r_malloc (size)) == NULL)
      return ret;
    rv = GetAdaptersAddresses (AF_UNSPEC, gaaflags, NULL, adapters, &size);
    if (rv != ERROR_BUFFER_OVERFLOW)
      break;
    r_free (adapters);
    adapters = NULL;
  }

  if (rv != NO_ERROR) {
    r_free (adapters);
    return ret;
  }

  for (ad = adapters; ad != NULL; ad = ad->Next) {
    IP_ADAPTER_UNICAST_ADDRESS * ua;
    RNetInterface * iface = r_net_interface_get (ret, ad->AdapterName);
    rsize hwlen = ad->PhysicalAddressLength;

    iface->index = ad->IfIndex != 0 ? ad->IfIndex : ad->Ipv6IfIndex;
    iface->type = r_net_type_from_iftype (ad->IfType);
    iface->mtu = (ad->Mtu == (ULONG) -1) ? 0 : (ruint) ad->Mtu;

    if (ad->OperStatus == IfOperStatusUp)
      iface->flags |= R_NET_IFACE_UP | R_NET_IFACE_RUNNING;
    if (ad->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
      iface->flags |= R_NET_IFACE_LOOPBACK;
    else if (ad->IfType == IF_TYPE_PPP)
      iface->flags |= R_NET_IFACE_POINTOPOINT;
    if (!(ad->Flags & IP_ADAPTER_NO_MULTICAST))
      iface->flags |= R_NET_IFACE_MULTICAST;

    if (hwlen > R_NET_IFACE_HWADDR_MAXLEN)
      hwlen = R_NET_IFACE_HWADDR_MAXLEN;
    r_memcpy (iface->hwaddr, ad->PhysicalAddress, hwlen);
    iface->hwaddrlen = hwlen;

    for (ua = ad->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
      SOCKADDR * sa = ua->Address.lpSockaddr;
      RNetInterfaceAddr * ia;

      if (sa == NULL || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6))
        continue;
      ia = r_mem_new0 (RNetInterfaceAddr);
      ia->addr = r_socket_address_new_from_native (sa, (rsize) ua->Address.iSockaddrLength);
      ia->prefixlen = ua->OnLinkPrefixLength;
      if (ia->addr != NULL)
        r_ptr_array_add (iface->addrs, ia, r_net_interface_addr_free);
      else
        r_net_interface_addr_free (ia);
    }
  }

  r_free (adapters);
  return ret;
}
#else
RPtrArray *
r_net_query_interfaces (void)
{
  return r_ptr_array_new ();
}
#endif
