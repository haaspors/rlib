/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include "rnet-private.h"
#include "rsocket-private.h"
#include "../rlib-private.h"

#include <rlib/net/rresolve.h>

#include <rlib/rlog.h>
#include <rlib/rmem.h>

#define R_LOG_CAT_DEFAULT &rlib_logcat

void
r_resolved_addr_free (RResolvedAddr * addr)
{
  while (addr != NULL) {
    RResolvedAddr * next = addr->next;

    r_socket_address_unref (addr->addr);
    r_free (addr);
    addr = next;
  }
}

RResolvedAddr *
r_resolve_sync (const rchar * host, const rchar * service,
    RResolveAddrFlags flags, const RResolveHints * hints, RResolveResult * res)
{
  struct addrinfo aihints;
  struct addrinfo * aires;
  int r;
  RResolvedAddr * ret = NULL;

  r_memclear (&aihints, sizeof (aihints));
  aihints.ai_flags = (int)flags;
  if (hints != NULL) {
    aihints.ai_family = (int)hints->family;
    if (hints->type == R_SOCKET_TYPE_STREAM)
      aihints.ai_socktype = SOCK_STREAM;
    else if (hints->type == R_SOCKET_TYPE_DATAGRAM)
      aihints.ai_socktype = SOCK_DGRAM;
    aihints.ai_protocol = 0;
  }

  if ((r = getaddrinfo (host, service, &aihints, &aires)) == 0) {
    struct addrinfo * it;
    RResolvedAddr * last = NULL;

    for (it = aires; it != NULL; it = it->ai_next) {
      RResolvedAddr * cur;

      R_LOG_DEBUG ("getaddrinfo family: %d, protocol %d, type %d, flags %d",
          it->ai_family, it->ai_protocol, it->ai_socktype, it->ai_flags);
      R_LOG_MEM_DUMP (R_LOG_LEVEL_TRACE, it->ai_addr, it->ai_addrlen);

      cur = r_mem_new (RResolvedAddr);
      cur->hints.family = (RSocketFamily)it->ai_family;
      switch (it->ai_socktype) {
        case SOCK_STREAM:
          cur->hints.type = R_SOCKET_TYPE_STREAM;
          break;
        case SOCK_DGRAM:
          cur->hints.type = R_SOCKET_TYPE_DATAGRAM;
          break;
        default:
          cur->hints.type = 0;
          break;
      }
      cur->hints.protocol = (RSocketProtocol)it->ai_protocol;
      cur->addr = r_socket_address_new_from_native (it->ai_addr, it->ai_addrlen);
      cur->next = NULL;

      if (last != NULL)
        last->next = cur;
      else
        ret = cur;
      last = cur;
    }
    freeaddrinfo (aires);
    if (res != NULL)
      *res = R_RESOLVE_OK;
  } else {
    /* FIXME: set result based on r! */
    if (res != NULL)
      *res = R_RESOLVE_ERROR;
  }

  return ret;
}

