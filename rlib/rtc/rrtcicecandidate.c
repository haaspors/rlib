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
#include "rrtc-private.h"
#include <rlib/rtc/rrtcicecandidate.h>

#include <rlib/rassert.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

static void
r_rtc_ice_candidate_free (RRtcIceCandidate * candidate)
{
  r_socket_address_unref (candidate->addr);
  r_free (candidate);
}

RRtcIceCandidate *
r_rtc_ice_candidate_new (const rchar * ip, ruint16 port, RRtcIceProtocol proto,
    RRtcIceCandidateType type, ruint64 pri)
{
  RRtcIceCandidate * ret;
  RSocketAddress * addr;

  if ((addr = r_socket_address_ipv4_new_from_string (ip, port)) != NULL) {
    ret = r_rtc_ice_candidate_new_full (addr, proto, type, pri);
    r_socket_address_unref (addr);
  } else {
    ret = NULL;
  }

  return ret;
}

RRtcIceCandidate *
r_rtc_ice_candidate_new_full (RSocketAddress * addr, RRtcIceProtocol proto,
    RRtcIceCandidateType type, ruint64 pri)
{
  RRtcIceCandidate * ret;

  if ((ret = r_mem_new (RRtcIceCandidate)) != NULL) {
    r_ref_init (ret, r_rtc_ice_candidate_free);

    ret->addr = r_socket_address_ref (addr);
    ret->proto = proto;
    ret->type = type;
    ret->pri = pri;
  }

  return ret;
}

RSocketAddress *
r_rtc_ice_candidate_get_addr (RRtcIceCandidate * candidate)
{
  return r_socket_address_ref (candidate->addr);
}

RRtcIceProtocol
r_rtc_ice_candidate_get_protocol (RRtcIceCandidate * candidate)
{
  return candidate->proto;
}

RRtcIceCandidateType
r_rtc_ice_candidate_get_type (RRtcIceCandidate * candidate)
{
  return candidate->type;
}

ruint64
r_rtc_ice_candidate_get_pri (RRtcIceCandidate * candidate)
{
  return candidate->pri;
}

