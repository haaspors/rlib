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
  if (candidate->raddr != NULL)
    r_socket_address_unref (candidate->raddr);
  r_free (candidate->foundation);
  r_free (candidate);
}

RRtcIceCandidate *
r_rtc_ice_candidate_new_full (const rchar * foundation, rssize fsize,
    ruint64 pri, RRtcIceComponent component,
    RRtcIceProtocol proto, RSocketAddress * addr, RRtcIceCandidateType type)
{
  RRtcIceCandidate * ret;

  if (R_UNLIKELY (type > R_RTC_ICE_CANDIDATE_LAST)) return NULL;
  if (R_UNLIKELY (component > R_RTC_ICE_COMPONENT_LAST)) return NULL;
  if (R_UNLIKELY (proto > R_RTC_ICE_PROTO_LAST)) return NULL;
  if (R_UNLIKELY (addr == NULL)) return NULL;

  if ((ret = r_mem_new (RRtcIceCandidate)) != NULL) {
    r_ref_init (ret, r_rtc_ice_candidate_free);

    ret->foundation = r_strdup_size (foundation, fsize);
    ret->component = component;
    ret->proto = proto;
    ret->pri = pri;
    ret->addr = r_socket_address_ref (addr);
    ret->type = type;
    ret->raddr = NULL;
  }

  return ret;
}

RRtcIceCandidate *
r_rtc_ice_candidate_new (const rchar * foundation, rssize fsize,
    ruint64 pri, RRtcIceComponent component,
    RRtcIceProtocol proto, const rchar * ip, ruint16 port,
    RRtcIceCandidateType type)
{
  RRtcIceCandidate * ret;
  RSocketAddress * addr;

  if ((addr = r_socket_address_ipv4_new_from_string (ip, port)) != NULL) {
    ret = r_rtc_ice_candidate_new_full (foundation, fsize,
        pri, component, proto, addr, type);
    r_socket_address_unref (addr);
  } else {
    ret = NULL;
  }

  return ret;
}

RRtcIceCandidate *
r_rtc_ice_candidate_new_from_sdp_attrib_value (const rchar * value, rssize size)
{
  RRtcIceCandidate * ret = NULL;
  RStrMatchResult * res;

  if (r_str_match_pattern (value, size, "* ? * * * * typ * *", &res) == R_STR_MATCH_RESULT_OK) {
    RRtcIceComponent comp;
    RRtcIceProtocol proto;
    RRtcIceCandidateType type;
    ruint64 pri;
    rchar * ip = NULL;
    ruint16 port;
    RStrKV kv = R_STR_KV_INIT;
    const rchar * next, * end, * rnext;

    switch (res->token[2].chunk.str[0]) {
      case '1':
        comp = R_RTC_ICE_COMPONENT_RTP;
        break;
      case '2':
        comp = R_RTC_ICE_COMPONENT_RTCP;
        break;
      default:
        goto parse_error;
    }

    if (r_str_chunk_casecmp (&res->token[4].chunk, R_STR_WITH_SIZE_ARGS ("udp")) == 0)
      proto = R_RTC_ICE_PROTO_UDP;
    else if (r_str_chunk_casecmp (&res->token[4].chunk, R_STR_WITH_SIZE_ARGS ("tcp")) == 0)
      proto = R_RTC_ICE_PROTO_TCP;
    else
      goto parse_error;

    pri = r_str_to_uint64 (res->token[6].chunk.str, NULL, 0, NULL);
    ip = r_str_chunk_dup (&res->token[8].chunk);
    port = r_str_to_uint16 (res->token[10].chunk.str, NULL, 0, NULL);

    if (r_str_chunk_casecmp (&res->token[12].chunk, R_STR_WITH_SIZE_ARGS ("host")) == 0)
      type = R_RTC_ICE_CANDIDATE_HOST;
    else if (r_str_chunk_casecmp (&res->token[12].chunk, R_STR_WITH_SIZE_ARGS ("srflx")) == 0)
      type = R_RTC_ICE_CANDIDATE_SRFLX;
    else if (r_str_chunk_casecmp (&res->token[12].chunk, R_STR_WITH_SIZE_ARGS ("prflx")) == 0)
      type = R_RTC_ICE_CANDIDATE_PRFLX;
    else if (r_str_chunk_casecmp (&res->token[12].chunk, R_STR_WITH_SIZE_ARGS ("relay")) == 0)
      type = R_RTC_ICE_CANDIDATE_RELAY;
    else
      goto parse_error;

    ret = r_rtc_ice_candidate_new (res->token[0].chunk.str, res->token[0].chunk.size,
        pri, comp, proto, ip, port, type);

    /* Parse raddr/rport */
    next = rnext = res->token[14].chunk.str;
    end = res->token[14].chunk.str + res->token[14].chunk.size;
    if (r_str_kv_parse_multiple (&kv, rnext, RPOINTER_TO_SIZE (end - rnext),
          R_STR_WITH_SIZE_ARGS (" "), R_STR_WITH_SIZE_ARGS (" "), &rnext) == R_STR_PARSE_OK &&
        r_str_chunk_casecmp (&kv.key, R_STR_WITH_SIZE_ARGS ("raddr")) == 0) {
      rchar * ip = r_str_kv_dup_value (&kv);
      if (r_str_kv_parse_multiple (&kv, rnext, RPOINTER_TO_SIZE (end - rnext),
          R_STR_WITH_SIZE_ARGS (" "), R_STR_WITH_SIZE_ARGS (" "), &rnext) == R_STR_PARSE_OK &&
          r_str_chunk_casecmp (&kv.key, R_STR_WITH_SIZE_ARGS ("rport")) == 0) {
        ret->raddr = r_socket_address_ipv4_new_from_string (ip,
            r_str_to_uint16 (kv.val.str, NULL, 10, NULL));
        next = rnext;
      }
      r_free (ip);
    }

    while (r_str_kv_parse_multiple (&kv, next, RPOINTER_TO_SIZE (end - next),
          R_STR_WITH_SIZE_ARGS (" "), R_STR_WITH_SIZE_ARGS (" "), &next) == R_STR_PARSE_OK) {
      /* FIXME: Parse attributes */
    }

parse_error:
    r_free (ip);
    r_free (res);
  }

  return ret;
}

const rchar *
r_rtc_ice_candidate_get_foundation (const RRtcIceCandidate * candidate)
{
  return candidate->foundation;
}

RSocketAddress *
r_rtc_ice_candidate_get_addr (RRtcIceCandidate * candidate)
{
  return r_socket_address_ref (candidate->addr);
}

RRtcIceProtocol
r_rtc_ice_candidate_get_protocol (const RRtcIceCandidate * candidate)
{
  return candidate->proto;
}

RRtcIceComponent
r_rtc_ice_candidate_get_component (const RRtcIceCandidate * candidate)
{
  return candidate->component;
}

RRtcIceCandidateType
r_rtc_ice_candidate_get_type (const RRtcIceCandidate * candidate)
{
  return candidate->type;
}

ruint64
r_rtc_ice_candidate_get_pri (const RRtcIceCandidate * candidate)
{
  return candidate->pri;
}

RSocketAddress *
r_rtc_ice_candidate_get_raddr (RRtcIceCandidate * candidate)
{
  return (candidate->raddr != NULL) ? r_socket_address_ref (candidate->raddr) : NULL;
}

