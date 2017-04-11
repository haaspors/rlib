/* RLIB - Convenience library for useful things
 * Copyright (C) 2017  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#include <rlib/rtc/rrtccryptotransport.h>

#include <rlib/rassert.h>
#include <rlib/rmem.h>


static void
r_rtc_raw_transport_free (RRtcCryptoTransport * crypto)
{
  r_rtc_crypto_transport_clear (crypto);
  r_free (crypto);
}

static RRtcError
r_rtc_raw_transport_start (rpointer rtc, REvLoop * loop)
{
  (void) rtc;
  (void) loop;
  return R_RTC_OK;
}

static void
r_rtc_raw_transport_ice_packet (rpointer data, RBuffer * buf, rpointer ctx)
{
  RRtcCryptoTransport * crypto = data;
  RRtcIceTransport * ice = ctx;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  r_assert_cmpptr (ice, ==, crypto->ice);

  if (r_buffer_map (buf, &info, R_MEM_MAP_READ)) {
    if (r_rtp_is_valid_hdr (info.data, info.size)) {
      r_buffer_unmap (buf, &info);
      R_LOG_TRACE ("RtcCryptoTransport %p RTP packet", crypto);
      r_rtc_rtp_listener_handle_rtp (crypto->listener, buf, crypto);
    } else if (r_rtcp_is_valid_hdr (info.data, info.size)) {
      r_buffer_unmap (buf, &info);
      R_LOG_TRACE ("RtcCryptoTransport %p RTCP packet", crypto);
      r_rtc_rtp_listener_handle_rtcp (crypto->listener, buf, crypto);
    } else {
      R_LOG_WARNING ("Unknown packet received");
      r_buffer_unmap (buf, &info);
    }
  } else {
    R_LOG_WARNING ("Unable to map buffer %p", buf);
  }
}

static RRtcError
r_rtc_raw_transport_send (rpointer rtc, RBuffer * buf)
{
  RRtcCryptoTransport * crypto = rtc;
  return r_rtc_ice_transport_send (crypto->ice, buf);
}

RRtcCryptoTransport *
r_rtc_crypto_transport_new_raw (RRtcIceTransport * ice)
{
  RRtcCryptoTransport * ret;

  if (R_UNLIKELY (ice == NULL)) return NULL;

  if ((ret = r_mem_new0 (RRtcCryptoTransport)) != NULL) {
    r_ref_init (ret, r_rtc_raw_transport_free);
    r_rtc_crypto_transport_init (ret, ice, r_rtc_raw_transport_start,
        r_rtc_raw_transport_ice_packet, r_rtc_raw_transport_send);
  }

  return ret;
}

