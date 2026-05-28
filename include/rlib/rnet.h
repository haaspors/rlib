/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_NET_H__
#define __R_NET_H__

/**
 * @defgroup r_net Networking
 *
 * @brief Socket abstractions, address parsing, DNS resolution and
 * the higher-level network protocol stacks (HTTP / TLS / STUN /
 * RTP / SRTP / SDP) that build on them.
 *
 * Layers, from foundation up:
 *
 *   - @c r_socket / @c r_socketaddress / @c r_iosocket — BSD-socket
 *     abstraction, address representation, IO over connected
 *     sockets.
 *   - @c r_resolve — DNS resolution (sync and async variants).
 *   - @c r_http_proto / @c r_tls_proto / @c r_stun / @c r_rtp /
 *     @c r_rtcp / @c r_sdp — wire-format parsers and constructors.
 *   - @c r_http_server / @c r_tls_server / @c r_srtp — higher-level
 *     server and session objects.
 *
 * Event-loop-driven socket I/O lives in @c r_ev (revtcp / revudp);
 * this group covers the protocol surface those callers reach for
 * once the bytes are in hand.
 */

#include <rlib/rlib.h>

#include <rlib/net/riosocket.h>
#include <rlib/net/rsocket.h>
#include <rlib/net/rsocketaddress.h>
#include <rlib/net/rresolve.h>
#include <rlib/net/rhttpserver.h>
#include <rlib/net/rsrtp.h>
#include <rlib/net/rtlsserver.h>
#include <rlib/net/proto/rhttp.h>
#include <rlib/net/proto/rrtp.h>
#include <rlib/net/proto/rsdp.h>
#include <rlib/net/proto/rstun.h>
#include <rlib/net/proto/rtls.h>

#endif /* __R_NET_H__ */

