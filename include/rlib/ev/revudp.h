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
#ifndef __R_EV_UDP_H__
#define __R_EV_UDP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/ev/revloop.h>
#include <rlib/rbuffer.h>
#include <rlib/rref.h>
#include <rlib/rsocketaddress.h>

R_BEGIN_DECLS

typedef struct _REvUDP REvUDP;
typedef RBuffer * (*REvUDPBufferAllocFunc) (rpointer data, REvUDP * evudp);
typedef void (*REvUDPBufferFunc) (rpointer data, RBuffer * buf, RSocketAddress * addr, REvUDP * evudp);

R_API REvUDP * r_ev_udp_new (RSocketFamily family, REvLoop * loop);
#define r_ev_udp_ref r_ref_ref
#define r_ev_udp_unref r_ref_unref

R_API rboolean r_ev_udp_bind (REvUDP * evudp,
    const RSocketAddress * address, rboolean reuse);
R_API rboolean r_ev_udp_recv_start (REvUDP * evudp,
    REvUDPBufferAllocFunc alloc, REvUDPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
/* Use task pool for receiving... */
R_API rboolean r_ev_udp_task_recv_start (REvUDP * evudp, ruint taskgroup,
    REvUDPBufferAllocFunc alloc, REvUDPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
R_API rboolean r_ev_udp_recv_stop (REvUDP * evudp);
R_API rboolean r_ev_udp_send (REvUDP * evudp, RBuffer * buf,
    RSocketAddress * address, REvUDPBufferFunc done,
    rpointer data, RDestroyNotify datanotify);
R_API rboolean r_ev_udp_send_take (REvUDP * evudp, rpointer buffer, rsize size,
    RSocketAddress * address, REvUDPBufferFunc done,
    rpointer data, RDestroyNotify datanotify);

R_END_DECLS

#endif /* __R_EV_UDP_H__ */

