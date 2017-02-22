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
#ifndef __R_EV_TCP_H__
#define __R_EV_TCP_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/ev/revloop.h>
#include <rlib/rbuffer.h>
#include <rlib/rref.h>
#include <rlib/rsocket.h>
#include <rlib/rsocketaddress.h>

R_BEGIN_DECLS

typedef struct _REvTCP REvTCP;
typedef RBuffer * (*REvTCPBufferAllocFunc) (rpointer data, REvTCP * evtcp);
typedef void (*REvTCPBufferFunc) (rpointer data, RBuffer * buf, REvTCP * evtcp);
typedef void (*REvTCPConnectedFunc) (rpointer data, REvTCP * evtcp, int status);
typedef void (*REvTCPConnectionReadyFunc) (rpointer data, REvTCP * newtcp, REvTCP * listening);

R_API REvTCP * r_ev_tcp_new (RSocketFamily family, REvLoop * loop);
R_API REvTCP * r_ev_tcp_new_bind (const RSocketAddress * addr, REvLoop * loop);
R_API rboolean r_ev_tcp_close (REvTCP * evtcp, REvIOFunc close_cb,
    rpointer data, RDestroyNotify datanotify);
#define r_ev_tcp_ref r_ref_ref
#define r_ev_tcp_unref r_ref_unref

R_API RSocketAddress * r_ev_tcp_get_local_address (const REvTCP * evtcp);
R_API RSocketAddress * r_ev_tcp_get_remote_address (const REvTCP * evtcp);

R_API RSocketStatus r_ev_tcp_bind (REvTCP * evtcp,
    const RSocketAddress * address, rboolean reuse);
R_API REvTCP * r_ev_tcp_accept (REvTCP * evtcp, RSocketStatus * res);
R_API RSocketStatus r_ev_tcp_connect (REvTCP * evtcp, const RSocketAddress * address,
    REvTCPConnectedFunc connected, rpointer data, RDestroyNotify datanotify);
R_API RSocketStatus r_ev_tcp_listen (REvTCP * evtcp, ruint8 backlog,
    REvTCPConnectionReadyFunc connection, rpointer data, RDestroyNotify datanotify);

R_API rboolean r_ev_tcp_recv_start (REvTCP * evtcp,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
/* Use task pool for receiving... */
R_API rboolean r_ev_tcp_task_recv_start (REvTCP * evtcp, ruint taskgroup,
    REvTCPBufferAllocFunc alloc, REvTCPBufferFunc recv,
    rpointer data, RDestroyNotify datanotify);
R_API rboolean r_ev_tcp_recv_stop (REvTCP * evtcp);
#define r_ev_tcp_send_and_forget(evtcp, buf) r_ev_tcp_send (evtcp, buf, NULL, NULL, NULL)
R_API rboolean r_ev_tcp_send (REvTCP * evtcp, RBuffer * buf,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify);
R_API rboolean r_ev_tcp_send_take (REvTCP * evtcp, rpointer buffer, rsize size,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify);
R_API rboolean r_ev_tcp_send_dup (REvTCP * evtcp, rconstpointer buffer, rsize size,
    REvTCPBufferFunc done, rpointer data, RDestroyNotify datanotify);

R_END_DECLS

#endif /* __R_EV_TCP_H__ */

