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
#ifndef __R_EV_IOCP_PRIV_H__
#define __R_EV_IOCP_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rev-iocp-private.h should only be used internally in rlib!"
#endif

#include "config.h"
#include <rlib/rtypes.h>

/* IOCP (completion-port) backend: the Windows default, opt out with -Drpoll. */
#if defined (R_OS_WIN32) && !defined (R_EV_USE_RPOLL)

#include <rlib/rmem.h>
#include <rlib/ev/revloop.h>

/* GetQueuedCompletionStatusEx / ConnectEx need Vista+ headers. */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

R_BEGIN_DECLS

/* Completion key reserved for r_ev_loop_wakeup's PostQueuedCompletionStatus;
 * every real I/O completion is recovered from its OVERLAPPED instead. */
#define R_EV_IOCP_WAKEUP_KEY    ((ULONG_PTR) 1)

typedef struct REvIOCPOp REvIOCPOp;

/* Completion handler for one overlapped op. @bytes is the transfer count the
 * port reported; the handler reads the authoritative status itself (via
 * WSAGetOverlappedResult on its own socket) since the port does not carry it. */
typedef void (*REvIOCPOpFunc) (REvIOCPOp * op, REvLoop * loop, rsize bytes);

/* One in-flight overlapped operation. The OVERLAPPED must be the first member
 * so the loop can recover the op from a completion's lpOverlapped via
 * CONTAINING_RECORD. The op (and any buffer it points at) must outlive the
 * in-flight operation -- including @wbuf: WSARecv/WSASend keep the WSABUF
 * descriptor referenced until the overlapped op completes, so it cannot live on
 * the caller's stack. */
struct REvIOCPOp {
  OVERLAPPED overlapped;
  REvIOCPOpFunc cb;
  rpointer data;
  WSABUF wbuf;
};

static inline void
r_ev_iocp_op_init (REvIOCPOp * op, REvIOCPOpFunc cb, rpointer data)
{
  r_memclear (&op->overlapped, sizeof (OVERLAPPED));
  op->cb = cb;
  op->data = data;
}

/* Cap a buffer length to what one WSABUF (32-bit ULONG) can describe. */
static inline ULONG
r_ev_iocp_wsabuf_len (rsize size)
{
  const rsize max = (rsize) 0xFFFFFFFFu;
  return (ULONG) (size > max ? max : size);
}

/* Associate @handle (a socket) with the loop's completion port; completions
 * for overlapped ops on it are then delivered to r_ev_loop_io_wait. */
R_API_HIDDEN rboolean r_ev_loop_iocp_associate (REvLoop * loop, RIOHandle handle);
/* Account for one overlapped op being posted / failing to post: a submitted
 * op keeps the loop alive until its completion arrives. */
R_API_HIDDEN void r_ev_loop_iocp_submit (REvLoop * loop);
R_API_HIDDEN void r_ev_loop_iocp_unsubmit (REvLoop * loop);

R_END_DECLS

#endif /* R_OS_WIN32 && !R_EV_USE_RPOLL */

#endif /* __R_EV_IOCP_PRIV_H__ */
