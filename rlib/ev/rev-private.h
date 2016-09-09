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
#ifndef __R_EV_PRIV_H__
#define __R_EV_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rev-private.h should only be used internally in rlib!"
#endif

#include <rlib/rtypes.h>

#include <rlib/ev/revloop.h>
#include <rlib/rfd.h>
#include <rlib/rlist.h>
#include <rlib/rsys.h>

R_BEGIN_DECLS

#define R_EV_LOOP_MAX_EVENTS              1024
#define R_EV_LOOP_DEFAULT_TASK_THREADS    r_sys_cpu_physical_count ()

typedef struct {
  REvIOEvents events;
  REvIOCB io_cb;
  rpointer data;
  RDestroyNotify notify;
} REvIOCtx;

#define r_ev_io_ctx_init(ctx, e, cb, d, n)                                    \
  R_STMT_START {                                                              \
    (ctx)->events = e;                                                        \
    (ctx)->io_cb = cb;                                                        \
    (ctx)->data = d;                                                          \
    (ctx)->notify = n;                                                        \
  } R_STMT_END
#define r_ev_io_ctx_clear(ctx)                                                \
  R_STMT_START {                                                              \
    if ((ctx)->notify != NULL) (ctx)->notify ((ctx)->data);                   \
    r_memset (ctx, 0, sizeof (REvIOCtx));                                     \
  } R_STMT_END
#define r_ev_io_invoke_cb(evio, events)                                       \
  R_STMT_START {                                                              \
    (evio)->current.io_cb ((evio)->current.data, events, evio);               \
  } R_STMT_END

typedef struct {
  REvIOFunc close_cb;
  rpointer data;
  RDestroyNotify notify;
} REvIOCloseCtx;

struct _REvIO {
  RRef ref;

  REvLoop * loop;
  RList * alnk; /* If NULL -> inactive, else -> link in REvLoop::active queue */
  RList * chglnk; /* If not NULL -> changing link in REvLoop::chg queue */
  REvIOCloseCtx close_ctx;

  REvHandle handle;
  REvIOCtx current;
  REvIOCtx pending;
};

#define R_EV_IO_FORMAT        "%p [%"R_EV_HANDLE_FMT"]"
#define R_EV_IO_ARGS(evio)    evio, (evio != NULL ? evio->handle : R_EV_HANDLE_INVALID)

#define R_EV_IO_IS_ACTIVE(evio) ((evio->alnk) != NULL)
#define R_EV_IO_IS_CHANGING(evio) ((evio->chglnk) != NULL)

R_API_HIDDEN void r_ev_io_init (REvIO * evio, REvLoop * loop, REvHandle handle,
    RDestroyNotify notify);
R_API_HIDDEN void r_ev_io_clear (REvIO * evio);

R_END_DECLS

#endif /* __R_EV_PRIV_H__ */

