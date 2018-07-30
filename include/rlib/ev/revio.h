/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_EV_IO_H__
#define __R_EV_IO_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

typedef enum {
  R_EV_IO_READABLE    = (1 << 0),
  /*R_EV_IO_PRI         = (1 << 1),*/
  R_EV_IO_WRITABLE    = (1 << 2),
  R_EV_IO_ERROR       = (1 << 3),
  R_EV_IO_HANGUP      = (1 << 4),
} REvIOEvent;
typedef ruint REvIOEvents;

typedef struct _REvLoop REvLoop;
typedef struct _REvIO REvIO;
typedef void (*REvIOFunc) (rpointer data, REvIO * evio);
typedef void (*REvIOCB) (rpointer data, REvIOEvents events, REvIO * evio);


R_API REvIO * r_ev_io_new (REvLoop * loop, RIOHandle handle);
#define r_ev_io_ref r_ref_ref
#define r_ev_io_unref r_ref_unref

R_API void r_ev_io_set_user (REvIO * evio, rpointer user, RDestroyNotify notify);
R_API rpointer r_ev_io_get_user (REvIO * evio) R_ATTR_WARN_UNUSED_RESULT;

R_API rpointer r_ev_io_start (REvIO * evio, REvIOEvents events, REvIOCB io_cb,
    rpointer data, RDestroyNotify datanotify) R_ATTR_WARN_UNUSED_RESULT;
R_API rboolean r_ev_io_stop (REvIO * evio, rpointer ctx);
R_API rboolean r_ev_io_close (REvIO * evio, REvIOFunc close_cb,
    rpointer data, RDestroyNotify datanotify);

R_END_DECLS

#endif /* __R_EV_IO_H__ */

