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

/**
 * @file rlib/ev/revio.h
 * @brief Event-loop I/O watcher over an @c RIOHandle: start / stop
 * readiness notifications and close.
 */

#include <rlib/rtypes.h>

#include <rlib/rref.h>

/**
 * @defgroup r_evio Event-loop I/O watcher
 * @ingroup r_ev
 *
 * @brief Watch an @c RIOHandle on an @ref REvLoop and fire a callback
 * when it becomes readable / writable (or errors / hangs up).
 *
 * Create an @ref REvIO for a handle, then @ref r_ev_io_start with the
 * @ref REvIOEvents of interest and a callback; the loop invokes it on
 * the loop thread each time the requested events occur. Higher-level
 * sources (@ref r_evtcp, @ref r_evudp) build on this. The
 * @ref r_evtcp / @ref r_evudp wrappers are usually more convenient
 * than driving @ref REvIO directly.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief I/O readiness event bits. */
typedef enum {
  R_EV_IO_READABLE    = (1 << 0), /**< Handle is readable. */
  /*R_EV_IO_PRI         = (1 << 1),*/
  R_EV_IO_WRITABLE    = (1 << 2), /**< Handle is writable. */
  R_EV_IO_ERROR       = (1 << 3), /**< Error condition on the handle. */
  R_EV_IO_HANGUP      = (1 << 4), /**< Peer hung up / handle closed. */
} REvIOEvent;
/** @brief Bitwise-OR of @ref REvIOEvent values. */
typedef ruint REvIOEvents;

/** @brief Opaque event-loop handle (defined in @ref r_evloop). */
typedef struct REvLoop REvLoop;
/** @brief Opaque, refcounted I/O watcher. */
typedef struct REvIO REvIO;
/** @brief Plain watcher callback (e.g. close completion). */
typedef void (*REvIOFunc) (rpointer data, REvIO * evio);
/** @brief Readiness callback; @p events is the set that fired. */
typedef void (*REvIOCB) (rpointer data, REvIOEvents events, REvIO * evio);


/** @brief Create an I/O watcher for @p handle on @p loop. */
R_API REvIO * r_ev_io_new (REvLoop * loop, RIOHandle handle);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_ev_io_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_ev_io_unref r_ref_unref

/** @brief Attach an opaque user pointer (freed via @p notify). */
R_API void r_ev_io_set_user (REvIO * evio, rpointer user, RDestroyNotify notify);
/** @brief Retrieve the user pointer set by @ref r_ev_io_set_user. */
R_API rpointer r_ev_io_get_user (REvIO * evio) R_ATTR_WARN_UNUSED_RESULT;

/**
 * @brief Start watching @p events, invoking @p io_cb when they fire.
 * @return An opaque start context to pass to @ref r_ev_io_stop.
 */
R_API rpointer r_ev_io_start (REvIO * evio, REvIOEvents events, REvIOCB io_cb,
    rpointer data, RDestroyNotify datanotify) R_ATTR_WARN_UNUSED_RESULT;
/** @brief Stop a watch started with @ref r_ev_io_start (@p ctx from that call). */
R_API rboolean r_ev_io_stop (REvIO * evio, rpointer ctx);
/** @brief Close the watched handle; @p close_cb fires once closed. */
R_API rboolean r_ev_io_close (REvIO * evio, REvIOFunc close_cb,
    rpointer data, RDestroyNotify datanotify);

R_END_DECLS

/** @} */

#endif /* __R_EV_IO_H__ */

