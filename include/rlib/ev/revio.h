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
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/ev/revio.h
 * @brief Shared event-loop I/O types.
 *
 * The low-level I/O-watcher API (@c r_ev_io_*) is internal to rlib: it is a
 * readiness-based (reactor) interface with no equivalent on a completion-based
 * (IOCP / proactor) backend, and applications use the higher-level
 * @ref r_evtcp / @ref r_evudp sources instead. Only the shared types those
 * public APIs reference live here.
 */

#include <rlib/rtypes.h>

/**
 * @defgroup r_evio Event-loop I/O types
 * @ingroup r_ev
 * @brief Shared types for the event-loop I/O sources.
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted I/O watcher (internal to rlib). */
typedef struct REvIO REvIO;
/** @brief Plain watcher callback (e.g. close completion). */
typedef void (*REvIOFunc) (rpointer data, REvIO * evio);

R_END_DECLS

/** @} */

#endif /* __R_EV_IO_H__ */

