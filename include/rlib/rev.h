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
#ifndef __R_EV_H__
#define __R_EV_H__

/**
 * @defgroup r_ev Event loop and async I/O
 *
 * @brief Edge-triggered event loop with TCP / UDP / DNS-resolve /
 * wakeup sources, layered on top of @c epoll (Linux), @c kqueue
 * (BSD / Darwin) and IOCP (Windows).
 *
 * @c r_evloop is the loop object; @c r_evtcp / @c r_evudp /
 * @c r_evresolve / @c r_evwakeup register sources that produce
 * I/O-ready, datagram or wakeup events. Callbacks fire on the
 * loop thread; long-running work belongs in @c r_taskqueue or
 * @c r_threadpool consumers.
 */

#include <rlib/rlib.h>

#include <rlib/ev/revloop.h>
#include <rlib/ev/revresolve.h>
#include <rlib/ev/revtcp.h>
#include <rlib/ev/revudp.h>
#include <rlib/ev/revwakeup.h>

#endif /* __R_EV_H__ */

