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
#ifndef __R_OS_H__
#define __R_OS_H__

/**
 * @defgroup r_os Operating system
 *
 * @brief OS-system facing primitives: processes, signals, system
 * info, environment variables, dynamic loading and TTY detection.
 *
 * Six headers:
 *
 *   - @c r_proc — process introspection and management.
 *   - @c r_signal — signal handlers and synchronous delivery.
 *   - @c r_sys — system info (uname-style, CPU count, hostname).
 *   - @c r_env — environment-variable accessors.
 *   - @c r_module — dynamic-library loading (@c dlopen / @c LoadLibrary).
 *   - @c r_tty — terminal detection and capability queries.
 */

#include <rlib/rlib.h>

#include <rlib/os/renv.h>
#include <rlib/os/rmodule.h>
#include <rlib/os/rproc.h>
#include <rlib/os/rsignal.h>
#include <rlib/os/rsys.h>
#include <rlib/os/rtty.h>

#endif /* __R_OS_H__ */

