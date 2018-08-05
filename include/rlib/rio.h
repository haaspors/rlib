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
#ifndef __R_IO_H__
#define __R_IO_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

R_API rboolean r_io_close (RIOHandle handle);

R_API rssize r_io_write (RIOHandle handle, rconstpointer buf, rsize size);
R_API rssize r_io_read (RIOHandle handle, rpointer buf, rsize size);

R_API rboolean r_io_flush (RIOHandle handle);

#ifdef R_OS_UNIX
R_API rboolean r_io_unix_set_nonblocking (RIOHandle handle, rboolean set);
R_API rboolean r_io_unix_set_cloexec (RIOHandle handle, rboolean set);
#endif

R_END_DECLS

#endif /* __R_IO_H__ */

