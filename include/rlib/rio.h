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

/**
 * @file rlib/rio.h
 * @brief Generic @c RIOHandle operations: close / read / write /
 * flush, plus Unix fd-flag helpers.
 */

#include <rlib/rtypes.h>

/**
 * @defgroup r_io Generic I/O
 *
 * @brief Foundational @c RIOHandle layer: a portable wrapper over
 * OS file descriptors (Unix) and @c HANDLE / @c SOCKET (Windows).
 *
 * Every IO-bearing subsystem builds on this layer:
 *
 *  - @ref r_iosocket adds the BSD socket operations on top.
 *  - @c r_file_io (file/) adds file-flavoured ops (open, seek, truncate).
 *  - @c r_ev (ev/) registers handles with the event loop.
 *
 * On Unix the handle is a numeric file descriptor; on Windows it is
 * an opaque @c HANDLE. Use the @c r_io_unix_* helpers (no-ops on
 * Windows) when you need to flip the @c O_NONBLOCK or @c FD_CLOEXEC
 * flags.
 *
 * @{
 */

R_BEGIN_DECLS

/**
 * @brief Close @p handle and release any backing OS resource.
 * @return @c TRUE on success.
 */
R_API rboolean r_io_close (RIOHandle handle);

/**
 * @brief Write @p size bytes from @p buf into @p handle.
 * @return Number of bytes written, or @c -1 on error.
 */
R_API rssize r_io_write (RIOHandle handle, rconstpointer buf, rsize size);
/**
 * @brief Read up to @p size bytes from @p handle into @p buf.
 * @return Number of bytes read (0 at EOF), or @c -1 on error.
 */
R_API rssize r_io_read (RIOHandle handle, rpointer buf, rsize size);

/** @brief Flush any pending OS-level write buffers on @p handle. */
R_API rboolean r_io_flush (RIOHandle handle);

#ifdef R_OS_UNIX
/** @brief Set or clear the @c O_NONBLOCK flag on @p handle. */
R_API rboolean r_io_unix_set_nonblocking (RIOHandle handle, rboolean set);
/** @brief Set or clear the @c FD_CLOEXEC flag on @p handle. */
R_API rboolean r_io_unix_set_cloexec (RIOHandle handle, rboolean set);
#endif

R_END_DECLS

/** @} */

#endif /* __R_IO_H__ */

