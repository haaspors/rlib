/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_FD_H__
#define __R_FD_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <fcntl.h>
#if defined (R_OS_WIN32)
#include <io.h>

/* FIXME: Do something clever with flags and mode instead of this? */
#if defined (_O_RDONLY) && !defined (O_RDONLY)
#define O_RDONLY _O_RDONLY
#endif
#if defined (_O_WRONLY) && !defined (O_WRONLY)
#define O_WRONLY _O_WRONLY
#endif
#if defined (_O_RDWR) && !defined (O_RDWR)
#define O_RDWR _O_RDWR
#endif

#if defined (_O_APPEND) && !defined (O_APPEND)
#define O_APPEND _O_APPEND
#endif
#if defined (_O_BINARY) && !defined (O_BINARY)
#define O_BINARY _O_BINARY
#endif
#if defined (_O_CREAT) && !defined (O_CREAT)
#define O_CREAT _O_CREAT
#endif
#if defined (_O_TRUNC) && !defined (O_TRUNC)
#define O_TRUNC _O_TRUNC
#endif
#endif

R_API int r_fd_open (const rchar * file, int flags, int mode);
R_API int r_fd_open_tmp (const rchar * dir, const rchar * pre, rchar ** path);
R_API int r_fd_open_tmp_full (const rchar * dir, const rchar * fileprefix,
    int flags, int mode, rchar ** path);
R_API rboolean r_fd_close (int fd);

R_API rssize r_fd_write (int fd, rconstpointer buf, rsize size);
R_API rssize r_fd_read (int fd, rpointer buf, rsize size);

R_API rboolean r_fd_truncate (int fd, rsize size);
R_API rboolean r_fd_flush (int fd);
R_API rssize r_fd_tell (int fd);
R_API rssize r_fd_seek (int fd, rssize offset, int mode);

R_END_DECLS

#endif /* __R_FD_H__ */

