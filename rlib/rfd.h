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
#if defined (R_OS_WIN32)
#include <io.h>
#elif defined (R_OS_UNIX)
#include <fcntl.h>
#endif
/* FIXME: Do something cleve with flags and mode? */

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

