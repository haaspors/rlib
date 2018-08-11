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
#ifndef __R_FILE_IO_H__
#define __R_FILE_IO_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rio.h>
#include <rlib/file/rfiletypes.h>

R_BEGIN_DECLS

R_API RIOHandle r_io_open_file (const rchar * file, RFileOpenMode mode,
    RFileAccess access, RFileShareMode share, RFileFlags flags, const RFilePermission * perm);
R_API RIOHandle r_io_open_tmp_full (const rchar * dir, const rchar * fileprefix,
    RFileAccess access, RFileShareMode share, RFileFlags flags, const RFilePermission * perm, rchar ** path);
static inline RIOHandle r_io_open_tmp (const rchar * dir, const rchar * pre, rchar ** path)
{ return r_io_open_tmp_full (dir, pre, R_FILE_WRITE, R_FILE_SHARE_EXCLUSIVE, R_FILE_FLAG_NONE, NULL, path); }

R_API rboolean r_io_truncate (RIOHandle handle, rsize size);

R_API roffset r_io_seek (RIOHandle handle, roffset offset, RSeekMode mode);
static inline roffset r_io_tell (RIOHandle handle)
{ return r_io_seek (handle, 0, R_SEEK_MODE_CUR); }

R_API ruint64 r_io_filesize (RIOHandle handle);

R_END_DECLS

#endif /* __R_FILE_IO_H__ */

