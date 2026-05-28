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

/**
 * @file rlib/file/rio.h
 * @brief File-flavoured operations over @c RIOHandle: open, temp-open,
 * truncate, seek and size.
 */

#include <rlib/rio.h>
#include <rlib/file/rfiletypes.h>

/** @addtogroup r_file
 *  @{ */

R_BEGIN_DECLS

/**
 * @brief Open a file as a raw @c RIOHandle.
 * @param file   Path to open.
 * @param mode   Create / open / truncate disposition.
 * @param access Requested access rights.
 * @param share  Sharing mode for concurrent openers.
 * @param flags  Auxiliary @ref RFileFlags.
 * @param perm   Permissions to apply when creating; may be @c NULL.
 * @return Open handle, or @c R_IO_HANDLE_INVALID on failure.
 */
R_API RIOHandle r_io_open_file (const rchar * file, RFileOpenMode mode,
    RFileAccess access, RFileShareMode share, RFileFlags flags, const RFilePermission * perm);
/**
 * @brief Create and open a uniquely-named temp file as an @c RIOHandle.
 *
 * @param dir        Target directory, or @c NULL for the system temp dir.
 * @param fileprefix Filename prefix.
 * @param access     Requested access rights.
 * @param share      Sharing mode for concurrent openers.
 * @param flags      Auxiliary @ref RFileFlags.
 * @param perm       Permissions to apply on create; may be @c NULL.
 * @param path       Optional out-pointer receiving the allocated final path.
 */
R_API RIOHandle r_io_open_tmp_full (const rchar * dir, const rchar * fileprefix,
    RFileAccess access, RFileShareMode share, RFileFlags flags, const RFilePermission * perm, rchar ** path);
/** @brief Convenience temp-open with write access and exclusive sharing. */
static inline RIOHandle r_io_open_tmp (const rchar * dir, const rchar * pre, rchar ** path)
{ return r_io_open_tmp_full (dir, pre, R_FILE_WRITE, R_FILE_SHARE_EXCLUSIVE, R_FILE_FLAG_NONE, NULL, path); }

/** @brief Truncate or extend @p handle to @p size bytes. */
R_API rboolean r_io_truncate (RIOHandle handle, rsize size);

/** @brief Reposition @p handle's offset relative to @p mode. */
R_API roffset r_io_seek (RIOHandle handle, roffset offset, RSeekMode mode);
/** @brief Return @p handle's current offset (seek by 0 from current). */
static inline roffset r_io_tell (RIOHandle handle)
{ return r_io_seek (handle, 0, R_SEEK_MODE_CUR); }

/** @brief Return the total size of the file behind @p handle in bytes. */
R_API ruint64 r_io_filesize (RIOHandle handle);

R_END_DECLS

/** @} */ /* r_file */

#endif /* __R_FILE_IO_H__ */

