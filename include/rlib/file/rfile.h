/* RLIB - Convenience library for useful things
 * Copyright (C) 2016-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_FILE_H__
#define __R_FILE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @defgroup r_file Files and filesystem
 *
 * @brief Buffered file objects, filesystem path / metadata helpers,
 * and low-level file I/O over @c RIOHandle.
 *
 * Three layers, plus shared types:
 *
 *   - @c RFile (rfile.h) — a refcounted buffered file handle (a thin
 *     layer over @c FILE) with whole-file read/write convenience
 *     helpers.
 *   - @c r_fs_* (rfs.h) — path manipulation (basename / dirname /
 *     build / join), temp-name generation, and filesystem metadata /
 *     existence tests.
 *   - @c r_io_*_file (file/rio.h) — open / seek / truncate / size on
 *     a bare @c RIOHandle, taking the @ref RFileOpenMode /
 *     @ref RFileAccess / @ref RFileFlags enums from rfiletypes.h.
 *
 * @{
 */

/**
 * @file rlib/file/rfile.h
 * @brief Refcounted buffered file object (@c RFile) and whole-file
 * read/write convenience helpers.
 */

#include <rlib/file/rfiletypes.h>
#include <rlib/rref.h>
#include <stdarg.h>
#include <stdio.h>

R_BEGIN_DECLS

/** @brief Thin wrapper over @c fopen that selects @c fopen_s on MSVC. */
R_API FILE * r_fopen (const rchar * path, const rchar * mode);

/** @name Whole-file convenience
 *  @{ */
/** @brief Read an entire file into a freshly-allocated buffer. */
R_API rboolean r_file_read_all (const rchar * filename, ruint8 ** data, rsize * size);
/** @brief Write @p size bytes to @p filename, replacing its contents. */
R_API rboolean r_file_write_all (const rchar * filename, rconstpointer data, rsize size);
/** @brief Read an unsigned integer from a file, returning @p def on failure. */
R_API ruint r_file_read_uint (const rchar * filename, ruint def);
/** @brief Read a signed integer from a file, returning @p def on failure. */
R_API int   r_file_read_int (const rchar * filename, int def);
/** @} */

/** @brief Opaque, refcounted buffered file handle. */
typedef struct RFile RFile;

/** @brief Open @p file with an @c fopen-style @p mode string. */
R_API RFile * r_file_open (const rchar * file, const rchar * mode);
/** @brief Create a temp file with default @c "w" mode; see @ref r_file_new_tmp_full. */
#define r_file_new_tmp(dir, pre, path) r_file_new_tmp_full (dir, pre, "w", path)
/**
 * @brief Create a uniquely-named temp file.
 * @param dir  Target directory, or @c NULL for the system temp dir.
 * @param pre  Filename prefix.
 * @param mode @c fopen-style mode string.
 * @param path Optional out-pointer receiving the allocated final path.
 */
R_API RFile * r_file_new_tmp_full (const rchar * dir, const rchar * pre,
    const rchar * mode, rchar ** path);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_file_ref r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_file_unref r_ref_unref

/** @brief Return the underlying file descriptor. */
R_API int r_file_get_fd (RFile * file);

/** @brief Read up to @p size bytes; @p actual receives the count read. */
R_API RIOError r_file_read (RFile * file, rpointer data, rsize size, rsize * actual);
/** @brief Read a single line (up to @p maxsize bytes, including the NUL). */
R_API RIOError r_file_read_line (RFile * file, rchar * data, rsize maxsize);
/** @brief Write @p size bytes; @p actual receives the count written. */
R_API RIOError r_file_write (RFile * file, rconstpointer data, rsize size, rsize * actual);
/** @brief @c scanf-style formatted read; @p actual receives items matched. */
R_API RIOError r_file_scanf (RFile * file, const rchar * fmt, rsize * actual, ...) R_ATTR_SCANF (2, 4);
/** @brief @c va_list variant of @ref r_file_scanf. */
R_API RIOError r_file_vscanf (RFile * file, const rchar * fmt, rsize * actual, va_list args) R_ATTR_SCANF (2, 0);
/** @brief Reposition the file offset relative to @p mode. */
R_API roffset  r_file_seek (RFile * file, roffset offset, RSeekMode mode);
/** @brief Return the current file offset. */
R_API roffset  r_file_tell (RFile * file);

/** @brief @c TRUE if the end-of-file indicator is set. */
R_API rboolean r_file_is_eof (RFile * file);
/** @brief @c TRUE if the error indicator is set. */
R_API rboolean r_file_has_error (RFile * file);

/** @brief Flush buffered writes to the OS. */
R_API rboolean r_file_flush (RFile * file);

R_END_DECLS

/** @} */ /* r_file */

#endif /* __R_FILE_H__ */


