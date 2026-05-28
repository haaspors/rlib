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
#ifndef __R_FS_H__
#define __R_FS_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/file/rfs.h
 * @brief Filesystem path manipulation, temp-name generation and
 * path metadata / existence tests.
 */

#include <rlib/rtypes.h>
#include <stdarg.h>

/** @addtogroup r_file
 *  @{ */

/** @brief Unix directory separator character (@c '/'). */
#define R_DIR_SEP_UNIX      '/'
/** @brief Unix directory separator as a string. */
#define R_DIR_SEP_UNIX_STR  "/"
/** @brief Windows directory separator character (@c '\\'). */
#define R_DIR_SEP_WIN32     '\\'
/** @brief Windows directory separator as a string. */
#define R_DIR_SEP_WIN32_STR "\\"

#ifdef R_OS_WIN32
/** @brief Native directory separator character for the target OS. */
#define R_DIR_SEP         R_DIR_SEP_WIN32
/** @brief Native directory separator as a string. */
#define R_DIR_SEP_STR     R_DIR_SEP_WIN32_STR
/** @brief @c TRUE if @p c is a directory separator on the target OS. */
#define R_IS_DIR_SEP(c)   ((c) == R_DIR_SEP_WIN32 || (c) == R_DIR_SEP_UNIX)
/** @brief @c PATH-style search-list separator character. */
#define R_SEARCH_SEP      ';'
/** @brief Search-list separator as a string. */
#define R_SEARCH_SEP_STR  ";"
/** @brief Executable filename suffix on the target OS. */
#define R_EXE_SUFFIX      ".exe"
#else
#define R_DIR_SEP         R_DIR_SEP_UNIX
#define R_DIR_SEP_STR     R_DIR_SEP_UNIX_STR
#define R_IS_DIR_SEP(c)   ((c) == R_DIR_SEP_UNIX)
#define R_SEARCH_SEP      ':'
#define R_SEARCH_SEP_STR  ":"
#define R_EXE_SUFFIX      ""
#endif

R_BEGIN_DECLS

/** @brief Return the final path component of @p file (newly allocated). */
R_API rchar * r_fs_path_basename (const rchar * file) R_ATTR_MALLOC;
/** @brief Return the directory portion of @p file (newly allocated). */
R_API rchar * r_fs_path_dirname  (const rchar * file) R_ATTR_MALLOC;

/** @brief Join a @c NULL-terminated list of components with the native separator. */
R_API rchar * r_fs_path_build      (const rchar * first, ...) R_ATTR_MALLOC;
/** @brief @c va_list variant of @ref r_fs_path_build. */
R_API rchar * r_fs_path_buildv     (const rchar * first, va_list ap) R_ATTR_MALLOC;
/** @brief @c NULL-terminated string-array variant of @ref r_fs_path_build. */
R_API rchar * r_fs_path_build_strv (rchar * const * strv) R_ATTR_MALLOC;

/** @brief Generate a temp filename in the system temp dir; see @ref r_fs_path_new_tmpname_full. */
#define r_fs_path_new_tmpfile() r_fs_path_new_tmpname_full (NULL, NULL, NULL)
/**
 * @brief Generate a unique temp-file path (does not create the file).
 * @param dir    Target directory, or @c NULL for the system temp dir.
 * @param prefix Optional filename prefix.
 * @param suffix Optional filename suffix.
 */
R_API rchar * r_fs_path_new_tmpname_full (const rchar * dir,
    const rchar * prefix, const rchar * suffix) R_ATTR_MALLOC;

/** @brief Return the system temp directory (borrowed pointer). */
R_API const rchar * r_fs_get_tmp_dir (void);
/** @brief Return the current working directory (newly allocated). */
R_API rchar * r_fs_get_cur_dir (void) R_ATTR_MALLOC;

/** @brief Return the size of @p path in bytes, or @c -1 on error. */
R_API rssize r_fs_get_filesize (const rchar * path);

/** @brief @c TRUE if @p path exists. */
R_API rboolean r_fs_test_exists (const rchar * path);

/** @brief @c TRUE if @p path is a directory. */
R_API rboolean r_fs_test_is_directory (const rchar * path);
/** @brief @c TRUE if @p path is a regular file. */
R_API rboolean r_fs_test_is_regular (const rchar * path);
/** @brief @c TRUE if @p path is a device node. */
R_API rboolean r_fs_test_is_device (const rchar * path);
/** @brief @c TRUE if @p path is a symbolic link. */
R_API rboolean r_fs_test_is_symlink (const rchar * path);

/** @brief @c TRUE if the caller can read @p path. */
R_API rboolean r_fs_test_read_access (const rchar * path);
/** @brief @c TRUE if the caller can write @p path. */
R_API rboolean r_fs_test_write_access (const rchar * path);
/** @brief @c TRUE if the caller can execute @p path. */
R_API rboolean r_fs_test_exec_access (const rchar * path);

/** @brief Create directory @p path with permission @p mode. */
R_API rboolean r_fs_mkdir (const rchar * path, int mode);
/** @brief Create @p path and any missing parent directories (@c mkdir @c -p). */
R_API rboolean r_fs_mkdir_full (const rchar * path, int mode);

/**
 * @brief @c TRUE if @p path is absolute.
 *
 * Absolute means a leading separator (Unix) or a drive-letter +
 * colon + separator or a UNC @c \\ prefix (Windows). @c NULL / empty
 * paths are not absolute.
 */
R_API rboolean r_fs_path_is_absolute (const rchar * path);

R_END_DECLS

/** @} */ /* r_file */

#endif /* __R_FS_H__ */

