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

#include <rlib/rtypes.h>
#include <stdarg.h>

#define R_DIR_SEP_UNIX      '/'
#define R_DIR_SEP_UNIX_STR  "/"
#define R_DIR_SEP_WIN32     '\\'
#define R_DIR_SEP_WIN32_STR "\\"

#ifdef R_OS_WIN32
#define R_DIR_SEP         R_DIR_SEP_WIN32
#define R_DIR_SEP_STR     R_DIR_SEP_WIN32_STR
#define R_IS_DIR_SEP(c)   ((c) == R_DIR_SEP_WIN32 || (c) == R_DIR_SEP_UNIX)
#define R_SEARCH_SEP      ';'
#define R_SEARCH_SEP_STR  ";"
#else
#define R_DIR_SEP         R_DIR_SEP_UNIX
#define R_DIR_SEP_STR     R_DIR_SEP_UNIX_STR
#define R_IS_DIR_SEP(c)   ((c) == R_DIR_SEP_UNIX)
#define R_SEARCH_SEP      ':'
#define R_SEARCH_SEP_STR  ":"
#endif

R_BEGIN_DECLS

R_API rchar * r_fs_path_basename (const rchar * file) R_ATTR_MALLOC;
R_API rchar * r_fs_path_dirname  (const rchar * file) R_ATTR_MALLOC;

R_API rchar * r_fs_path_build      (const rchar * first, ...) R_ATTR_MALLOC;
R_API rchar * r_fs_path_buildv     (const rchar * first, va_list ap) R_ATTR_MALLOC;
R_API rchar * r_fs_path_build_strv (rchar * const * strv) R_ATTR_MALLOC;

#define r_fs_path_new_tmpfile() r_fs_path_new_tmpname_full (NULL, NULL, NULL)
R_API rchar * r_fs_path_new_tmpname_full (const rchar * dir,
    const rchar * prefix, const rchar * suffix) R_ATTR_MALLOC;

R_API const rchar * r_fs_get_tmp_dir (void);
R_API rchar * r_fs_get_cur_dir (void) R_ATTR_MALLOC;

R_API rssize r_fs_get_filesize (const rchar * path);

R_API rboolean r_fs_test_exists (const rchar * path);

R_API rboolean r_fs_test_is_directory (const rchar * path);
R_API rboolean r_fs_test_is_regular (const rchar * path);
R_API rboolean r_fs_test_is_device (const rchar * path);
R_API rboolean r_fs_test_is_symlink (const rchar * path);

R_API rboolean r_fs_test_read_access (const rchar * path);
R_API rboolean r_fs_test_write_access (const rchar * path);
R_API rboolean r_fs_test_exec_access (const rchar * path);

R_API rboolean r_fs_mkdir (const rchar * path, int mode);
R_API rboolean r_fs_mkdir_full (const rchar * path, int mode);

R_END_DECLS

#endif /* __R_FS_H__ */

