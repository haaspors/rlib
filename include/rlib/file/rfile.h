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

#include <rlib/file/rfiletypes.h>
#include <rlib/rref.h>
#include <stdarg.h>

R_BEGIN_DECLS

/* Convenience API for whole file */
R_API rboolean r_file_read_all (const rchar * filename, ruint8 ** data, rsize * size);
R_API rboolean r_file_write_all (const rchar * filename, rconstpointer data, rsize size);
R_API ruint r_file_read_uint (const rchar * filename, ruint def);
R_API int   r_file_read_int (const rchar * filename, int def);

typedef struct _RFile RFile;

R_API RFile * r_file_open (const rchar * file, const rchar * mode);
#define r_file_new_tmp(dir, pre, path) r_file_new_tmp_full (dir, pre, "w", path)
R_API RFile * r_file_new_tmp_full (const rchar * dir, const rchar * pre,
    const rchar * mode, rchar ** path);
#define r_file_ref r_ref_ref
#define r_file_unref r_ref_unref

R_API int r_file_get_fd (RFile * file);

R_API RIOError r_file_read (RFile * file, rpointer data, rsize size, rsize * actual);
R_API RIOError r_file_read_line (RFile * file, rchar * data, rsize maxsize);
R_API RIOError r_file_write (RFile * file, rconstpointer data, rsize size, rsize * actual);
R_API RIOError r_file_scanf (RFile * file, const rchar * fmt, rsize * actual, ...) R_ATTR_SCANF (2, 4);
R_API RIOError r_file_vscanf (RFile * file, const rchar * fmt, rsize * actual, va_list args) R_ATTR_SCANF (2, 0);
R_API roffset  r_file_seek (RFile * file, roffset offset, RSeekMode mode);
R_API roffset  r_file_tell (RFile * file);

R_API rboolean r_file_is_eof (RFile * file);
R_API rboolean r_file_has_error (RFile * file);

R_API rboolean r_file_flush (RFile * file);

R_END_DECLS

#endif /* __R_FILE_H__ */


