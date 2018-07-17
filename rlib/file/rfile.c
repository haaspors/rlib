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

#include "config.h"
#include "rfile-private.h"
#include <rlib/file/rfile.h>

#include <rlib/file/rfs.h>
#include <rlib/rmem.h>

#include <stdio.h>
#include <errno.h>


struct _RFile {
  RRef ref;
  FILE * file;
};

static void
r_file_free (RFile * file)
{
  fclose (file->file);
  r_free (file);
}

static RFile *
r_file_new_from_file (FILE * file)
{
  RFile * ret;

  if (R_UNLIKELY (file == NULL))
    return NULL;

  if ((ret = r_mem_new (RFile)) != NULL) {
    r_ref_init (ret, r_file_free);
    ret->file = file;
  }

  return ret;
}

RFile *
r_file_open (const rchar * file, const rchar * mode)
{
  FILE * f;

  if (R_UNLIKELY (file == NULL))
    return NULL;

  do {
    f = fopen (file, mode);
  } while (R_UNLIKELY (f == NULL && errno == EINTR));

  return r_file_new_from_file (f);
}

RFile *
r_file_new_tmp_full (const rchar * dir, const rchar * pre, const rchar * mode,
    rchar ** path)
{
  RFile * ret;
  rchar * file;

  if ((file = r_fs_path_new_tmpname_full (dir, pre, "")) != NULL) {
    if ((ret = r_file_open (file, mode)) != NULL && path != NULL)
      *path = file;
    else
      r_free (file);
  } else {
    ret = NULL;
  }

  return ret;
}

int
r_file_get_fd (RFile * file)
{
  return fileno (file->file);
}

static RIOError
_r_errno_to_io_error (int e)
{
  switch (e) {
    case EINVAL:
      return R_FILE_ERROR_INVAL;
    case EBADF:
      return R_FILE_ERROR_BAD_FILE;
    case EAGAIN:
#if defined (EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
      return R_FILE_ERROR_AGAIN;
    default:
      return R_FILE_ERROR_ERROR;
  }
}

RIOError
r_file_read (RFile * file, rpointer data, rsize size, rsize * actual)
{
  rsize acc = 0, cur;
  RIOError ret = R_FILE_ERROR_OK;

  while (acc != size && feof (file->file) == 0) {
    acc += (cur = fread (&((ruint8 *)data)[acc], 1, size - acc, file->file));

    if (ferror (file->file) && errno != EINTR) {
      ret = _r_errno_to_io_error (errno);
      break;
    }
  }

  if (actual)
    *actual = acc;

  return ret;
}

RIOError
r_file_read_line (RFile * file, rchar * data, rsize maxsize)
{
  return fgets (data, maxsize, file->file) ? R_FILE_ERROR_OK : R_FILE_ERROR_ERROR;
}

RIOError
r_file_write (RFile * file, rconstpointer data, rsize size, rsize * actual)
{
  rsize acc = 0, cur;
  RIOError ret = R_FILE_ERROR_OK;

  while (acc != size) {
    acc += (cur = fwrite (&((const ruint8 *)data)[acc], 1, size - acc, file->file));

    if (acc != size && errno != EINTR) {
      ret = _r_errno_to_io_error (errno);
      break;
    }
  }

  if (actual)
    *actual = acc;

  return ret;
}

RIOError
r_file_vscanf (RFile * file, const rchar * fmt, rsize * actual, va_list args)
{
  int res;
  do {
    res = vfscanf (file->file, fmt, args);
  } while (R_UNLIKELY (res < 0 && errno == EINTR));

  if (res >= 0) {
    if (actual != NULL)
      *actual = res;
    return R_FILE_ERROR_OK;
  }

  return _r_errno_to_io_error (errno);
}

RIOError
r_file_scanf (RFile * file, const rchar * fmt, rsize * actual, ...)
{
  RIOError ret;
  va_list args;

  va_start (args, actual);
  ret = r_file_vscanf (file, fmt, actual, args);
  va_end (args);

  return ret;
}

roffset
r_file_seek (RFile * file, roffset offset, RSeekMode mode)
{
  return (roffset)fseek (file->file, offset, r_file_seek_mode_to_whence (mode));
}

roffset
r_file_tell (RFile * file)
{
  return (roffset)ftell (file->file);
}

rboolean
r_file_is_eof (RFile * file)
{
  return feof (file->file) != 0;
}

rboolean
r_file_has_error (RFile * file)
{
  return ferror (file->file) != 0;
}

rboolean
r_file_flush (RFile * file)
{
  return fflush (file->file) != 0;
}

rboolean
r_file_read_all (const rchar * filename, ruint8 ** data, rsize * size)
{
  rboolean ret;
  RFile * f;
  rssize fsize;

  if (R_UNLIKELY (filename == NULL)) return FALSE;
  if (R_UNLIKELY (data == NULL)) return FALSE;
  if (R_UNLIKELY (size == NULL)) return FALSE;

  if ((fsize = r_fs_get_filesize (filename)) >= 0 &&
      (f = r_file_open (filename, "r")) != NULL) {
    *size = fsize;
    if ((*data = r_malloc (*size)) != NULL) {
      ruint8 * ptr = *data;
      rsize actual;

      ret = TRUE;
      while (fsize > 0 && ret) {
        if ((ret = r_file_read (f, ptr, fsize, &actual) == R_FILE_ERROR_OK)) {
          ptr += actual;
          fsize -= actual;
        }
      }
    } else {
      ret = FALSE;
    }

    r_file_unref (f);
  } else {
    ret = FALSE;
  }

  return ret;
}

rboolean
r_file_write_all (const rchar * filename, rconstpointer data, rsize size)
{
  rboolean ret;
  RFile * f;

  if (R_UNLIKELY (filename == NULL)) return FALSE;
  if (R_UNLIKELY (data == NULL)) return FALSE;

  if ((f = r_file_open (filename, "w")) != NULL) {
    rsize actual;
    const ruint8 * ptr = data;

    ret = TRUE;
    while (size > 0 && ret) {
      if ((ret = r_file_write (f, ptr, size, &actual) == R_FILE_ERROR_OK)) {
        ptr += actual;
        size -= actual;
      }
    }
    r_file_unref (f);
  } else {
    ret = FALSE;
  }

  return ret;
}

ruint
r_file_read_uint (const rchar * filename, ruint def)
{
  RFile * f;

  if ((f = r_file_open (filename, "r")) != NULL) {
    rintmax v = def;
    r_file_scanf (f, "%"RINTMAX_MODIFIER"i", NULL, &v);
    r_file_unref (f);

    def = (ruint)v;
  }

  return def;
}

int
r_file_read_int (const rchar * filename, int def)
{
  RFile * f;

  if ((f = r_file_open (filename, "r")) != NULL) {
    r_file_scanf (f, "%i", NULL, &def);
    r_file_unref (f);
  }

  return def;
}

