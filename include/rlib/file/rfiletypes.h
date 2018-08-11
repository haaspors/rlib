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
#ifndef __R_FILE_TYPES_H__
#define __R_FILE_TYPES_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <stdio.h>

typedef enum {
  R_FILE_ACCESS_NONE  = 0x00,
  R_FILE_EXECUTE      = 0x01,
  R_FILE_WRITE        = 0x02,
  R_FILE_READ         = 0x04,
  R_FILE_RDWR         = (R_FILE_READ | R_FILE_WRITE),
  R_FILE_ACCESS_ALL   = (R_FILE_EXECUTE | R_FILE_RDWR),
} RFileAccess;

typedef struct {
  RFileAccess others;
  RFileAccess group;
  RFileAccess user;
} RFilePermission;

typedef enum {
  R_FILE_CREATE_NEW         = 1,
  R_FILE_CREATE_ALWAYS      = 2,
  R_FILE_OPEN_EXISTING      = 3,
  R_FILE_OPEN_ALWAYS        = 4,
  R_FILE_TRUNCATE_EXISTING  = 5,
} RFileOpenMode;

typedef enum {
  R_FILE_FLAG_NONE          = 0x00,
  R_FILE_FLAG_NONBLOCK      = 0x01,
  R_FILE_FLAG_CLOEXEC       = 0x02,
  R_FILE_FLAG_TEMPORARY     = 0x04,
  R_FILE_FLAG_DIRECTORY     = 0x08,
  R_FILE_FLAG_NO_CACHE      = 0x10,
} RFileFlags;

typedef enum {
  R_FILE_SHARE_EXCLUSIVE  = 0,
  R_FILE_SHARE_READ       = 1,
  R_FILE_SHARE_WRITE      = 2,
  R_FILE_SHARE_DELETE     = 4,
  R_FILE_SHARE_ALL        = (R_FILE_SHARE_READ | R_FILE_SHARE_WRITE | R_FILE_SHARE_DELETE),
} RFileShareMode;

typedef enum {
  R_SEEK_MODE_SET,
  R_SEEK_MODE_CUR,
  R_SEEK_MODE_END
} RSeekMode;

typedef enum {
  R_FILE_ERROR_OK,
  R_FILE_ERROR_AGAIN,
  R_FILE_ERROR_INVAL,
  R_FILE_ERROR_BAD_FILE,
  R_FILE_ERROR_ERROR
} RIOError;


#endif /* __R_FILE_TYPES_H__ */

