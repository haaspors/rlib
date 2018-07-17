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

