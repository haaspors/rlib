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
#ifndef __R_FILE_PRIV_H__
#define __R_FILE_PRIV_H__

#if !defined(RLIB_COMPILATION)
#error "rfile-private.h should only be used internally in rlib!"
#endif

#include <rlib/file/rfiletypes.h>

R_BEGIN_DECLS

static inline int
r_file_seek_mode_to_whence (RSeekMode mode)
{
  switch (mode) {
    case R_SEEK_MODE_CUR:
      return SEEK_CUR;
    case R_SEEK_MODE_SET:
      return SEEK_SET;
    case R_SEEK_MODE_END:
      return SEEK_END;
    default:
      return -1;
  }
}


R_END_DECLS

#endif /* __R_FILE_PRIV_H__ */

