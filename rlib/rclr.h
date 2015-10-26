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
#ifndef __R_CLR_H__
#define __R_CLR_H__

#include <rlib/rtypes.h>

R_BEGIN_DECLS

#define R_CLR_BLACK               0
#define R_CLR_RED                 1
#define R_CLR_GREEN               2
#define R_CLR_YELLOW              3
#define R_CLR_BLUE                4
#define R_CLR_MAGENTA             5
#define R_CLR_CYAN                6
#define R_CLR_WHITE               7
#define R_CLR_EXT                 8
#define R_CLR_DEFAULT             9

#define R_CLR_FG_SHIFT            0
#define R_CLR_BG_SHIFT            4

typedef enum
{
  R_CLR_FG_BLACK                = (R_CLR_BLACK    << R_CLR_FG_SHIFT),
  R_CLR_FG_RED                  = (R_CLR_RED      << R_CLR_FG_SHIFT),
  R_CLR_FG_GREEN                = (R_CLR_GREEN    << R_CLR_FG_SHIFT),
  R_CLR_FG_YELLOW               = (R_CLR_YELLOW   << R_CLR_FG_SHIFT),
  R_CLR_FG_BLUE                 = (R_CLR_BLUE     << R_CLR_FG_SHIFT),
  R_CLR_FG_MAGENTA              = (R_CLR_MAGENTA  << R_CLR_FG_SHIFT),
  R_CLR_FG_CYAN                 = (R_CLR_CYAN     << R_CLR_FG_SHIFT),
  R_CLR_FG_WHITE                = (R_CLR_WHITE    << R_CLR_FG_SHIFT),
  R_CLR_FG_EXT                  = (R_CLR_EXT      << R_CLR_FG_SHIFT),
  R_CLR_FG_DEFAULT              = (R_CLR_DEFAULT  << R_CLR_FG_SHIFT),
  R_CLR_BG_BLACK                = (R_CLR_BLACK    << R_CLR_BG_SHIFT),
  R_CLR_BG_RED                  = (R_CLR_RED      << R_CLR_BG_SHIFT),
  R_CLR_BG_GREEN                = (R_CLR_GREEN    << R_CLR_BG_SHIFT),
  R_CLR_BG_YELLOW               = (R_CLR_YELLOW   << R_CLR_BG_SHIFT),
  R_CLR_BG_BLUE                 = (R_CLR_BLUE     << R_CLR_BG_SHIFT),
  R_CLR_BG_MAGENTA              = (R_CLR_MAGENTA  << R_CLR_BG_SHIFT),
  R_CLR_BG_CYAN                 = (R_CLR_CYAN     << R_CLR_BG_SHIFT),
  R_CLR_BG_WHITE                = (R_CLR_WHITE    << R_CLR_BG_SHIFT),
  R_CLR_BG_EXT                  = (R_CLR_EXT      << R_CLR_BG_SHIFT),
  R_CLR_BG_DEFAULT              = (R_CLR_DEFAULT  << R_CLR_BG_SHIFT),
  /* other formats */
  R_CLR_FMT_BOLD                = 0x0100,
  R_CLR_FMT_UNDERLINE           = 0x0200
} RColorFlags;

#define R_CLR_FG_MASK             0x000F
#define R_CLR_BG_MASK             0x00F0
#define R_CLR_FMT_MASK            0xFF00

R_END_DECLS

#endif /* __R_CLR_H__ */

