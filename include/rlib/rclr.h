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

/**
 * @file rlib/rclr.h
 * @brief ANSI colour and text-attribute bitmask used by @c r_tty and
 * @c r_log.
 */

#include <rlib/rtypes.h>

/**
 * @defgroup r_clr Terminal colour flags
 *
 * @brief Packed foreground / background / attribute bits for terminal
 * styling.
 *
 * Layout (16-bit @ref RColorFlags):
 *
 *  - Bits 0-3: foreground colour (one of @c R_CLR_BLACK ... @c R_CLR_DEFAULT)
 *  - Bits 4-7: background colour
 *  - Bits 8+: format attributes (bold, underline)
 *
 * The @c R_CLR_FG_* and @c R_CLR_BG_* enum values are pre-shifted
 * so they can be OR'd together directly. @ref r_tty_clr_to_str
 * renders these into an ANSI SGR escape sequence.
 *
 * @{
 */

R_BEGIN_DECLS

/** @name Colour codes (pre-shift, share the same numeric values as ANSI SGR 30/40 range)
 *  @{ */
#define R_CLR_BLACK               0   /**< Colour code: black. */
#define R_CLR_RED                 1   /**< Colour code: red. */
#define R_CLR_GREEN               2   /**< Colour code: green. */
#define R_CLR_YELLOW              3   /**< Colour code: yellow. */
#define R_CLR_BLUE                4   /**< Colour code: blue. */
#define R_CLR_MAGENTA             5   /**< Colour code: magenta. */
#define R_CLR_CYAN                6   /**< Colour code: cyan. */
#define R_CLR_WHITE               7   /**< Colour code: white. */
#define R_CLR_EXT                 8   /**< Colour code: extended (38/48 escape follows). */
#define R_CLR_DEFAULT             9   /**< Colour code: terminal default. */
/** @} */

/** @brief Bit shift for the foreground colour nibble. */
#define R_CLR_FG_SHIFT            0
/** @brief Bit shift for the background colour nibble. */
#define R_CLR_BG_SHIFT            4

/**
 * @brief Combined foreground / background / attribute flags.
 *
 * Combine an @c R_CLR_FG_*, an @c R_CLR_BG_* and any @c R_CLR_FMT_*
 * flags with bitwise OR.
 */
typedef enum
{
  R_CLR_FG_BLACK                = (R_CLR_BLACK    << R_CLR_FG_SHIFT), /**< FG black. */
  R_CLR_FG_RED                  = (R_CLR_RED      << R_CLR_FG_SHIFT), /**< FG red. */
  R_CLR_FG_GREEN                = (R_CLR_GREEN    << R_CLR_FG_SHIFT), /**< FG green. */
  R_CLR_FG_YELLOW               = (R_CLR_YELLOW   << R_CLR_FG_SHIFT), /**< FG yellow. */
  R_CLR_FG_BLUE                 = (R_CLR_BLUE     << R_CLR_FG_SHIFT), /**< FG blue. */
  R_CLR_FG_MAGENTA              = (R_CLR_MAGENTA  << R_CLR_FG_SHIFT), /**< FG magenta. */
  R_CLR_FG_CYAN                 = (R_CLR_CYAN     << R_CLR_FG_SHIFT), /**< FG cyan. */
  R_CLR_FG_WHITE                = (R_CLR_WHITE    << R_CLR_FG_SHIFT), /**< FG white. */
  R_CLR_FG_EXT                  = (R_CLR_EXT      << R_CLR_FG_SHIFT), /**< FG extended. */
  R_CLR_FG_DEFAULT              = (R_CLR_DEFAULT  << R_CLR_FG_SHIFT), /**< FG terminal default. */
  R_CLR_BG_BLACK                = (R_CLR_BLACK    << R_CLR_BG_SHIFT), /**< BG black. */
  R_CLR_BG_RED                  = (R_CLR_RED      << R_CLR_BG_SHIFT), /**< BG red. */
  R_CLR_BG_GREEN                = (R_CLR_GREEN    << R_CLR_BG_SHIFT), /**< BG green. */
  R_CLR_BG_YELLOW               = (R_CLR_YELLOW   << R_CLR_BG_SHIFT), /**< BG yellow. */
  R_CLR_BG_BLUE                 = (R_CLR_BLUE     << R_CLR_BG_SHIFT), /**< BG blue. */
  R_CLR_BG_MAGENTA              = (R_CLR_MAGENTA  << R_CLR_BG_SHIFT), /**< BG magenta. */
  R_CLR_BG_CYAN                 = (R_CLR_CYAN     << R_CLR_BG_SHIFT), /**< BG cyan. */
  R_CLR_BG_WHITE                = (R_CLR_WHITE    << R_CLR_BG_SHIFT), /**< BG white. */
  R_CLR_BG_EXT                  = (R_CLR_EXT      << R_CLR_BG_SHIFT), /**< BG extended. */
  R_CLR_BG_DEFAULT              = (R_CLR_DEFAULT  << R_CLR_BG_SHIFT), /**< BG terminal default. */
  R_CLR_FMT_BOLD                = 0x0100,                             /**< Bold attribute. */
  R_CLR_FMT_UNDERLINE           = 0x0200                              /**< Underline attribute. */
} RColorFlags;

/** @brief Mask isolating the FG nibble. */
#define R_CLR_FG_MASK             0x000F
/** @brief Mask isolating the BG nibble. */
#define R_CLR_BG_MASK             0x00F0
/** @brief Mask isolating the FMT bits. */
#define R_CLR_FMT_MASK            0xFF00

R_END_DECLS

/** @} */

#endif /* __R_CLR_H__ */

