/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_MACHO_PARSER_H__
#define __R_MACHO_PARSER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/binfmt/rmacho.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

R_API rboolean r_macho_is_valid (rconstpointer mem);
R_API rsize r_macho_calc_size (rconstpointer mem);

typedef struct _RMachoParser RMachoParser;

R_API RMachoParser * r_macho_parser_new (const rchar * filename);
R_API RMachoParser * r_macho_parser_new_from_fd (int fd);
R_API RMachoParser * r_macho_parser_new_from_mem (rpointer mem, rsize size);
#define r_macho_parser_ref    r_ref_ref
#define r_macho_parser_unref  r_ref_unref

R_API ruint32 r_macho_parser_get_magic (RMachoParser * parser);

/* Macho Header */
R_API RMacho32Hdr * r_macho_parser_get_hdr32 (RMachoParser * parser);
R_API RMacho64Hdr * r_macho_parser_get_hdr64 (RMachoParser * parser);

R_API ruint32 r_macho_parser_get_base_addr32 (RMachoParser * parser);
R_API ruint64 r_macho_parser_get_base_addr64 (RMachoParser * parser);

R_API rsize r_macho_parser_get_loadcmd_count (RMachoParser * parser);
R_API RMachoLoadCmd * r_macho_parser_get_loadcmd (RMachoParser * parser, ruint16 idx);

R_API RMachoSegment32Cmd * r_macho_parser_find_segment32 (RMachoParser * parser, const rchar * name, rssize size);
R_API RMachoSegment64Cmd * r_macho_parser_find_segment64 (RMachoParser * parser, const rchar * name, rssize size);

R_API RMachoSection32 * r_macho_parser_get_section32 (RMachoParser * parser, RMachoSegment32Cmd * cmd, ruint16 idx);
R_API RMachoSection64 * r_macho_parser_get_section64 (RMachoParser * parser, RMachoSegment64Cmd * cmd, ruint16 idx);
R_API RMachoSection32 * r_macho_parser_find_section32 (RMachoParser * parser, const rchar * name, rssize size);
R_API RMachoSection64 * r_macho_parser_find_section64 (RMachoParser * parser, const rchar * name, rssize size);

R_API rpointer r_macho_parser_s32cmd_get_data (RMachoParser * parser, RMachoSegment32Cmd * sc, rsize * size);
R_API rpointer r_macho_parser_s64cmd_get_data (RMachoParser * parser, RMachoSegment64Cmd * sc, rsize * size);

R_END_DECLS

#endif /* __R_MACHO_PARSER_H__ */

