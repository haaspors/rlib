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
#ifndef __R_PE_PARSER_H__
#define __R_PE_PARSER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/binfmt/rpecoff.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

typedef struct _RPeParser RPeParser;

R_API RPeParser * r_pe_parser_new (const rchar * filename);
R_API RPeParser * r_pe_parser_new_from_handle (RIOHandle handle);
R_API RPeParser * r_pe_parser_new_from_mem (rpointer mem, rsize size);
#define r_pe_parser_ref    r_ref_ref
#define r_pe_parser_unref  r_ref_unref

R_API ruint16 r_pe_parser_get_machine (const RPeParser * parser);
R_API ruint16 r_pe_parser_get_section_count (const RPeParser * parser);
R_API ruint32 r_pe_parser_get_time_date_stamp (const RPeParser * parser);
R_API ruint32 r_pe_parser_get_ptr_symbol_table (const RPeParser * parser);
R_API ruint32 r_pe_parser_get_symbol_count (const RPeParser * parser);
R_API ruint16 r_pe_parser_get_size_opt_hdr (const RPeParser * parser);
R_API ruint16 r_pe_parser_get_characteristics (const RPeParser * parser);

R_API ruint16 r_pe_parser_get_pe32_magic (RPeParser * parser);
R_API RPeOptHdr * r_pe_parser_get_optional_hdr (RPeParser * parser);
R_API RPe32ImageHdr * r_pe_parser_get_pe32_image_hdr (RPeParser * parser);
R_API RPe32PlusImageHdr * r_pe_parser_get_pe32p_image_hdr (RPeParser * parser);


R_API RPeSectionHdr * r_pe_parser_get_section_hdr_by_idx (RPeParser * parser,
    ruint16 idx);
R_API RPeSectionHdr * r_pe_parser_get_section_hdr_by_data_dir (RPeParser * parser,
    RPeDataDirEntry entry);
R_API RPeSectionHdr * r_pe_parser_get_section_hdr_by_name (RPeParser * parser,
    const rchar * name, rssize nsize);

R_END_DECLS

#endif /* __R_PE_PARSER_H__ */


