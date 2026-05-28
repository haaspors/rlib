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

/**
 * @addtogroup r_binfmt_pe
 *
 * The parser interface in @c rpeparser.h drives PE / COFF
 * traversal via an opaque @ref RPeParser handle. Open one with
 * @ref r_pe_parser_new (from a path),
 * @ref r_pe_parser_new_from_handle (from an open file descriptor)
 * or @ref r_pe_parser_new_from_mem (from an already-mapped
 * buffer); accessors hand back pointers into the underlying bytes.
 *
 * After construction, callers typically:
 *
 *   - Pull the COFF header fields (@ref r_pe_parser_get_machine,
 *     @ref r_pe_parser_get_characteristics, ...).
 *   - Inspect the optional header via
 *     @ref r_pe_parser_get_pe32_magic and the typed
 *     @ref r_pe_parser_get_pe32_image_hdr /
 *     @ref r_pe_parser_get_pe32p_image_hdr.
 *   - Walk the section table by index, by name, or by following a
 *     data-directory entry (import directory, resource directory,
 *     ...).
 */

/**
 * @file rlib/binfmt/rpeparser.h
 * @ingroup r_binfmt_pe
 * @brief PE / COFF parser: opaque @c RPeParser handle plus
 * accessors for the COFF header, PE32 / PE32+ optional header, and
 * section table.
 */

#include <rlib/binfmt/rpe.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

/** @addtogroup r_binfmt_pe
 *  @{ */

/** @brief Opaque, refcounted PE / COFF parser. */
typedef struct RPeParser RPeParser;

/**
 * @brief Open a PE / COFF file by path.
 * @return New parser on success, @c NULL on I/O failure or malformed input.
 */
R_API RPeParser * r_pe_parser_new (const rchar * filename);
/** @brief Build a parser around an already-open OS file handle. */
R_API RPeParser * r_pe_parser_new_from_handle (RIOHandle handle);
/**
 * @brief Build a parser around an already-mapped buffer.
 *
 * The parser does not take ownership of @p mem.
 */
R_API RPeParser * r_pe_parser_new_from_mem (rpointer mem, rsize size);
/** @brief Increment the parser's refcount. */
#define r_pe_parser_ref    r_ref_ref
/** @brief Decrement the parser's refcount; frees when it reaches zero. */
#define r_pe_parser_unref  r_ref_unref

/** @brief COFF @c machine (target architecture) from the file header. */
R_API ruint16 r_pe_parser_get_machine (const RPeParser * parser);
/** @brief COFF @c NumberOfSections from the file header. */
R_API ruint16 r_pe_parser_get_section_count (const RPeParser * parser);
/** @brief COFF @c TimeDateStamp (Unix-style build time) from the file header. */
R_API ruint32 r_pe_parser_get_time_date_stamp (const RPeParser * parser);
/** @brief COFF @c PointerToSymbolTable from the file header. */
R_API ruint32 r_pe_parser_get_ptr_symbol_table (const RPeParser * parser);
/** @brief COFF @c NumberOfSymbols from the file header. */
R_API ruint32 r_pe_parser_get_symbol_count (const RPeParser * parser);
/** @brief COFF @c SizeOfOptionalHeader from the file header. */
R_API ruint16 r_pe_parser_get_size_opt_hdr (const RPeParser * parser);
/** @brief COFF @c Characteristics bitmask (@c R_PE_FILE_*) from the file header. */
R_API ruint16 r_pe_parser_get_characteristics (const RPeParser * parser);

/**
 * @brief Optional-header magic value (@c R_PE_PE32_MAGIC or
 * @c R_PE_PE32PLUS_MAGIC).
 *
 * Use this to decide which of the two image-header accessors below
 * to call.
 */
R_API ruint16 r_pe_parser_get_pe32_magic (RPeParser * parser);
/** @brief Pointer to the common prefix of the optional header. */
R_API RPeOptHdr * r_pe_parser_get_optional_hdr (RPeParser * parser);
/** @brief Typed PE32 image header pointer, or @c NULL if the file is PE32+. */
R_API RPe32ImageHdr * r_pe_parser_get_pe32_image_hdr (RPeParser * parser);
/** @brief Typed PE32+ image header pointer, or @c NULL if the file is PE32. */
R_API RPe32PlusImageHdr * r_pe_parser_get_pe32p_image_hdr (RPeParser * parser);


/** @brief Section header at index @p idx in the section table. */
R_API RPeSectionHdr * r_pe_parser_get_section_hdr_by_idx (RPeParser * parser,
    ruint16 idx);
/**
 * @brief Section header pointed at by the data-directory entry
 * @p entry (the section whose RVA range covers the directory's RVA).
 */
R_API RPeSectionHdr * r_pe_parser_get_section_hdr_by_data_dir (RPeParser * parser,
    RPeDataDirEntry entry);
/**
 * @brief First section whose name matches @p name (e.g. @c ".text",
 * @c ".rdata"), or @c NULL.
 */
R_API RPeSectionHdr * r_pe_parser_get_section_hdr_by_name (RPeParser * parser,
    const rchar * name, rssize nsize);

/** @} */

R_END_DECLS

#endif /* __R_PE_PARSER_H__ */


