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

/**
 * @addtogroup r_binfmt_macho
 *
 * The parser interface in @c rmachoparser.h drives Mach-O traversal
 * via an opaque @ref RMachoParser handle. Open one with
 * @ref r_macho_parser_new (from a path),
 * @ref r_macho_parser_new_from_handle (from an open file
 * descriptor) or @ref r_macho_parser_new_from_mem (from an
 * already-mapped buffer); accessors hand back pointers into the
 * underlying bytes.
 *
 * Mach-O carries either a 32 or 64-bit header followed by a flat
 * list of load commands. Callers iterate the commands by index via
 * @ref r_macho_parser_get_loadcmd, inspect the @c cmd field of each
 * @ref RMachoLoadCmd, and cast through to the concrete @c RMacho*Cmd
 * struct in @c rmacho.h based on the command kind. The
 * @c find_segment / @c find_section helpers cover the most common
 * "give me the @c __TEXT segment / the @c __cstring section" cases
 * directly.
 */

/**
 * @file rlib/binfmt/rmachoparser.h
 * @ingroup r_binfmt_macho
 * @brief Mach-O parser: opaque @c RMachoParser handle plus 32 /
 * 64-bit accessors for the file header, load-command list, and
 * segment / section descriptors.
 */

#include <rlib/binfmt/rmacho.h>

#include <rlib/rref.h>

R_BEGIN_DECLS

/** @addtogroup r_binfmt_macho
 *  @{ */

/** @brief @c TRUE iff @p mem starts with a Mach-O magic number. */
R_API rboolean r_macho_is_valid (rconstpointer mem);
/**
 * @brief Return the on-disk size of the Mach-O image at @p mem, or
 * @c 0 if @p mem doesn't carry a valid Mach-O.
 */
R_API rsize r_macho_calc_size (rconstpointer mem);

/** @brief Opaque, refcounted Mach-O parser. */
typedef struct RMachoParser RMachoParser;

/**
 * @brief Open a Mach-O file by path.
 * @return New parser on success, @c NULL on I/O failure or malformed input.
 */
R_API RMachoParser * r_macho_parser_new (const rchar * filename);
/** @brief Build a parser around an already-open OS file handle. */
R_API RMachoParser * r_macho_parser_new_from_handle (RIOHandle handle);
/**
 * @brief Build a parser around an already-mapped buffer.
 *
 * The parser does not take ownership of @p mem.
 */
R_API RMachoParser * r_macho_parser_new_from_mem (rpointer mem, rsize size);
/** @brief Increment the parser's refcount. */
#define r_macho_parser_ref    r_ref_ref
/** @brief Decrement the parser's refcount; frees when it reaches zero. */
#define r_macho_parser_unref  r_ref_unref

/**
 * @brief Return the file's magic number (@c R_MACHO_MAGIC_32 / @c R_MACHO_MAGIC_64).
 *
 * Use this to decide which of @ref r_macho_parser_get_hdr32 /
 * @ref r_macho_parser_get_hdr64 to call.
 */
R_API ruint32 r_macho_parser_get_magic (RMachoParser * parser);

/** @brief Typed 32-bit header pointer, or @c NULL if the file is 64-bit. */
R_API RMacho32Hdr * r_macho_parser_get_hdr32 (RMachoParser * parser);
/** @brief Typed 64-bit header pointer, or @c NULL if the file is 32-bit. */
R_API RMacho64Hdr * r_macho_parser_get_hdr64 (RMachoParser * parser);

/** @brief Image base virtual address for a 32-bit Mach-O. */
R_API ruint32 r_macho_parser_get_base_addr32 (RMachoParser * parser);
/** @brief Image base virtual address for a 64-bit Mach-O. */
R_API ruint64 r_macho_parser_get_base_addr64 (RMachoParser * parser);

/** @brief Total number of load commands in the file (matches header @c ncmds). */
R_API rsize r_macho_parser_get_loadcmd_count (RMachoParser * parser);
/**
 * @brief Return the @p idx -th load command's base header.
 *
 * Inspect the returned @c cmd field and cast to the concrete
 * @c RMacho*Cmd type in @c rmacho.h.
 */
R_API RMachoLoadCmd * r_macho_parser_get_loadcmd (RMachoParser * parser, ruint16 idx);

/**
 * @brief First 32-bit @c LC_SEGMENT command whose @c segname matches
 * @p name, or @c NULL.
 */
R_API RMachoSegment32Cmd * r_macho_parser_find_segment32 (RMachoParser * parser, const rchar * name, rssize size);
/**
 * @brief First 64-bit @c LC_SEGMENT_64 command whose @c segname
 * matches @p name, or @c NULL.
 */
R_API RMachoSegment64Cmd * r_macho_parser_find_segment64 (RMachoParser * parser, const rchar * name, rssize size);

/** @brief @p idx -th section inside a 32-bit segment command. */
R_API RMachoSection32 * r_macho_parser_get_section32 (RMachoParser * parser, RMachoSegment32Cmd * cmd, ruint16 idx);
/** @brief @p idx -th section inside a 64-bit segment command. */
R_API RMachoSection64 * r_macho_parser_get_section64 (RMachoParser * parser, RMachoSegment64Cmd * cmd, ruint16 idx);
/** @brief First 32-bit section across all segments matching @p name, or @c NULL. */
R_API RMachoSection32 * r_macho_parser_find_section32 (RMachoParser * parser, const rchar * name, rssize size);
/** @brief First 64-bit section across all segments matching @p name, or @c NULL. */
R_API RMachoSection64 * r_macho_parser_find_section64 (RMachoParser * parser, const rchar * name, rssize size);

/**
 * @brief Slice the file bytes a 32-bit segment command refers to.
 * @param parser  The parser.
 * @param sc      Segment command.
 * @param size    Out: payload size in bytes (from @c filesize).
 */
R_API rpointer r_macho_parser_s32cmd_get_data (RMachoParser * parser, RMachoSegment32Cmd * sc, rsize * size);
/**
 * @brief Slice the file bytes a 64-bit segment command refers to.
 * @param parser  The parser.
 * @param sc      Segment command.
 * @param size    Out: payload size in bytes.
 */
R_API rpointer r_macho_parser_s64cmd_get_data (RMachoParser * parser, RMachoSegment64Cmd * sc, rsize * size);

/** @} */

R_END_DECLS

#endif /* __R_MACHO_PARSER_H__ */

