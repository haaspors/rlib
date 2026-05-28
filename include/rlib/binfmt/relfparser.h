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
#ifndef __R_ELF_PARSER_H__
#define __R_ELF_PARSER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @addtogroup r_binfmt_elf
 *
 * The parser interface in @c relfparser.h drives ELF traversal via
 * an opaque @ref RElfParser handle. Open one with
 * @ref r_elf_parser_new (from a path),
 * @ref r_elf_parser_new_from_handle (from an open file descriptor)
 * or @ref r_elf_parser_new_from_mem (from an already-mapped
 * buffer); accessors hand back pointers into the underlying bytes
 * sized to the file's ELF class (32-bit vs 64-bit variants live
 * side by side with @c _32 / @c _64 suffixes).
 *
 * Callers pick the class either by inspecting the ELF identifier
 * (@ref r_elf_parser_get_class returns @c R_ELF_CLASS32 or
 * @c R_ELF_CLASS64) or by passing the file through one of the
 * sized accessor families and observing @c NULL when the class
 * doesn't match.
 */

/**
 * @file rlib/binfmt/relfparser.h
 * @ingroup r_binfmt_elf
 * @brief ELF parser: opaque @c RElfParser handle plus 32 / 64-bit
 * accessors for the file header, program / section headers, string
 * and symbol tables, and RELA-style relocations.
 */

#include <rlib/binfmt/relf.h>


/* FIXME: Add Rel API */
/* FIXME: Figure out how to read non-native endianess formats */
/* FIXME: Add high level API: */
/*    * TODO: Add find corresponding rel/rela section for text/data section */
/* FIXME: Go over ELF chapter 2 loading and dynamic linking */
/*    * TODO: Improve Program header API */
/*    * TODO: Add Note API */
/*    * TODO: Add program loading and dynamic linking API? */


R_BEGIN_DECLS

/** @addtogroup r_binfmt_elf
 *  @{ */

/**
 * @brief @c TRUE iff @p mem starts with a valid ELF identifier and
 * the header it carries is self-consistent.
 */
#define r_elf_is_valid(mem) (r_elf_calc_size (mem) > 0)
/**
 * @brief Return the on-disk size of the ELF image at @p mem, or @c 0
 * if @p mem doesn't carry a valid ELF.
 *
 * Computed from the section table extent; useful for slicing a
 * blob known to contain one ELF before passing it to
 * @ref r_elf_parser_new_from_mem.
 */
R_API rsize r_elf_calc_size (rpointer mem);

/** @brief Opaque, refcounted ELF parser. */
typedef struct RElfParser RElfParser;

/**
 * @brief Open an ELF file by path.
 * @return New parser on success, @c NULL on I/O failure or malformed input.
 */
R_API RElfParser * r_elf_parser_new (const rchar * filename);
/** @brief Build a parser around an already-open OS file handle. */
R_API RElfParser * r_elf_parser_new_from_handle (RIOHandle handle);
/**
 * @brief Build a parser around an already-mapped buffer.
 *
 * The parser does not take ownership of @p mem; callers keep the
 * mapping alive for the parser's lifetime.
 */
R_API RElfParser * r_elf_parser_new_from_mem (rpointer mem, rsize size);
/** @brief Increment the parser's refcount. */
R_API RElfParser * r_elf_parser_ref (RElfParser * parser);
/** @brief Decrement the parser's refcount; frees and unmaps when it reaches zero. */
R_API void r_elf_parser_unref (RElfParser * parser);

/** @brief Return @c ident[R_ELF_IDX_CLASS] (@c R_ELF_CLASS32 / @c R_ELF_CLASS64). */
R_API ruint8 r_elf_parser_get_class (RElfParser * parser);
/** @brief Return @c ident[R_ELF_IDX_DATA] (@c R_ELF_DATA2LSB / @c R_ELF_DATA2MSB). */
R_API ruint8 r_elf_parser_get_data (RElfParser * parser);
/** @brief Return @c ident[R_ELF_IDX_VERSION] (typically @c R_ELF_VER_CURRENT). */
R_API ruint8 r_elf_parser_get_version (RElfParser * parser);
/** @brief Return @c ident[R_ELF_IDX_OSABI] (System V, Linux, FreeBSD, ...). */
R_API ruint8 r_elf_parser_get_osabi (RElfParser * parser);
/** @brief Return @c ident[R_ELF_IDX_ABIVERSION]. */
R_API ruint8 r_elf_parser_get_abi_version (RElfParser * parser);

/**
 * @brief Return a pointer to the raw ELF header bytes.
 *
 * Cast through @ref RElf32EHdr or @ref RElf64EHdr according to
 * @ref r_elf_parser_get_class; the typed helpers below do that for
 * you.
 */
R_API rpointer r_elf_parser_get_elf_header (RElfParser * parser);
/** @brief Typed ELF32 header pointer, or @c NULL if the file is ELF64. */
R_API RElf32EHdr * r_elf_parser_get_ehdr32 (RElfParser * parser);
/** @brief Typed ELF64 header pointer, or @c NULL if the file is ELF32. */
R_API RElf64EHdr * r_elf_parser_get_ehdr64 (RElfParser * parser);

/** @brief Number of program-header entries (@c e_phnum). */
R_API ruint16 r_elf_parser_prg_header_count (RElfParser * parser);
/** @brief Pointer to the start of the program-header table. */
R_API rpointer r_elf_parser_get_prg_header_table (RElfParser * parser);
/** @brief Pointer to the @p idx -th ELF32 program header. */
R_API RElf32PHdr * r_elf_parser_get_phdr32 (RElfParser * parser, ruint16 idx);
/** @brief Pointer to the @p idx -th ELF64 program header. */
R_API RElf64PHdr * r_elf_parser_get_phdr64 (RElfParser * parser, ruint16 idx);

/** @brief Lowest @c PT_LOAD virtual address (image base) for an ELF32. */
R_API ruint32 r_elf_parser_get_base_addr32 (RElfParser * parser);
/** @brief Lowest @c PT_LOAD virtual address (image base) for an ELF64. */
R_API ruint64 r_elf_parser_get_base_addr64 (RElfParser * parser);

/** @brief Number of section-header entries (@c e_shnum). */
R_API ruint16 r_elf_parser_section_header_count (RElfParser * parser);
/** @brief Pointer to the start of the section-header table. */
R_API rpointer r_elf_parser_get_section_header_table (RElfParser * parser);
/** @brief Pointer to the @p idx -th ELF32 section header. */
R_API RElf32SHdr * r_elf_parser_get_shdr32 (RElfParser * parser, ruint16 idx);
/** @brief Pointer to the @p idx -th ELF64 section header. */
R_API RElf64SHdr * r_elf_parser_get_shdr64 (RElfParser * parser, ruint16 idx);
/** @brief First ELF32 section header whose name matches @p name, or @c NULL. */
R_API RElf32SHdr * r_elf_parser_find_shdr32 (RElfParser * parser, const rchar * name, rssize size);
/** @brief First ELF64 section header whose name matches @p name, or @c NULL. */
R_API RElf64SHdr * r_elf_parser_find_shdr64 (RElfParser * parser, const rchar * name, rssize size);
/** @brief First ELF32 section header of the given @c sh_type, or @c NULL. */
R_API RElf32SHdr * r_elf_parser_find_shdr32_by_type (RElfParser * parser, ruint32 type);
/** @brief First ELF64 section header of the given @c sh_type, or @c NULL. */
R_API RElf64SHdr * r_elf_parser_find_shdr64_by_type (RElfParser * parser, ruint32 type);
/** @brief Resolved section name for an ELF32 section header. */
R_API rchar * r_elf_parser_shdr32_get_name (RElfParser * parser, RElf32SHdr * shdr);
/** @brief Resolved section name for an ELF64 section header. */
R_API rchar * r_elf_parser_shdr64_get_name (RElfParser * parser, RElf64SHdr * shdr);
/**
 * @brief Slice the ELF32 section payload out of the image.
 * @param parser  The parser.
 * @param shdr    Section header naming the bytes to slice.
 * @param size    Out: section payload size in bytes.
 */
R_API rpointer r_elf_parser_shdr32_get_data (RElfParser * parser, RElf32SHdr * shdr, rsize * size);
/**
 * @brief Slice the ELF64 section payload out of the image.
 * @param parser  The parser.
 * @param shdr    Section header naming the bytes to slice.
 * @param size    Out: section payload size in bytes.
 */
R_API rpointer r_elf_parser_shdr64_get_data (RElfParser * parser, RElf64SHdr * shdr, rsize * size);
/** @brief Convenience: ELF32 section payload by index. */
#define r_elf_parser_shdr32_get_data_by_idx(parser, idx, size)                \
  r_elf_parser_shdr32_get_data (parser, r_elf_parser_get_shdr32 (parser, idx), size)
/** @brief Convenience: ELF64 section payload by index. */
#define r_elf_parser_shdr64_get_data_by_idx(parser, idx, size)                \
  r_elf_parser_shdr64_get_data (parser, r_elf_parser_get_shdr64 (parser, idx), size)
/**
 * @brief Look up a section by name and return its payload directly.
 *
 * Class-agnostic wrapper that dispatches to the right
 * @ref r_elf_parser_find_shdr32 / @ref r_elf_parser_find_shdr64 +
 * @ref r_elf_parser_shdr32_get_data / @ref r_elf_parser_shdr64_get_data.
 *
 * @param parser   The parser.
 * @param name     Section name (NUL-terminated or first @p size bytes).
 * @param size     Length of @p name, or @c -1 for NUL-terminated.
 * @param secsize  Out: section payload size in bytes.
 */
R_API rpointer r_elf_parser_find_section_data (RElfParser * parser,
    const rchar * name, rssize size, rsize * secsize);

/** @brief Section-table index of the section-header string table (@c shstrndx). */
R_API ruint16 r_elf_parser_strtbl_idx (RElfParser * parser);
/** @brief ELF32 section header of the section-header string table. */
R_API RElf32SHdr * r_elf_parser_get_strtbl32 (RElfParser * parser);
/** @brief ELF64 section header of the section-header string table. */
R_API RElf64SHdr * r_elf_parser_get_strtbl64 (RElfParser * parser);

/** @brief String at offset @p idx in the section-header string table. */
R_API rchar * r_elf_parser_strtbl_get_str (RElfParser * parser, ruint32 idx);
/** @brief String at offset @p idx in an arbitrary ELF32 string-table section. */
R_API rchar * r_elf_parser_strtbl32_get_str (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);
/** @brief String at offset @p idx in an arbitrary ELF64 string-table section. */
R_API rchar * r_elf_parser_strtbl64_get_str (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);

/** @brief Number of symbol-table entries in an ELF32 SYMTAB / DYNSYM section. */
R_API ruint32 r_elf_parser_symtbl32_sym_count (RElfParser * parser, RElf32SHdr * shdr);
/** @brief Number of symbol-table entries in an ELF64 SYMTAB / DYNSYM section. */
R_API ruint64 r_elf_parser_symtbl64_sym_count (RElfParser * parser, RElf64SHdr * shdr);
/** @brief ELF32 symbol at index @p idx within @p shdr. */
R_API RElf32Sym * r_elf_parser_symtbl32_get_sym (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);
/** @brief ELF64 symbol at index @p idx within @p shdr. */
R_API RElf64Sym * r_elf_parser_symtbl64_get_sym (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);

/** @brief Resolved name of an ELF32 symbol (via the SYMTAB section's linked string table). */
R_API rchar * r_elf_parser_symtbl32_sym32_get_name (RElfParser * parser, RElf32SHdr * shdr, RElf32Sym * sym);
/** @brief Resolved name of an ELF64 symbol. */
R_API rchar * r_elf_parser_symtbl64_sym64_get_name (RElfParser * parser, RElf64SHdr * shdr, RElf64Sym * sym);
/**
 * @brief Slice the bytes an ELF32 symbol refers to (variable / function
 * body, depending on @c st_shndx) out of the image.
 * @param parser  The parser.
 * @param shdr    SYMTAB / DYNSYM section @p sym lives in.
 * @param sym     Symbol whose backing bytes to return.
 * @param size    Out: payload size, taken from the symbol's @c st_size.
 */
R_API rpointer r_elf_parser_symtbl32_sym32_get_data (RElfParser * parser, RElf32SHdr * shdr, RElf32Sym * sym, rsize * size);
/**
 * @brief Slice the bytes an ELF64 symbol refers to out of the image.
 * @param parser  The parser.
 * @param shdr    SYMTAB / DYNSYM section @p sym lives in.
 * @param sym     Symbol whose backing bytes to return.
 * @param size    Out: payload size from @c st_size.
 */
R_API rpointer r_elf_parser_symtbl64_sym64_get_data (RElfParser * parser, RElf64SHdr * shdr, RElf64Sym * sym, rsize * size);
/** @brief First ELF32 symbol whose name matches @p name, or @c NULL. */
R_API RElf32Sym * r_elf_parser_symtbl32_find_sym_by_name (RElfParser * parser,
    RElf32SHdr * shdr, const rchar * name, rssize size);
/** @brief First ELF64 symbol whose name matches @p name, or @c NULL. */
R_API RElf64Sym * r_elf_parser_symtbl64_find_sym_by_name (RElfParser * parser,
    RElf64SHdr * shdr, const rchar * name, rssize size);

/* ELF Section Header - relocation */
/*R_API ruint32 r_elf_parser_reltbl32_rel_count (RElfParser * parser, RElf32SHdr * shdr);*/
/*R_API ruint64 r_elf_parser_reltbl64_rel_count (RElfParser * parser, RElf64SHdr * shdr);*/
/*R_API RElf32Rel * r_elf_parser_reltbl32_get_rel (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);*/
/*R_API RElf64Rel * r_elf_parser_reltbl64_get_rel (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);*/
/*R_API RElf32Sym * r_elf_parser_rel32_get_sym (RElfParser * parser, RElf32SHdr * shdr, RElf32Rel * rel, RElf32SHdr ** symtbl)*/;
/*R_API RElf64Sym * r_elf_parser_rel64_get_sym (RElfParser * parser, RElf64SHdr * shdr, RElf64Rel * rel, RElf64SHdr ** symtbl)*/;
/*R_API ruint32 * r_elf_parser_rel32_get_dst (RElfParser * parser, RElf32SHdr * shdr, RElf32Rel * rel)*/;
/*R_API ruint64 * r_elf_parser_rel64_get_dst (RElfParser * parser, RElf64SHdr * shdr, RElf64Rel * rel)*/;

/** @brief Number of relocations in an ELF32 RELA section. */
R_API ruint32 r_elf_parser_relatbl32_rela_count (RElfParser * parser, RElf32SHdr * shdr);
/** @brief Number of relocations in an ELF64 RELA section. */
R_API ruint64 r_elf_parser_relatbl64_rela_count (RElfParser * parser, RElf64SHdr * shdr);
/** @brief ELF32 relocation entry at @p idx within a RELA section. */
R_API RElf32Rela * r_elf_parser_relatbl32_get_rela (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);
/** @brief ELF64 relocation entry at @p idx within a RELA section. */
R_API RElf64Rela * r_elf_parser_relatbl64_get_rela (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);
/**
 * @brief Symbol referred to by an ELF32 RELA entry.
 * @param parser  The parser.
 * @param shdr    RELA section containing @p rela.
 * @param rela    The relocation entry.
 * @param symtbl  Out: section header of the symbol table @p shdr is
 *                linked to. Pass @c NULL to discard.
 */
R_API RElf32Sym * r_elf_parser_rela32_get_sym (RElfParser * parser, RElf32SHdr * shdr, RElf32Rela * rela, RElf32SHdr ** symtbl);
/**
 * @brief Symbol referred to by an ELF64 RELA entry.
 * @param parser  The parser.
 * @param shdr    RELA section containing @p rela.
 * @param rela    The relocation entry.
 * @param symtbl  Out: linked symbol-table section.
 */
R_API RElf64Sym * r_elf_parser_rela64_get_sym (RElfParser * parser, RElf64SHdr * shdr, RElf64Rela * rela, RElf64SHdr ** symtbl);
/**
 * @brief Pointer to the ELF32 location patched by a RELA entry
 * (i.e. the byte position the relocation rewrites).
 */
R_API ruint32 * r_elf_parser_rela32_get_dst (RElfParser * parser, RElf32SHdr * shdr, RElf32Rela * rela);
/** @brief Pointer to the ELF64 location patched by a RELA entry. */
R_API ruint64 * r_elf_parser_rela64_get_dst (RElfParser * parser, RElf64SHdr * shdr, RElf64Rela * rela);

/** @} */

R_END_DECLS

#endif /* __R_ELF_PARSER_H__ */

