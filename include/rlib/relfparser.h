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

#include <rlib/relf.h>


/* FIXME: Add Rel API */
/* FIXME: Figure out how to read non-native endianess formats */
/* FIXME: Add high level API: */
/*    * TODO: Add find symbol by name */
/*    * TODO: Add find corresponding rel/rela section for text/data section */
/* FIXME: Go over ELF chapter 2 loading and dynamic linking */
/*    * TODO: Improve Program header API */
/*    * TODO: Add Note API */
/*    * TODO: Add program loading and dynamic linking API? */


R_BEGIN_DECLS

#define r_elf_is_valid(mem) (r_elf_calc_size (mem) > 0)
R_API rsize r_elf_calc_size (rpointer mem);

typedef struct _RElfParser RElfParser;

R_API RElfParser * r_elf_parser_new (const rchar * filename);
R_API RElfParser * r_elf_parser_new_from_fd (int fd);
R_API RElfParser * r_elf_parser_new_from_mem (rpointer mem, rsize size);
R_API RElfParser * r_elf_parser_ref (RElfParser * parser);
R_API void r_elf_parser_unref (RElfParser * parser);

/* ELF Ident */
R_API ruint8 r_elf_parser_get_class (RElfParser * parser);
R_API ruint8 r_elf_parser_get_data (RElfParser * parser);
R_API ruint8 r_elf_parser_get_version (RElfParser * parser);
R_API ruint8 r_elf_parser_get_osabi (RElfParser * parser);
R_API ruint8 r_elf_parser_get_abi_version (RElfParser * parser);

/* ELF Header */
R_API rpointer r_elf_parser_get_elf_header (RElfParser * parser);
R_API RElf32EHdr * r_elf_parser_get_ehdr32 (RElfParser * parser);
R_API RElf64EHdr * r_elf_parser_get_ehdr64 (RElfParser * parser);

/* ELF Program Header */
R_API ruint16 r_elf_parser_prg_header_count (RElfParser * parser);
R_API rpointer r_elf_parser_get_prg_header_table (RElfParser * parser);
R_API RElf32PHdr * r_elf_parser_get_phdr32 (RElfParser * parser, ruint16 idx);
R_API RElf64PHdr * r_elf_parser_get_phdr64 (RElfParser * parser, ruint16 idx);

R_API ruint32 r_elf_parser_get_base_addr32 (RElfParser * parser);
R_API ruint64 r_elf_parser_get_base_addr64 (RElfParser * parser);

/* ELF Section Header */
R_API ruint16 r_elf_parser_section_header_count (RElfParser * parser);
R_API rpointer r_elf_parser_get_section_header_table (RElfParser * parser);
R_API RElf32SHdr * r_elf_parser_get_shdr32 (RElfParser * parser, ruint16 idx);
R_API RElf64SHdr * r_elf_parser_get_shdr64 (RElfParser * parser, ruint16 idx);
R_API RElf32SHdr * r_elf_parser_find_shdr32 (RElfParser * parser, const rchar * name, rssize size);
R_API RElf64SHdr * r_elf_parser_find_shdr64 (RElfParser * parser, const rchar * name, rssize size);
R_API rchar * r_elf_parser_shdr32_get_name (RElfParser * parser, RElf32SHdr * shdr);
R_API rchar * r_elf_parser_shdr64_get_name (RElfParser * parser, RElf64SHdr * shdr);
R_API rpointer r_elf_parser_shdr32_get_data (RElfParser * parser, RElf32SHdr * shdr, rsize * size);
R_API rpointer r_elf_parser_shdr64_get_data (RElfParser * parser, RElf64SHdr * shdr, rsize * size);
#define r_elf_parser_shdr32_get_data_by_idx(parser, idx, size)                \
  r_elf_parser_shdr32_get_data (parser, r_elf_parser_get_shdr32 (parser, idx), size)
#define r_elf_parser_shdr64_get_data_by_idx(parser, idx, size)                \
  r_elf_parser_shdr64_get_data (parser, r_elf_parser_get_shdr64 (parser, idx), size)
R_API rpointer r_elf_parser_find_section_data (RElfParser * parser,
    const rchar * name, rssize size, rsize * secsize);

/* ELF Section Header - string table */
R_API ruint16 r_elf_parser_strtbl_idx (RElfParser * parser);
R_API RElf32SHdr * r_elf_parser_get_strtbl32 (RElfParser * parser);
R_API RElf64SHdr * r_elf_parser_get_strtbl64 (RElfParser * parser);

R_API rchar * r_elf_parser_strtbl_get_str (RElfParser * parser, ruint32 idx);
R_API rchar * r_elf_parser_strtbl32_get_str (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);
R_API rchar * r_elf_parser_strtbl64_get_str (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);

/* ELF Section Header - symbol table */
R_API ruint32 r_elf_parser_symtbl32_sym_count (RElfParser * parser, RElf32SHdr * shdr);
R_API ruint64 r_elf_parser_symtbl64_sym_count (RElfParser * parser, RElf64SHdr * shdr);
R_API RElf32Sym * r_elf_parser_symtbl32_get_sym (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);
R_API RElf64Sym * r_elf_parser_symtbl64_get_sym (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);

/* ELF Symbol table entry */
R_API rchar * r_elf_parser_symtbl32_sym32_get_name (RElfParser * parser, RElf32SHdr * shdr, RElf32Sym * sym);
R_API rchar * r_elf_parser_symtbl64_sym64_get_name (RElfParser * parser, RElf64SHdr * shdr, RElf64Sym * sym);
R_API rpointer r_elf_parser_symtbl32_sym32_get_data (RElfParser * parser, RElf32SHdr * shdr, RElf32Sym * sym, rsize * size);
R_API rpointer r_elf_parser_symtbl64_sym64_get_data (RElfParser * parser, RElf64SHdr * shdr, RElf64Sym * sym, rsize * size);

/* ELF Section Header - relocation */
/*R_API ruint32 r_elf_parser_reltbl32_rel_count (RElfParser * parser, RElf32SHdr * shdr);*/
/*R_API ruint64 r_elf_parser_reltbl64_rel_count (RElfParser * parser, RElf64SHdr * shdr);*/
/*R_API RElf32Rel * r_elf_parser_reltbl32_get_rel (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);*/
/*R_API RElf64Rel * r_elf_parser_reltbl64_get_rel (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);*/
/*R_API RElf32Sym * r_elf_parser_rel32_get_sym (RElfParser * parser, RElf32SHdr * shdr, RElf32Rel * rel, RElf32SHdr ** symtbl)*/;
/*R_API RElf64Sym * r_elf_parser_rel64_get_sym (RElfParser * parser, RElf64SHdr * shdr, RElf64Rel * rel, RElf64SHdr ** symtbl)*/;
/*R_API ruint32 * r_elf_parser_rel32_get_dst (RElfParser * parser, RElf32SHdr * shdr, RElf32Rel * rel)*/;
/*R_API ruint64 * r_elf_parser_rel64_get_dst (RElfParser * parser, RElf64SHdr * shdr, RElf64Rel * rel)*/;

R_API ruint32 r_elf_parser_relatbl32_rela_count (RElfParser * parser, RElf32SHdr * shdr);
R_API ruint64 r_elf_parser_relatbl64_rela_count (RElfParser * parser, RElf64SHdr * shdr);
R_API RElf32Rela * r_elf_parser_relatbl32_get_rela (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx);
R_API RElf64Rela * r_elf_parser_relatbl64_get_rela (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx);
R_API RElf32Sym * r_elf_parser_rela32_get_sym (RElfParser * parser, RElf32SHdr * shdr, RElf32Rela * rela, RElf32SHdr ** symtbl);
R_API RElf64Sym * r_elf_parser_rela64_get_sym (RElfParser * parser, RElf64SHdr * shdr, RElf64Rela * rela, RElf64SHdr ** symtbl);
R_API ruint32 * r_elf_parser_rela32_get_dst (RElfParser * parser, RElf32SHdr * shdr, RElf32Rela * rela);
R_API ruint64 * r_elf_parser_rela64_get_dst (RElfParser * parser, RElf64SHdr * shdr, RElf64Rela * rela);

R_END_DECLS

#endif /* __R_ELF_PARSER_H__ */

