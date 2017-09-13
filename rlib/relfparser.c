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

#include "config.h"

#include <rlib/relfparser.h>
#include <rlib/ratomic.h>
#include <rlib/rmem.h>
#include <rlib/rmemfile.h>
#include <rlib/rstr.h>

#define RELF32_IDX  0
#define RELF64_IDX  1

struct _RElfParser {
  rauint refcount;
  RMemFile * file;
  rpointer mem;
  rsize size;
  int elfidx;
};

rsize
r_elf_calc_size (rpointer mem)
{
  ruint8 * ident = mem;
  if (ident[R_ELF_IDX_MAG0] == R_ELF_MAG0 && ident[R_ELF_IDX_MAG1] == R_ELF_MAG1 &&
      ident[R_ELF_IDX_MAG2] == R_ELF_MAG2 && ident[R_ELF_IDX_MAG3] == R_ELF_MAG3) {
    rsize phend, shend;

    switch (ident[R_ELF_IDX_CLASS]) {
      case R_ELF_CLASS32:
        {
          RElf32EHdr * hdr = mem;
          phend = hdr->phoff + hdr->phentsize * hdr->phnum;
          shend = hdr->shoff + hdr->shentsize * hdr->shnum;
        }
        break;
      case R_ELF_CLASS64:
        {
          RElf64EHdr * hdr = mem;
          phend = hdr->phoff + hdr->phentsize * hdr->phnum;
          shend = hdr->shoff + hdr->shentsize * hdr->shnum;
        }
        break;
      case R_ELF_CLASSNONE:
      default:
       goto beach;
    }

    return MAX (phend, shend);
  }

beach:
  return 0;
}


static int
_check_elf32_header (RElf32EHdr * hdr, rsize size)
{
  rsize phsize, shsize;

  if (R_UNLIKELY (size < sizeof (RElf32EHdr) || size < hdr->ehsize))
    return -1;

  phsize = hdr->phentsize * hdr->phnum;
  shsize = hdr->shentsize * hdr->shnum;
  if (size < hdr->ehsize + phsize + shsize)
    return -1;
  if (size < hdr->phoff + phsize || size < hdr->shoff + shsize)
    return -1;

  return RELF32_IDX;
}

static int
_check_elf64_header (RElf64EHdr * hdr, rsize size)
{
  rsize phsize, shsize;

  if (R_UNLIKELY (size < sizeof (RElf64EHdr) || size < hdr->ehsize))
    return -1;

  phsize = hdr->phentsize * hdr->phnum;
  shsize = hdr->shentsize * hdr->shnum;
  if (size < hdr->ehsize + phsize + shsize)
    return -1;
  if (size < hdr->phoff + phsize || size < hdr->shoff + shsize)
    return -1;

  return RELF64_IDX;
}

static int
_check_elf_header (rpointer mem, rsize size)
{
  if (size >= R_ELF_NIDENT && mem != NULL) {
    ruint8 * ident = mem;
    if (ident[R_ELF_IDX_MAG0] == R_ELF_MAG0 && ident[R_ELF_IDX_MAG1] == R_ELF_MAG1 &&
        ident[R_ELF_IDX_MAG2] == R_ELF_MAG2 && ident[R_ELF_IDX_MAG3] == R_ELF_MAG3) {
      switch (ident[R_ELF_IDX_CLASS]) {
        case R_ELF_CLASS32:
          return _check_elf32_header (mem, size);
        case R_ELF_CLASS64:
          return _check_elf64_header (mem, size);
        case R_ELF_CLASSNONE:
        default:
         break;;
      }
    }
  }

  return -1;
}

static RElfParser *
r_elf_parser_new_from_mem_file (RMemFile * file)
{
  RElfParser * ret = NULL;
  int elfidx;

  if (file != NULL) {
    rpointer mem = r_mem_file_get_mem (file);
    rsize size = r_mem_file_get_size (file);

    if ((elfidx = _check_elf_header (mem, size)) >= 0) {
      if (R_LIKELY (ret = r_mem_new (RElfParser))) {
        r_atomic_uint_store (&ret->refcount, 1);
        ret->file = r_mem_file_ref (file);
        ret->mem = mem;
        ret->size = size;
        ret->elfidx = elfidx;
      }
    }
  }

  return ret;
}

RElfParser *
r_elf_parser_new (const rchar * filename)
{
  RElfParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new (filename, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
  if (file != NULL) {
    ret = r_elf_parser_new_from_mem_file (file);
    r_mem_file_unref (file);
  }

  return ret;
}

RElfParser *
r_elf_parser_new_from_fd (int fd)
{
  RElfParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new_from_fd (fd, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
  if (file != NULL) {
    ret = r_elf_parser_new_from_mem_file (file);
    r_mem_file_unref (file);
  }

  return ret;
}

RElfParser *
r_elf_parser_new_from_mem (rpointer mem, rsize size)
{
  RElfParser * ret = NULL;
  int elfidx;

  if ((elfidx = _check_elf_header (mem, size)) >= 0) {
    if (R_LIKELY (ret = r_mem_new (RElfParser))) {
      r_atomic_uint_store (&ret->refcount, 1);
      ret->file = NULL;
      ret->mem = mem;
      ret->size = size;
      ret->elfidx = elfidx;
    }
  }

  return ret;
}

static void
r_elf_parser_free (RElfParser * parser)
{
  if (parser->file != NULL)
    r_mem_file_unref (parser->file);
  r_free (parser);
}

RElfParser *
r_elf_parser_ref (RElfParser * parser)
{
  r_atomic_uint_fetch_add (&parser->refcount, 1);
  return parser;
}

void
r_elf_parser_unref (RElfParser * parser)
{
  if (r_atomic_uint_fetch_sub (&parser->refcount, 1) == 1)
    r_elf_parser_free (parser);
}

ruint8
r_elf_parser_get_class (RElfParser * parser)
{
  return ((ruint8 *)parser->mem)[R_ELF_IDX_CLASS];
}

ruint8
r_elf_parser_get_data (RElfParser * parser)
{
  return ((ruint8 *)parser->mem)[R_ELF_IDX_DATA];
}

ruint8
r_elf_parser_get_version (RElfParser * parser)
{
  return ((ruint8 *)parser->mem)[R_ELF_IDX_VERSION];
}

ruint8
r_elf_parser_get_osabi (RElfParser * parser)
{
  return ((ruint8 *)parser->mem)[R_ELF_IDX_OSABI];
}

ruint8
r_elf_parser_get_abi_version (RElfParser * parser)
{
  return ((ruint8 *)parser->mem)[R_ELF_IDX_ABIVERSION];
}

rpointer
r_elf_parser_get_elf_header (RElfParser * parser)
{
  return parser->mem;
}

RElf32EHdr *
r_elf_parser_get_ehdr32 (RElfParser * parser)
{
  return parser->elfidx == RELF32_IDX ? parser->mem : NULL;
}

RElf64EHdr *
r_elf_parser_get_ehdr64 (RElfParser * parser)
{
  return parser->elfidx == RELF64_IDX ? parser->mem : NULL;
}

static ruint16
r_elf_parser_ehdr32_prg_header_count (RElfParser * parser)
{
  RElf32EHdr * ehdr = r_elf_parser_get_ehdr32 (parser);
  return ehdr->phnum;
}

static ruint16
r_elf_parser_ehdr64_prg_header_count (RElfParser * parser)
{
  RElf64EHdr * ehdr = r_elf_parser_get_ehdr64 (parser);
  return ehdr->phnum;
}

ruint16
r_elf_parser_prg_header_count (RElfParser * parser)
{
  ruint16 (*ft[])() = {
    r_elf_parser_ehdr32_prg_header_count,
    r_elf_parser_ehdr64_prg_header_count,
  };

  return ft[parser->elfidx] (parser);
}

RElf32PHdr *
r_elf_parser_get_phdr32 (RElfParser * parser, ruint16 idx)
{
  RElf32EHdr * ehdr = r_elf_parser_get_ehdr32 (parser);
  ruint8 * ptr;
  if (ehdr == NULL || idx >= ehdr->phnum || ehdr->phoff == 0)
    return NULL;

  ptr = parser->mem;
  ptr += ehdr->phoff;
  ptr += ehdr->phentsize * idx;
  return (RElf32PHdr *)ptr;
}

RElf64PHdr *
r_elf_parser_get_phdr64 (RElfParser * parser, ruint16 idx)
{
  RElf64EHdr * ehdr = r_elf_parser_get_ehdr64 (parser);
  ruint8 * ptr;
  if (ehdr == NULL || idx >= ehdr->phnum || ehdr->phoff == 0)
    return NULL;

  ptr = parser->mem;
  ptr += ehdr->phoff;
  ptr += ehdr->phentsize * idx;
  return (RElf64PHdr *)ptr;
}

rpointer
r_elf_parser_get_prg_header_table (RElfParser * parser)
{
  RFuncUniversalReturn ft[] = {
    (RFuncUniversalReturn) r_elf_parser_get_phdr32,
    (RFuncUniversalReturn) r_elf_parser_get_phdr64,
  };

  return ft[parser->elfidx] (parser, 0);
}

static ruint16
r_elf_parser_ehdr32_section_header_count (RElfParser * parser)
{
  RElf32EHdr * ehdr = r_elf_parser_get_ehdr32 (parser);
  return ehdr->shnum;
}

static ruint16
r_elf_parser_ehdr64_section_header_count (RElfParser * parser)
{
  RElf64EHdr * ehdr = r_elf_parser_get_ehdr64 (parser);
  return ehdr->shnum;
}

ruint16
r_elf_parser_section_header_count (RElfParser * parser)
{
  ruint16 (*ft[])() = {
    r_elf_parser_ehdr32_section_header_count,
    r_elf_parser_ehdr64_section_header_count,
  };

  return ft[parser->elfidx] (parser);
}

rpointer
r_elf_parser_get_section_header_table (RElfParser * parser)
{
  RFuncUniversalReturn ft[] = {
    (RFuncUniversalReturn) r_elf_parser_get_shdr32,
    (RFuncUniversalReturn) r_elf_parser_get_shdr64,
  };

  return ft[parser->elfidx] (parser, 0);
}

RElf32SHdr *
r_elf_parser_get_shdr32 (RElfParser * parser, ruint16 idx)
{
  RElf32EHdr * ehdr = r_elf_parser_get_ehdr32 (parser);
  ruint8 * ptr;
  if (ehdr == NULL || idx >= ehdr->shnum || ehdr->shoff == 0)
    return NULL;

  ptr = parser->mem;
  ptr += ehdr->shoff;
  ptr += ehdr->shentsize * idx;
  return (RElf32SHdr *)ptr;
}

RElf64SHdr *
r_elf_parser_get_shdr64 (RElfParser * parser, ruint16 idx)
{
  RElf64EHdr * ehdr = r_elf_parser_get_ehdr64 (parser);
  ruint8 * ptr;
  if (ehdr == NULL || idx >= ehdr->shnum || ehdr->shoff == 0)
    return NULL;

  ptr = parser->mem;
  ptr += ehdr->shoff;
  ptr += ehdr->shentsize * idx;
  return (RElf64SHdr *)ptr;
}

RElf32SHdr *
r_elf_parser_find_shdr32 (RElfParser * parser, const rchar * name, rssize size)
{
  RElf32EHdr * ehdr;

  if ((ehdr = r_elf_parser_get_ehdr32 (parser)) != NULL) {
    ruint16 i;
    ruint8 * ptr = parser->mem;
    ptr += ehdr->shoff;

    for (i = 0; i < ehdr->shnum; i++) {
      RElf32SHdr * shdr = (RElf32SHdr *)(ptr + ehdr->shentsize * i);
      rchar * secname = r_elf_parser_strtbl_get_str (parser, shdr->name);
      if (r_strcmp_size (name, size, secname, -1) == 0)
        return shdr;
    }
  }

  return NULL;
}

RElf64SHdr *
r_elf_parser_find_shdr64 (RElfParser * parser, const rchar * name, rssize size)
{
  RElf64EHdr * ehdr;

  if ((ehdr = r_elf_parser_get_ehdr64 (parser)) != NULL) {
    ruint16 i;
    ruint8 * ptr = parser->mem;
    ptr += ehdr->shoff;

    for (i = 0; i < ehdr->shnum; i++) {
      RElf64SHdr * shdr = (RElf64SHdr *)(ptr + ehdr->shentsize * i);
      rchar * secname = r_elf_parser_strtbl_get_str (parser, shdr->name);
      if (r_strcmp_size (name, size, secname, -1) == 0)
        return shdr;
    }
  }

  return NULL;
}

rchar *
r_elf_parser_shdr32_get_name (RElfParser * parser, RElf32SHdr * shdr)
{
  if (shdr != NULL)
    return r_elf_parser_strtbl32_get_str (parser, NULL, shdr->name);
  return NULL;
}

rchar *
r_elf_parser_shdr64_get_name (RElfParser * parser, RElf64SHdr * shdr)
{
  if (shdr != NULL)
    return r_elf_parser_strtbl64_get_str (parser, NULL, shdr->name);
  return NULL;
}

rpointer
r_elf_parser_shdr32_get_data (RElfParser * parser, RElf32SHdr * shdr, rsize * size)
{
  if (shdr != NULL && shdr->offset > 0) {
    if (size != NULL)
      *size = shdr->size;
    return (ruint8 *)parser->mem + shdr->offset;
  }

  return NULL;
}

rpointer
r_elf_parser_shdr64_get_data (RElfParser * parser, RElf64SHdr * shdr, rsize * size)
{
  if (shdr != NULL && shdr->offset > 0) {
    if (size != NULL)
      *size = shdr->size;
    return (ruint8 *)parser->mem + shdr->offset;
  }

  return NULL;
}

static rpointer
r_elf_parser_find_shdr32_data (RElfParser * parser,
    const rchar * name, rssize size, rsize * secsize)
{
  return r_elf_parser_shdr32_get_data (parser,
      r_elf_parser_find_shdr32 (parser, name, size), secsize);
}

static rpointer
r_elf_parser_find_shdr64_data (RElfParser * parser,
    const rchar * name, rssize size, rsize * secsize)
{
  return r_elf_parser_shdr64_get_data (parser,
      r_elf_parser_find_shdr64 (parser, name, size), secsize);
}

rpointer
r_elf_parser_find_section_data (RElfParser * parser,
    const rchar * name, rssize size, rsize * secsize)
{
  RFuncUniversalReturn ft[] = {
    (RFuncUniversalReturn) r_elf_parser_find_shdr32_data,
    (RFuncUniversalReturn) r_elf_parser_find_shdr64_data,
  };

  return ft[parser->elfidx] (parser, name, size, secsize);
}

static ruint16
r_elf_parser_ehdr32_strtbl_idx (RElfParser * parser)
{
  RElf32EHdr * ehdr = r_elf_parser_get_ehdr32 (parser);
  return ehdr->shstrndx;
}

static ruint16
r_elf_parser_ehdr64_strtbl_idx (RElfParser * parser)
{
  RElf64EHdr * ehdr = r_elf_parser_get_ehdr64 (parser);
  return ehdr->shstrndx;
}

ruint16
r_elf_parser_strtbl_idx (RElfParser * parser)
{
  ruint16 (*ft[])() = {
    r_elf_parser_ehdr32_strtbl_idx,
    r_elf_parser_ehdr64_strtbl_idx,
  };

  return ft[parser->elfidx] (parser);
}

RElf32SHdr *
r_elf_parser_get_strtbl32 (RElfParser * parser)
{
  RElf32EHdr * ehdr = r_elf_parser_get_ehdr32 (parser);
  return ehdr != NULL ? r_elf_parser_get_shdr32 (parser, ehdr->shstrndx) : NULL;
}

RElf64SHdr *
r_elf_parser_get_strtbl64 (RElfParser * parser)
{
  RElf64EHdr * ehdr = r_elf_parser_get_ehdr64 (parser);
  return ehdr != NULL ? r_elf_parser_get_shdr64 (parser, ehdr->shstrndx) : NULL;
}

rchar *
r_elf_parser_strtbl_get_str (RElfParser * parser, ruint32 idx)
{
  rchar * (*ft[])() = {
    r_elf_parser_strtbl32_get_str,
    r_elf_parser_strtbl64_get_str,
  };

  return ft[parser->elfidx] (parser, NULL, idx);
}

rchar *
r_elf_parser_strtbl32_get_str (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx)
{
  rchar * ret;

  if (shdr == NULL) {
    if ((shdr = r_elf_parser_get_strtbl32 (parser)) == NULL)
      return NULL;
  }
  if (shdr->type != R_ELF_STYPE_STRTAB)
    return NULL;

  ret = parser->mem;
  ret += shdr->offset + idx;
  return ret;
}

rchar *
r_elf_parser_strtbl64_get_str (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx)
{
  rchar * ret;

  if (shdr == NULL) {
    if ((shdr = r_elf_parser_get_strtbl64 (parser)) == NULL)
      return NULL;
  }
  if (shdr->type != R_ELF_STYPE_STRTAB)
    return NULL;

  ret = parser->mem;
  ret += shdr->offset + idx;
  return ret;
}

ruint32
r_elf_parser_symtbl32_sym_count (RElfParser * parser, RElf32SHdr * shdr)
{
  if (parser != NULL && shdr != NULL && shdr->entsize >= sizeof (RElf32Sym) &&
      (shdr->type == R_ELF_STYPE_SYMTAB || shdr->type == R_ELF_STYPE_DYNSYM))
    return shdr->size / shdr->entsize;

  return 0;
}

ruint64
r_elf_parser_symtbl64_sym_count (RElfParser * parser, RElf64SHdr * shdr)
{
  if (parser != NULL && shdr != NULL && shdr->entsize >= sizeof (RElf64Sym) &&
      (shdr->type == R_ELF_STYPE_SYMTAB || shdr->type == R_ELF_STYPE_DYNSYM))
    return shdr->size / shdr->entsize;

  return 0;
}

RElf32Sym *
r_elf_parser_symtbl32_get_sym (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx)
{
  ruint32 count = r_elf_parser_symtbl32_sym_count (parser, shdr);
  if (count > idx) {
    ruint8 * mem = parser->mem;
    return (RElf32Sym *)(mem + shdr->offset + shdr->entsize * idx);
  }

  return NULL;
}

RElf64Sym *
r_elf_parser_symtbl64_get_sym (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx)
{
  ruint64 count = r_elf_parser_symtbl64_sym_count (parser, shdr);
  if (count > idx) {
    ruint8 * mem = parser->mem;
    return (RElf64Sym *)(mem + shdr->offset + shdr->entsize * idx);
  }

  return NULL;
}

rchar *
r_elf_parser_symtbl32_sym32_get_name (RElfParser * parser, RElf32SHdr * shdr, RElf32Sym * sym)
{
  if (parser != NULL && shdr != NULL && sym != NULL && sym->name != 0 &&
      (shdr->type == R_ELF_STYPE_SYMTAB || shdr->type == R_ELF_STYPE_DYNSYM)) {
    RElf32SHdr * strtbl;
    if ((strtbl = r_elf_parser_get_shdr32 (parser, shdr->link)) != NULL)
      return r_elf_parser_strtbl32_get_str (parser, strtbl, sym->name);
  }

  return NULL;
}

rchar *
r_elf_parser_symtbl64_sym64_get_name (RElfParser * parser, RElf64SHdr * shdr, RElf64Sym * sym)
{
  if (parser != NULL && shdr != NULL && sym != NULL && sym->name != 0 &&
      (shdr->type == R_ELF_STYPE_SYMTAB || shdr->type == R_ELF_STYPE_DYNSYM)) {
    RElf64SHdr * strtbl;
    if ((strtbl = r_elf_parser_get_shdr64 (parser, shdr->link)) != NULL)
      return r_elf_parser_strtbl64_get_str (parser, strtbl, sym->name);
  }

  return NULL;
}

rpointer
r_elf_parser_symtbl32_sym32_get_data (RElfParser * parser, RElf32SHdr * shdr, RElf32Sym * sym, rsize * size)
{
  if (parser != NULL && shdr != NULL && sym != NULL && sym->shndx != 0 &&
      (shdr->type == R_ELF_STYPE_SYMTAB || shdr->type == R_ELF_STYPE_DYNSYM)) {
    RElf32SHdr * shdr;
    if ((shdr = r_elf_parser_get_shdr32 (parser, sym->shndx)) != NULL) {
      ruint8 * mem = parser->mem;
      if (size != NULL)
        *size = sym->size;
      return mem + shdr->offset + sym->value;
    }
  }

  return NULL;
}

rpointer
r_elf_parser_symtbl64_sym64_get_data (RElfParser * parser, RElf64SHdr * shdr, RElf64Sym * sym, rsize * size)
{
  if (parser != NULL && shdr != NULL && sym != NULL && sym->shndx != 0 &&
      (shdr->type == R_ELF_STYPE_SYMTAB || shdr->type == R_ELF_STYPE_DYNSYM)) {
    RElf64SHdr * shdr;
    if ((shdr = r_elf_parser_get_shdr64 (parser, sym->shndx)) != NULL) {
      ruint8 * mem = parser->mem;
      if (size != NULL)
        *size = sym->size;
      return mem + shdr->offset + sym->value;
    }
  }

  return NULL;
}

ruint32
r_elf_parser_relatbl32_rela_count (RElfParser * parser, RElf32SHdr * shdr)
{
  if (parser != NULL && shdr != NULL && shdr->entsize >= sizeof (RElf32Rela) &&
      shdr->type == R_ELF_STYPE_RELA)
    return shdr->size / shdr->entsize;

  return 0;
}

ruint64
r_elf_parser_relatbl64_rela_count (RElfParser * parser, RElf64SHdr * shdr)
{
  if (parser != NULL && shdr != NULL && shdr->entsize >= sizeof (RElf64Rela) &&
      shdr->type == R_ELF_STYPE_RELA)
    return shdr->size / shdr->entsize;

  return 0;
}

RElf32Rela *
r_elf_parser_relatbl32_get_rela (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx)
{
  ruint32 count = r_elf_parser_relatbl32_rela_count (parser, shdr);
  if (count > idx) {
    ruint8 * mem = parser->mem;
    return (RElf32Rela *)(mem + shdr->offset + shdr->entsize * idx);
  }

  return NULL;
}

RElf64Rela *
r_elf_parser_relatbl64_get_rela (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx)
{
  ruint64 count = r_elf_parser_relatbl64_rela_count (parser, shdr);
  if (count > idx) {
    ruint8 * mem = parser->mem;
    return (RElf64Rela *)(mem + shdr->offset + shdr->entsize * idx);
  }

  return NULL;
}

RElf32Sym *
r_elf_parser_rela32_get_sym (RElfParser * parser, RElf32SHdr * shdr,
    RElf32Rela * rela, RElf32SHdr ** symtbl)
{
  RElf32SHdr * stbl;

  if (shdr != NULL && shdr->link != R_ELF_SHN_UNDEF) {
    if ((stbl = r_elf_parser_get_shdr32 (parser, shdr->link)) != NULL) {
      ruint32 symidx;
      if (symtbl != NULL)
        *symtbl = stbl;

      if (rela != NULL && (symidx = R_ELF32_RELINFO_SYM (rela->info)) > 0)
        return r_elf_parser_symtbl32_get_sym (parser, stbl, symidx);
    }
  }

  if (symtbl != NULL)
    *symtbl = NULL;
  return NULL;
}

RElf64Sym *
r_elf_parser_rela64_get_sym (RElfParser * parser, RElf64SHdr * shdr,
    RElf64Rela * rela, RElf64SHdr ** symtbl)
{
  RElf64SHdr * stbl;

  if (shdr != NULL && shdr->link != R_ELF_SHN_UNDEF) {
    if ((stbl = r_elf_parser_get_shdr64 (parser, shdr->link)) != NULL) {
      ruint64 symidx;
      if (symtbl != NULL)
        *symtbl = stbl;

      if (rela != NULL && (symidx = R_ELF64_RELINFO_SYM (rela->info)) > 0)
        return r_elf_parser_symtbl64_get_sym (parser, stbl, symidx);
    }
  }

  if (symtbl != NULL)
    *symtbl = NULL;
  return NULL;
}

ruint32 *
r_elf_parser_rela32_get_dst (RElfParser * parser,
    RElf32SHdr * shdr, RElf32Rela * rela)
{
  if (parser != NULL && shdr != NULL && rela != NULL) {
    if (shdr->flags & R_ELF_SFLAGS_ALLOC) {
      return RUINT_TO_POINTER (rela->offset);
    } else {
      if (shdr->info != R_ELF_SHN_UNDEF) {
        return (ruint32 *)((ruint8 *)r_elf_parser_shdr32_get_data_by_idx (parser,
              shdr->info, NULL) + rela->offset);
      }
    }
  }

  return NULL;
}

ruint64 *
r_elf_parser_rela64_get_dst (RElfParser * parser,
    RElf64SHdr * shdr, RElf64Rela * rela)
{
  if (parser != NULL && shdr != NULL && rela != NULL) {
    if (shdr->flags & R_ELF_SFLAGS_ALLOC) {
      return RUINT_TO_POINTER (rela->offset);
    } else {
      if (shdr->info != R_ELF_SHN_UNDEF) {
        return (ruint64 *)((ruint8 *)r_elf_parser_shdr64_get_data_by_idx (parser,
              shdr->info, NULL) + rela->offset);
      }
    }
  }

  return NULL;
}

