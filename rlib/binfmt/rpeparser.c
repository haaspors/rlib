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

#include "config.h"
#include <rlib/binfmt/rpeparser.h>

#include <rlib/rmem.h>
#include <rlib/rmemfile.h>
#include <rlib/rstr.h>

struct _RPeParser {
  RRef ref;
  RMemFile * file;
  rpointer mem;
  rsize size;
  RPeImageHdr * imghdr;
  RPeSectionHdr * sectbl;
  rpointer rawdata;
};

static RPeParser *
r_pe_parser_new_from_mem_file (RMemFile * file)
{
  RPeParser * ret = NULL;

  if (file != NULL) {
    rpointer mem = r_mem_file_get_mem (file);
    rsize size = r_mem_file_get_size (file);

    if ((ret = r_pe_parser_new_from_mem (mem, size)) != NULL) {
      ret->file = r_mem_file_ref (file);
    }
  }

  return ret;
}

RPeParser *
r_pe_parser_new (const rchar * filename)
{
  RPeParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new (filename, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
  if (file != NULL) {
    ret = r_pe_parser_new_from_mem_file (file);
    r_mem_file_unref (file);
  }

  return ret;
}

RPeParser *
r_pe_parser_new_from_handle (RIOHandle handle)
{
  RPeParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new_from_handle (handle, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
  if (file != NULL) {
    ret = r_pe_parser_new_from_mem_file (file);
    r_mem_file_unref (file);
  }

  return ret;
}

static void
r_pe_parser_free (RPeParser * parser)
{
  if (parser->file != NULL)
    r_mem_file_unref (parser->file);
  r_free (parser);
}

RPeParser *
r_pe_parser_new_from_mem (rpointer mem, rsize size)
{
  RPeParser * ret = NULL;
  RPeImageHdr * hdr;
  const RPeDosHdr * dos;
  rsize sectbl_off, rawdata_off;

  if (R_UNLIKELY (mem == NULL || size < sizeof (RPeDosHdr)))
    return NULL;

  /* Pre-validate dos->lfanew before r_pe_image_from_dos_header dereferences it. */
  dos = mem;
  if (dos->magic != R_PE_DOS_MAGIC ||
      dos->lfanew > size ||
      size - dos->lfanew < sizeof (RPeImageHdr))
    return NULL;

  if ((hdr = r_pe_image_from_dos_header (mem)) != NULL) {
    sectbl_off = (rsize)dos->lfanew + sizeof (RPeImageHdr) + hdr->coff.size_opthdr;
    if (sectbl_off > size ||
        (size - sectbl_off) / sizeof (RPeSectionHdr) < hdr->coff.nsect)
      return NULL;
    rawdata_off = sectbl_off + (rsize)hdr->coff.nsect * sizeof (RPeSectionHdr);

    if (R_LIKELY (ret = r_mem_new (RPeParser))) {
      r_ref_init (ret, r_pe_parser_free);
      ret->file = NULL;
      ret->mem = mem;
      ret->size = size;
      ret->imghdr = hdr;
      ret->sectbl = (RPeSectionHdr *)((ruint8 *)mem + sectbl_off);
      ret->rawdata = (ruint8 *)mem + rawdata_off;
    }
  }

  return ret;
}

ruint16
r_pe_parser_get_machine (const RPeParser * parser)
{
  return parser->imghdr->coff.machine;
}

ruint16
r_pe_parser_get_section_count (const RPeParser * parser)
{
  return parser->imghdr->coff.nsect;
}

ruint32
r_pe_parser_get_time_date_stamp (const RPeParser * parser)
{
  return parser->imghdr->coff.ts;
}

ruint32
r_pe_parser_get_ptr_symbol_table (const RPeParser * parser)
{
  return parser->imghdr->coff.ptr_symtbl;
}

ruint32
r_pe_parser_get_symbol_count (const RPeParser * parser)
{
  return parser->imghdr->coff.nsyms;
}

ruint16
r_pe_parser_get_size_opt_hdr (const RPeParser * parser)
{
  return parser->imghdr->coff.size_opthdr;
}

ruint16
r_pe_parser_get_characteristics (const RPeParser * parser)
{
  return parser->imghdr->coff.characteristics;
}


ruint16
r_pe_parser_get_pe32_magic (RPeParser * parser)
{
  if (parser != NULL && parser->imghdr != NULL) {
    const RPeOptHdr * opt = (const RPeOptHdr *)(parser->imghdr + 1);
    return opt->magic;
  }

  return 0;
}

RPeOptHdr *
r_pe_parser_get_optional_hdr (RPeParser * parser)
{
  if (parser != NULL && parser->imghdr != NULL) {
    return (RPeOptHdr *)(parser->imghdr + 1);
  }

  return NULL;
}

RPe32ImageHdr *
r_pe_parser_get_pe32_image_hdr (RPeParser * parser)
{
  if (r_pe_parser_get_pe32_magic (parser) == R_PE_PE32_MAGIC)
    return (RPe32ImageHdr *)parser->imghdr;

  return NULL;
}

RPe32PlusImageHdr *
r_pe_parser_get_pe32p_image_hdr (RPeParser * parser)
{
  if (r_pe_parser_get_pe32_magic (parser) == R_PE_PE32PLUS_MAGIC)
    return (RPe32PlusImageHdr *)parser->imghdr;

  return NULL;
}



RPeSectionHdr *
r_pe_parser_get_section_hdr_by_idx (RPeParser * parser, ruint16 idx)
{
  if (parser != NULL && idx < parser->imghdr->coff.nsect)
    return &parser->sectbl[idx];

  return NULL;
}

RPeSectionHdr *
r_pe_parser_get_section_hdr_by_data_dir (RPeParser * parser, RPeDataDirEntry entry)
{
  const RPeDataDirectory * dd = NULL;
  ruint32 nentries = 0;
  ruint32 rva;
  ruint16 i;

  if (R_UNLIKELY (parser == NULL || parser->imghdr == NULL)) return NULL;
  if (R_UNLIKELY ((unsigned int) entry >= R_PE_DATA_DIR_ZERO)) return NULL;

  switch (r_pe_parser_get_pe32_magic (parser)) {
    case R_PE_PE32_MAGIC: {
      RPe32ImageHdr * h = (RPe32ImageHdr *) parser->imghdr;
      dd = h->datadir;
      nentries = h->winopt.number_rva_and_sizes;
      break;
    }
    case R_PE_PE32PLUS_MAGIC: {
      RPe32PlusImageHdr * h = (RPe32PlusImageHdr *) parser->imghdr;
      dd = h->datadir;
      nentries = h->winopt.number_rva_and_sizes;
      break;
    }
    default:
      return NULL;
  }

  if ((unsigned int) entry >= nentries || dd[entry].vmaddr == 0)
    return NULL;

  rva = dd[entry].vmaddr;
  for (i = 0; i < parser->imghdr->coff.nsect; i++) {
    RPeSectionHdr * sec = &parser->sectbl[i];
    if (rva >= sec->vmaddr && rva < sec->vmaddr + sec->vmsize)
      return sec;
  }

  return NULL;
}

RPeSectionHdr *
r_pe_parser_get_section_hdr_by_name (RPeParser * parser, const rchar * name, rssize nsize)
{
  ruint16 i;

  if (R_UNLIKELY (parser == NULL || parser->imghdr == NULL)) return NULL;
  if (R_UNLIKELY (name == NULL)) return NULL;

  for (i = 0; i < parser->imghdr->coff.nsect; i++) {
    RPeSectionHdr * sec = &parser->sectbl[i];
    if (r_strcmp_size (sec->name, -1, name, nsize) == 0)
      return sec;
  }

  return NULL;
}

