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
r_pe_parser_new_from_fd (int fd)
{
  RPeParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new_from_fd (fd, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
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
  RPeParser * ret;
  RPeImageHdr * hdr;

  if ((hdr = r_pe_image_from_dos_header (mem)) != NULL) {
    if (R_LIKELY (ret = r_mem_new (RPeParser))) {
      r_ref_init (ret, r_pe_parser_free);
      ret->file = NULL;
      ret->mem = mem;
      ret->size = size;
      ret->imghdr = hdr;
      ret->sectbl = (RPeSectionHdr *)((ruint8 *)(hdr + 1) + hdr->coff.size_opthdr);
      ret->rawdata = ret->sectbl + hdr->coff.nsect;
    }
  } else {
    ret = NULL;
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
  /* TODO: Implement */
  (void) parser;
  (void) entry;

  return NULL;
}

RPeSectionHdr *
r_pe_parser_get_section_hdr_by_name (RPeParser * parser, const rchar * name, rssize nsize)
{
  ruint16 i;

  for (i = 0; i < parser->imghdr->coff.nsect; i++) {
    RPeSectionHdr * sec = &parser->sectbl[i];
    if (r_strcmp_size (sec->name, -1, name, nsize) == 0)
      return sec;
  }

  return NULL;
}

