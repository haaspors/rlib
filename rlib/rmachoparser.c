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

#include "config.h"

#include <rlib/rmachoparser.h>

#include <rlib/rassert.h>
#include <rlib/rmem.h>
#include <rlib/rmemfile.h>
#include <rlib/rstr.h>
#include <rlib/rtty.h>

#define RMACHO32_IDX  0
#define RMACHO64_IDX  1

struct _RMachoParser {
  RRef ref;
  RMemFile * file;
  rpointer mem;
  rsize size;
  int machoidx;
  rpointer lc;
  rpointer data;
};


static int
_check_macho32_header (RMacho32Hdr * hdr, rsize size)
{
  if (R_UNLIKELY (size < sizeof (RMacho32Hdr)))
    return -1;
  if (size < sizeof (RMacho32Hdr) + hdr->sizeofcmds)
    return -1;

  return RMACHO32_IDX;
}

static int
_check_macho64_header (RMacho64Hdr * hdr, rsize size)
{
  if (R_UNLIKELY (size < sizeof (RMacho64Hdr)))
    return -1;
  if (size < sizeof (RMacho64Hdr) + hdr->sizeofcmds)
    return -1;

  return RMACHO64_IDX;
}

static int
_check_macho_header (rpointer mem, rsize size)
{
  if (size >= sizeof (ruint32) && mem != NULL) {
    ruint32 * hdr = mem;
    switch (hdr[0]) {
      case R_MACHO_MAGIC_32:
        return _check_macho32_header (mem, size);
      case R_MACHO_MAGIC_64:
        return _check_macho64_header (mem, size);
      default:
        break;
    }
  }

  return -1;
}

rboolean
r_macho_is_valid (rconstpointer mem)
{
  switch (((const ruint32 *)mem)[0]) {
    case R_MACHO_MAGIC_32:
    case R_MACHO_MAGIC_64:
      return TRUE;
    default:
      break;
  }

  return FALSE;
}

rsize
r_macho_calc_size (rconstpointer mem)
{
  const RMachoLoadCmd * lc;
  rsize hdrsize, datasize;
  ruint32 ncmds;

  switch (((ruint32 *)mem)[0]) {
    case R_MACHO_MAGIC_32:
      {
        const RMacho32Hdr * hdr = mem;
        ncmds = hdr->ncmds;
        lc = (const RMachoLoadCmd *)(hdr + 1);
        hdrsize = sizeof (RMacho32Hdr) + hdr->sizeofcmds;
      }
      break;
    case R_MACHO_MAGIC_64:
      {
        const RMacho64Hdr * hdr = mem;
        ncmds = hdr->ncmds;
        lc = (const RMachoLoadCmd *)(hdr + 1);
        hdrsize = sizeof (RMacho64Hdr) + hdr->sizeofcmds;
      }
      break;
    default:
     return 0;
  }

  for (datasize = 0; ncmds > 0; ncmds--, lc = (const RMachoLoadCmd *)RPOINTER_TO_SIZE (lc) + lc->cmdsize) {
    rsize cursize;
    switch (lc->cmd) {
      case R_MACHO_LC_SEGMENT:
        {
          const RMachoSegment32Cmd * cmd = (const RMachoSegment32Cmd *)lc;
          cursize = cmd->fileoff + cmd->filesize;
          datasize = MAX (cursize, datasize);
        }
        break;
      case R_MACHO_LC_SEGMENT_64:
        {
          const RMachoSegment64Cmd * cmd = (const RMachoSegment64Cmd *)lc;
          cursize = cmd->fileoff + cmd->filesize;
          datasize = MAX (cursize, datasize);
        }
        break;
    }
  }

  return hdrsize + datasize;
}


static void
r_macho_parser_free (RMachoParser * parser)
{
  if (parser->file != NULL)
    r_mem_file_unref (parser->file);
  r_free (parser);
}

RMachoParser *
r_macho_parser_new_from_mem (rpointer mem, rsize size)
{
  RMachoParser * ret;
  int machoidx;

  if ((machoidx = _check_macho_header (mem, size)) >= 0) {
    if (R_LIKELY (ret = r_mem_new (RMachoParser))) {
      r_ref_init (ret, r_macho_parser_free);
      ret->file = NULL;
      ret->mem = mem;
      ret->size = size;
      ret->machoidx = machoidx;

      switch (machoidx) {
        case RMACHO32_IDX:
          ret->lc = (ruint8 *)ret->mem + sizeof (RMacho32Hdr);
          break;
        case RMACHO64_IDX:
          ret->lc = (ruint8 *)ret->mem + sizeof (RMacho64Hdr);
          break;
        default:
          r_assert_not_reached ();
      }

      ret->data = (ruint8 *)ret->lc + ((RMacho32Hdr *)ret->mem)->sizeofcmds;
    }
  } else {
    ret = NULL;
  }

  return ret;
}

static RMachoParser *
r_macho_parser_new_from_mem_file (RMemFile * file)
{
  RMachoParser * ret = NULL;

  if (file != NULL) {
    rpointer mem = r_mem_file_get_mem (file);
    rsize size = r_mem_file_get_size (file);

    if ((ret = r_macho_parser_new_from_mem (mem, size)) != NULL) {
      ret->file = r_mem_file_ref (file);
    }
  }

  return ret;
}

RMachoParser *
r_macho_parser_new (const rchar * filename)
{
  RMachoParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new (filename, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
  if (file != NULL) {
    ret = r_macho_parser_new_from_mem_file (file);
    r_mem_file_unref (file);
  }

  return ret;
}

RMachoParser *
r_macho_parser_new_from_fd (int fd)
{
  RMachoParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new_from_fd (fd, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
  if (file != NULL) {
    ret = r_macho_parser_new_from_mem_file (file);
    r_mem_file_unref (file);
  }

  return ret;
}

ruint32
r_macho_parser_get_magic (RMachoParser * parser)
{
  return *(ruint32 *)parser->mem;
}

RMacho32Hdr *
r_macho_parser_get_hdr32 (RMachoParser * parser)
{
  return parser->machoidx == RMACHO32_IDX ? parser->mem : NULL;
}

RMacho64Hdr *
r_macho_parser_get_hdr64 (RMachoParser * parser)
{
  return parser->machoidx == RMACHO64_IDX ? parser->mem : NULL;
}

rsize
r_macho_parser_get_loadcmd_count (RMachoParser * parser)
{
  return ((const RMacho32Hdr *)parser->mem)->ncmds;
}

RMachoLoadCmd *
r_macho_parser_get_loadcmd (RMachoParser * parser, ruint16 idx)
{
  const RMacho32Hdr * hdr = parser->mem;
  RMachoLoadCmd * lc = parser->lc;

  while (idx-- > 0) {
    lc = (RMachoLoadCmd *)((ruint8 *)lc + lc->cmdsize);
    if ((ruint8 *)lc - ((ruint8 *)parser->lc) + sizeof (RMachoLoadCmd) > hdr->sizeofcmds)
      return NULL;
  }

  return lc;
}

RMachoSegment32Cmd *
r_macho_parser_find_segment32 (RMachoParser * parser, const rchar * name, rssize size)
{
  const RMacho32Hdr * hdr;

  if ((hdr = r_macho_parser_get_hdr32 (parser)) != NULL) {
    RMachoLoadCmd * lc;
    ruint16 i;
    for (i = hdr->ncmds, lc = parser->lc; i > 0;
        i--, lc = (RMachoLoadCmd *)(RPOINTER_TO_SIZE (lc) + lc->cmdsize)) {
      if (lc->cmd == R_MACHO_LC_SEGMENT) {
        RMachoSegment32Cmd * seg = (RMachoSegment32Cmd *)lc;
        if (r_strcmp_size (seg->segname, -1, name, size) == 0)
          return seg;
      }
    }
  }

  return NULL;
}

RMachoSegment64Cmd *
r_macho_parser_find_segment64 (RMachoParser * parser, const rchar * name, rssize size)
{
  const RMacho64Hdr * hdr;

  if ((hdr = r_macho_parser_get_hdr64 (parser)) != NULL) {
    RMachoLoadCmd * lc;
    ruint16 i;
    for (i = hdr->ncmds, lc = parser->lc; i > 0;
        i--, lc = (RMachoLoadCmd *)(RPOINTER_TO_SIZE (lc) + lc->cmdsize)) {
      if (lc->cmd == R_MACHO_LC_SEGMENT_64) {
        RMachoSegment64Cmd * seg = (RMachoSegment64Cmd *)lc;
        if (r_strcmp_size (seg->segname, -1, name, size) == 0)
          return seg;
      }
    }
  }

  return NULL;
}

RMachoSection32 *
r_macho_parser_get_section32 (RMachoParser * parser, RMachoSegment32Cmd * cmd, ruint16 idx)
{
  if (R_UNLIKELY (parser == NULL || cmd == NULL || idx >= cmd->nsects))
    return NULL;
  return ((RMachoSection32 * )(cmd + 1)) + idx;
}

RMachoSection64 *
r_macho_parser_get_section64 (RMachoParser * parser, RMachoSegment64Cmd * cmd, ruint16 idx)
{
  if (R_UNLIKELY (parser == NULL || cmd == NULL || idx >= cmd->nsects))
    return NULL;
  return ((RMachoSection64 * )(cmd + 1)) + idx;
}

RMachoSection32 *
r_macho_parser_find_section32 (RMachoParser * parser, const rchar * name, rssize size)
{
  const RMacho32Hdr * hdr;
  RMachoLoadCmd * lc;
  ruint32 i, j;

  if (R_UNLIKELY (parser == NULL || name == NULL))
    return NULL;

  hdr = parser->mem;
  for (i = hdr->ncmds, lc = parser->lc; i > 0;
      i--, lc = (RMachoLoadCmd *)(RPOINTER_TO_SIZE (lc) + lc->cmdsize)) {
    if (lc->cmd == R_MACHO_LC_SEGMENT) {
      RMachoSegment32Cmd * seg = (RMachoSegment32Cmd *)lc;
      RMachoSection32 * sec = (RMachoSection32 * )(seg + 1);

      for (j = 0; j < seg->nsects; j++) {
        if (r_strcmp_size (sec->sectname, -1, name, size) == 0)
          return &sec[j];
      }
    }
  }

  return NULL;
}

RMachoSection64 *
r_macho_parser_find_section64 (RMachoParser * parser, const rchar * name, rssize size)
{
  const RMacho64Hdr * hdr;
  RMachoLoadCmd * lc;
  ruint32 i, j;

  if (R_UNLIKELY (parser == NULL || name == NULL))
    return NULL;

  hdr = parser->mem;
  for (i = hdr->ncmds, lc = parser->lc; i > 0;
      i--, lc = (RMachoLoadCmd *)(RPOINTER_TO_SIZE (lc) + lc->cmdsize)) {
    if (lc->cmd == R_MACHO_LC_SEGMENT_64) {
      RMachoSegment64Cmd * seg = (RMachoSegment64Cmd *)lc;
      RMachoSection64 * sec = (RMachoSection64 * )(seg + 1);

      for (j = 0; j < seg->nsects; j++) {
        if (r_strcmp_size (sec[j].sectname, -1, name, size) == 0)
          return &sec[j];
      }
    }
  }

  return NULL;
}

rpointer
r_macho_parser_s32cmd_get_data (RMachoParser * parser, RMachoSegment32Cmd * sc, rsize * size)
{
  if (R_UNLIKELY (parser == NULL || sc == NULL))
    return NULL;

  if (size != NULL)
    *size = (rsize)sc->filesize;
  return (ruint8 *)parser->data + sc->fileoff;
}

rpointer
r_macho_parser_s64cmd_get_data (RMachoParser * parser, RMachoSegment64Cmd * sc, rsize * size)
{
  if (R_UNLIKELY (parser == NULL || sc == NULL))
    return NULL;

  if (size != NULL)
    *size = (rsize)sc->filesize;
  return (ruint8 *)parser->data + sc->fileoff;
}

