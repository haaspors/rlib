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
#include <rlib/binfmt/relfparser.h>

#include <rlib/concurrency/ratomic.h>
#include <rlib/rmem.h>
#include <rlib/rmemfile.h>
#include <rlib/rstr.h>

#define RELF32_IDX  0
#define RELF64_IDX  1

struct RElfParser {
  rauint refcount;
  RMemFile * file;
  rpointer mem;
  rboolean owns_mem;
  rsize size;
  int elfidx;
};

/* TRUE when the ELF's e_ident[EI_DATA] byte order differs from the host, so
 * multi-byte fields must be swapped before they can be read natively. */
static rboolean
r_elf_data_needs_swap (ruint8 data)
{
#if R_BYTE_ORDER == R_BIG_ENDIAN
  return data == R_ELF_DATA2LSB;
#else
  return data == R_ELF_DATA2MSB;
#endif
}

rsize
r_elf_calc_size (rpointer mem)
{
  ruint8 * ident = mem;
  if (ident[R_ELF_IDX_MAG0] == R_ELF_MAG0 && ident[R_ELF_IDX_MAG1] == R_ELF_MAG1 &&
      ident[R_ELF_IDX_MAG2] == R_ELF_MAG2 && ident[R_ELF_IDX_MAG3] == R_ELF_MAG3) {
    rboolean swap = r_elf_data_needs_swap (ident[R_ELF_IDX_DATA]);
    rsize phend, shend;

    switch (ident[R_ELF_IDX_CLASS]) {
      case R_ELF_CLASS32:
        {
          RElf32EHdr * hdr = mem;
          ruint32 phoff = hdr->phoff, shoff = hdr->shoff;
          ruint16 phentsize = hdr->phentsize, phnum = hdr->phnum;
          ruint16 shentsize = hdr->shentsize, shnum = hdr->shnum;
          if (swap) {
            phoff = RUINT32_BSWAP (phoff); shoff = RUINT32_BSWAP (shoff);
            phentsize = RUINT16_BSWAP (phentsize); phnum = RUINT16_BSWAP (phnum);
            shentsize = RUINT16_BSWAP (shentsize); shnum = RUINT16_BSWAP (shnum);
          }
          phend = phoff + (rsize)phentsize * phnum;
          shend = shoff + (rsize)shentsize * shnum;
        }
        break;
      case R_ELF_CLASS64:
        {
          RElf64EHdr * hdr = mem;
          ruint64 phoff = hdr->phoff, shoff = hdr->shoff;
          ruint16 phentsize = hdr->phentsize, phnum = hdr->phnum;
          ruint16 shentsize = hdr->shentsize, shnum = hdr->shnum;
          if (swap) {
            phoff = RUINT64_BSWAP (phoff); shoff = RUINT64_BSWAP (shoff);
            phentsize = RUINT16_BSWAP (phentsize); phnum = RUINT16_BSWAP (phnum);
            shentsize = RUINT16_BSWAP (shentsize); shnum = RUINT16_BSWAP (shnum);
          }
          phend = phoff + (rsize)phentsize * phnum;
          shend = shoff + (rsize)shentsize * shnum;
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

  phsize = (rsize)hdr->phentsize * hdr->phnum;
  shsize = (rsize)hdr->shentsize * hdr->shnum;
  if (size < hdr->ehsize || size - hdr->ehsize < phsize + shsize)
    return -1;
  if (hdr->phoff > size || size - hdr->phoff < phsize) return -1;
  if (hdr->shoff > size || size - hdr->shoff < shsize) return -1;

  return RELF32_IDX;
}

static int
_check_elf64_header (RElf64EHdr * hdr, rsize size)
{
  rsize phsize, shsize;

  if (R_UNLIKELY (size < sizeof (RElf64EHdr) || size < hdr->ehsize))
    return -1;

  phsize = (rsize)hdr->phentsize * hdr->phnum;
  shsize = (rsize)hdr->shentsize * hdr->shnum;
  if (size < hdr->ehsize || size - hdr->ehsize < phsize + shsize)
    return -1;
  if (hdr->phoff > size || size - hdr->phoff < phsize) return -1;
  if (hdr->shoff > size || size - hdr->shoff < shsize) return -1;

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

/* In-place byte-order swap of each multi-byte field of the fixed-layout ELF
 * structures.  The 1-byte fields (ident[], st_info, st_other) are left as-is.
 * Only called for non-native ELFs, on a private copy. */
static void
r_elf_swap_ehdr32 (RElf32EHdr * h)
{
  h->type      = RUINT16_BSWAP (h->type);
  h->machine   = RUINT16_BSWAP (h->machine);
  h->version   = RUINT32_BSWAP (h->version);
  h->entry     = RUINT32_BSWAP (h->entry);
  h->phoff     = RUINT32_BSWAP (h->phoff);
  h->shoff     = RUINT32_BSWAP (h->shoff);
  h->flags     = RUINT32_BSWAP (h->flags);
  h->ehsize    = RUINT16_BSWAP (h->ehsize);
  h->phentsize = RUINT16_BSWAP (h->phentsize);
  h->phnum     = RUINT16_BSWAP (h->phnum);
  h->shentsize = RUINT16_BSWAP (h->shentsize);
  h->shnum     = RUINT16_BSWAP (h->shnum);
  h->shstrndx  = RUINT16_BSWAP (h->shstrndx);
}

static void
r_elf_swap_ehdr64 (RElf64EHdr * h)
{
  h->type      = RUINT16_BSWAP (h->type);
  h->machine   = RUINT16_BSWAP (h->machine);
  h->version   = RUINT32_BSWAP (h->version);
  h->entry     = RUINT64_BSWAP (h->entry);
  h->phoff     = RUINT64_BSWAP (h->phoff);
  h->shoff     = RUINT64_BSWAP (h->shoff);
  h->flags     = RUINT32_BSWAP (h->flags);
  h->ehsize    = RUINT16_BSWAP (h->ehsize);
  h->phentsize = RUINT16_BSWAP (h->phentsize);
  h->phnum     = RUINT16_BSWAP (h->phnum);
  h->shentsize = RUINT16_BSWAP (h->shentsize);
  h->shnum     = RUINT16_BSWAP (h->shnum);
  h->shstrndx  = RUINT16_BSWAP (h->shstrndx);
}

static void
r_elf_swap_phdr32 (RElf32PHdr * h)
{
  h->type   = RUINT32_BSWAP (h->type);
  h->offset = RUINT32_BSWAP (h->offset);
  h->vaddr  = RUINT32_BSWAP (h->vaddr);
  h->paddr  = RUINT32_BSWAP (h->paddr);
  h->filesz = RUINT32_BSWAP (h->filesz);
  h->memsz  = RUINT32_BSWAP (h->memsz);
  h->flags  = RUINT32_BSWAP (h->flags);
  h->align  = RUINT32_BSWAP (h->align);
}

static void
r_elf_swap_phdr64 (RElf64PHdr * h)
{
  h->type   = RUINT32_BSWAP (h->type);
  h->flags  = RUINT32_BSWAP (h->flags);
  h->offset = RUINT64_BSWAP (h->offset);
  h->vaddr  = RUINT64_BSWAP (h->vaddr);
  h->paddr  = RUINT64_BSWAP (h->paddr);
  h->filesz = RUINT64_BSWAP (h->filesz);
  h->memsz  = RUINT64_BSWAP (h->memsz);
  h->align  = RUINT64_BSWAP (h->align);
}

static void
r_elf_swap_shdr32 (RElf32SHdr * h)
{
  h->name      = RUINT32_BSWAP (h->name);
  h->type      = RUINT32_BSWAP (h->type);
  h->flags     = RUINT32_BSWAP (h->flags);
  h->addr      = RUINT32_BSWAP (h->addr);
  h->offset    = RUINT32_BSWAP (h->offset);
  h->size      = RUINT32_BSWAP (h->size);
  h->link      = RUINT32_BSWAP (h->link);
  h->info      = RUINT32_BSWAP (h->info);
  h->addralign = RUINT32_BSWAP (h->addralign);
  h->entsize   = RUINT32_BSWAP (h->entsize);
}

static void
r_elf_swap_shdr64 (RElf64SHdr * h)
{
  h->name      = RUINT32_BSWAP (h->name);
  h->type      = RUINT32_BSWAP (h->type);
  h->flags     = RUINT64_BSWAP (h->flags);
  h->addr      = RUINT64_BSWAP (h->addr);
  h->offset    = RUINT64_BSWAP (h->offset);
  h->size      = RUINT64_BSWAP (h->size);
  h->link      = RUINT32_BSWAP (h->link);
  h->info      = RUINT32_BSWAP (h->info);
  h->addralign = RUINT64_BSWAP (h->addralign);
  h->entsize   = RUINT64_BSWAP (h->entsize);
}

static void
r_elf_swap_sym32 (RElf32Sym * s)
{
  s->name  = RUINT32_BSWAP (s->name);
  s->value = RUINT32_BSWAP (s->value);
  s->size  = RUINT32_BSWAP (s->size);
  s->shndx = RUINT16_BSWAP (s->shndx);
}

static void
r_elf_swap_sym64 (RElf64Sym * s)
{
  s->name  = RUINT32_BSWAP (s->name);
  s->shndx = RUINT16_BSWAP (s->shndx);
  s->value = RUINT64_BSWAP (s->value);
  s->size  = RUINT64_BSWAP (s->size);
}

static void
r_elf_swap_rel32 (RElf32Rel * r)
{
  r->offset = RUINT32_BSWAP (r->offset);
  r->info   = RUINT32_BSWAP (r->info);
}

static void
r_elf_swap_rel64 (RElf64Rel * r)
{
  r->offset = RUINT64_BSWAP (r->offset);
  r->info   = RUINT64_BSWAP (r->info);
}

static void
r_elf_swap_rela32 (RElf32Rela * r)
{
  r->offset = RUINT32_BSWAP (r->offset);
  r->info   = RUINT32_BSWAP (r->info);
  r->addend = (rint32) RUINT32_BSWAP ((ruint32) r->addend);
}

static void
r_elf_swap_rela64 (RElf64Rela * r)
{
  r->offset = RUINT64_BSWAP (r->offset);
  r->info   = RUINT64_BSWAP (r->info);
  r->addend = (rint64) RUINT64_BSWAP ((ruint64) r->addend);
}

static void
r_elf_swap_dyn32 (RElf32Dyn * d)
{
  d->tag    = (rint32) RUINT32_BSWAP ((ruint32) d->tag);
  d->un.val = (rint32) RUINT32_BSWAP ((ruint32) d->un.val);
}

static void
r_elf_swap_dyn64 (RElf64Dyn * d)
{
  d->tag    = (rint64) RUINT64_BSWAP ((ruint64) d->tag);
  d->un.val = (rint64) RUINT64_BSWAP ((ruint64) d->un.val);
}

/* Swap the multi-byte header fields (namesz/descsz/type) of every note in a
 * NOTE section's packed stream; the name/descriptor payloads are opaque bytes.
 * Each field is swapped before its swapped value is used to advance, so the
 * walk stays correct.  The Nhdr layout is identical for 32- and 64-bit. */
static void
r_elf_normalize_notes (ruint8 * data, rsize size)
{
  rsize off = 0;

  while (off + sizeof (RElf32NHdr) <= size) {
    RElf32NHdr * n = (RElf32NHdr *)(data + off);
    rsize esz;
    n->namesz = RUINT32_BSWAP (n->namesz);
    n->descsz = RUINT32_BSWAP (n->descsz);
    n->type   = RUINT32_BSWAP (n->type);
    esz = sizeof (RElf32NHdr) +
        (((rsize) n->namesz + 3) & ~(rsize)3) +
        (((rsize) n->descsz + 3) & ~(rsize)3);
    if (esz < sizeof (RElf32NHdr) || off + esz > size)
      break;
    off += esz;
  }
}

/* Swap the per-entry contents of a section that holds fixed-layout entries
 * (symbol / relocation tables) or a note stream.  Opaque sections (PROGBITS,
 * STRTAB, ...) are left untouched.  The section header is already host order. */
static void
r_elf_normalize_section32 (ruint8 * base, rsize size, RElf32SHdr * sh)
{
  rsize off = sh->offset, sz = sh->size, es = sh->entsize, i, n;

  if (off > size || size - off < sz)
    return;

  if (sh->type == R_ELF_STYPE_NOTE) {
    r_elf_normalize_notes (base + off, sz);
    return;
  }

  if (es == 0)
    return;
  n = sz / es;

  switch (sh->type) {
    case R_ELF_STYPE_SYMTAB:
    case R_ELF_STYPE_DYNSYM:
      for (i = 0; i < n; i++)
        r_elf_swap_sym32 ((RElf32Sym *)(base + off + i * es));
      break;
    case R_ELF_STYPE_REL:
      for (i = 0; i < n; i++)
        r_elf_swap_rel32 ((RElf32Rel *)(base + off + i * es));
      break;
    case R_ELF_STYPE_RELA:
      for (i = 0; i < n; i++)
        r_elf_swap_rela32 ((RElf32Rela *)(base + off + i * es));
      break;
    case R_ELF_STYPE_DYNAMIC:
      for (i = 0; i < n; i++)
        r_elf_swap_dyn32 ((RElf32Dyn *)(base + off + i * es));
      break;
    default:
      break;
  }
}

static void
r_elf_normalize_section64 (ruint8 * base, rsize size, RElf64SHdr * sh)
{
  rsize off = sh->offset, sz = sh->size, es = sh->entsize, i, n;

  if (off > size || size - off < sz)
    return;

  if (sh->type == R_ELF_STYPE_NOTE) {
    r_elf_normalize_notes (base + off, sz);
    return;
  }

  if (es == 0)
    return;
  n = sz / es;

  switch (sh->type) {
    case R_ELF_STYPE_SYMTAB:
    case R_ELF_STYPE_DYNSYM:
      for (i = 0; i < n; i++)
        r_elf_swap_sym64 ((RElf64Sym *)(base + off + i * es));
      break;
    case R_ELF_STYPE_REL:
      for (i = 0; i < n; i++)
        r_elf_swap_rel64 ((RElf64Rel *)(base + off + i * es));
      break;
    case R_ELF_STYPE_RELA:
      for (i = 0; i < n; i++)
        r_elf_swap_rela64 ((RElf64Rela *)(base + off + i * es));
      break;
    case R_ELF_STYPE_DYNAMIC:
      for (i = 0; i < n; i++)
        r_elf_swap_dyn64 ((RElf64Dyn *)(base + off + i * es));
      break;
    default:
      break;
  }
}

static void
r_elf_normalize_tables32 (ruint8 * base, rsize size)
{
  RElf32EHdr * eh = (RElf32EHdr *) base;
  ruint16 i;

  for (i = 0; i < eh->phnum; i++)
    r_elf_swap_phdr32 ((RElf32PHdr *)(base + eh->phoff + (rsize)i * eh->phentsize));

  for (i = 0; i < eh->shnum; i++) {
    RElf32SHdr * sh = (RElf32SHdr *)(base + eh->shoff + (rsize)i * eh->shentsize);
    r_elf_swap_shdr32 (sh);
    r_elf_normalize_section32 (base, size, sh);
  }

  /* A section-less image (e.g. a core dump) carries notes only in PT_NOTE
   * segments; with sections present, those bytes alias a NOTE section already
   * normalized above, so only swap segment notes when there are no sections. */
  if (eh->shnum == 0) {
    for (i = 0; i < eh->phnum; i++) {
      RElf32PHdr * ph = (RElf32PHdr *)(base + eh->phoff + (rsize)i * eh->phentsize);
      if (ph->type == R_ELF_PTYPE_NOTE && ph->offset <= size &&
          size - ph->offset >= ph->filesz)
        r_elf_normalize_notes (base + ph->offset, ph->filesz);
    }
  }
}

static void
r_elf_normalize_tables64 (ruint8 * base, rsize size)
{
  RElf64EHdr * eh = (RElf64EHdr *) base;
  ruint16 i;

  for (i = 0; i < eh->phnum; i++)
    r_elf_swap_phdr64 ((RElf64PHdr *)(base + eh->phoff + (rsize)i * eh->phentsize));

  for (i = 0; i < eh->shnum; i++) {
    RElf64SHdr * sh = (RElf64SHdr *)(base + eh->shoff + (rsize)i * eh->shentsize);
    r_elf_swap_shdr64 (sh);
    r_elf_normalize_section64 (base, size, sh);
  }

  /* A section-less image (e.g. a core dump) carries notes only in PT_NOTE
   * segments; with sections present, those bytes alias a NOTE section already
   * normalized above, so only swap segment notes when there are no sections. */
  if (eh->shnum == 0) {
    for (i = 0; i < eh->phnum; i++) {
      RElf64PHdr * ph = (RElf64PHdr *)(base + eh->phoff + (rsize)i * eh->phentsize);
      if (ph->type == R_ELF_PTYPE_NOTE && ph->offset <= size &&
          size - ph->offset >= ph->filesz)
        r_elf_normalize_notes (base + ph->offset, ph->filesz);
    }
  }
}

/* Swap a non-native ELF (already copied to private memory) to host order:
 * header first, then validate, then the program/section tables and the
 * fixed-layout entries they describe.  Returns the elf index or -1. */
static int
r_elf_normalize_copy (rpointer mem, rsize size)
{
  ruint8 * ident = mem;
  int elfidx;

  switch (ident[R_ELF_IDX_CLASS]) {
    case R_ELF_CLASS32:
      r_elf_swap_ehdr32 (mem);
      break;
    case R_ELF_CLASS64:
      r_elf_swap_ehdr64 (mem);
      break;
    default:
      return -1;
  }

  if ((elfidx = _check_elf_header (mem, size)) < 0)
    return -1;

  if (elfidx == RELF32_IDX)
    r_elf_normalize_tables32 (mem, size);
  else
    r_elf_normalize_tables64 (mem, size);

  return elfidx;
}

/* Validate the ELF at @mem and pick the memory the parser should read from.
 * Native-endianness ELFs are used in place (no copy); non-native ones are
 * copied to private, owned memory normalized to host order. */
static int
r_elf_parser_prepare (rpointer mem, rsize size, rpointer * out_mem,
    rboolean * out_owns)
{
  ruint8 * ident = mem;

  *out_mem = mem;
  *out_owns = FALSE;

  if (size < R_ELF_NIDENT || mem == NULL)
    return -1;
  if (!(ident[R_ELF_IDX_MAG0] == R_ELF_MAG0 && ident[R_ELF_IDX_MAG1] == R_ELF_MAG1 &&
        ident[R_ELF_IDX_MAG2] == R_ELF_MAG2 && ident[R_ELF_IDX_MAG3] == R_ELF_MAG3))
    return -1;

  if (!r_elf_data_needs_swap (ident[R_ELF_IDX_DATA]))
    return _check_elf_header (mem, size);

  {
    rpointer copy = r_memdup (mem, size);
    int elfidx;

    if (R_UNLIKELY (copy == NULL))
      return -1;
    if ((elfidx = r_elf_normalize_copy (copy, size)) < 0) {
      r_free (copy);
      return -1;
    }
    *out_mem = copy;
    *out_owns = TRUE;
    return elfidx;
  }
}

static RElfParser *
r_elf_parser_new_from_mem_file (RMemFile * file)
{
  RElfParser * ret = NULL;
  int elfidx;

  if (file != NULL) {
    rpointer mem = r_mem_file_get_mem (file);
    rsize size = r_mem_file_get_size (file);
    rpointer pmem;
    rboolean owns;

    if ((elfidx = r_elf_parser_prepare (mem, size, &pmem, &owns)) >= 0) {
      if (R_LIKELY (ret = r_mem_new (RElfParser))) {
        r_atomic_uint_store (&ret->refcount, 1);
        ret->file = owns ? NULL : r_mem_file_ref (file);
        ret->mem = pmem;
        ret->owns_mem = owns;
        ret->size = size;
        ret->elfidx = elfidx;
      } else if (owns) {
        r_free (pmem);
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
r_elf_parser_new_from_handle (RIOHandle handle)
{
  RElfParser * ret = NULL;
  RMemFile * file;

  file = r_mem_file_new_from_handle (handle, R_MEM_PROT_READ|R_MEM_PROT_WRITE, FALSE);
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
  rpointer pmem;
  rboolean owns;

  if ((elfidx = r_elf_parser_prepare (mem, size, &pmem, &owns)) >= 0) {
    if (R_LIKELY (ret = r_mem_new (RElfParser))) {
      r_atomic_uint_store (&ret->refcount, 1);
      ret->file = NULL;
      ret->mem = pmem;
      ret->owns_mem = owns;
      ret->size = size;
      ret->elfidx = elfidx;
    } else if (owns) {
      r_free (pmem);
    }
  }

  return ret;
}

static void
r_elf_parser_free (RElfParser * parser)
{
  if (parser->owns_mem)
    r_free (parser->mem);
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
  return ehdr != NULL ? ehdr->phnum : 0;
}

static ruint16
r_elf_parser_ehdr64_prg_header_count (RElfParser * parser)
{
  RElf64EHdr * ehdr = r_elf_parser_get_ehdr64 (parser);
  return ehdr != NULL ? ehdr->phnum : 0;
}

ruint16
r_elf_parser_prg_header_count (RElfParser * parser)
{
  switch (parser->elfidx) {
    case RELF32_IDX: return r_elf_parser_ehdr32_prg_header_count (parser);
    case RELF64_IDX: return r_elf_parser_ehdr64_prg_header_count (parser);
  }
  return 0;
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
  ptr += (rsize)ehdr->phentsize * idx;
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
  ptr += (rsize)ehdr->phentsize * idx;
  return (RElf64PHdr *)ptr;
}

rpointer
r_elf_parser_get_prg_header_table (RElfParser * parser)
{
  switch (parser->elfidx) {
    case RELF32_IDX: return r_elf_parser_get_phdr32 (parser, 0);
    case RELF64_IDX: return r_elf_parser_get_phdr64 (parser, 0);
  }
  return NULL;
}

ruint32
r_elf_parser_get_base_addr32 (RElfParser * parser)
{
  ruint16 i, count = r_elf_parser_ehdr32_prg_header_count (parser);

  for (i = 0; i < count; i++) {
    RElf32PHdr * hdr = r_elf_parser_get_phdr32 (parser, i);
    if (hdr->type == R_ELF_PTYPE_LOAD)
      return hdr->vaddr;
  }

  return 0;
}

ruint64
r_elf_parser_get_base_addr64 (RElfParser * parser)
{
  ruint16 i, count = r_elf_parser_ehdr64_prg_header_count (parser);

  for (i = 0; i < count; i++) {
    RElf64PHdr * hdr = r_elf_parser_get_phdr64 (parser, i);
    if (hdr->type == R_ELF_PTYPE_LOAD)
      return hdr->vaddr;
  }

  return 0;
}

RElf32PHdr *
r_elf_parser_find_phdr32_by_type (RElfParser * parser, ruint32 type)
{
  RElf32EHdr * ehdr;

  if ((ehdr = r_elf_parser_get_ehdr32 (parser)) != NULL) {
    ruint16 i;
    for (i = 0; i < ehdr->phnum; i++) {
      RElf32PHdr * hdr = r_elf_parser_get_phdr32 (parser, i);
      if (hdr != NULL && hdr->type == type)
        return hdr;
    }
  }

  return NULL;
}

RElf64PHdr *
r_elf_parser_find_phdr64_by_type (RElfParser * parser, ruint32 type)
{
  RElf64EHdr * ehdr;

  if ((ehdr = r_elf_parser_get_ehdr64 (parser)) != NULL) {
    ruint16 i;
    for (i = 0; i < ehdr->phnum; i++) {
      RElf64PHdr * hdr = r_elf_parser_get_phdr64 (parser, i);
      if (hdr != NULL && hdr->type == type)
        return hdr;
    }
  }

  return NULL;
}

rpointer
r_elf_parser_phdr32_get_data (RElfParser * parser, RElf32PHdr * phdr, rsize * size)
{
  if (parser != NULL && phdr != NULL && phdr->offset <= parser->size &&
      parser->size - phdr->offset >= phdr->filesz) {
    if (size != NULL)
      *size = phdr->filesz;
    return (ruint8 *)parser->mem + phdr->offset;
  }

  if (size != NULL)
    *size = 0;
  return NULL;
}

rpointer
r_elf_parser_phdr64_get_data (RElfParser * parser, RElf64PHdr * phdr, rsize * size)
{
  if (parser != NULL && phdr != NULL && phdr->offset <= parser->size &&
      parser->size - phdr->offset >= phdr->filesz) {
    if (size != NULL)
      *size = phdr->filesz;
    return (ruint8 *)parser->mem + phdr->offset;
  }

  if (size != NULL)
    *size = 0;
  return NULL;
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
  switch (parser->elfidx) {
    case RELF32_IDX: return r_elf_parser_ehdr32_section_header_count (parser);
    case RELF64_IDX: return r_elf_parser_ehdr64_section_header_count (parser);
  }
  return 0;
}

rpointer
r_elf_parser_get_section_header_table (RElfParser * parser)
{
  switch (parser->elfidx) {
    case RELF32_IDX: return r_elf_parser_get_shdr32 (parser, 0);
    case RELF64_IDX: return r_elf_parser_get_shdr64 (parser, 0);
  }
  return NULL;
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
  ptr += (rsize)ehdr->shentsize * idx;
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
  ptr += (rsize)ehdr->shentsize * idx;
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

RElf32SHdr *
r_elf_parser_find_shdr32_by_type (RElfParser * parser, ruint32 type)
{
  RElf32EHdr * ehdr;

  if ((ehdr = r_elf_parser_get_ehdr32 (parser)) != NULL) {
    ruint16 i;
    ruint8 * ptr = parser->mem;
    ptr += ehdr->shoff;

    for (i = 0; i < ehdr->shnum; i++) {
      RElf32SHdr * shdr = (RElf32SHdr *)(ptr + ehdr->shentsize * i);
      if (shdr->type == type) return shdr;
    }
  }

  return NULL;
}

RElf64SHdr *
r_elf_parser_find_shdr64_by_type (RElfParser * parser, ruint32 type)
{
  RElf64EHdr * ehdr;

  if ((ehdr = r_elf_parser_get_ehdr64 (parser)) != NULL) {
    ruint16 i;
    ruint8 * ptr = parser->mem;
    ptr += ehdr->shoff;

    for (i = 0; i < ehdr->shnum; i++) {
      RElf64SHdr * shdr = (RElf64SHdr *)(ptr + ehdr->shentsize * i);
      if (shdr->type == type) return shdr;
    }
  }

  return NULL;
}

RElf32SHdr *
r_elf_parser_find_reloc_shdr32 (RElfParser * parser, ruint32 secidx)
{
  RElf32EHdr * ehdr;

  if (secidx != R_ELF_SHN_UNDEF &&
      (ehdr = r_elf_parser_get_ehdr32 (parser)) != NULL) {
    ruint16 i;
    ruint8 * ptr = parser->mem;
    ptr += ehdr->shoff;

    for (i = 0; i < ehdr->shnum; i++) {
      RElf32SHdr * shdr = (RElf32SHdr *)(ptr + ehdr->shentsize * i);
      if ((shdr->type == R_ELF_STYPE_REL || shdr->type == R_ELF_STYPE_RELA) &&
          shdr->info == secidx)
        return shdr;
    }
  }

  return NULL;
}

RElf64SHdr *
r_elf_parser_find_reloc_shdr64 (RElfParser * parser, ruint32 secidx)
{
  RElf64EHdr * ehdr;

  if (secidx != R_ELF_SHN_UNDEF &&
      (ehdr = r_elf_parser_get_ehdr64 (parser)) != NULL) {
    ruint16 i;
    ruint8 * ptr = parser->mem;
    ptr += ehdr->shoff;

    for (i = 0; i < ehdr->shnum; i++) {
      RElf64SHdr * shdr = (RElf64SHdr *)(ptr + ehdr->shentsize * i);
      if ((shdr->type == R_ELF_STYPE_REL || shdr->type == R_ELF_STYPE_RELA) &&
          shdr->info == secidx)
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
  switch (parser->elfidx) {
    case RELF32_IDX: return r_elf_parser_find_shdr32_data (parser, name, size, secsize);
    case RELF64_IDX: return r_elf_parser_find_shdr64_data (parser, name, size, secsize);
  }
  return NULL;
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
  switch (parser->elfidx) {
    case RELF32_IDX: return r_elf_parser_ehdr32_strtbl_idx (parser);
    case RELF64_IDX: return r_elf_parser_ehdr64_strtbl_idx (parser);
  }
  return 0;
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
  switch (parser->elfidx) {
    case RELF32_IDX: return r_elf_parser_strtbl32_get_str (parser, NULL, idx);
    case RELF64_IDX: return r_elf_parser_strtbl64_get_str (parser, NULL, idx);
  }
  return NULL;
}

rchar *
r_elf_parser_strtbl32_get_str (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx)
{
  if (R_UNLIKELY (parser == NULL)) return NULL;
  if (shdr == NULL) {
    if ((shdr = r_elf_parser_get_strtbl32 (parser)) == NULL)
      return NULL;
  }
  if (shdr->type != R_ELF_STYPE_STRTAB)
    return NULL;

  if (R_UNLIKELY (shdr->offset > parser->size ||
        shdr->size > parser->size - shdr->offset ||
        idx >= shdr->size))
    return NULL;

  return (rchar *)parser->mem + shdr->offset + idx;
}

rchar *
r_elf_parser_strtbl64_get_str (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx)
{
  if (R_UNLIKELY (parser == NULL)) return NULL;
  if (shdr == NULL) {
    if ((shdr = r_elf_parser_get_strtbl64 (parser)) == NULL)
      return NULL;
  }
  if (shdr->type != R_ELF_STYPE_STRTAB)
    return NULL;

  if (R_UNLIKELY (shdr->offset > parser->size ||
        shdr->size > parser->size - shdr->offset ||
        idx >= shdr->size))
    return NULL;

  return (rchar *)parser->mem + shdr->offset + idx;
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

RElf32Sym *
r_elf_parser_symtbl32_find_sym_by_name (RElfParser * parser,
    RElf32SHdr * shdr, const rchar * name, rssize size)
{
  ruint32 i, c;

  if (R_UNLIKELY (parser == NULL || shdr == NULL || name == NULL)) return NULL;

  c = r_elf_parser_symtbl32_sym_count (parser, shdr);
  for (i = 0; i < c; i++) {
    RElf32Sym * sym = r_elf_parser_symtbl32_get_sym (parser, shdr, i);
    const rchar * sname;
    if (sym == NULL) continue;
    sname = r_elf_parser_symtbl32_sym32_get_name (parser, shdr, sym);
    if (sname != NULL && r_strcmp_size (sname, -1, name, size) == 0)
      return sym;
  }
  return NULL;
}

RElf64Sym *
r_elf_parser_symtbl64_find_sym_by_name (RElfParser * parser,
    RElf64SHdr * shdr, const rchar * name, rssize size)
{
  ruint64 i, c;

  if (R_UNLIKELY (parser == NULL || shdr == NULL || name == NULL)) return NULL;

  c = r_elf_parser_symtbl64_sym_count (parser, shdr);
  for (i = 0; i < c; i++) {
    RElf64Sym * sym = r_elf_parser_symtbl64_get_sym (parser, shdr, i);
    const rchar * sname;
    if (sym == NULL) continue;
    sname = r_elf_parser_symtbl64_sym64_get_name (parser, shdr, sym);
    if (sname != NULL && r_strcmp_size (sname, -1, name, size) == 0)
      return sym;
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


ruint32
r_elf_parser_reltbl32_rel_count (RElfParser * parser, RElf32SHdr * shdr)
{
  if (parser != NULL && shdr != NULL && shdr->entsize >= sizeof (RElf32Rel) &&
      shdr->type == R_ELF_STYPE_REL)
    return shdr->size / shdr->entsize;

  return 0;
}

ruint64
r_elf_parser_reltbl64_rel_count (RElfParser * parser, RElf64SHdr * shdr)
{
  if (parser != NULL && shdr != NULL && shdr->entsize >= sizeof (RElf64Rel) &&
      shdr->type == R_ELF_STYPE_REL)
    return shdr->size / shdr->entsize;

  return 0;
}

RElf32Rel *
r_elf_parser_reltbl32_get_rel (RElfParser * parser, RElf32SHdr * shdr, ruint32 idx)
{
  ruint32 count = r_elf_parser_reltbl32_rel_count (parser, shdr);
  if (count > idx) {
    ruint8 * mem = parser->mem;
    return (RElf32Rel *)(mem + shdr->offset + shdr->entsize * idx);
  }

  return NULL;
}

RElf64Rel *
r_elf_parser_reltbl64_get_rel (RElfParser * parser, RElf64SHdr * shdr, ruint64 idx)
{
  ruint64 count = r_elf_parser_reltbl64_rel_count (parser, shdr);
  if (count > idx) {
    ruint8 * mem = parser->mem;
    return (RElf64Rel *)(mem + shdr->offset + shdr->entsize * idx);
  }

  return NULL;
}

RElf32Sym *
r_elf_parser_rel32_get_sym (RElfParser * parser, RElf32SHdr * shdr,
    RElf32Rel * rel, RElf32SHdr ** symtbl)
{
  RElf32SHdr * stbl;

  if (shdr != NULL && shdr->link != R_ELF_SHN_UNDEF) {
    if ((stbl = r_elf_parser_get_shdr32 (parser, shdr->link)) != NULL) {
      ruint32 symidx;
      if (symtbl != NULL)
        *symtbl = stbl;

      if (rel != NULL && (symidx = R_ELF32_RELINFO_SYM (rel->info)) > 0)
        return r_elf_parser_symtbl32_get_sym (parser, stbl, symidx);
    }
  }

  if (symtbl != NULL)
    *symtbl = NULL;
  return NULL;
}

RElf64Sym *
r_elf_parser_rel64_get_sym (RElfParser * parser, RElf64SHdr * shdr,
    RElf64Rel * rel, RElf64SHdr ** symtbl)
{
  RElf64SHdr * stbl;

  if (shdr != NULL && shdr->link != R_ELF_SHN_UNDEF) {
    if ((stbl = r_elf_parser_get_shdr64 (parser, shdr->link)) != NULL) {
      ruint64 symidx;
      if (symtbl != NULL)
        *symtbl = stbl;

      if (rel != NULL && (symidx = R_ELF64_RELINFO_SYM (rel->info)) > 0)
        return r_elf_parser_symtbl64_get_sym (parser, stbl, symidx);
    }
  }

  if (symtbl != NULL)
    *symtbl = NULL;
  return NULL;
}

ruint32 *
r_elf_parser_rel32_get_dst (RElfParser * parser,
    RElf32SHdr * shdr, RElf32Rel * rel)
{
  if (parser != NULL && shdr != NULL && rel != NULL) {
    if (shdr->flags & R_ELF_SFLAGS_ALLOC) {
      return RUINT_TO_POINTER (rel->offset);
    } else {
      if (shdr->info != R_ELF_SHN_UNDEF) {
        return (ruint32 *)((ruint8 *)r_elf_parser_shdr32_get_data_by_idx (parser,
              shdr->info, NULL) + rel->offset);
      }
    }
  }

  return NULL;
}

ruint64 *
r_elf_parser_rel64_get_dst (RElfParser * parser,
    RElf64SHdr * shdr, RElf64Rel * rel)
{
  if (parser != NULL && shdr != NULL && rel != NULL) {
    if (shdr->flags & R_ELF_SFLAGS_ALLOC) {
      return RUINT_TO_POINTER (rel->offset);
    } else {
      if (shdr->info != R_ELF_SHN_UNDEF) {
        return (ruint64 *)((ruint8 *)r_elf_parser_shdr64_get_data_by_idx (parser,
              shdr->info, NULL) + rel->offset);
      }
    }
  }

  return NULL;
}
