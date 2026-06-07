#include <rlib/rbinfmt.h>
#include "elfobj.inc"

/* Endianness-independent field writers, selecting big- or little-endian
 * stores so the same builder can emit either byte order. */
static void w16 (ruint8 * p, rboolean be, rsize v)
{ if (be) r_store_be16 (p, (ruint16) v); else r_store_le16 (p, (ruint16) v); }
static void w32 (ruint8 * p, rboolean be, rsize v)
{ if (be) r_store_be32 (p, (ruint32) v); else r_store_le32 (p, (ruint32) v); }
static void w64 (ruint8 * p, rboolean be, ruint64 v)
{ if (be) r_store_be64 (p, v); else r_store_le64 (p, v); }

static void
wr_shdr64 (ruint8 * p, rboolean be, ruint32 name, ruint32 type, ruint64 flags,
    ruint64 addr, ruint64 offset, ruint64 size, ruint32 link, ruint32 info,
    ruint64 addralign, ruint64 entsize)
{
  w32 (p +  0, be, name);   w32 (p +  4, be, type);  w64 (p +  8, be, flags);
  w64 (p + 16, be, addr);   w64 (p + 24, be, offset); w64 (p + 32, be, size);
  w32 (p + 40, be, link);   w32 (p + 44, be, info);  w64 (p + 48, be, addralign);
  w64 (p + 56, be, entsize);
}

/* Build a minimal but self-consistent ELF64 (1 PT_LOAD segment; .text /
 * .symtab / .rela.text / .strtab / .shstrtab sections) in @p buf, encoded in
 * the byte order named by @p data.  Returns the image size.  Used as an
 * independent oracle for the parser's endianness normalization. */
static rsize
build_min_elf64 (ruint8 * buf, ruint8 data)
{
  const rboolean be = (data == R_ELF_DATA2MSB);
  static const rchar shstr[] =
      "\0.text\0.symtab\0.rela.text\0.rel.text\0.note.test\0.strtab\0.shstrtab";
  static const rchar symstr[] = "\0rfunc";
  static const rchar note_name[] = "GNU";              /* sizeof == 4 (w/ NUL) */
  static const ruint8 note_desc[] = { 0xde, 0xad, 0xbe, 0xef };
  const ruint32 n_text = 1, n_symtab = 7, n_rela = 15, n_rel = 26,
      n_note = 36, n_strtab = 47, n_shstrtab = 55; /* name offsets within shstr */
  const rsize note_sz =
      sizeof (RElf64NHdr) + sizeof (note_name) + sizeof (note_desc);
  rsize off_ph, off_text, off_shstr, off_symstr, off_symtab, off_rela, off_rel,
      off_note, off_sht;
  rsize cur;
  ruint8 * p;

  cur = sizeof (RElf64EHdr);
  off_ph = cur;     cur += 2 * sizeof (RElf64PHdr);   /* PT_LOAD + PT_NOTE */
  off_text = cur;   cur += 4;
  off_shstr = cur;  cur += sizeof (shstr);
  off_symstr = cur; cur += sizeof (symstr);
  cur = (cur + 7) & ~(rsize)7;
  off_symtab = cur; cur += 2 * sizeof (RElf64Sym);
  off_rela = cur;   cur += sizeof (RElf64Rela);
  off_rel = cur;    cur += sizeof (RElf64Rel);
  off_note = cur;   cur += note_sz;
  cur = (cur + 7) & ~(rsize)7;
  off_sht = cur;    cur += 8 * sizeof (RElf64SHdr);

  r_memset (buf, 0, cur);

  /* ELF header */
  buf[R_ELF_IDX_MAG0] = R_ELF_MAG0; buf[R_ELF_IDX_MAG1] = R_ELF_MAG1;
  buf[R_ELF_IDX_MAG2] = R_ELF_MAG2; buf[R_ELF_IDX_MAG3] = R_ELF_MAG3;
  buf[R_ELF_IDX_CLASS] = R_ELF_CLASS64;
  buf[R_ELF_IDX_DATA] = data;
  buf[R_ELF_IDX_VERSION] = R_ELF_VER_CURRENT;
  w16 (buf + 16, be, R_ELF_ETYPE_REL);      /* type */
  w16 (buf + 18, be, R_ELF_MACHINE_X86_64); /* machine */
  w32 (buf + 20, be, R_ELF_VER_CURRENT);    /* version */
  w64 (buf + 24, be, 0);                    /* entry */
  w64 (buf + 32, be, off_ph);               /* phoff */
  w64 (buf + 40, be, off_sht);              /* shoff */
  w32 (buf + 48, be, 0);                    /* flags */
  w16 (buf + 52, be, sizeof (RElf64EHdr));  /* ehsize */
  w16 (buf + 54, be, sizeof (RElf64PHdr));  /* phentsize */
  w16 (buf + 56, be, 2);                    /* phnum */
  w16 (buf + 58, be, sizeof (RElf64SHdr));  /* shentsize */
  w16 (buf + 60, be, 8);                    /* shnum */
  w16 (buf + 62, be, 7);                    /* shstrndx */

  /* Program header (PT_LOAD) */
  p = buf + off_ph;
  w32 (p +  0, be, R_ELF_PTYPE_LOAD);       /* type */
  w32 (p +  4, be, R_ELF_PFLAGS_R | R_ELF_PFLAGS_X); /* flags */
  w64 (p +  8, be, 0);                      /* offset */
  w64 (p + 16, be, 0x400000);               /* vaddr */
  w64 (p + 24, be, 0x400000);               /* paddr */
  w64 (p + 32, be, cur);                    /* filesz */
  w64 (p + 40, be, cur);                    /* memsz */
  w64 (p + 48, be, 0x1000);                 /* align */

  /* Program header (PT_NOTE) aliasing the .note.test section bytes */
  p = buf + off_ph + sizeof (RElf64PHdr);
  w32 (p +  0, be, R_ELF_PTYPE_NOTE);       /* type */
  w32 (p +  4, be, R_ELF_PFLAGS_R);         /* flags */
  w64 (p +  8, be, off_note);               /* offset */
  w64 (p + 16, be, 0);                      /* vaddr */
  w64 (p + 24, be, 0);                      /* paddr */
  w64 (p + 32, be, note_sz);                /* filesz */
  w64 (p + 40, be, note_sz);                /* memsz */
  w64 (p + 48, be, 4);                      /* align */

  /* .text */
  r_memset (buf + off_text, 0x90, 4);

  /* string tables */
  r_memcpy (buf + off_shstr, shstr, sizeof (shstr));
  r_memcpy (buf + off_symstr, symstr, sizeof (symstr));

  /* .symtab: [0] = undefined, [1] = GLOBAL FUNC "rfunc" */
  p = buf + off_symtab + sizeof (RElf64Sym);
  w32 (p +  0, be, 1);                      /* name -> "rfunc" */
  p[4] = R_ELF_SYMINFO_CREATE (R_ELF_SYMBIND_GLOBAL, R_ELF_SYMTYPE_FUNC);
  p[5] = R_ELF_SYMOTHER_DEFAULT;
  w16 (p +  6, be, 1);                      /* shndx -> .text */
  w64 (p +  8, be, 0x100);                  /* value */
  w64 (p + 16, be, 0x20);                   /* size */

  /* .rela.text: one entry against symbol 1, negative addend */
  p = buf + off_rela;
  w64 (p +  0, be, 0x4);                                    /* offset */
  w64 (p +  8, be, ((ruint64) 1 << 32) | R_ELF_RELTYPE_X86_64_64); /* info */
  w64 (p + 16, be, (ruint64) (rint64) -8);                 /* addend */

  /* .rel.text: one entry against symbol 1 (no addend) */
  p = buf + off_rel;
  w64 (p +  0, be, 0x8);                                    /* offset */
  w64 (p +  8, be, ((ruint64) 1 << 32) | R_ELF_RELTYPE_X86_64_PC32); /* info */

  /* .note.test: one note (name "GNU", 4-byte descriptor) */
  p = buf + off_note;
  w32 (p + 0, be, sizeof (note_name));      /* namesz (incl. NUL) */
  w32 (p + 4, be, sizeof (note_desc));      /* descsz */
  w32 (p + 8, be, 1);                       /* type */
  r_memcpy (p + 12, note_name, sizeof (note_name));
  r_memcpy (p + 16, note_desc, sizeof (note_desc));

  /* section header table */
  wr_shdr64 (buf + off_sht + 0 * sizeof (RElf64SHdr), be,
      0, R_ELF_STYPE_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
  wr_shdr64 (buf + off_sht + 1 * sizeof (RElf64SHdr), be,
      n_text, R_ELF_STYPE_PROGBITS, R_ELF_SFLAGS_ALLOC | R_ELF_SFLAGS_EXECINSTR,
      0, off_text, 4, 0, 0, 1, 0);
  wr_shdr64 (buf + off_sht + 2 * sizeof (RElf64SHdr), be,
      n_symtab, R_ELF_STYPE_SYMTAB, 0, 0, off_symtab, 2 * sizeof (RElf64Sym),
      6, 1, 8, sizeof (RElf64Sym));
  wr_shdr64 (buf + off_sht + 3 * sizeof (RElf64SHdr), be,
      n_rela, R_ELF_STYPE_RELA, R_ELF_SFLAGS_INFO_LINK, 0, off_rela,
      sizeof (RElf64Rela), 2, 1, 8, sizeof (RElf64Rela));
  wr_shdr64 (buf + off_sht + 4 * sizeof (RElf64SHdr), be,
      n_rel, R_ELF_STYPE_REL, R_ELF_SFLAGS_INFO_LINK, 0, off_rel,
      sizeof (RElf64Rel), 2, 1, 8, sizeof (RElf64Rel));
  wr_shdr64 (buf + off_sht + 5 * sizeof (RElf64SHdr), be,
      n_note, R_ELF_STYPE_NOTE, 0, 0, off_note, note_sz, 0, 0, 4, 0);
  wr_shdr64 (buf + off_sht + 6 * sizeof (RElf64SHdr), be,
      n_strtab, R_ELF_STYPE_STRTAB, 0, 0, off_symstr, sizeof (symstr),
      0, 0, 1, 0);
  wr_shdr64 (buf + off_sht + 7 * sizeof (RElf64SHdr), be,
      n_shstrtab, R_ELF_STYPE_STRTAB, 0, 0, off_shstr, sizeof (shstr),
      0, 0, 1, 0);

  return cur;
}

/* Build a section-less ELF64 (core-dump style) whose only structure is a
 * single PT_NOTE segment, in the byte order named by @p data.  Exercises the
 * segment-note normalization path, where no NOTE section aliases the bytes. */
static rsize
build_min_note_elf64 (ruint8 * buf, ruint8 data)
{
  const rboolean be = (data == R_ELF_DATA2MSB);
  static const rchar note_name[] = "CORE";   /* sizeof 5 -> 4-byte-padded to 8 */
  static const ruint8 note_desc[] = { 0x01, 0x02, 0x03, 0x04 };
  const rsize namepad = (sizeof (note_name) + 3) & ~(rsize)3;
  const rsize descpad = (sizeof (note_desc) + 3) & ~(rsize)3;
  const rsize note_sz = sizeof (RElf64NHdr) + namepad + descpad;
  rsize off_ph, off_note, cur;
  ruint8 * p;

  cur = sizeof (RElf64EHdr);
  off_ph = cur;     cur += sizeof (RElf64PHdr);
  off_note = cur;   cur += note_sz;

  r_memset (buf, 0, cur);

  buf[R_ELF_IDX_MAG0] = R_ELF_MAG0; buf[R_ELF_IDX_MAG1] = R_ELF_MAG1;
  buf[R_ELF_IDX_MAG2] = R_ELF_MAG2; buf[R_ELF_IDX_MAG3] = R_ELF_MAG3;
  buf[R_ELF_IDX_CLASS] = R_ELF_CLASS64;
  buf[R_ELF_IDX_DATA] = data;
  buf[R_ELF_IDX_VERSION] = R_ELF_VER_CURRENT;
  w16 (buf + 16, be, R_ELF_ETYPE_CORE);     /* type */
  w16 (buf + 18, be, R_ELF_MACHINE_X86_64); /* machine */
  w32 (buf + 20, be, R_ELF_VER_CURRENT);    /* version */
  w64 (buf + 32, be, off_ph);               /* phoff */
  w64 (buf + 40, be, 0);                    /* shoff (no sections) */
  w16 (buf + 52, be, sizeof (RElf64EHdr));  /* ehsize */
  w16 (buf + 54, be, sizeof (RElf64PHdr));  /* phentsize */
  w16 (buf + 56, be, 1);                    /* phnum */
  /* shentsize / shnum / shstrndx stay 0 */

  p = buf + off_ph;
  w32 (p +  0, be, R_ELF_PTYPE_NOTE);       /* type */
  w32 (p +  4, be, R_ELF_PFLAGS_R);         /* flags */
  w64 (p +  8, be, off_note);               /* offset */
  w64 (p + 32, be, note_sz);                /* filesz */
  w64 (p + 40, be, note_sz);                /* memsz */
  w64 (p + 48, be, 4);                      /* align */

  p = buf + off_note;
  w32 (p + 0, be, sizeof (note_name));      /* namesz */
  w32 (p + 4, be, sizeof (note_desc));      /* descsz */
  w32 (p + 8, be, R_ELF_NTYPE_PRSTATUS);    /* type */
  r_memcpy (p + 12, note_name, sizeof (note_name));
  r_memcpy (p + 12 + namepad, note_desc, sizeof (note_desc));

  return cur;
}

/* Build a shared-object-style ELF64 with a PT_DYNAMIC segment plus .dynamic /
 * .dynstr sections (DT_NEEDED, DT_SONAME, DT_STRTAB, DT_STRSZ, DT_NULL), in
 * the byte order named by @p data.  Returns the image size. */
static rsize
build_min_dyn_elf64 (ruint8 * buf, ruint8 data)
{
  const rboolean be = (data == R_ELF_DATA2MSB);
  static const rchar dynstr[] = "\0libc.so.6\0mylib.so";
  static const rchar shstr[] = "\0.dynstr\0.dynamic\0.shstrtab";
  const ruint32 n_needed = 1, n_soname = 11;          /* offsets in dynstr */
  const ruint32 n_dynstr = 1, n_dynamic = 9, n_shstrtab = 18; /* offsets in shstr */
  const rsize dynsz = 5 * sizeof (RElf64Dyn);
  rsize off_ph, off_dynstr, off_dyn, off_shstr, off_sht, cur;
  ruint8 * p;

  cur = sizeof (RElf64EHdr);
  off_ph = cur;     cur += sizeof (RElf64PHdr);
  off_dynstr = cur; cur += sizeof (dynstr);
  cur = (cur + 7) & ~(rsize)7;
  off_dyn = cur;    cur += dynsz;
  off_shstr = cur;  cur += sizeof (shstr);
  cur = (cur + 7) & ~(rsize)7;
  off_sht = cur;    cur += 4 * sizeof (RElf64SHdr);

  r_memset (buf, 0, cur);

  buf[R_ELF_IDX_MAG0] = R_ELF_MAG0; buf[R_ELF_IDX_MAG1] = R_ELF_MAG1;
  buf[R_ELF_IDX_MAG2] = R_ELF_MAG2; buf[R_ELF_IDX_MAG3] = R_ELF_MAG3;
  buf[R_ELF_IDX_CLASS] = R_ELF_CLASS64;
  buf[R_ELF_IDX_DATA] = data;
  buf[R_ELF_IDX_VERSION] = R_ELF_VER_CURRENT;
  w16 (buf + 16, be, R_ELF_ETYPE_DYN);      /* type */
  w16 (buf + 18, be, R_ELF_MACHINE_X86_64); /* machine */
  w32 (buf + 20, be, R_ELF_VER_CURRENT);    /* version */
  w64 (buf + 32, be, off_ph);               /* phoff */
  w64 (buf + 40, be, off_sht);              /* shoff */
  w16 (buf + 52, be, sizeof (RElf64EHdr));  /* ehsize */
  w16 (buf + 54, be, sizeof (RElf64PHdr));  /* phentsize */
  w16 (buf + 56, be, 1);                    /* phnum */
  w16 (buf + 58, be, sizeof (RElf64SHdr));  /* shentsize */
  w16 (buf + 60, be, 4);                    /* shnum */
  w16 (buf + 62, be, 3);                    /* shstrndx */

  /* Program header (PT_DYNAMIC) pointing at the .dynamic section */
  p = buf + off_ph;
  w32 (p +  0, be, R_ELF_PTYPE_DYNAMIC);    /* type */
  w32 (p +  4, be, R_ELF_PFLAGS_R | R_ELF_PFLAGS_W); /* flags */
  w64 (p +  8, be, off_dyn);                /* offset */
  w64 (p + 16, be, off_dyn);                /* vaddr */
  w64 (p + 24, be, off_dyn);                /* paddr */
  w64 (p + 32, be, dynsz);                  /* filesz */
  w64 (p + 40, be, dynsz);                  /* memsz */
  w64 (p + 48, be, 8);                      /* align */

  r_memcpy (buf + off_dynstr, dynstr, sizeof (dynstr));
  r_memcpy (buf + off_shstr, shstr, sizeof (shstr));

  /* .dynamic entries */
  p = buf + off_dyn;
  w64 (p +  0, be, R_ELF_DTYPE_NEEDED); w64 (p +  8, be, n_needed);
  w64 (p + 16, be, R_ELF_DTYPE_SONAME); w64 (p + 24, be, n_soname);
  w64 (p + 32, be, R_ELF_DTYPE_STRTAB); w64 (p + 40, be, off_dynstr);
  w64 (p + 48, be, R_ELF_DTYPE_STRSZ);  w64 (p + 56, be, sizeof (dynstr));
  w64 (p + 64, be, R_ELF_DTYPE_NULL);   w64 (p + 72, be, 0);

  /* section header table */
  wr_shdr64 (buf + off_sht + 0 * sizeof (RElf64SHdr), be,
      0, R_ELF_STYPE_NULL, 0, 0, 0, 0, 0, 0, 0, 0);
  wr_shdr64 (buf + off_sht + 1 * sizeof (RElf64SHdr), be,
      n_dynstr, R_ELF_STYPE_STRTAB, R_ELF_SFLAGS_ALLOC, 0, off_dynstr,
      sizeof (dynstr), 0, 0, 1, 0);
  wr_shdr64 (buf + off_sht + 2 * sizeof (RElf64SHdr), be,
      n_dynamic, R_ELF_STYPE_DYNAMIC, R_ELF_SFLAGS_WRITE | R_ELF_SFLAGS_ALLOC,
      0, off_dyn, dynsz, 1, 0, 8, sizeof (RElf64Dyn));
  wr_shdr64 (buf + off_sht + 3 * sizeof (RElf64SHdr), be,
      n_shstrtab, R_ELF_STYPE_STRTAB, 0, 0, off_shstr, sizeof (shstr),
      0, 0, 1, 0);

  return cur;
}

/* Assert the parser produced the known field values, regardless of the
 * source byte order. */
static void
verify_min_elf64 (RElfParser * parser)
{
  RElf64EHdr * eh;
  RElf64PHdr * ph;
  RElf64SHdr * sh, * symtbl = NULL;
  RElf64Sym * sym;
  RElf64Rela * rela;

  r_assert_cmpuint (r_elf_parser_get_class (parser), ==, R_ELF_CLASS64);

  r_assert_cmpptr ((eh = r_elf_parser_get_ehdr64 (parser)), !=, NULL);
  r_assert_cmpuint (eh->type, ==, R_ELF_ETYPE_REL);
  r_assert_cmpuint (eh->machine, ==, R_ELF_MACHINE_X86_64);
  r_assert_cmpuint (eh->phnum, ==, 2);
  r_assert_cmpuint (eh->shnum, ==, 8);
  r_assert_cmpuint (eh->shstrndx, ==, 7);

  r_assert_cmpptr ((ph = r_elf_parser_get_phdr64 (parser, 0)), !=, NULL);
  r_assert_cmpuint (ph->type, ==, R_ELF_PTYPE_LOAD);
  r_assert_cmpuint (ph->vaddr, ==, 0x400000);
  r_assert_cmpuint (ph->align, ==, 0x1000);
  r_assert_cmpptr (r_elf_parser_find_phdr64_by_type (parser, R_ELF_PTYPE_LOAD),
      ==, ph);
  r_assert_cmpptr (r_elf_parser_find_phdr64_by_type (parser, R_ELF_PTYPE_DYNAMIC),
      ==, NULL);
  r_assert_cmpptr (r_elf_parser_find_phdr32_by_type (parser, R_ELF_PTYPE_LOAD),
      ==, NULL);
  {
    rsize psz = 0;
    /* p_offset == 0, so the segment data starts at the ELF header. */
    r_assert_cmpptr (r_elf_parser_phdr64_get_data (parser, ph, &psz), ==,
        r_elf_parser_get_elf_header (parser));
    r_assert_cmpuint (psz, ==, ph->filesz);
  }

  r_assert_cmpptr ((sh = r_elf_parser_find_shdr64 (parser, ".text", -1)), !=, NULL);
  r_assert_cmpuint (sh->type, ==, R_ELF_STYPE_PROGBITS);
  r_assert_cmpuint (sh->size, ==, 4);

  r_assert_cmpptr ((sh = r_elf_parser_find_shdr64_by_type (parser,
        R_ELF_STYPE_SYMTAB)), !=, NULL);
  r_assert_cmpuint (r_elf_parser_symtbl64_sym_count (parser, sh), ==, 2);
  r_assert_cmpptr ((sym = r_elf_parser_symtbl64_get_sym (parser, sh, 1)), !=, NULL);
  r_assert_cmpstr (r_elf_parser_symtbl64_sym64_get_name (parser, sh, sym),
      ==, "rfunc");
  r_assert_cmpuint (sym->value, ==, 0x100);
  r_assert_cmpuint (sym->size, ==, 0x20);
  r_assert_cmpuint (R_ELF_SYMINFO_BIND (sym->info), ==, R_ELF_SYMBIND_GLOBAL);
  r_assert_cmpuint (R_ELF_SYMINFO_TYPE (sym->info), ==, R_ELF_SYMTYPE_FUNC);
  r_assert_cmpuint (sym->shndx, ==, 1);

  r_assert_cmpptr ((sh = r_elf_parser_find_shdr64_by_type (parser,
        R_ELF_STYPE_RELA)), !=, NULL);
  r_assert_cmpuint (r_elf_parser_relatbl64_rela_count (parser, sh), ==, 1);
  r_assert_cmpptr ((rela = r_elf_parser_relatbl64_get_rela (parser, sh, 0)), !=, NULL);
  r_assert_cmpuint (rela->offset, ==, 0x4);
  r_assert_cmpuint (R_ELF64_RELINFO_SYM (rela->info), ==, 1);
  r_assert_cmpuint (R_ELF64_RELINFO_TYPE (rela->info), ==, R_ELF_RELTYPE_X86_64_64);
  r_assert_cmpint (rela->addend, ==, -8);
  r_assert_cmpptr ((sym = r_elf_parser_rela64_get_sym (parser, sh, rela, &symtbl)),
      !=, NULL);
  r_assert_cmpstr (r_elf_parser_symtbl64_sym64_get_name (parser, symtbl, sym),
      ==, "rfunc");

  {
    RElf64Rel * rel;
    RElf64SHdr * relsymtbl = NULL;

    r_assert_cmpptr ((sh = r_elf_parser_find_shdr64_by_type (parser,
          R_ELF_STYPE_REL)), !=, NULL);
    r_assert_cmpuint (r_elf_parser_reltbl64_rel_count (parser, sh), ==, 1);
    r_assert_cmpptr ((rel = r_elf_parser_reltbl64_get_rel (parser, sh, 0)), !=, NULL);
    r_assert_cmpuint (rel->offset, ==, 0x8);
    r_assert_cmpuint (R_ELF64_RELINFO_SYM (rel->info), ==, 1);
    r_assert_cmpuint (R_ELF64_RELINFO_TYPE (rel->info), ==, R_ELF_RELTYPE_X86_64_PC32);
    r_assert_cmpptr ((sym = r_elf_parser_rel64_get_sym (parser, sh, rel, &relsymtbl)),
        !=, NULL);
    r_assert_cmpstr (r_elf_parser_symtbl64_sym64_get_name (parser, relsymtbl, sym),
        ==, "rfunc");
  }

  {
    RElf64NHdr * nhdr;
    ruint8 * desc;
    rsize dsize = 0;

    r_assert_cmpptr ((sh = r_elf_parser_find_shdr64_by_type (parser,
          R_ELF_STYPE_NOTE)), !=, NULL);
    r_assert_cmpuint (r_elf_parser_notetbl64_note_count (parser, sh), ==, 1);
    r_assert_cmpptr (r_elf_parser_notetbl64_get_note (parser, sh, 1), ==, NULL);
    r_assert_cmpptr ((nhdr = r_elf_parser_notetbl64_get_note (parser, sh, 0)),
        !=, NULL);
    r_assert_cmpuint (nhdr->namesz, ==, 4);
    r_assert_cmpuint (nhdr->descsz, ==, 4);
    r_assert_cmpuint (nhdr->type, ==, 1);
    r_assert_cmpstr (r_elf_nhdr64_get_name (nhdr), ==, "GNU");
    r_assert_cmpptr ((desc = r_elf_nhdr64_get_desc (nhdr, &dsize)),
        !=, NULL);
    r_assert_cmpuint (dsize, ==, 4);
    r_assert_cmpuint (desc[0], ==, 0xde);
    r_assert_cmpuint (desc[3], ==, 0xef);
  }

  /* The PT_NOTE segment aliases the .note.test section bytes; same note. */
  {
    RElf64PHdr * ph;
    RElf64NHdr * nhdr;

    r_assert_cmpptr ((ph = r_elf_parser_find_phdr64_by_type (parser,
          R_ELF_PTYPE_NOTE)), !=, NULL);
    r_assert_cmpuint (r_elf_parser_phdr64_note_count (parser, ph), ==, 1);
    r_assert_cmpptr ((nhdr = r_elf_parser_phdr64_get_note (parser, ph, 0)),
        !=, NULL);
    r_assert_cmpuint (nhdr->type, ==, 1);
    r_assert_cmpstr (r_elf_nhdr64_get_name (nhdr), ==, "GNU");
  }
}

RTEST (relf, endianness, RTEST_FAST)
{
  ruint8 le[1024], be[1024], be_copy[1024];
  RElfParser * parser;
  rsize sz_le, sz_be;

  sz_le = build_min_elf64 (le, R_ELF_DATA2LSB);
  sz_be = build_min_elf64 (be, R_ELF_DATA2MSB);
  r_assert_cmpuint (sz_le, ==, sz_be);
  r_memcpy (be_copy, be, sz_be);

  /* calc_size is endianness-aware and agrees across byte orders. */
  r_assert_cmpuint (r_elf_calc_size (le), ==, sz_le);
  r_assert_cmpuint (r_elf_calc_size (be), ==, sz_be);

  /* Native little-endian image: parsed in place, identical field values. */
  r_assert_cmpptr ((parser = r_elf_parser_new_from_mem (le, sz_le)), !=, NULL);
  r_assert_cmpuint (r_elf_parser_get_data (parser), ==, R_ELF_DATA2LSB);
  verify_min_elf64 (parser);
  r_elf_parser_unref (parser);

  /* Non-native big-endian image: normalized on a private copy, same values. */
  r_assert_cmpptr ((parser = r_elf_parser_new_from_mem (be, sz_be)), !=, NULL);
  r_assert_cmpuint (r_elf_parser_get_data (parser), ==, R_ELF_DATA2MSB);
  verify_min_elf64 (parser);
  r_elf_parser_unref (parser);

  /* The caller's big-endian buffer must be left untouched (we copy). */
  r_assert_cmpint (r_memcmp (be, be_copy, sz_be), ==, 0);
}
RTEST_END;

RTEST (relf, rel, RTEST_FAST)
{
  ruint8 buf[1024];
  RElfParser * parser;
  RElf64SHdr * sh;
  RElf64Rel * rel;
  rsize sz;

  sz = build_min_elf64 (buf, R_ELF_DATA2LSB);
  r_assert_cmpptr ((parser = r_elf_parser_new_from_mem (buf, sz)), !=, NULL);

  /* 32-bit accessors return nothing on a 64-bit ELF. */
  r_assert_cmpptr (r_elf_parser_find_shdr32_by_type (parser, R_ELF_STYPE_REL),
      ==, NULL);

  r_assert_cmpptr ((sh = r_elf_parser_find_shdr64_by_type (parser,
        R_ELF_STYPE_REL)), !=, NULL);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, sh), ==, ".rel.text");
  r_assert_cmpuint (sh->entsize, ==, sizeof (RElf64Rel));

  r_assert_cmpuint (r_elf_parser_reltbl64_rel_count (parser, sh), ==, 1);
  /* Out-of-range index must not return an entry. */
  r_assert_cmpptr (r_elf_parser_reltbl64_get_rel (parser, sh, 1), ==, NULL);
  r_assert_cmpptr ((rel = r_elf_parser_reltbl64_get_rel (parser, sh, 0)), !=, NULL);

  r_assert_cmpuint (rel->offset, ==, 0x8);
  r_assert_cmpuint (R_ELF64_RELINFO_SYM (rel->info), ==, 1);
  r_assert_cmpuint (R_ELF64_RELINFO_TYPE (rel->info), ==, R_ELF_RELTYPE_X86_64_PC32);

  /* dst points at the patched location in the linked (.text) section. */
  r_assert_cmpptr (r_elf_parser_rel64_get_dst (parser, sh, rel), ==,
      (ruint8 *)r_elf_parser_shdr64_get_data_by_idx (parser, sh->info, NULL)
        + rel->offset);

  /* The relocation section relocating .text (section index 1): both
   * .rela.text and .rel.text target it; the first in section order wins. */
  {
    RElf64SHdr * rsh;
    r_assert_cmpptr ((rsh = r_elf_parser_find_reloc_shdr64 (parser, 1)), !=, NULL);
    r_assert_cmpuint (rsh->info, ==, 1);
    r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, rsh), ==, ".rela.text");

    /* A section nothing relocates, the UNDEF index, and a wrong-class lookup
     * all return NULL. */
    r_assert_cmpptr (r_elf_parser_find_reloc_shdr64 (parser, 2), ==, NULL);
    r_assert_cmpptr (r_elf_parser_find_reloc_shdr64 (parser, 0), ==, NULL);
    r_assert_cmpptr (r_elf_parser_find_reloc_shdr32 (parser, 1), ==, NULL);
  }

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, note, RTEST_FAST)
{
  ruint8 buf[1024];
  RElfParser * parser;
  RElf64SHdr * sh, * text;
  RElf64NHdr * nhdr;
  rsize sz, dsize = 0;

  sz = build_min_elf64 (buf, R_ELF_DATA2LSB);
  r_assert_cmpptr ((parser = r_elf_parser_new_from_mem (buf, sz)), !=, NULL);

  r_assert_cmpptr ((sh = r_elf_parser_find_shdr64_by_type (parser,
        R_ELF_STYPE_NOTE)), !=, NULL);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, sh), ==, ".note.test");
  r_assert_cmpuint (r_elf_parser_notetbl64_note_count (parser, sh), ==, 1);
  r_assert_cmpptr ((nhdr = r_elf_parser_notetbl64_get_note (parser, sh, 0)),
      !=, NULL);
  r_assert_cmpstr (r_elf_nhdr64_get_name (nhdr), ==, "GNU");
  r_assert_cmpptr (r_elf_nhdr64_get_desc (nhdr, &dsize), !=, NULL);
  r_assert_cmpuint (dsize, ==, 4);

  /* 32-bit accessors on a 64-bit ELF yield nothing. */
  r_assert_cmpuint (r_elf_parser_notetbl32_note_count (parser,
        (RElf32SHdr *) sh), ==, 0);
  r_assert_cmpptr (r_elf_parser_notetbl32_get_note (parser,
        (RElf32SHdr *) sh, 0), ==, NULL);

  /* A non-NOTE section reports zero notes and no entry. */
  r_assert_cmpptr ((text = r_elf_parser_find_shdr64 (parser, ".text", -1)),
      !=, NULL);
  r_assert_cmpuint (r_elf_parser_notetbl64_note_count (parser, text), ==, 0);
  r_assert_cmpptr (r_elf_parser_notetbl64_get_note (parser, text, 0), ==, NULL);

  /* NULL inputs are rejected. */
  r_assert_cmpptr (r_elf_nhdr64_get_name (NULL), ==, NULL);
  r_assert_cmpptr (r_elf_nhdr64_get_desc (NULL, &dsize), ==, NULL);
  r_assert_cmpuint (dsize, ==, 0);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, note_segment, RTEST_FAST)
{
  ruint8 buf[256];
  int i;

  /* A section-less image exposes its notes only via the PT_NOTE segment; run
   * both byte orders so the segment-note normalization fallback is covered. */
  for (i = 0; i < 2; i++) {
    ruint8 enc = (i == 0) ? R_ELF_DATA2LSB : R_ELF_DATA2MSB;
    RElfParser * parser;
    RElf64PHdr * ph;
    RElf64NHdr * nhdr;
    ruint8 * desc;
    rsize dsize = 0;
    rsize sz = build_min_note_elf64 (buf, enc);

    r_assert_cmpptr ((parser = r_elf_parser_new_from_mem (buf, sz)), !=, NULL);
    r_assert_cmpuint (r_elf_parser_section_header_count (parser), ==, 0);
    r_assert_cmpptr ((ph = r_elf_parser_find_phdr64_by_type (parser,
          R_ELF_PTYPE_NOTE)), !=, NULL);
    r_assert_cmpuint (r_elf_parser_phdr64_note_count (parser, ph), ==, 1);
    r_assert_cmpptr ((nhdr = r_elf_parser_phdr64_get_note (parser, ph, 0)),
        !=, NULL);
    r_assert_cmpuint (nhdr->type, ==, R_ELF_NTYPE_PRSTATUS);
    r_assert_cmpstr (r_elf_nhdr64_get_name (nhdr), ==, "CORE");
    r_assert_cmpptr ((desc = r_elf_nhdr64_get_desc (nhdr, &dsize)), !=, NULL);
    r_assert_cmpuint (dsize, ==, 4);
    r_assert_cmpuint (desc[0], ==, 0x01);
    r_assert_cmpuint (desc[3], ==, 0x04);

    r_elf_parser_unref (parser);
  }
}
RTEST_END;

RTEST (relf, dynamic, RTEST_FAST)
{
  ruint8 buf[512];
  int i;

  /* Run both byte orders so DYNAMIC-entry normalization is covered. */
  for (i = 0; i < 2; i++) {
    ruint8 enc = (i == 0) ? R_ELF_DATA2LSB : R_ELF_DATA2MSB;
    RElfParser * parser;
    RElf64SHdr * dyn;
    RElf64Dyn * d;
    rsize sz = build_min_dyn_elf64 (buf, enc);

    r_assert_cmpptr ((parser = r_elf_parser_new_from_mem (buf, sz)), !=, NULL);

    r_assert_cmpptr ((dyn = r_elf_parser_find_shdr64_by_type (parser,
          R_ELF_STYPE_DYNAMIC)), !=, NULL);
    r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, dyn), ==, ".dynamic");
    r_assert_cmpuint (r_elf_parser_dyntbl64_dyn_count (parser, dyn), ==, 5);

    r_assert_cmpptr ((d = r_elf_parser_dyntbl64_get_dyn (parser, dyn, 0)),
        !=, NULL);
    r_assert_cmpint (d->tag, ==, R_ELF_DTYPE_NEEDED);
    /* Out-of-range index yields no entry. */
    r_assert_cmpptr (r_elf_parser_dyntbl64_get_dyn (parser, dyn, 5), ==, NULL);

    /* String-valued tags resolve through the linked .dynstr. */
    r_assert_cmpptr ((d = r_elf_parser_dyntbl64_find_dyn_by_tag (parser, dyn,
          R_ELF_DTYPE_SONAME)), !=, NULL);
    r_assert_cmpstr (r_elf_parser_dyn64_get_str (parser, dyn, d), ==, "mylib.so");
    r_assert_cmpptr ((d = r_elf_parser_dyntbl64_find_dyn_by_tag (parser, dyn,
          R_ELF_DTYPE_NEEDED)), !=, NULL);
    r_assert_cmpstr (r_elf_parser_dyn64_get_str (parser, dyn, d), ==, "libc.so.6");

    /* Integer-valued tag. */
    r_assert_cmpptr ((d = r_elf_parser_dyntbl64_find_dyn_by_tag (parser, dyn,
          R_ELF_DTYPE_STRSZ)), !=, NULL);
    r_assert_cmpuint (d->un.val, ==, 20);

    /* Absent tag and wrong-class lookups yield nothing. */
    r_assert_cmpptr (r_elf_parser_dyntbl64_find_dyn_by_tag (parser, dyn,
          R_ELF_DTYPE_RPATH), ==, NULL);
    r_assert_cmpuint (r_elf_parser_dyntbl32_dyn_count (parser,
          (RElf32SHdr *) dyn), ==, 0);

    /* PT_DYNAMIC segment is found too. */
    r_assert_cmpptr (r_elf_parser_find_phdr64_by_type (parser,
          R_ELF_PTYPE_DYNAMIC), !=, NULL);

    r_elf_parser_unref (parser);
  }
}
RTEST_END;

RTEST (relf, calc_size, RTEST_FAST)
{
  ruint8 bad_elf[] = { 0xBA, 0xDE, 0x1F, 0x01, 0xBA, 0xDE, 0x1F, 0x02 };
  r_assert (!r_elf_is_valid (bad_elf));
  r_assert_cmpuint (r_elf_calc_size (elf_o), ==, sizeof (elf_o));
}
RTEST_END;

RTEST (relf, from_mem, RTEST_FAST)
{
  RElfParser * parser;
  ruint8 bad_elf[] = { 0xBA, 0xDE, 0x1F, 0x01, 0xBA, 0xDE, 0x1F, 0x02,
                       0xBA, 0xDE, 0x1F, 0x03, 0xBA, 0xDE, 0x1F, 0x04 };

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);
  r_elf_parser_unref (parser);

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (bad_elf, sizeof (bad_elf))), ==, NULL);
}
RTEST_END;

RTEST (relf, ident, RTEST_FAST)
{
  RElfParser * parser;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpuint (r_elf_parser_get_class (parser), ==, R_ELF_CLASS64);
  r_assert_cmpuint (r_elf_parser_get_data (parser), ==, R_ELF_DATA2LSB);
  r_assert_cmpuint (r_elf_parser_get_version (parser), ==, R_ELF_VER_CURRENT);
  r_assert_cmpuint (r_elf_parser_get_osabi (parser), ==, R_ELF_OSABI_NONE);
  r_assert_cmpuint (r_elf_parser_get_abi_version (parser), ==, 0);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, ehdr, RTEST_FAST)
{
  RElfParser * parser;
  RElf64EHdr * hdr;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpptr (r_elf_parser_get_elf_header (parser), !=, NULL);
  r_assert_cmpptr (r_elf_parser_get_ehdr32 (parser), ==, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_get_ehdr64 (parser)), !=, NULL);

  r_assert_cmpuint (hdr->type, ==, R_ELF_ETYPE_REL);
  r_assert_cmpuint (hdr->machine, ==, R_ELF_MACHINE_X86_64);
  r_assert_cmpuint (hdr->version, ==, R_ELF_VER_CURRENT);
  r_assert_cmpuint (hdr->entry, ==, 0);
  r_assert_cmpuint (hdr->ehsize, ==, sizeof (RElf64EHdr));
  r_assert_cmpuint (hdr->phoff, ==, 0);
  r_assert_cmpuint (hdr->phentsize, ==, 0);
  r_assert_cmpuint (hdr->phnum, ==, 0);
  r_assert_cmpuint (hdr->shoff, ==, 2832);
  r_assert_cmpuint (hdr->shentsize, ==, 64);
  r_assert_cmpuint (hdr->shnum, ==, 19);
  r_assert_cmpuint (hdr->shstrndx, ==, 16);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, phdr, RTEST_FAST)
{
  RElfParser * parser;
  RElf64PHdr * hdr;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpuint (r_elf_parser_prg_header_count (parser), ==, 0);
  r_assert_cmpptr (r_elf_parser_get_prg_header_table (parser), ==, NULL);
  r_assert_cmpptr (r_elf_parser_get_phdr32 (parser, 0), ==, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_get_phdr64 (parser, 0)), ==, NULL);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, find_shdr, RTEST_FAST)
{
  RElfParser * parser;
  RElf64SHdr * hdr;
  ruint8 * data;
  rsize size;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpptr ((hdr = r_elf_parser_find_shdr64 (parser, "foobar", -1)), ==, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_find_shdr64 (parser, ".text", -1)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_PROGBITS);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".text");

  r_assert_cmpptr ((hdr = r_elf_parser_find_shdr64 (parser, ".data", -1)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_PROGBITS);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".data");

  r_assert_cmpptr ((data = r_elf_parser_find_section_data (parser,
          ".data", -1, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, 8);
  r_assert_cmpptr ((data = r_elf_parser_find_section_data (parser,
          ".text", -1, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, 323);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, shdr, RTEST_FAST)
{
  RElfParser * parser;
  RElf64SHdr * hdr;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpuint (r_elf_parser_section_header_count (parser), ==, 19);
  r_assert_cmpuint (r_elf_parser_strtbl_idx (parser), ==, 16);
  r_assert_cmpptr (r_elf_parser_get_section_header_table (parser), !=, NULL);
  r_assert_cmpptr (r_elf_parser_get_shdr32 (parser, 0), ==, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_get_shdr64 (parser, 19)), ==, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_get_shdr64 (parser, 0)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_NULL); /* Inactive section */

  r_assert_cmpptr ((hdr = r_elf_parser_get_shdr64 (parser, 1)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_PROGBITS);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".text");

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, strtbl, RTEST_FAST)
{
  RElfParser * parser;
  RElf64SHdr * hdr;
  rsize size;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);
  r_assert_cmpptr (r_elf_parser_get_strtbl32 (parser), ==, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_get_strtbl64 (parser)), !=, NULL);

  r_assert_cmpuint (hdr->name, ==, 17);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_STRTAB);
  r_assert_cmpuint (hdr->flags, ==, 0);
  r_assert_cmpuint (hdr->addr, ==, 0);
  r_assert_cmpuint (hdr->offset, ==, 936);
  r_assert_cmpuint (hdr->size, ==, 159);
  r_assert_cmpuint (hdr->link, ==, 0);
  r_assert_cmpuint (hdr->info, ==, 0);
  r_assert_cmpuint (hdr->addralign, ==, 1);
  r_assert_cmpuint (hdr->entsize, ==, 0);
  r_assert_cmpstr (r_elf_parser_strtbl_get_str (parser, hdr->name), ==, ".shstrtab");
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".shstrtab");
  r_assert_cmpptr (r_elf_parser_shdr64_get_data (parser, hdr, &size), ==, elf_o + hdr->offset);
  r_assert_cmpuint (size, ==, hdr->size);

  /* Index past the end of the strtab must not return an OOB pointer. */
  r_assert_cmpptr (r_elf_parser_strtbl64_get_str (parser, hdr, hdr->size), ==, NULL);
  r_assert_cmpptr (r_elf_parser_strtbl64_get_str (parser, hdr, RUINT64_MAX), ==, NULL);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, symtbl, RTEST_FAST)
{
  RElfParser * parser;
  RElf64SHdr * hdr;
  RElf64Sym * sym;
  rsize size;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpptr ((hdr = r_elf_parser_get_shdr64 (parser, 17)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_SYMTAB);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".symtab");
  r_assert_cmpuint (hdr->flags, ==, 0);
  r_assert_cmpuint (hdr->addr, ==, 0);
  r_assert_cmpuint (hdr->offset, ==, 1096);
  r_assert_cmpuint (hdr->size, ==, 600);
  r_assert_cmpuint (hdr->link, ==, 18);
  r_assert_cmpuint (hdr->info, ==, 15);
  r_assert_cmpuint (hdr->addralign, ==, 8);
  r_assert_cmpuint (hdr->entsize, ==, sizeof (RElf64Sym));

  r_assert_cmpuint (r_elf_parser_symtbl64_sym_count (parser, hdr), ==, 25);
  r_assert_cmpptr ((sym = r_elf_parser_symtbl64_get_sym (parser, hdr, 0)), !=, NULL);

  /* first symbol (idx 0) is undefined! */
  r_assert_cmpuint (sym->name, ==, 0);
  r_assert_cmpuint (sym->value, ==, 0);
  r_assert_cmpuint (sym->size, ==, 0);
  r_assert_cmpuint (sym->info, ==, 0);
  r_assert_cmpuint (sym->other, ==, 0);
  r_assert_cmpuint (sym->shndx, ==, 0);

  r_assert_cmpptr ((sym = r_elf_parser_symtbl64_get_sym (parser, hdr, 4)), !=, NULL);
  r_assert_cmpuint (sym->name, ==, 0);
  r_assert_cmpuint (sym->value, ==, 0);
  r_assert_cmpuint (sym->size, ==, 0);
  r_assert_cmpuint (R_ELF_SYMINFO_BIND (sym->info), ==, R_ELF_SYMBIND_LOCAL);
  r_assert_cmpuint (R_ELF_SYMINFO_TYPE (sym->info), ==, R_ELF_SYMTYPE_SECTION);
  r_assert_cmpuint (sym->other, ==, R_ELF_SYMOTHER_DEFAULT);
  r_assert_cmpuint (sym->shndx, ==, 5);

  /* First non LOCAL symbol */
  r_assert_cmpptr ((sym = r_elf_parser_symtbl64_get_sym (parser, hdr, hdr->info)), !=, NULL);
  r_assert_cmpuint (sym->name, ==, 47);
  r_assert_cmpstr (r_elf_parser_symtbl64_sym64_get_name (parser, hdr, sym),
      ==, "_r_test_mark_position");
  r_assert_cmpuint (sym->value, ==, 0);
  r_assert_cmpuint (sym->size, ==, 0);
  r_assert_cmpuint (R_ELF_SYMINFO_BIND (sym->info), ==, R_ELF_SYMBIND_GLOBAL);
  r_assert_cmpuint (R_ELF_SYMINFO_TYPE (sym->info), ==, R_ELF_SYMTYPE_NOTYPE);
  r_assert_cmpuint (sym->other, ==, R_ELF_SYMOTHER_DEFAULT);
  r_assert_cmpuint (sym->shndx, ==, 0);

  /* GLOBAL data/object symbol (hidden) */
  r_assert_cmpptr ((sym = r_elf_parser_symtbl64_get_sym (parser, hdr, 24)), !=, NULL);
  r_assert_cmpstr (r_elf_parser_symtbl64_sym64_get_name (parser, hdr, sym),
      ==, "__rtest_rrand_prng_data");
  r_assert_cmpuint (sym->value, ==, 0);
  r_assert_cmpuint (sym->size, ==, 128);
  r_assert_cmpuint (R_ELF_SYMINFO_BIND (sym->info), ==, R_ELF_SYMBIND_GLOBAL);
  r_assert_cmpuint (R_ELF_SYMINFO_TYPE (sym->info), ==, R_ELF_SYMTYPE_OBJECT);
  r_assert_cmpuint (sym->other, ==, R_ELF_SYMOTHER_HIDDEN);
  r_assert_cmpuint (sym->shndx, ==, 10);
  r_assert_cmpptr (r_elf_parser_symtbl64_sym64_get_data (parser, hdr, sym, &size), ==,
      r_elf_parser_shdr64_get_data (parser, r_elf_parser_get_shdr64 (parser, sym->shndx), NULL));
  r_assert_cmpuint (size, ==, sym->size);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, find_shdr_by_type, RTEST_FAST)
{
  /* The test ELF has a SYMTAB at idx 17, a RELA at idx 11, and a
   * STRTAB at idx 18 (linked from symtab).  find_shdr64_by_type
   * should return the first section of each type. */
  RElfParser * parser;
  RElf64SHdr * shdr;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpptr ((shdr = r_elf_parser_find_shdr64_by_type (parser,
        R_ELF_STYPE_SYMTAB)), !=, NULL);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, shdr), ==, ".symtab");
  r_assert_cmpptr (shdr, ==, r_elf_parser_get_shdr64 (parser, 17));

  r_assert_cmpptr ((shdr = r_elf_parser_find_shdr64_by_type (parser,
        R_ELF_STYPE_RELA)), !=, NULL);
  r_assert_cmpuint (shdr->type, ==, R_ELF_STYPE_RELA);

  /* No section of this type -> NULL. */
  r_assert_cmpptr (r_elf_parser_find_shdr64_by_type (parser,
        R_ELF_STYPE_DYNAMIC), ==, NULL);

  /* 32-bit lookup on a 64-bit ELF returns NULL too. */
  r_assert_cmpptr (r_elf_parser_find_shdr32_by_type (parser,
        R_ELF_STYPE_SYMTAB), ==, NULL);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, symtbl_find_by_name, RTEST_FAST)
{
  /* Walk the symtab section and resolve a known symbol name to the
   * exact entry that index lookup returns; verify the index-25 sym
   * "__rtest_rrand_prng_data" and the global hidden marker symbol
   * "_r_test_mark_position" round-trip cleanly. */
  RElfParser * parser;
  RElf64SHdr * hdr;
  RElf64Sym * sym;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_get_shdr64 (parser, 17)), !=, NULL);

  /* Match via -1 (strlen) and via explicit size. */
  r_assert_cmpptr ((sym = r_elf_parser_symtbl64_find_sym_by_name (parser, hdr,
        R_STR_WITH_SIZE_ARGS ("__rtest_rrand_prng_data"))), !=, NULL);
  r_assert_cmpptr (sym, ==, r_elf_parser_symtbl64_get_sym (parser, hdr, 24));

  r_assert_cmpptr ((sym = r_elf_parser_symtbl64_find_sym_by_name (parser, hdr,
        "_r_test_mark_position", -1)), !=, NULL);
  r_assert_cmpstr (r_elf_parser_symtbl64_sym64_get_name (parser, hdr, sym),
      ==, "_r_test_mark_position");

  /* Unknown name returns NULL. */
  r_assert_cmpptr (r_elf_parser_symtbl64_find_sym_by_name (parser, hdr,
        R_STR_WITH_SIZE_ARGS ("definitely_not_here")), ==, NULL);

  /* NULL inputs are rejected. */
  r_assert_cmpptr (r_elf_parser_symtbl64_find_sym_by_name (NULL, hdr,
        R_STR_WITH_SIZE_ARGS ("anything")), ==, NULL);
  r_assert_cmpptr (r_elf_parser_symtbl64_find_sym_by_name (parser, NULL,
        R_STR_WITH_SIZE_ARGS ("anything")), ==, NULL);
  r_assert_cmpptr (r_elf_parser_symtbl64_find_sym_by_name (parser, hdr,
        NULL, 0), ==, NULL);

  r_elf_parser_unref (parser);
}
RTEST_END;

RTEST (relf, relocation, RTEST_FAST)
{
  RElfParser * parser;
  RElf64SHdr * hdr, * symtbl = NULL;
  RElf64Rela * rela;
  RElf64Sym * sym;

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpptr ((hdr = r_elf_parser_get_shdr64 (parser, 11)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_RELA);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".rela.rtest");
  r_assert_cmpuint (hdr->flags, ==, R_ELF_SFLAGS_INFO_LINK);
  r_assert_cmpuint (hdr->addr, ==, 0);
  r_assert_cmpuint (hdr->offset, ==, 2736);
  r_assert_cmpuint (hdr->size, ==, 72);
  r_assert_cmpuint (hdr->link, ==, 17);
  r_assert_cmpuint (hdr->info, ==, 10);
  r_assert_cmpuint (hdr->addralign, ==, 8);
  r_assert_cmpuint (hdr->entsize, ==, sizeof (RElf64Rela));

  r_assert_cmpuint (r_elf_parser_relatbl64_rela_count (parser, hdr), ==, 3);
  r_assert_cmpptr ((rela = r_elf_parser_relatbl64_get_rela (parser, hdr, 0)), !=, NULL);

  r_assert_cmpuint (rela->offset, ==, 8);
  r_assert_cmpuint (R_ELF64_RELINFO_SYM (rela->info), ==, 5);
  r_assert_cmpuint (R_ELF64_RELINFO_TYPE (rela->info), ==, R_ELF_RELTYPE_X86_64_64);
  r_assert_cmpuint (rela->addend, ==, 73);
  r_assert_cmpptr ((sym = r_elf_parser_rela64_get_sym (parser, hdr, rela, &symtbl)), !=, NULL);
  r_assert_cmpptr (symtbl, !=, NULL);
  r_assert_cmpuint (R_ELF_SYMINFO_BIND (sym->info), ==, R_ELF_SYMBIND_LOCAL);
  r_assert_cmpuint (R_ELF_SYMINFO_TYPE (sym->info), ==, R_ELF_SYMTYPE_SECTION);
  r_assert_cmpuint (sym->other, ==, R_ELF_SYMOTHER_DEFAULT);
  r_assert_cmpuint (sym->shndx, ==, 6);
  r_assert_cmpstr ("rrand", ==,
      (rchar *)r_elf_parser_symtbl64_sym64_get_data (parser,
        symtbl, sym, NULL) + rela->addend);
  r_assert_cmpptr (r_elf_parser_rela64_get_dst (parser, hdr, rela), ==,
      (ruint8 *)r_elf_parser_shdr64_get_data_by_idx (parser, hdr->info, NULL) + rela->offset);

  r_elf_parser_unref (parser);
}
RTEST_END;

