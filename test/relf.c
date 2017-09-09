#include <rlib/rlib.h>
#include "elfobj.inc"

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

  /* FIXME: Add elfprg.inc and test properly */
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

  r_assert_cmpptr ((parser =
        r_elf_parser_new_from_mem (elf_o, sizeof (elf_o))), !=, NULL);

  r_assert_cmpptr ((hdr = r_elf_parser_find_shdr64 (parser, "foobar", -1)), ==, NULL);
  r_assert_cmpptr ((hdr = r_elf_parser_find_shdr64 (parser, ".text", -1)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_PROGBITS);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".text");

  r_assert_cmpptr ((hdr = r_elf_parser_find_shdr64 (parser, ".data", -1)), !=, NULL);
  r_assert_cmpuint (hdr->type, ==, R_ELF_STYPE_PROGBITS);
  r_assert_cmpstr (r_elf_parser_shdr64_get_name (parser, hdr), ==, ".data");

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
      r_elf_parser_shdr64_get_data_by_idx (parser, hdr->info, NULL) + rela->offset);

  r_elf_parser_unref (parser);
}
RTEST_END;

