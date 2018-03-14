#include <rlib/rbinfmt.h>

static void
dump_opt_hdr (RPeOptHdr * opt)
{
  r_print ("\tLinkerVer:  %u.%u\n", opt->major_linker_ver, opt->minor_linker_ver);
  r_print ("\tEntrypoint: 0x%.8x\n", opt->addr_entrypoint);
  r_print ("\tCode addr:  0x%.8x\n", opt->base_code);
  r_print ("\tCode size:  0x%.8x\n", opt->size_code);
}

static void
dump_pe32_image (RPe32ImageHdr * img)
{
  dump_opt_hdr (&img->opt);
  r_print ("\tImage base:   0x%.8x\n", img->winopt.image_base);
  r_print ("\tSect align:   0x%.8x\n", img->winopt.section_alignment);
  r_print ("\tFile align:   0x%.8x\n", img->winopt.file_alignment);
  r_print ("\tImage size:   0x%.8x\n", img->winopt.size_image);
  r_print ("\tHeaders size: 0x%.8x\n", img->winopt.size_headers);
  r_print ("\tOS ver:       %u.%u\n", img->winopt.major_os_ver, img->winopt.minor_os_ver);
  r_print ("\tImage ver:    %u.%u\n", img->winopt.major_image_ver, img->winopt.minor_image_ver);
  r_print ("\tSubSys ver:   %u.%u\n", img->winopt.major_subsystem_ver, img->winopt.minor_subsystem_ver);
  r_print ("\tSubSys:       %.4x\n", img->winopt.subsystem);
  r_print ("\tChecksum:     0x%.8x\n", img->winopt.checksum);
  r_print ("\tDLL flags:    0x%.4x\n", img->winopt.dll_characteristics);
  r_print ("\tLoader flags: 0x%.8x\n", img->winopt.loader_flags);
  r_print ("\tStack:        0x%.8x (res) 0x%.8x (commit)\n",
      img->winopt.size_stack_reserve, img->winopt.size_stack_commit);
  r_print ("\tHeap:         0x%.8x (res) 0x%.8x (commit)\n",
      img->winopt.size_stack_reserve, img->winopt.size_stack_commit);
}

static void
dump_pe32p_image (RPe32PlusImageHdr * img)
{
  dump_opt_hdr (&img->opt);
  r_print ("\tImage base:   0x%.12"RINT64_MODIFIER"x\n", img->winopt.image_base);
  r_print ("\tSect align:   0x%.8x\n", img->winopt.section_alignment);
  r_print ("\tFile align:   0x%.8x\n", img->winopt.file_alignment);
  r_print ("\tImage size:   0x%.8x\n", img->winopt.size_image);
  r_print ("\tHeaders size: 0x%.8x\n", img->winopt.size_headers);
  r_print ("\tOS ver:       %u.%u\n", img->winopt.major_os_ver, img->winopt.minor_os_ver);
  r_print ("\tImage ver:    %u.%u\n", img->winopt.major_image_ver, img->winopt.minor_image_ver);
  r_print ("\tSubSys ver:   %u.%u\n", img->winopt.major_subsystem_ver, img->winopt.minor_subsystem_ver);
  r_print ("\tSubSys:       %.4x\n", img->winopt.subsystem);
  r_print ("\tChecksum:     0x%.8x\n", img->winopt.checksum);
  r_print ("\tDLL flags:    0x%.4x\n", img->winopt.dll_characteristics);
  r_print ("\tLoader flags: 0x%.8x\n", img->winopt.loader_flags);
  r_print ("\tStack:        0x%.12"RINT64_MODIFIER"x (res) 0x%.12"RINT64_MODIFIER"x (commit)\n",
      img->winopt.size_stack_reserve, img->winopt.size_stack_commit);
  r_print ("\tHeap:         0x%.12"RINT64_MODIFIER"x (res) 0x%.12"RINT64_MODIFIER"x (commit)\n",
      img->winopt.size_stack_reserve, img->winopt.size_stack_commit);
}

static void
dump_section (RPeParser * parser, RPeSectionHdr * sec)
{
  r_print ("\tSection:   '%s'\n", sec->name);
  r_print ("\t\tvmsize:   0x%.8x\n", sec->vmsize);
  r_print ("\t\tvmaddr:   0x%.8x\n", sec->vmaddr);
  r_print ("\t\tSize:     0x%.8x\n", sec->size_raw_data);
  r_print ("\t\tOffset:   0x%.8x\n", sec->ptr_raw_data);
  r_print ("\t\tReloc:    0x%.8x\n", sec->ptr_relocs);
  r_print ("\t\tReloc#:   %u\n", sec->nrelocs);
  r_print ("\t\tLinenum:  0x%.8x\n", sec->ptr_linenos);
  r_print ("\t\tLinenum#: %u\n", sec->nlinenos);
  r_print ("\t\tFlags:    0x%.8x\n", sec->characteristics);
}

int
main (int argc, char ** argv)
{
  RPeParser * parser;
  RPeSectionHdr * sec;
  RPe32ImageHdr * pe32;
  RPe32PlusImageHdr * pe32p;
  ruint16 i;

  if (argc < 2) {
    r_printerr ("Usage: %s <filename>\n", argv[0]);
    return -1;
  } else if ((parser = r_pe_parser_new (argv[1])) == NULL) {
    r_printerr ("Unable to parse '%s' as Mach-O\n", argv[1]);
    return -1;
  }

  switch (r_pe_parser_get_pe32_magic (parser)) {
    case R_PE_PE32_MAGIC:
      r_print ("PE32\n");
      break;
    case R_PE_PE32PLUS_MAGIC:
      r_print ("PE32+\n");
      break;
    default:
      r_print ("Unknown PE format\n");
      return -1;
  }

  r_print ("\tMachine:    %s\n", r_pe_machine_str (r_pe_parser_get_machine (parser)));
  r_print ("\tSections:   %u\n", r_pe_parser_get_section_count (parser));
  r_print ("\tSymbols:    %u\n", r_pe_parser_get_symbol_count (parser));
  r_print ("\tFlags:      0x%.4x\n\n", r_pe_parser_get_characteristics (parser));

  if ((pe32 = r_pe_parser_get_pe32_image_hdr (parser)) != NULL)
    dump_pe32_image (pe32);
  if ((pe32p = r_pe_parser_get_pe32p_image_hdr (parser)) != NULL)
    dump_pe32p_image (pe32p);

  r_print ("\nSections\n");
  for (i = 0; (sec = r_pe_parser_get_section_hdr_by_idx (parser, i)) != NULL; i++)
    dump_section (parser, sec);

  return 0;
}

