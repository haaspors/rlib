#include <rlib/rbinfmt.h>

static void
dump_section32 (const RMachoSection32 * s)
{
  r_print ("\t\tSection:   '%s' (Seg: '%s' - 32bit)\n", s->sectname, s->segname);
  r_print ("\t\t\tAddr:     0x%.8x\n", s->addr);
  r_print ("\t\t\tSize:     0x%.8x\n", s->size);
  r_print ("\t\t\tOffs:     0x%.8x\n", s->offset);
  r_print ("\t\t\tAlign:    0x%.8x\n", s->align);
  r_print ("\t\t\tReloff:   0x%.8x\n", s->reloff);
  r_print ("\t\t\tRelocs:   0x%.8x\n", s->nreloc);
  r_print ("\t\t\tFlags:    0x%.8x\n", s->flags);
}

static void
dump_section64 (const RMachoSection64 * s)
{
  r_print ("\t\tSection:   '%s' (Seg: '%s' - 64bit)\n", s->sectname, s->segname);
  r_print ("\t\t\tAddr:     0x%.12"RINT64_MODIFIER"x\n", s->addr);
  r_print ("\t\t\tSize:     0x%.12"RINT64_MODIFIER"x\n", s->size);
  r_print ("\t\t\tOffs:     0x%.8x\n", s->offset);
  r_print ("\t\t\tAlign:    0x%.8x\n", s->align);
  r_print ("\t\t\tReloff:   0x%.8x\n", s->reloff);
  r_print ("\t\t\tRelocs:   0x%.8x\n", s->nreloc);
  r_print ("\t\t\tFlags:    0x%.8x\n", s->flags);
}

static void
dump_lc (const RMachoLoadCmd * cmd)
{
  r_print ("\tLoadCMD: %s (LC size: %u)\n", r_macho_lc_str (cmd->cmd), cmd->cmdsize);
  switch (cmd->cmd) {
    case R_MACHO_LC_SEGMENT:
      {
        const RMachoSegment32Cmd * seg = (const RMachoSegment32Cmd *)cmd;
        const RMachoSection32 * sec = (const RMachoSection32 * )(seg + 1);
        ruint32 i;

        r_print ("\t\tName:      %s\n", seg->segname);
        r_print ("\t\tSections:  %u\n", seg->nsects);
        r_print ("\t\tVM addr:   0x%.8x\n", seg->vmaddr);
        r_print ("\t\tVM size:   0x%.8x\n", seg->vmsize);
        r_print ("\t\tFile offs: 0x%.8x\n", seg->fileoff);
        r_print ("\t\tFile size: 0x%.8x\n", seg->filesize);
        r_print ("\t\tMax prot:  0x%.8x\n", seg->maxprot);
        r_print ("\t\tInit prot: 0x%.8x\n", seg->initprot);
        r_print ("\t\tFlags:     0x%.8x\n", seg->flags);

        for (i = 0; i < seg->nsects; i++)
          dump_section32 (sec + i);
      }
      break;
    case R_MACHO_LC_SEGMENT_64:
      {
        const RMachoSegment64Cmd * seg = (const RMachoSegment64Cmd *)cmd;
        const RMachoSection64 * sec = (const RMachoSection64 * )(seg + 1);
        ruint32 i;

        r_print ("\t\tName:      %s\n", seg->segname);
        r_print ("\t\tSections:  %u\n", seg->nsects);
        r_print ("\t\tVM addr:   0x%.12"RINT64_MODIFIER"x\n", seg->vmaddr);
        r_print ("\t\tVM size:   0x%.12"RINT64_MODIFIER"x\n", seg->vmsize);
        r_print ("\t\tFile offs: 0x%.12"RINT64_MODIFIER"x\n", seg->fileoff);
        r_print ("\t\tFile size: 0x%.12"RINT64_MODIFIER"x\n", seg->filesize);
        r_print ("\t\tMax prot:  0x%.8x\n", seg->maxprot);
        r_print ("\t\tInit prot: 0x%.8x\n", seg->initprot);
        r_print ("\t\tFlags:     0x%.8x\n", seg->flags);

        for (i = 0; i < seg->nsects; i++)
          dump_section64 (sec + i);
      }
      break;
    default:
      r_print ("\t\tCmd:       0x%.8x\n", cmd->cmd);
      break;
  }
}

static rboolean
dump_lcs (RMachoParser * parser, ruint cmds)
{
  ruint16 i;

  r_print ("\nLoad Commands\n");

  for (i = 0; i < cmds; i++) {
    RMachoLoadCmd * cmd = r_macho_parser_get_loadcmd (parser, i);
    if (R_UNLIKELY (cmd == NULL)) {
      r_printerr ("ERROR: Couldn't get load command %u\n", i);
      return FALSE;
    }
    dump_lc (cmd);
  }

  return TRUE;
}

static void
dump_macho32 (RMachoParser * parser, RMacho32Hdr * hdr32)
{
  rchar * tmp;

  r_print ("MachO 32bit\n");
  r_print ("\tFile:  %s\n", r_macho_file_str (hdr32->filetype));
  r_print ("\tCPU:   %s\n", (tmp = r_macho_cpu_str (hdr32->cputype, hdr32->cpusubtype))); r_free (tmp);
  r_print ("\tCmds:  %u (size: %u)\n", hdr32->ncmds, hdr32->sizeofcmds);
  r_print ("\tFlags: 0x%.8x\n", hdr32->flags);

  dump_lcs (parser, hdr32->ncmds);
}

static void
dump_macho64 (RMachoParser * parser, RMacho64Hdr * hdr64)
{
  rchar * tmp;

  r_print ("MachO 64bit\n");
  r_print ("\tFile:  %s\n", r_macho_file_str (hdr64->filetype));
  r_print ("\tCPU:   %s\n", (tmp = r_macho_cpu_str (hdr64->cputype, hdr64->cpusubtype))); r_free (tmp);
  r_print ("\tCmds:  %u (size: %u)\n", hdr64->ncmds, hdr64->sizeofcmds);
  r_print ("\tFlags: 0x%.8x\n", hdr64->flags);

  dump_lcs (parser, hdr64->ncmds);
}

int
main (int argc, char ** argv)
{
  RMachoParser * parser;
  RMacho32Hdr * hdr32;
  RMacho64Hdr * hdr64;

  if (argc < 2) {
    r_printerr ("Usage: %s <filename>\n", argv[0]);
    return -1;
  } else if ((parser = r_macho_parser_new (argv[1])) == NULL) {
    r_printerr ("Unable to parse '%s' as Mach-O\n", argv[1]);
    return -1;
  }

  if ((hdr32 = r_macho_parser_get_hdr32 (parser)) != NULL) {
    dump_macho32 (parser, hdr32);
  } else if ((hdr64 = r_macho_parser_get_hdr64 (parser)) != NULL) {
    dump_macho64 (parser, hdr64);
  } else {
    return -1;
  }

  return 0;
}

