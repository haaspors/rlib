#include <rlib/rlib.h>
#include "macho32.inc"

RTEST (rmacho, is_valid, RTEST_FAST)
{
  static ruint8 bad_macho[] = { 0xae, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x00 };
  r_assert (!r_macho_is_valid (bad_macho));
  r_assert (r_macho_is_valid (mach_o_32_tiny));
}
RTEST_END;

RTEST (rmacho, calc_size, RTEST_FAST)
{
  static ruint8 bad_macho[] = { 0xae, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x00 };
  r_assert_cmpuint (r_macho_calc_size (bad_macho), ==, 0);
  r_assert_cmpuint (r_macho_calc_size (mach_o_32_tiny), ==, sizeof (mach_o_32_tiny));
}
RTEST_END;

RTEST (rmacho, from_mem, RTEST_FAST)
{
  RMachoParser * parser;
  static ruint8 bad_macho[] = {
    0xae, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x00,
  };
  static ruint8 small_macho[] = {
    0xce, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
  };

  r_assert_cmpptr (r_macho_parser_new_from_mem (bad_macho, sizeof (bad_macho)), ==, NULL);
  r_assert_cmpptr (r_macho_parser_new_from_mem (small_macho, sizeof (small_macho)), ==, NULL);
  r_assert_cmpptr ((parser =
        r_macho_parser_new_from_mem (mach_o_32_tiny, sizeof (mach_o_32_tiny))), !=, NULL);
  r_macho_parser_unref (parser);
}
RTEST_END;

RTEST (rmacho, get_hdr, RTEST_FAST)
{
  RMacho32Hdr * hdr;
  RMachoParser * parser;

  r_assert_cmpptr ((parser =
        r_macho_parser_new_from_mem (mach_o_32_tiny, sizeof (mach_o_32_tiny))), !=, NULL);
  r_assert_cmpptr ((hdr = r_macho_parser_get_hdr32 (parser)), !=, NULL);
  r_assert_cmpptr (r_macho_parser_get_hdr64 (parser), ==, NULL);

  r_assert_cmpuint (hdr->cputype, ==, R_MACH_CPU_TYPE_I386);
  r_assert_cmpuint (hdr->cpusubtype, ==, R_MACH_CPU_SUBTYPE_I386_ALL);
  r_assert_cmpuint (hdr->filetype, ==, R_MACHO_FT_EXECUTE);
  r_assert_cmpuint (hdr->ncmds, ==, 2);
  r_assert_cmpuint (hdr->sizeofcmds, ==, 0x88);
  r_assert_cmpuint (hdr->flags, ==, R_MACHO_FLAG_NOUNDEFS);

  r_macho_parser_unref (parser);
}
RTEST_END;

RTEST (rmacho, get_lc, RTEST_FAST)
{
  RMachoParser * parser;
  RMachoLoadCmd * lc;

  r_assert_cmpptr ((parser =
        r_macho_parser_new_from_mem (mach_o_32_tiny, sizeof (mach_o_32_tiny))), !=, NULL);

  r_assert_cmpuint (r_macho_parser_get_loadcmd_count (parser), ==, 2);
  r_assert_cmpptr (r_macho_parser_get_loadcmd (parser, 2), ==, NULL);

  r_assert_cmpptr ((lc = r_macho_parser_get_loadcmd (parser, 0)), !=, NULL);
  r_assert_cmpuint (lc->cmd, ==, R_MACHO_LC_SEGMENT);
  r_assert_cmpuint (lc->cmdsize, ==, 0x38);
  {
    RMachoSegment32Cmd * sc = (RMachoSegment32Cmd *)lc;
    r_assert_cmpstr (sc->segname, ==, R_MACHO_SEG_TEXT);
    r_assert_cmpuint (sc->fileoff, ==, 0);
    r_assert_cmpuint (sc->filesize, ==, 0x40);
    r_assert_cmpuint (sc->nsects, ==, 0);
    r_assert_cmpuint (sc->flags, ==, 0);
  }

  r_assert_cmpptr ((lc = r_macho_parser_get_loadcmd (parser, 1)), !=, NULL);
  r_assert_cmpuint (lc->cmd, ==, R_MACHO_LC_UNIXTHREAD);
  r_assert_cmpuint (lc->cmdsize, ==, 0x50);
  {
    RMachoThreadCmd * tc = (RMachoThreadCmd *)lc;
    r_assert_cmpuint (tc->flavor, ==, 1);
    r_assert_cmpuint (tc->count, ==, 16);
  }

  r_macho_parser_unref (parser);
}
RTEST_END;

RTEST (rmacho, segment_cmd_get_data, RTEST_FAST)
{
  RMachoParser * parser;
  RMachoSegment32Cmd * sc;
  rpointer data;
  rsize size;

  r_assert_cmpptr ((parser =
        r_macho_parser_new_from_mem (mach_o_32_tiny, sizeof (mach_o_32_tiny))), !=, NULL);
  r_assert_cmpuint (r_macho_parser_get_loadcmd_count (parser), ==, 2);

  r_assert_cmpptr ((sc = (RMachoSegment32Cmd *)r_macho_parser_get_loadcmd (parser, 0)), !=, NULL);
  r_assert_cmpuint (sc->lc.cmd, ==, R_MACHO_LC_SEGMENT);

  r_assert_cmpptr (r_macho_parser_s32cmd_get_data (NULL, NULL, NULL), ==, NULL);
  r_assert_cmpptr (r_macho_parser_s32cmd_get_data (parser, NULL, NULL), ==, NULL);
  r_assert_cmpptr ((data = r_macho_parser_s32cmd_get_data (parser, sc, &size)), !=, NULL);
  r_assert_cmpuint (size, ==, 0x40);
  r_assert_cmpptr ((ruint8 *)data + size, ==, mach_o_32_tiny + sizeof (mach_o_32_tiny));

  r_macho_parser_unref (parser);
}
RTEST_END;

RTEST (rmacho, find_segment, RTEST_FAST)
{
  RMachoParser * parser;
  RMachoSegment32Cmd * sc;

  r_assert_cmpptr ((parser =
        r_macho_parser_new_from_mem (mach_o_32_tiny, sizeof (mach_o_32_tiny))), !=, NULL);

  r_assert_cmpptr ((sc = (RMachoSegment32Cmd *)r_macho_parser_find_segment32 (parser, R_STR_WITH_SIZE_ARGS (R_MACHO_SEG_TEXT))), !=, NULL);
  r_assert_cmpuint (sc->lc.cmd, ==, R_MACHO_LC_SEGMENT);
  r_assert_cmpstr (sc->segname, ==, R_MACHO_SEG_TEXT);
  r_assert_cmpuint (sc->vmaddr, ==, 0);
  r_assert_cmpuint (sc->vmsize, ==, 0x1000);
  r_assert_cmpuint (sc->fileoff, ==, 0);
  r_assert_cmpuint (sc->filesize, ==, 0x40);
  r_assert_cmpuint (sc->nsects, ==, 0);
  r_assert_cmpuint (sc->flags, ==, 0);

  r_macho_parser_unref (parser);
}
RTEST_END;

