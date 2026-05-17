#include <rlib/rbinfmt.h>
#include "pe32.inc"
#include "pe32plus.inc"

static ruint8 bad_pe[] = { 0xae, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x00 };

RTEST (rpe, is_valid, RTEST_FAST)
{
  r_assert (!r_pe_image_is_valid (bad_pe));
  r_assert (r_pe_image_is_valid (pe_32_tiny));
  r_assert (r_pe_image_is_valid (pe_32p_tiny));
}
RTEST_END;

RTEST (rpe, pe32_magic, RTEST_FAST)
{
  r_assert_cmpuint (r_pe_image_pe32_magic (bad_pe), ==, 0);
  r_assert_cmpuint (r_pe_image_pe32_magic (pe_32_tiny), ==, R_PE_PE32_MAGIC);
  r_assert_cmpuint (r_pe_image_pe32_magic (pe_32p_tiny), ==, R_PE_PE32PLUS_MAGIC);
}
RTEST_END;

RTEST (rpe, image_size, RTEST_FAST)
{
  r_assert_cmphex (r_pe_image_size (bad_pe), ==, 0);
  r_assert_cmphex (r_pe_image_size (pe_32_tiny), ==, sizeof (pe_32_tiny));
  r_assert_cmphex (r_pe_image_size (pe_32p_tiny), ==, 0x40); /* smallest value */
}
RTEST_END;

RTEST (rpe, image_calc_size, RTEST_FAST)
{
  /* calc_size walks the section table rather than reading size_image
   * out of the optional header, so it reflects the actual on-disk
   * extent.  For the tiny PE32 with one .text section at file offset
   * 464 of length 4 the disk image ends at 468 == sizeof (pe_32_tiny). */
  r_assert_cmphex (r_pe_image_calc_size (NULL), ==, 0);
  r_assert_cmphex (r_pe_image_calc_size (bad_pe), ==, 0);
  r_assert_cmphex (r_pe_image_calc_size (pe_32_tiny), ==, sizeof (pe_32_tiny));
}
RTEST_END;

RTEST (rpeparser, oversize_lfanew, RTEST_FAST)
{
  /* DOS header with valid magic but lfanew pointing far past the buffer
   * must be rejected without dereferencing the bogus pointer. */
  ruint8 evil[sizeof (RPeDosHdr)] = { 0 };
  RPeDosHdr * dos = (RPeDosHdr *)evil;

  dos->magic = R_PE_DOS_MAGIC;
  dos->lfanew = 0xFFFFFFFF;

  r_assert_cmpptr (r_pe_parser_new_from_mem (evil, sizeof (evil)), ==, NULL);
}
RTEST_END;

RTEST (rpeparser, pe32_from_mem, RTEST_FAST)
{
  RPeParser * parser;

  r_assert_cmpptr (r_pe_parser_new_from_mem (bad_pe, sizeof (bad_pe)), ==, NULL);
  r_assert_cmpptr ((parser =
        r_pe_parser_new_from_mem (pe_32_tiny, sizeof (pe_32_tiny))), !=, NULL);

  r_assert_cmphex (r_pe_parser_get_machine (parser), ==, R_PE_MACHINE_I386);
  r_assert_cmpuint (r_pe_parser_get_section_count (parser), ==, 1);
  r_assert_cmphex (r_pe_parser_get_time_date_stamp (parser), ==, 0x4545BE5D);
  r_assert_cmphex (r_pe_parser_get_ptr_symbol_table (parser), ==, 0x0);
  r_assert_cmpuint (r_pe_parser_get_symbol_count (parser), ==, 0);
  r_assert_cmphex (r_pe_parser_get_size_opt_hdr (parser), ==,
      sizeof (RPeOptHdr) + sizeof (RPe32WinOptHdr) + sizeof (RPeDataDirectory) * 16);
  r_assert_cmphex (r_pe_parser_get_characteristics (parser), ==,
      R_PE_FILE_RELOCS_STRIPPED | R_PE_FILE_EXECUTABLE_IMAGE |
      R_PE_FILE_32BIT_MACHINE);

  r_assert_cmphex (r_pe_parser_get_pe32_magic (parser), ==, R_PE_PE32_MAGIC);
  r_pe_parser_unref (parser);
}
RTEST_END;

RTEST (rpeparser, pe32plus_from_mem, RTEST_FAST)
{
  RPeParser * parser;

  r_assert_cmpptr ((parser =
        r_pe_parser_new_from_mem (pe_32p_tiny, sizeof (pe_32p_tiny))), !=, NULL);

  r_assert_cmphex (r_pe_parser_get_machine (parser), ==, R_PE_MACHINE_AMD64);
  r_assert_cmpuint (r_pe_parser_get_section_count (parser), ==, 0);
  r_assert_cmphex (r_pe_parser_get_time_date_stamp (parser), ==, 0x72700000);
  r_assert_cmphex (r_pe_parser_get_ptr_symbol_table (parser), ==, 0x66746e69);
  r_assert_cmpuint (r_pe_parser_get_symbol_count (parser), ==, 0);
  r_assert_cmphex (r_pe_parser_get_size_opt_hdr (parser), ==, 0);
  r_assert_cmphex (r_pe_parser_get_characteristics (parser), ==,
      R_PE_FILE_EXECUTABLE_IMAGE | R_PE_FILE_32BIT_MACHINE);

  r_assert_cmphex (r_pe_parser_get_pe32_magic (parser), ==, R_PE_PE32PLUS_MAGIC);
  r_pe_parser_unref (parser);
}
RTEST_END;

RTEST (rpeparser, get_section_by_idx, RTEST_FAST)
{
  RPeParser * parser;
  RPeSectionHdr * sec;

  r_assert_cmpptr ((parser =
        r_pe_parser_new_from_mem (pe_32_tiny, sizeof (pe_32_tiny))), !=, NULL);

  r_assert_cmpuint (r_pe_parser_get_section_count (parser), ==, 1);
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_idx (parser, 1), ==, NULL);

  r_assert_cmpptr ((sec = r_pe_parser_get_section_hdr_by_idx (parser, 0)), !=, NULL);
  r_assert_cmpstr (sec->name, ==, ".text");
  r_assert_cmpuint (sec->vmaddr, ==, 464);
  r_assert_cmpuint (sec->size_raw_data, ==, 4);
  r_assert_cmpuint (sec->ptr_raw_data, ==, 464);
  r_assert_cmpuint (sec->ptr_relocs, ==, 0);
  r_assert_cmpuint (sec->ptr_linenos, ==, 0);
  r_assert_cmpuint (sec->nrelocs, ==, 0);
  r_assert_cmpuint (sec->nlinenos, ==, 0);
  r_assert_cmphex (sec->characteristics, ==,
      R_PE_SCN_CNT_CODE | R_PE_SCN_MEM_EXECUTE | R_PE_SCN_MEM_READ);

  r_pe_parser_unref (parser);

  r_assert_cmpptr ((parser =
        r_pe_parser_new_from_mem (pe_32p_tiny, sizeof (pe_32p_tiny))), !=, NULL);
  r_assert_cmpuint (r_pe_parser_get_section_count (parser), ==, 0);
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_idx (parser, 0), ==, NULL);
  r_pe_parser_unref (parser);
}
RTEST_END;

RTEST (rpeparser, get_section_by_name, RTEST_FAST)
{
  RPeParser * parser;
  RPeSectionHdr * sec;

  /* NULL inputs should not crash. */
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_name (NULL,
        R_STR_WITH_SIZE_ARGS (".text")), ==, NULL);

  r_assert_cmpptr ((parser =
        r_pe_parser_new_from_mem (pe_32_tiny, sizeof (pe_32_tiny))), !=, NULL);

  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_name (parser,
        NULL, 0), ==, NULL);
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_name (parser,
        R_STR_WITH_SIZE_ARGS (".foobar")), ==, NULL);
  r_assert_cmpptr ((sec = r_pe_parser_get_section_hdr_by_name (parser,
          R_STR_WITH_SIZE_ARGS (".text"))), !=, NULL);
  r_assert_cmpstr (sec->name, ==, ".text");

  r_pe_parser_unref (parser);
}
RTEST_END;

RTEST (rpeparser, get_section_by_data_dir, RTEST_FAST)
{
  /* Drive r_pe_parser_get_section_hdr_by_data_dir against the tiny
   * PE32 image: zero out the datadir to verify "no entry -> NULL",
   * then point the EXPORT entry at an RVA inside the .text section
   * (vmaddr=464, vmsize=4) and expect the lookup to return .text. */
  ruint8 mut[sizeof (pe_32_tiny)];
  RPeParser * parser;
  RPe32ImageHdr * hdr;
  RPeSectionHdr * sec;

  r_memcpy (mut, pe_32_tiny, sizeof (pe_32_tiny));
  r_assert_cmpptr ((parser =
        r_pe_parser_new_from_mem (mut, sizeof (mut))), !=, NULL);
  r_assert_cmpptr ((hdr = r_pe_parser_get_pe32_image_hdr (parser)), !=, NULL);

  /* All datadirs zero -> nothing to map. */
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_data_dir (parser,
        R_PE_DATA_DIR_EXPORT), ==, NULL);

  /* Point EXPORT into the .text section's vmaddr range. */
  hdr->datadir[R_PE_DATA_DIR_EXPORT].vmaddr = 466;
  hdr->datadir[R_PE_DATA_DIR_EXPORT].size = 1;
  r_assert_cmpptr ((sec = r_pe_parser_get_section_hdr_by_data_dir (parser,
          R_PE_DATA_DIR_EXPORT)), !=, NULL);
  r_assert_cmpstr (sec->name, ==, ".text");

  /* Other entries still empty. */
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_data_dir (parser,
        R_PE_DATA_DIR_IMPORT), ==, NULL);

  /* RVA outside any section is unmapped. */
  hdr->datadir[R_PE_DATA_DIR_IMPORT].vmaddr = 0x80000000;
  hdr->datadir[R_PE_DATA_DIR_IMPORT].size = 1;
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_data_dir (parser,
        R_PE_DATA_DIR_IMPORT), ==, NULL);

  /* Out-of-range index returns NULL rather than reading past the array. */
  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_data_dir (parser,
        R_PE_DATA_DIR_ZERO), ==, NULL);

  r_pe_parser_unref (parser);
}
RTEST_END;

