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

  r_assert_cmpptr ((parser =
        r_pe_parser_new_from_mem (pe_32_tiny, sizeof (pe_32_tiny))), !=, NULL);

  r_assert_cmpptr (r_pe_parser_get_section_hdr_by_name (parser,
        R_STR_WITH_SIZE_ARGS (".foobar")), ==, NULL);
  r_assert_cmpptr ((sec = r_pe_parser_get_section_hdr_by_name (parser,
          R_STR_WITH_SIZE_ARGS (".text"))), !=, NULL);
  r_assert_cmpstr (sec->name, ==, ".text");

  r_pe_parser_unref (parser);
}
RTEST_END;

