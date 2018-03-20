#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  int ret = 0;
  RArgParser * parser = r_arg_parser_new (NULL, "1.0");
  RArgParseCtx * ctx;
  RArgParseResult res;
  const RArgOptionEntry entries[] = {
    { "hr", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Human readable format", NULL },
  };

  r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries));

  if ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)) != NULL) {
    if (argc == 1) {
      if (r_arg_parse_ctx_has_option (ctx, "hr")) {
        RBitset * bitset;
        rsize bits;
        if (!r_bitset_init_stack (bitset, 256)) {
          r_print ("internal error\n");
          return -1;
        }

        if (r_bitset_set_from_human_readable_file (bitset, argv[0], &bits)) {
          ruint i;
          r_print ("Read %"RSIZE_FMT" from '%s'\n", bits, argv[0]);
          for (i = 0; i < 256; i += 32)
            r_print ("%.8"RINT32_MODIFIER"x\n", r_bitset_get_u32_at (bitset, i));
        } else {
          r_print ("Unable to read bitset from '%s'\n", argv[0]);
        }
      } else {
        RFile * f;
        if ((f = r_file_open (argv[0], "r")) != NULL) {
          ruint32 val;
          rsize tokens;

          while (r_file_scanf (f, "%"RINT32_MODIFIER"x,", &tokens, &val) == R_FILE_ERROR_OK &&
              tokens == 1) {
            r_print ("%.8"RINT32_MODIFIER"x\n", val);
          }

          r_file_unref (f);
        } else {
          r_print ("'%s' not found\n", argv[0]);
        }
      }
    } else {
      r_print ("Missing file\n");
      ret = r_arg_parser_print_help (parser, R_ARG_PARSE_FLAG_DONT_EXIT, NULL, 1);
    }

    r_arg_parse_ctx_unref (ctx);
  } else {
    ret = r_arg_parser_print_help (parser, R_ARG_PARSE_FLAG_DONT_EXIT, NULL, -1);
  }

  r_arg_parser_unref (parser);

  return ret;
}

