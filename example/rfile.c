#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  int ret = 0;
  ROptionParser * parser = r_option_parser_new (NULL, "1.0");
  ROptionParseResult res;
  rboolean hr;
  const ROptionArgument args[] = {
    R_OPT_ARG ("hr", 0, R_OPTION_TYPE_NONE, &hr, R_OPTION_FLAG_NONE, "Human readable format", NULL),
  };

  r_option_parser_add_arguments (parser, args, R_N_ELEMENTS (args));
  res = r_option_parser_parse (parser, &argc, &argv);

  switch (res) {
    case R_OPTION_PARSE_VERSION:
      {
        rchar * output = r_option_parser_get_version_output (parser);
        r_print ("%s", output);
        r_free (output);
      }
      break;
    case R_OPTION_PARSE_OK:
      if (argc == 1) {
        if (hr) {
          RBitset * bitset;
          rsize bits;
          if (!r_bitset_init_stack (bitset, 256))
            break;

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
        break;
      } else {
        r_print ("Missing file\n");
      }
      /* else fallthrough */
    case R_OPTION_PARSE_HELP:
    default:
      {
        rchar * output = r_option_parser_get_help_output (parser);
        r_print ("%s", output);
        r_free (output);
      }
      break;
  }

  r_option_parser_free (parser);

  return ret;
}

