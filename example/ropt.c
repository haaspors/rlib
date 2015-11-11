#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  ROptionParser * parser = r_option_parser_new (NULL, "1.0");
  ROptionParseResult res;
  rchar * output = NULL;
  rboolean foo;
  rchar * input;
  int ret = 0;
  const ROptionArgument args[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE, "Do Foo", NULL),
    R_OPT_ARG ("input", 'i', R_OPTION_TYPE_STRING, &input, R_OPTION_FLAG_NONE, "Do Foo", NULL),
    R_OPT_ARG ("ret", 'r', R_OPTION_TYPE_INT, &ret, R_OPTION_FLAG_NONE, "Return value program will return", NULL),
  };

  r_option_parser_add_arguments (parser, args, R_N_ELEMENTS (args));
  res = r_option_parser_parse (parser, &argc, &argv);

  switch (res) {
    case R_OPTION_PARSE_VERSION:
      output = r_option_parser_get_version_output (parser);
      r_print ("%s", output);
      break;
    case R_OPTION_PARSE_OK:
      if (foo || input != NULL) {
        if (input != NULL)
          r_print ("Input: %s\n", input);
        if (foo)
          r_print ("You specified foo, thanks!\n");
      } else {
        r_print ("Run this program with -h or --help to see options\n");
      }
      break;
    case R_OPTION_PARSE_HELP:
    default:
      output = r_option_parser_get_help_output (parser);
      r_print ("%s", output);
      break;
  }

  r_free (input);
  r_free (output);
  r_option_parser_free (parser);

  return ret;
}
