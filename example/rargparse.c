#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  RArgParser * parser = r_arg_parser_new (NULL, "1.0");
  RArgParseCtx * ctx;
  RArgParseResult res;
  int ret = 0;
  const RArgOptionEntry entries[] = {
    { "foo",    'f', R_ARG_OPTION_TYPE_NONE,   R_ARG_OPTION_FLAG_NONE, "Do Foo", NULL },
    { "input",  'i', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Input string", NULL },
    { "ret",    'r', R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "Return value program will return", NULL },
  };

  r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries));

  if ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)) != NULL) {
    r_assert_cmpuint (res, ==, R_ARG_PARSE_OK);

    if (r_arg_parse_ctx_option_count (ctx) > 0) {
      rchar * input;

      if (r_arg_parse_ctx_get_option_bool (ctx, "foo"))
        r_print ("You specified foo, thanks!\n");

      ret = r_arg_parse_ctx_get_option_int (ctx, "ret");

      if ((input = r_arg_parse_ctx_get_option_string (ctx, "input")) != NULL) {
        r_print ("Input: %s\n", input);
        r_free (input);
      }
    } else {
      ret = r_arg_parser_print_help (parser, R_ARG_PARSE_FLAG_DONT_EXIT, NULL, 1);
    }

    r_arg_parse_ctx_unref (ctx);
  } else {
    ret = r_arg_parser_print_help (parser, R_ARG_PARSE_FLAG_DONT_EXIT, NULL, -1);
  }

  r_arg_parser_unref (parser);

  return ret;
}
