#include <rlib/rlib.h>
#include <rlib/ros.h>

static rchar rargparse_help_tmpl[] =
  "Usage:\n"
  "  %s [options]\n"
  "%s"
  "\nOptions:\n"
  "%s"
  "%s";
static rchar rargparse_helpopt[] =
  "  --version                      Show application version number and exit\n"
  "  -h, --help                     Show this help message and exit\n";

RTEST (rargparse, new_n_free, RTEST_FAST)
{
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  r_assert_cmpptr (parser, !=, NULL);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, help_help_options, RTEST_FAST)
{
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  rchar * expected, * help, * exe;

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);

  expected = r_strprintf (rargparse_help_tmpl, exe, "", rargparse_helpopt, "");
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);

  expected = r_strprintf (rargparse_help_tmpl, exe, "", "", "");
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_DISALE_HELP, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, help_summary, RTEST_FAST)
{
  rchar * expected, * help, * exe;
  RArgParser * parser = r_arg_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_arg_parser_set_summary (parser, "This is the summary");
  expected = r_strprintf (rargparse_help_tmpl, exe,
      "\nThis is the summary\n", rargparse_helpopt, "");
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, help_epilog, RTEST_FAST)
{
  rchar * expected, * help, * exe;
  RArgParser * parser = r_arg_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_arg_parser_set_epilog (parser, "This is the epilog");
  expected = r_strprintf (rargparse_help_tmpl, exe,
      "", rargparse_helpopt, "\nThis is the epilog\n");
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, group, RTEST_FAST)
{
  RArgOptionGroup * group;
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
  };

  r_assert_cmpptr ((group = r_arg_option_group_new (NULL, NULL, NULL, NULL, NULL)), ==, NULL);
  r_assert_cmpptr ((group = r_arg_option_group_new ("foobar", NULL, NULL, NULL, NULL)), !=, NULL);
  r_assert (r_arg_option_group_add_entries (group, entries, R_N_ELEMENTS (entries)));
  r_arg_option_group_unref (group);
}
RTEST_END;

RTEST (rargparse, args_error, RTEST_FAST)
{
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  static RArgOptionEntry missing_long[] = {
    { "", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
  };
  static RArgOptionEntry bad_type[] = {
    { "foo", 0, R_ARG_OPTION_TYPE_COUNT, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
  };
  static RArgOptionEntry duplicate_longarg[] = {
    { "foo", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
    { "foo", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Opps duplicate", NULL },
  };
  static RArgOptionEntry duplicate_shortarg[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
    { "bar", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Opps duplicate", NULL },
  };
  static RArgOptionEntry invalid_shortname[] = {
    { "foo", '-', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE,
      "shortarg/name can't use '-', ignored", NULL },
  };
  static RArgOptionEntry inverse_string[] = {
    { "bar", 0, R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_INVERSE,
      "There is no such thing as inverse string, but it will be ignored", NULL },
  };
  rboolean res;

  r_assert (!r_arg_parser_add_option_entries (parser, NULL, 0));
  r_assert (!r_arg_parser_add_option_entries (parser, missing_long, 1));
  r_assert (!r_arg_parser_add_option_entries (parser, bad_type, 1));
  r_assert (!r_arg_parser_add_option_entries (parser, duplicate_longarg, 2));
  r_assert (!r_arg_parser_add_option_entries (parser, duplicate_shortarg, 2));
  r_assert_logs_level (
      res = r_arg_parser_add_option_entries (parser, invalid_shortname, 1),
      R_LOG_LEVEL_WARNING);
  r_assert (res);
  r_assert_logs_level (
      res = r_arg_parser_add_option_entries (parser, inverse_string, 1),
      R_LOG_LEVEL_WARNING);
  r_assert (res);
  /* 2 options was added, --foo and --bar */

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, no_val_works, RTEST_FAST)
{
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  static RArgOptionEntry missing_val[] = {
    { "foo", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
  };
  r_assert (r_arg_parser_add_option_entries (parser, missing_val, 1));
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, help_args, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
    { "hidden", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_HIDDEN, "Not shown", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
  };
  const rchar * args_help =
    "  -f, --foo                      Do foo\n"
    "  -b, --bar                      Do bar\n";
  rchar * expected, * help, * exe;
  RArgParser * parser = r_arg_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  expected = r_strprintf (rargparse_help_tmpl, exe, "", rargparse_helpopt, args_help);
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, help_argname, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do foo", "foo" },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
    { "num", 'n', R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_NONE, "Integer", "NUM" },
    { "val", 0, R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_NONE, "Value", NULL },
    { "num64", 0, R_ARG_OPTION_TYPE_INT64, R_ARG_OPTION_FLAG_NONE, "Integer 64bit", "NUM" },
    { "double", 'd', R_ARG_OPTION_TYPE_DOUBLE, R_ARG_OPTION_FLAG_NONE, "Double", "NUM" },
    { "output", 'o', R_ARG_OPTION_TYPE_FILENAME, R_ARG_OPTION_FLAG_NONE, "Output file", "FILE" },
    { "input", 'i', R_ARG_OPTION_TYPE_FILENAME, R_ARG_OPTION_FLAG_NONE, "Input file", NULL },
    { "outstr", 'u', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Output string", "STR" },
    { "instr", 's', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Input string", NULL },
  };
  const rchar * args_help =
    "  -f, --foo                      Do foo\n"
    "  -b, --bar                      Do bar\n"
    "  -n, --num=NUM                  Integer\n"
    "  --val=VALUE                    Value\n"
    "  --num64=NUM                    Integer 64bit\n"
    "  -d, --double=NUM               Double\n"
    "  -o, --output=FILE              Output file\n"
    "  -i, --input=FILENAME           Input file\n"
    "  -u, --outstr=STR               Output string\n"
    "  -s, --instr=STRING             Input string\n";
  rchar * expected, * help, * exe;
  RArgParser * parser = r_arg_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  expected = r_strprintf (rargparse_help_tmpl, exe, "", rargparse_helpopt, args_help);
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_shortargs, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "-f", "-b", NULL);
  rchar ** argv = strv;
  int argc = 3;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpptr (argv, ==, strv + 3);
  r_assert (r_arg_parse_ctx_has_option (ctx, "foo"));
  r_assert (r_arg_parse_ctx_has_option (ctx, "bar"));
  r_assert (r_arg_parse_ctx_get_option_bool (ctx,  "foo"));
  r_assert (!r_arg_parse_ctx_get_option_bool (ctx, "bar"));
  r_arg_parse_ctx_unref (ctx);

  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_shortargs_chain, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "-fb", NULL);
  rchar ** argv = strv;
  int argc = 2;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpptr (argv, ==, strv + 2);
  r_assert (r_arg_parse_ctx_has_option (ctx, "foo"));
  r_assert (r_arg_parse_ctx_has_option (ctx, "bar"));
  r_assert (r_arg_parse_ctx_get_option_bool (ctx,  "foo"));
  r_assert (!r_arg_parse_ctx_get_option_bool (ctx, "bar"));
  r_arg_parse_ctx_unref (ctx);

  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_longargs, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "--foo", "--bar", NULL);
  rchar ** argv = strv;
  int argc = 3;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpptr (argv, ==, strv + 3);
  r_assert (r_arg_parse_ctx_has_option (ctx, "foo"));
  r_assert (r_arg_parse_ctx_has_option (ctx, "bar"));
  r_assert (r_arg_parse_ctx_get_option_bool (ctx,  "foo"));
  r_assert (!r_arg_parse_ctx_get_option_bool (ctx, "bar"));
  r_arg_parse_ctx_unref (ctx);

  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_help, RTEST_FAST)
{
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  strv = argv = r_strv_new ("rlibtest", "--help", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_HELP);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-h", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_HELP);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-?", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_HELP);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_version, RTEST_FAST)
{
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  strv = argv = r_strv_new ("rlibtest", "--version", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VERSION);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, get_version_output, RTEST_FAST)
{
  RArgParser * parser;
  rchar * verstr;

  parser = r_arg_parser_new (NULL, NULL);
  r_assert_cmpptr ((verstr = r_arg_parser_get_version (parser)), !=, NULL);
  r_assert_cmpstr (verstr, ==, "rlibtest"R_EXE_SUFFIX" (\"version not specified\")\n");
  r_free (verstr);
  r_arg_parser_unref (parser);

  parser = r_arg_parser_new ("myapp", "1.0 (myversion)");
  r_assert_cmpptr ((verstr = r_arg_parser_get_version (parser)), !=, NULL);
  r_assert_cmpstr (verstr, ==, "myapp version 1.0 (myversion)\n");
  r_free (verstr);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_partial, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "-f", "command", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 1);
  r_assert_cmpstr (*argv, ==, "command");
  r_arg_parse_ctx_unref (ctx);

  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_stop_after_dash_dash, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  strv = argv = r_strv_new ("rlibtest", "--", "-b", "command", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpstr (*argv, ==, "-b");
  r_assert_cmpint (argc, ==, 3);
  r_arg_parse_ctx_unref (ctx);

  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_int, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "22", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 22);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f=-11", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, -11);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f0x42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 0x42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Overflow */
  strv = argv = r_strv_new ("rlibtest", "-f0x1ffffffff", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "NaInt", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument, but = sign */
  strv = argv = r_strv_new ("rlibtest", "-f=", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_ERROR);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_int64, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_INT64, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, 42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "22", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, 22);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f=-11", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, -11);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f0xEEFFFFFFfffffff", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, RINT64_CONSTANT (0xEEFFFFFFfffffff));
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Overflow */
  strv = argv = r_strv_new ("rlibtest", "-f0x1FFFFFFFFffffffff", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "NaInt", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument, but = sign */
  strv = argv = r_strv_new ("rlibtest", "-f=", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_ERROR);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_double, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_DOUBLE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpdouble (r_arg_parse_ctx_get_option_double (ctx, "foo"), ==, 42.0);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "--foo=0.2", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpdouble (r_arg_parse_ctx_get_option_double (ctx, "foo"), ==, .2);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "-0.2", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpdouble (r_arg_parse_ctx_get_option_double (ctx, "foo"), ==, -0.2);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_string, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv, * tmp;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "42");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "--foo=badgers rock", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "badgers rock");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-fbadgers loves unicorns", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "badgers loves unicorns");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "badgers", "loves", "unicorns", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 2);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "badgers");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Missing string argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_ERROR);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_required, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_REQUIRED, "Do foo", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_MISSING_OPTION);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "--foo", "0", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 0);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_unknown_option, RTEST_FAST)
{
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL },
  };
  rchar ** strv, ** argv;
  RArgParseCtx * ctx;
  RArgParseResult res;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "--bar", "0", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_UNKNOWN_OPTION);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 1);

  strv = argv = r_strv_new ("rlibtest", "-bf", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_UNKNOWN_OPTION);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "--bar", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_ALLOW_UNKNOWN,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert (r_arg_parse_ctx_get_option_bool (ctx, "foo"));
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-bf", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_ALLOW_UNKNOWN,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert (r_arg_parse_ctx_get_option_bool (ctx, "foo"));
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, get_value, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do bar", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv, * foo = NULL;
  rboolean bar;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);

  r_assert (!r_arg_parse_ctx_get_option_value (ctx, "dummy", R_ARG_OPTION_TYPE_NONE, &foo));
  r_assert (!r_arg_parse_ctx_get_option_value (ctx, "foo", R_ARG_OPTION_TYPE_INT, &foo));
  r_assert (r_arg_parse_ctx_get_option_value (ctx, "foo", R_ARG_OPTION_TYPE_STRING, &foo));
  r_assert_cmpstr (foo, ==, "42"); r_free (foo);

  r_assert (!r_arg_parse_ctx_get_option_value (ctx, "bar", R_ARG_OPTION_TYPE_BOOL, &bar));
  r_assert (!r_arg_parse_ctx_get_option_bool (ctx, "bar"));
  r_arg_parse_ctx_unref (ctx);

  r_arg_parser_unref (parser);
  r_strv_free (strv);
}
RTEST_END;
