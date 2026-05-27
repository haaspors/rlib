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
  "  --version                     Show application version number and exit\n"
  "  -h, --help                    Show this help message and exit\n";

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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
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
    { "", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
  };
  static RArgOptionEntry bad_type[] = {
    { "foo", 0, R_ARG_OPTION_TYPE_COUNT, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
  };
  static RArgOptionEntry duplicate_longarg[] = {
    { "foo", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
    { "foo", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Opps duplicate", NULL, NULL },
  };
  static RArgOptionEntry duplicate_shortarg[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
    { "bar", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Opps duplicate", NULL, NULL },
  };
  static RArgOptionEntry invalid_shortname[] = {
    { "foo", '-', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE,
      "shortarg/name can't use '-', ignored", NULL, NULL },
  };
  static RArgOptionEntry inverse_string[] = {
    { "bar", 0, R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_INVERSE,
      "There is no such thing as inverse string, but it will be ignored", NULL, NULL },
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
    { "foo", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
  };
  r_assert (r_arg_parser_add_option_entries (parser, missing_val, 1));
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, help_args, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
    { "hidden", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_HIDDEN, "Not shown", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
  };
  const rchar * args_help =
    "  -f, --foo                     Do foo\n"
    "  -b, --bar                     Do bar\n";
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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do foo", "foo", NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
    { "num", 'n', R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_NONE, "Integer", "NUM", NULL },
    { "val", 0, R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_NONE, "Value", NULL, NULL },
    { "num64", 0, R_ARG_OPTION_TYPE_INT64, R_ARG_OPTION_FLAG_NONE, "Integer 64bit", "NUM", NULL },
    { "double", 'd', R_ARG_OPTION_TYPE_DOUBLE, R_ARG_OPTION_FLAG_NONE, "Double", "NUM", NULL },
    { "output", 'o', R_ARG_OPTION_TYPE_FILENAME, R_ARG_OPTION_FLAG_NONE, "Output file", "FILE", NULL },
    { "input", 'i', R_ARG_OPTION_TYPE_FILENAME, R_ARG_OPTION_FLAG_NONE, "Input file", NULL, NULL },
    { "outstr", 'u', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Output string", "STR", NULL },
    { "instr", 's', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Input string", NULL, NULL },
  };
  const rchar * args_help =
    "  -f, --foo                     Do foo\n"
    "  -b, --bar                     Do bar\n"
    "  -n, --num=NUM                 Integer\n"
    "  --val=VALUE                   Value\n"
    "  --num64=NUM                   Integer 64bit\n"
    "  -d, --double=NUM              Double\n"
    "  -o, --output=FILE             Output file\n"
    "  -i, --input=FILENAME          Input file\n"
    "  -u, --outstr=STR              Output string\n"
    "  -s, --instr=STRING            Input string\n";
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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
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
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_HELP);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-h", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_HELP);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-?", NULL);
  argc = (int) r_strv_len (argv);
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
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "-f", "command", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_INVERSE, "Do bar", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  strv = argv = r_strv_new ("rlibtest", "--", "-b", "command", "-f", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "22", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 22);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f=-11", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, -11);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f0x42", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 0x42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Overflow */
  strv = argv = r_strv_new ("rlibtest", "-f0x1ffffffff", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "NaInt", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument, but = sign */
  strv = argv = r_strv_new ("rlibtest", "-f=", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_INT64, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, 42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "22", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, 22);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f=-11", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, -11);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f0xEEFFFFFFfffffff", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "foo"), ==, RINT64_CONSTANT (0xEEFFFFFFfffffff));
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Overflow */
  strv = argv = r_strv_new ("rlibtest", "-f0x1FFFFFFFFffffffff", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "NaInt", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument, but = sign */
  strv = argv = r_strv_new ("rlibtest", "-f=", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_DOUBLE, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpdouble (r_arg_parse_ctx_get_option_double (ctx, "foo"), ==, 42.0);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "--foo=0.2", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpdouble (r_arg_parse_ctx_get_option_double (ctx, "foo"), ==, .2);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "-0.2", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv, * tmp;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "42");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "--foo=badgers rock", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "badgers rock");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-fbadgers loves unicorns", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "badgers loves unicorns");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "badgers", "loves", "unicorns", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 2);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "foo")), ==, "badgers");
  r_free (tmp);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Missing string argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_REQUIRED, "Do foo", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  RArgParseResult res;
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "foo"), ==, 42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_MISSING_OPTION);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "--foo", "0", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE,    "Do foo", NULL, NULL },
  };
  rchar ** strv, ** argv;
  RArgParseCtx * ctx;
  RArgParseResult res;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "--bar", "0", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_UNKNOWN_OPTION);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 1);

  strv = argv = r_strv_new ("rlibtest", "-bf", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_UNKNOWN_OPTION);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "--bar", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_ALLOW_UNKNOWN,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert (r_arg_parse_ctx_get_option_bool (ctx, "foo"));
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-bf", NULL);
  argc = (int) r_strv_len (argv);
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
    { "foo", 'f', R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "Do foo", NULL, NULL },
    { "bar", 'b', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Do bar", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv, * foo = NULL;
  rboolean bar;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = (int) r_strv_len (argv);
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

static rchar rargparse_help_with_cmd_tmpl[] =
  "Usage:\n"
  "  %s [options] <command>\n"
  "%s"
  "\nOptions:\n"
  "%s"
  "\nCommands:\n"
  "%s"
  "%s";

RTEST (rargparse, add_command_should_incl_help, RTEST_FAST)
{
  RArgParser * parser, * cmd;
  rchar * expected, * help, * exe;

  r_assert_cmpptr ((parser = r_arg_parser_new (NULL, NULL)), !=, NULL);

  r_assert_cmpptr (r_arg_parser_add_command (parser, NULL, NULL), ==, NULL);
  r_assert_cmpptr ((cmd = r_arg_parser_add_command (parser, "foo", "bar")), !=, NULL);
  r_arg_parser_unref (cmd);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);

  expected = r_strprintf (rargparse_help_with_cmd_tmpl, exe, "", rargparse_helpopt,
      "  help                          Show this help message and exit\n"
      "  foo                           bar\n", "");
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, command_help, RTEST_FAST)
{
  RArgParser * parser, * cmd;
  rchar * expected, * help, * exe, * tmp;

  r_assert_cmpptr ((parser = r_arg_parser_new (NULL, NULL)), !=, NULL);

  r_assert_cmpptr (r_arg_parser_add_command (parser, NULL, NULL), ==, NULL);
  r_assert_cmpptr ((cmd = r_arg_parser_add_command (parser, "foo", "bar")), !=, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  tmp = r_strprintf ("%s foo", exe);
  r_free (exe);
  exe = tmp;

  expected = r_strprintf (rargparse_help_tmpl, exe, "\nbar\n",
      "  -h, --help                    Show this help message and exit\n", "");
  r_assert_cmpstr ((help = r_arg_parser_get_help (cmd, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (cmd);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, add_command_and_parse, RTEST_FAST)
{
  RArgParser * parser, * cmd;
  rchar ** strv, ** argv/*, * foo*/ = NULL;
  int argc;
  RArgParseCtx * ctx, * cmdctx;
  RArgParseResult res;

  r_assert_cmpptr ((parser = r_arg_parser_new (NULL, NULL)), !=, NULL);

  r_assert_cmpptr ((cmd = r_arg_parser_add_command (parser, "foo", "bar")), !=, NULL);
  r_arg_parser_unref (cmd);

  strv = argv = r_strv_new ("rlibtest", "--foo", "--bar", "0", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_UNKNOWN_OPTION);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "foo", "0", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), !=, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_OK);
  r_assert_cmpint (argc, ==, 1);
  r_assert_cmpint (r_arg_parse_ctx_option_count (ctx), ==, 0);
  r_assert (!r_arg_parse_ctx_get_option_bool (ctx, "foo"));
  r_assert_cmpstr (r_arg_parse_ctx_get_command (ctx), ==, "foo");
  r_assert_cmpptr ((cmdctx = r_arg_parse_ctx_get_command_ctx (ctx)), !=, NULL);
  r_assert_cmpint (r_arg_parse_ctx_option_count (cmdctx), ==, 0);
  r_arg_parse_ctx_unref (cmdctx);

  r_arg_parse_ctx_unref (ctx);
  r_arg_parser_unref (parser);
  r_strv_free (strv);
}
RTEST_END;


RTEST (rargparse, default_value_used_when_absent, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "num",  0, R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "Integer",   NULL, "42" },
    { "big",  0, R_ARG_OPTION_TYPE_INT64,  R_ARG_OPTION_FLAG_NONE, "Integer64", NULL, "1234567890123" },
    { "d",    0, R_ARG_OPTION_TYPE_DOUBLE, R_ARG_OPTION_FLAG_NONE, "Double",    NULL, "3.14" },
    { "s",    0, R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "String",    NULL, "hello" },
    { "f",    0, R_ARG_OPTION_TYPE_FILENAME, R_ARG_OPTION_FLAG_NONE, "Filename",NULL, "/tmp/x" },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", NULL);
  rchar ** argv = strv;
  int argc = 1;
  rchar * tmp;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);

  /* Nothing was actually provided on the command line. */
  r_assert (!r_arg_parse_ctx_has_option (ctx, "num"));
  r_assert (!r_arg_parse_ctx_has_option (ctx, "big"));
  r_assert (!r_arg_parse_ctx_has_option (ctx, "d"));
  r_assert (!r_arg_parse_ctx_has_option (ctx, "s"));
  r_assert (!r_arg_parse_ctx_has_option (ctx, "f"));
  r_assert_cmpint (r_arg_parse_ctx_option_count (ctx), ==, 0);

  /* But the getters return the per-entry defval. */
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "num"), ==, 42);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int64 (ctx, "big"), ==, RINT64_CONSTANT (1234567890123));
  r_assert_cmpdouble (r_arg_parse_ctx_get_option_double (ctx, "d"), ==, 3.14);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "s")), ==, "hello");
  r_free (tmp);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_filename (ctx, "f")), ==, "/tmp/x");
  r_free (tmp);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, default_value_overridden_when_present, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "num", 'n', R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "Integer", NULL, "42" },
    { "s",    0,  R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "String",  NULL, "hello" },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "-n", "7", "--s", "world", NULL);
  rchar ** argv = strv;
  int argc = (int) r_strv_len (strv);
  rchar * tmp;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);

  r_assert (r_arg_parse_ctx_has_option (ctx, "num"));
  r_assert (r_arg_parse_ctx_has_option (ctx, "s"));
  /* User value wins over defval. */
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "num"), ==, 7);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "s")), ==, "world");
  r_free (tmp);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, no_default_returns_zero, RTEST_FAST)
{
  /* Pre-defval behaviour: missing options return the type's zero value.
   * Verify defval = NULL preserves it. */
  static RArgOptionEntry entries[] = {
    { "num", 0, R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "Integer", NULL, NULL },
    { "s",   0, R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "String",  NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", NULL);
  rchar ** argv = strv;
  int argc = 1;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);

  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "num"), ==, 0);
  r_assert_cmpptr (r_arg_parse_ctx_get_option_string (ctx, "s"), ==, NULL);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, default_value_ignored_for_bool, RTEST_FAST)
{
  /* BOOL ("NONE") options have no string value -- defval is meaningless and
   * the entry init should warn and drop it. */
  static RArgOptionEntry entries[] = {
    { "foo", 0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Bool", NULL, "true" },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", NULL);
  rchar ** argv = strv;
  int argc = 1;
  rboolean res;

  r_assert_logs_level (
      res = r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)),
      R_LOG_LEVEL_WARNING);
  r_assert (res);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);

  /* defval dropped: --foo absent -> FALSE, same as if no default had been set. */
  r_assert (!r_arg_parse_ctx_get_option_bool (ctx, "foo"));

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, default_value_clears_required, RTEST_FAST)
{
  /* REQUIRED + defval is incoherent -- the defval makes the option not
   * actually required. Entry init warns and clears REQUIRED so the
   * required-options check at parse time passes even though the option
   * wasn't on the command line. */
  static RArgOptionEntry entries[] = {
    { "num", 0, R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_REQUIRED, "Integer", NULL, "42" },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", NULL);
  rchar ** argv = strv;
  int argc = 1;
  rboolean res;

  r_assert_logs_level (
      res = r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)),
      R_LOG_LEVEL_WARNING);
  r_assert (res);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "num"), ==, 42);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, default_value_in_help, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "num", 'n', R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "Integer", "NUM",  "42" },
    { "s",   0,   R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_NONE, "String",  NULL,   "hi" },
    { "plain", 0, R_ARG_OPTION_TYPE_INT,    R_ARG_OPTION_FLAG_NONE, "No default", NULL, NULL },
  };
  const rchar * args_help =
    "  -n, --num=NUM                 Integer [default: 42]\n"
    "  --s=STRING                    String [default: hi]\n"
    "  --plain=VALUE                 No default\n";
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

RTEST (rargparse, positional_bind, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "outfile", 0, R_ARG_OPTION_TYPE_FILENAME,
      R_ARG_OPTION_FLAG_POSITIONAL, "Output file", "OUTFILE", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "/tmp/out.txt", NULL);
  rchar ** argv = strv;
  int argc = (int) r_strv_len (strv);
  rchar * tmp;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpint (argc, ==, 0);
  r_assert (r_arg_parse_ctx_has_option (ctx, "outfile"));
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_filename (ctx, "outfile")), ==, "/tmp/out.txt");
  r_free (tmp);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_multiple_in_order, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "src",  0, R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_POSITIONAL, "Source", "SRC", NULL },
    { "dst",  0, R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_POSITIONAL, "Destination", "DST", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "a.txt", "b.txt", NULL);
  rchar ** argv = strv;
  int argc = (int) r_strv_len (strv);
  rchar * tmp;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "src")), ==, "a.txt");
  r_free (tmp);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "dst")), ==, "b.txt");
  r_free (tmp);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_options_then_positional, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "verbose", 'v', R_ARG_OPTION_TYPE_NONE,     R_ARG_OPTION_FLAG_NONE, "Verbose", NULL, NULL },
    { "n",        0,  R_ARG_OPTION_TYPE_INT,      R_ARG_OPTION_FLAG_NONE, "Count",   NULL, NULL },
    { "outfile",  0,  R_ARG_OPTION_TYPE_FILENAME, R_ARG_OPTION_FLAG_POSITIONAL, "Output", "OUT", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "-v", "--n", "3", "out.txt", NULL);
  rchar ** argv = strv;
  int argc = (int) r_strv_len (strv);
  rchar * tmp;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert (r_arg_parse_ctx_get_option_bool (ctx, "verbose"));
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "n"), ==, 3);
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_filename (ctx, "outfile")), ==, "out.txt");
  r_free (tmp);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_missing_required, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "outfile", 0, R_ARG_OPTION_TYPE_FILENAME,
      R_ARG_OPTION_FLAG_POSITIONAL, "Output", "OUT", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", NULL);
  rchar ** argv = strv;
  int argc = 1;
  RArgParseResult res;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_MISSING_OPTION);

  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_default_used_when_absent, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "outfile", 0, R_ARG_OPTION_TYPE_FILENAME,
      R_ARG_OPTION_FLAG_POSITIONAL, "Output", "OUT", "/tmp/default" },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", NULL);
  rchar ** argv = strv;
  int argc = 1;
  rchar * tmp;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert (!r_arg_parse_ctx_has_option (ctx, "outfile"));
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_filename (ctx, "outfile")), ==, "/tmp/default");
  r_free (tmp);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_double_dash_terminator, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "verbose", 'v', R_ARG_OPTION_TYPE_NONE,   R_ARG_OPTION_FLAG_NONE, "Verbose", NULL, NULL },
    { "name",     0,  R_ARG_OPTION_TYPE_STRING, R_ARG_OPTION_FLAG_POSITIONAL, "Name", "NAME", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", "-v", "--", "--something-that-looks-like-an-option", NULL);
  rchar ** argv = strv;
  int argc = (int) r_strv_len (strv);
  rchar * tmp;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert (r_arg_parse_ctx_get_option_bool (ctx, "verbose"));
  r_assert_cmpstr ((tmp = r_arg_parse_ctx_get_option_string (ctx, "name")),
      ==, "--something-that-looks-like-an-option");
  r_free (tmp);

  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_type_checked, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "count", 0, R_ARG_OPTION_TYPE_INT,
      R_ARG_OPTION_FLAG_POSITIONAL, "Count", "N", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv;
  rchar ** argv;
  int argc;
  RArgParseResult res;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "42", NULL);
  argc = (int) r_strv_len (strv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, &res)), !=, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_OK);
  r_assert_cmpint (r_arg_parse_ctx_get_option_int (ctx, "count"), ==, 42);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "not-a-number", NULL);
  argc = (int) r_strv_len (strv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_type_none_rejected, RTEST_FAST)
{
  static RArgOptionEntry bad[] = {
    { "outfile", 0, R_ARG_OPTION_TYPE_NONE,
      R_ARG_OPTION_FLAG_POSITIONAL, "Output", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  r_assert (!r_arg_parser_add_option_entries (parser, bad, R_N_ELEMENTS (bad)));
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_shortarg_warned, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "outfile", 'o', R_ARG_OPTION_TYPE_FILENAME,
      R_ARG_OPTION_FLAG_POSITIONAL, "Output", "OUT", NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  rboolean res;
  r_assert_logs_level (
      res = r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)),
      R_LOG_LEVEL_WARNING);
  r_assert (res);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, positional_in_help, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "src", 0, R_ARG_OPTION_TYPE_STRING,
      R_ARG_OPTION_FLAG_POSITIONAL, "Source file", "SRC", NULL },
    { "dst", 0, R_ARG_OPTION_TYPE_STRING,
      R_ARG_OPTION_FLAG_POSITIONAL, "Destination", "DST", "/tmp/d" },
  };
  static const rchar * help_tmpl =
    "Usage:\n"
    "  %s [options] SRC [DST]\n"
    "\nOptions:\n"
    "%s"
    "\nArguments:\n"
    "  SRC                           Source file\n"
    "  DST                           Destination [default: /tmp/d]\n";
  rchar * expected, * help, * exe;
  RArgParser * parser = r_arg_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  expected = r_strprintf (help_tmpl, exe, rargparse_helpopt);
  r_assert_cmpstr ((help = r_arg_parser_get_help (parser, R_ARG_PARSE_FLAG_NONE, NULL)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, required_without_default_still_required, RTEST_FAST)
{
  /* Sanity-check: defval=NULL + REQUIRED still rejects parses that miss
   * the option, so we haven't accidentally weakened the required check. */
  static RArgOptionEntry entries[] = {
    { "num", 0, R_ARG_OPTION_TYPE_INT, R_ARG_OPTION_FLAG_REQUIRED, "Integer", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv = r_strv_new ("rlibtest", NULL);
  rchar ** argv = strv;
  int argc = 1;
  RArgParseResult res;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser,
          R_ARG_PARSE_FLAG_DONT_EXIT | R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT,
          &argc, (const rchar ***)&argv, &res)), ==, NULL);
  r_assert_cmpint (res, ==, R_ARG_PARSE_MISSING_OPTION);

  r_strv_free (strv);
  r_arg_parser_unref (parser);
}
RTEST_END;

RTEST (rargparse, parse_string_array, RTEST_FAST)
{
  static RArgOptionEntry entries[] = {
    { "filter", 'f', R_ARG_OPTION_TYPE_STRING_ARRAY, R_ARG_OPTION_FLAG_NONE,
        "Repeatable filter", NULL, NULL },
  };
  RArgParser * parser = r_arg_parser_new (NULL, NULL);
  RArgParseCtx * ctx;
  rchar ** strv, ** argv, ** got;
  int argc;

  r_assert (r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries)));

  /* Absent option yields a NULL array. */
  strv = argv = r_strv_new ("rlibtest", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  r_assert_cmpptr (r_arg_parse_ctx_get_option_string_array (ctx, "filter"),
      ==, NULL);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Single occurrence yields a one-entry array. */
  strv = argv = r_strv_new ("rlibtest", "-f", "alpha", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  got = r_arg_parse_ctx_get_option_string_array (ctx, "filter");
  r_assert_cmpptr (got, !=, NULL);
  r_assert_cmpuint (r_strv_len (got), ==, 1);
  r_assert_cmpstr (got[0], ==, "alpha");
  r_strv_free (got);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  /* Multiple occurrences accumulate in argv order, mixing short and
   * long, with and without =. */
  strv = argv = r_strv_new ("rlibtest", "-f", "alpha", "--filter=beta",
      "--filter", "gamma", "-f=delta", NULL);
  argc = (int) r_strv_len (argv);
  r_assert_cmpptr ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,
          &argc, (const rchar ***)&argv, NULL)), !=, NULL);
  got = r_arg_parse_ctx_get_option_string_array (ctx, "filter");
  r_assert_cmpptr (got, !=, NULL);
  r_assert_cmpuint (r_strv_len (got), ==, 4);
  r_assert_cmpstr (got[0], ==, "alpha");
  r_assert_cmpstr (got[1], ==, "beta");
  r_assert_cmpstr (got[2], ==, "gamma");
  r_assert_cmpstr (got[3], ==, "delta");
  r_strv_free (got);
  r_arg_parse_ctx_unref (ctx);
  r_strv_free (strv);

  r_arg_parser_unref (parser);
}
RTEST_END;

