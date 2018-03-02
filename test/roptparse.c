#include <rlib/rlib.h>
#include <rlib/ros.h>

static rchar g__roptparse_usage_tmpl[] =
  "Usage:\n"
  "  %s [options]\n"
  "%s"
  "\nOptions:\n"
  "%s"
  "%s";
static rchar g__roptparse_helpopt[] =
  "  --version                      Show application version number and exit\n"
  "  -h, --help                     Show this help message and exit\n";

RTEST (roptparse, new_n_free, RTEST_FAST)
{
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  r_assert_cmpptr (parser, !=, NULL);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, help_help_options, RTEST_FAST)
{
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar * expected;
  rchar * help;
  rchar * exe;

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);

  r_assert (r_option_parser_is_help_enabled (parser));
  expected = r_strprintf (g__roptparse_usage_tmpl, exe, "", g__roptparse_helpopt, "");
  r_assert_cmpstr ((help = r_option_parser_get_help_output (parser)), ==, expected);
  r_free (expected);
  r_free (help);

  r_option_parser_set_help_enabled (parser, FALSE);
  expected = r_strprintf (g__roptparse_usage_tmpl, exe, "", "", "");
  r_assert_cmpstr ((help = r_option_parser_get_help_output (parser)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, help_summary, RTEST_FAST)
{
  rchar * expected, * help, * exe;
  ROptionParser * parser = r_option_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_option_parser_set_summary (parser, "This is the summary");
  expected = r_strprintf (g__roptparse_usage_tmpl, exe,
      "\nThis is the summary\n", g__roptparse_helpopt, "");
  r_assert_cmpstr ((help = r_option_parser_get_help_output (parser)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, help_epilog, RTEST_FAST)
{
  rchar * expected, * help, * exe;
  ROptionParser * parser = r_option_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_option_parser_set_epilog (parser, "This is the epilog");
  expected = r_strprintf (g__roptparse_usage_tmpl, exe,
      "", g__roptparse_helpopt, "\nThis is the epilog\n");
  r_assert_cmpstr ((help = r_option_parser_get_help_output (parser)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, group, RTEST_FAST)
{
  static rboolean foo, bar;
  ROptionGroup * group;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE,    "Do foo", NULL),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &bar, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
  };

  r_assert_cmpptr ((group = r_option_group_new (NULL, NULL, NULL, NULL, NULL)), ==, NULL);
  r_assert_cmpptr ((group = r_option_group_new ("foobar", NULL, NULL, NULL, NULL)), !=, NULL);
  r_assert (r_option_group_add_entries (group, entries, R_N_ELEMENTS (entries)));
  r_option_group_unref (group);
}
RTEST_END;

RTEST (roptparse, args_error, RTEST_FAST)
{
  static rboolean foo, res;
  static rchar * str = NULL;
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  static ROptionEntry missing_long[] = {
    R_OPT_ARG ("", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
  };
  static ROptionEntry missing_variable[] = {
    R_OPT_ARG ("foo", 0, R_OPTION_TYPE_NONE, NULL, R_OPTION_FLAG_NONE, "Do foo", NULL),
  };
  static ROptionEntry bad_type[] = {
    R_OPT_ARG ("foo", 0, R_OPTION_TYPE_COUNT, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
  };
  static ROptionEntry duplicate_longarg[] = {
    R_OPT_ARG ("foo", 0, R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
    R_OPT_ARG ("foo", 0, R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE, "Opps duplicate", NULL),
  };
  static ROptionEntry duplicate_shortarg[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
    R_OPT_ARG ("bar", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE, "Opps duplicate", NULL),
  };
  static ROptionEntry invalid_shortname[] = {
    R_OPT_ARG ("foo", '-', R_OPTION_TYPE_STRING, &str, R_OPTION_FLAG_NONE,
        "shortarg/name can't use '-', ignored",
        NULL),
  };
  static ROptionEntry inverse_string[] = {
    R_OPT_ARG ("bar", 0, R_OPTION_TYPE_STRING, &str, R_OPTION_FLAG_INVERSE,
        "There is no such thing as inverse string, but it will be ignored",
        NULL),
  };

  r_assert (!r_option_parser_add_entries (parser, NULL, 0));
  r_assert (!r_option_parser_add_entries (parser, missing_long, 1));
  r_assert (!r_option_parser_add_entries (parser, missing_variable, 1));
  r_assert (!r_option_parser_add_entries (parser, bad_type, 1));
  r_assert (!r_option_parser_add_entries (parser, duplicate_longarg, 2));
  r_assert (!r_option_parser_add_entries (parser, duplicate_shortarg, 2));
  r_assert_logs_level (
      res = r_option_parser_add_entries (parser, invalid_shortname, 1),
      R_LOG_LEVEL_WARNING);
  r_assert (res);
  r_assert_logs_level (
      res = r_option_parser_add_entries (parser, inverse_string, 1),
      R_LOG_LEVEL_WARNING);
  r_assert (res);
  /* 2 options was added, --foo and --bar */

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, help_args, RTEST_FAST)
{
  static int dummy;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &dummy, R_OPTION_FLAG_NONE,    "Do foo", NULL),
    R_OPT_ARG ("hidden", 0, R_OPTION_TYPE_NONE, &dummy, R_OPTION_FLAG_HIDDEN, "Not shown", NULL),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &dummy, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
  };
  const rchar * args_help =
    "  -f, --foo                      Do foo\n"
    "  -b, --bar                      Do bar\n";
  rchar * expected, * help, * exe;
  ROptionParser * parser = r_option_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  expected = r_strprintf (g__roptparse_usage_tmpl, exe, "", g__roptparse_helpopt, args_help);
  r_assert_cmpstr ((help = r_option_parser_get_help_output (parser)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, help_argname, RTEST_FAST)
{
  static int dummy;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &dummy, R_OPTION_FLAG_INVERSE, "Do foo", "foo"),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &dummy, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
    R_OPT_ARG ("num", 'n', R_OPTION_TYPE_INT, &dummy, R_OPTION_FLAG_NONE, "Integer", "NUM"),
    R_OPT_ARG ("val", 0, R_OPTION_TYPE_INT, &dummy, R_OPTION_FLAG_NONE, "Value", NULL),
    R_OPT_ARG ("num64", 0, R_OPTION_TYPE_INT64, &dummy, R_OPTION_FLAG_NONE, "Integer 64bit", "NUM"),
    R_OPT_ARG ("double", 'd', R_OPTION_TYPE_DOUBLE, &dummy, R_OPTION_FLAG_NONE, "Double", "NUM"),
    R_OPT_ARG ("output", 'o', R_OPTION_TYPE_FILENAME, &dummy, R_OPTION_FLAG_NONE, "Output file", "FILE"),
    R_OPT_ARG ("input", 'i', R_OPTION_TYPE_FILENAME, &dummy, R_OPTION_FLAG_NONE, "Input file", NULL),
    R_OPT_ARG ("outstr", 'u', R_OPTION_TYPE_STRING, &dummy, R_OPTION_FLAG_NONE, "Output string", "STR"),
    R_OPT_ARG ("instr", 's', R_OPTION_TYPE_STRING, &dummy, R_OPTION_FLAG_NONE, "Input string", NULL),
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
  ROptionParser * parser = r_option_parser_new (NULL, NULL);

  r_assert_cmpptr ((exe = r_proc_get_exe_name ()), !=, NULL);
  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  expected = r_strprintf (g__roptparse_usage_tmpl, exe, "", g__roptparse_helpopt, args_help);
  r_assert_cmpstr ((help = r_option_parser_get_help_output (parser)), ==, expected);
  r_free (expected);
  r_free (help);
  r_free (exe);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_shortargs, RTEST_FAST)
{
  static rboolean foo, bar;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE,    "Do foo", NULL),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &bar, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv = r_strv_new ("rlibtest", "-f", "-b", NULL);
  rchar ** argv = strv;
  int argc = 3;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert (!foo);
  r_assert (bar);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpptr (argv, ==, strv + 3);
  r_assert (foo);
  r_assert (!bar);

  r_strv_free (strv);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_shortargs_chain, RTEST_FAST)
{
  static rboolean foo, bar;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE,    "Do foo", NULL),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &bar, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv = r_strv_new ("rlibtest", "-fb", NULL);
  rchar ** argv = strv;
  int argc = 2;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpptr (argv, ==, strv + 2);
  r_assert (foo);
  r_assert (!bar);

  r_strv_free (strv);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_longargs, RTEST_FAST)
{
  static rboolean foo, bar;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE,    "Do foo", NULL),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &bar, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv = r_strv_new ("rlibtest", "--foo", "--bar", NULL);
  rchar ** argv = strv;
  int argc = 3;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpptr (argv, ==, strv + 3);
  r_assert (foo);
  r_assert (!bar);

  r_strv_free (strv);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_help, RTEST_FAST)
{
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  strv = argv = r_strv_new ("rlibtest", "--help", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_HELP);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-h", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_HELP);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-?", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_HELP);
  r_strv_free (strv);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_version, RTEST_FAST)
{
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  strv = argv = r_strv_new ("rlibtest", "--version", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_VERSION);
  r_strv_free (strv);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, get_version_output, RTEST_FAST)
{
  ROptionParser * parser;
  rchar * verstr;

  parser = r_option_parser_new (NULL, NULL);
  r_assert_cmpptr ((verstr = r_option_parser_get_version_output (parser)), !=, NULL);
  r_assert_cmpstr (verstr, ==, "rlibtest"R_EXE_SUFFIX" (\"version not specified\")\n");
  r_free (verstr);
  r_option_parser_free (parser);

  parser = r_option_parser_new ("myapp", "1.0 (myversion)");
  r_assert_cmpptr ((verstr = r_option_parser_get_version_output (parser)), !=, NULL);
  r_assert_cmpstr (verstr, ==, "myapp version 1.0 (myversion)\n");
  r_free (verstr);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_partial, RTEST_FAST)
{
  static rboolean foo, bar;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE,    "Do foo", NULL),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &bar, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));

  strv = argv = r_strv_new ("rlibtest", "-f", "command", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_assert_cmpint (argc, ==, 1);
  r_assert_cmpstr (*argv, ==, "command");

  r_strv_free (strv);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_stop_after_dash_dash, RTEST_FAST)
{
  static rboolean foo, bar;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE,    "Do foo", NULL),
    R_OPT_ARG ("bar", 'b', R_OPTION_TYPE_NONE, &bar, R_OPTION_FLAG_INVERSE, "Do bar", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  strv = argv = r_strv_new ("rlibtest", "--", "-b", "command", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_assert_cmpstr (*argv, ==, "-b");
  r_assert_cmpint (argc, ==, 3);

  r_strv_free (strv);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_int, RTEST_FAST)
{
  static int foo;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_INT, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (foo, ==, 0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 42);

  strv = argv = r_strv_new ("rlibtest", "-f", "22", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 22);

  strv = argv = r_strv_new ("rlibtest", "-f=-11", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, -11);

  strv = argv = r_strv_new ("rlibtest", "-f0x42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 0x42);

  /* Overflow */
  strv = argv = r_strv_new ("rlibtest", "-f0x1ffffffff", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==,
      R_OPTION_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "NaInt", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==,
      R_OPTION_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument, but = sign */
  strv = argv = r_strv_new ("rlibtest", "-f=", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_ERROR);
  r_strv_free (strv);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_int64, RTEST_FAST)
{
  static rint64 foo;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_INT64, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (foo, ==, 0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 42);

  strv = argv = r_strv_new ("rlibtest", "-f", "22", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 22);

  strv = argv = r_strv_new ("rlibtest", "-f=-11", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, -11);

  strv = argv = r_strv_new ("rlibtest", "-f0xEEFFFFFFfffffff", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, RINT64_CONSTANT (0xEEFFFFFFfffffff));

  /* Overflow */
  strv = argv = r_strv_new ("rlibtest", "-f0x1FFFFFFFFffffffff", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==,
      R_OPTION_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "-f", "NaInt", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==,
      R_OPTION_PARSE_VALUE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument, but = sign */
  strv = argv = r_strv_new ("rlibtest", "-f=", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_ERROR);
  r_strv_free (strv);

  /* Missing integer argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_ERROR);
  r_strv_free (strv);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_double, RTEST_FAST)
{
  static rdouble foo;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_DOUBLE, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (foo, ==, .0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 42);

  strv = argv = r_strv_new ("rlibtest", "--foo=0.2", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, .2);

  strv = argv = r_strv_new ("rlibtest", "-f", "-0.2", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, -0.2);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_string, RTEST_FAST)
{
  static rchar * foo;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_STRING, &foo, R_OPTION_FLAG_NONE, "Do foo", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (foo, ==, .0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr (foo, ==, "42");

  strv = argv = r_strv_new ("rlibtest", "--foo=badgers rock", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr (foo, ==, "badgers rock");

  strv = argv = r_strv_new ("rlibtest", "-fbadgers loves unicorns", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpstr (foo, ==, "badgers loves unicorns");

  strv = argv = r_strv_new ("rlibtest", "-f", "badgers", "loves", "unicorns", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 2);
  r_assert_cmpstr (foo, ==, "badgers");

  /* Missing string argument */
  strv = argv = r_strv_new ("rlibtest", "-f", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_ERROR);
  r_strv_free (strv);

  r_free (foo);
  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_required, RTEST_FAST)
{
  static int foo;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_INT, &foo, R_OPTION_FLAG_REQUIRED, "Do foo", NULL),
  };
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (foo, ==, 0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "42", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 42);

  strv = argv = r_strv_new ("rlibtest", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_MISSING_OPTION);
  r_strv_free (strv);

  strv = argv = r_strv_new ("rlibtest", "--foo", "0", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert_cmpint (foo, ==, 0);

  r_option_parser_free (parser);
}
RTEST_END;

RTEST (roptparse, parse_unknown_option, RTEST_FAST)
{
  ROptionParser * parser = r_option_parser_new (NULL, NULL);
  static rboolean foo;
  static ROptionEntry entries[] = {
    R_OPT_ARG ("foo", 'f', R_OPTION_TYPE_NONE, &foo, R_OPTION_FLAG_NONE,    "Do foo", NULL),
  };
  rchar ** strv, ** argv;
  int argc;

  r_assert (r_option_parser_add_entries (parser, entries, R_N_ELEMENTS (entries)));
  r_assert_cmpint (foo, ==, 0);

  strv = argv = r_strv_new ("rlibtest", "--foo", "--bar", "0", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_UNKNOWN_OPTION);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 1);

  strv = argv = r_strv_new ("rlibtest", "-bf", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_UNKNOWN_OPTION);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);

  r_option_parser_set_ignore_unknown_options (parser, TRUE);
  foo = FALSE;
  strv = argv = r_strv_new ("rlibtest", "--foo", "--bar", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert (foo);

  foo = FALSE;
  strv = argv = r_strv_new ("rlibtest", "-bf", NULL);
  argc = r_strv_len (argv);
  r_assert_cmpint (r_option_parser_parse (parser, &argc, &argv), ==, R_OPTION_PARSE_OK);
  r_strv_free (strv);
  r_assert_cmpint (argc, ==, 0);
  r_assert (foo);

  r_option_parser_free (parser);
}
RTEST_END;

