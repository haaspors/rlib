#include <rlib/rlib.h>

static const rchar json_test_null[] = "null";
static const rchar json_test_true[] = "true";
static const rchar json_test_false[] = "false";
static const rchar json_test_number_int_pos[] = "1234";
static const rchar json_test_number_int_neg[] = "-4321";
static const rchar json_test_number_double[] = "-0.1234";

RTEST (rjson_parser, new, RTEST_FAST)
{
  RJsonParser * parser;

  r_assert_cmpptr (r_json_parser_new (NULL, 10), ==, NULL);
  r_assert_cmpptr (r_json_parser_new (json_test_null, 0), ==, NULL);
  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_test_null))), !=, NULL);

  r_json_parser_unref (parser);
}
RTEST_END;

RTEST (rjson_parser, object_simple, RTEST_FAST)
{
  RJsonParser * parser;
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;
  RStrChunk name = R_STR_CHUNK_INIT;
  RJsonScanCtx value = R_JSON_SCAN_CTX_INIT;

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("{}"))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_OBJECT);
  r_assert_cmpint (r_json_scan_ctx_scan_object_field (&ctx, &name, &value), ==, R_JSON_EMPTY);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("{ \"test\": true }"))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_OBJECT);
  r_assert_cmpint (r_json_scan_ctx_scan_object_field (&ctx, &name, &value), ==, R_JSON_OK);
  r_assert_cmpint (r_str_chunk_cmp (&name, R_STR_WITH_SIZE_ARGS ("test")), ==, 0);
  r_assert_cmpint (value.type, ==, R_JSON_TYPE_TRUE);
  r_assert_cmpstr (value.data.str, ==, "true }");
  r_assert_cmpstr (ctx.data.str, ==, "}");
  r_assert_cmpint (r_json_scan_ctx_scan_object_field (&ctx, &name, &value), ==, R_JSON_END);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);
}
RTEST_END;

RTEST (rjson_parser, array_simple, RTEST_FAST)
{
  RJsonParser * parser;
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;
  RJsonScanCtx value = R_JSON_SCAN_CTX_INIT;

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("[]"))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_ARRAY);
  r_assert_cmpint (r_json_scan_ctx_scan_array_value (&ctx, &value), ==, R_JSON_EMPTY);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);


  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("[ null ]"))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_ARRAY);
  r_assert_cmpint (r_json_scan_ctx_scan_array_value (&ctx, &value), ==, R_JSON_OK);
  r_assert_cmpint (value.type, ==, R_JSON_TYPE_NULL);
  r_assert_cmpstr (value.data.str, ==, "null ]");
  r_assert_cmpstr (ctx.data.str, ==, "]");
  r_assert_cmpint (r_json_scan_ctx_scan_array_value (&ctx, &value), ==, R_JSON_END);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);
}
RTEST_END;

RTEST (rjson_parser, scan_start_null_true_false, RTEST_FAST)
{
  RJsonParser * parser;
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_test_null))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_NULL);
  r_assert_cmpptr (ctx.data.str, ==, json_test_null);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_test_true))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_TRUE);
  r_assert_cmpptr (ctx.data.str, ==, json_test_true);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_test_false))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_FALSE);
  r_assert_cmpptr (ctx.data.str, ==, json_test_false);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);
}
RTEST_END;

RTEST (rjson_parser, number, RTEST_FAST)
{
  RJsonParser * parser;
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;
  RStrChunk str = R_STR_CHUNK_INIT;
  int i;
  rdouble d;
  rchar * endptr;

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_test_number_int_pos))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_NUMBER);
  r_assert_cmpptr (ctx.data.str, ==, json_test_number_int_pos);

  r_assert_cmpint (r_json_scan_ctx_parse_number (&ctx, &str, &endptr), ==, R_JSON_OK);
  r_assert_cmpptr (str.str, ==, json_test_number_int_pos);
  r_assert_cmpuint (str.size, ==, r_strlen (json_test_number_int_pos));
  r_assert_cmpptr (endptr, ==, json_test_number_int_pos + r_strlen (json_test_number_int_pos));

  r_assert_cmpint (r_json_scan_ctx_parse_number_int (&ctx, &i, NULL), ==, R_JSON_OK);
  r_assert_cmpint (i, ==, 1234);

  r_assert_cmpint (r_json_scan_ctx_parse_number_double (&ctx, &d, NULL), ==, R_JSON_OK);
  r_assert_cmpdouble (d, ==, 1234.0);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_test_number_int_neg))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (r_json_scan_ctx_parse_number (&ctx, &str, &endptr), ==, R_JSON_OK);
  r_assert_cmpptr (endptr, ==, json_test_number_int_neg + r_strlen (json_test_number_int_neg));
  r_assert_cmpint (r_json_scan_ctx_parse_number_int (&ctx, &i, NULL), ==, R_JSON_OK);
  r_assert_cmpint (i, ==, -4321);
  r_assert_cmpint (r_json_scan_ctx_parse_number_double (&ctx, &d, NULL), ==, R_JSON_OK);
  r_assert_cmpdouble (d, ==, -4321.0);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_test_number_double))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (r_json_scan_ctx_parse_number (&ctx, &str, &endptr), ==, R_JSON_OK);
  r_assert_cmpptr (endptr, ==, json_test_number_double + r_strlen (json_test_number_double));
  r_assert_cmpint (r_json_scan_ctx_parse_number_int (&ctx, &i, NULL), ==, R_JSON_OK);
  r_assert_cmpint (i, ==, 0);
  r_assert_cmpint (r_json_scan_ctx_parse_number_double (&ctx, &d, NULL), ==, R_JSON_OK);
  r_assert_cmpdouble (d, ==, -0.1234);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);
}
RTEST_END;

RTEST (rjson_parser, bad_number, RTEST_FAST)
{
  RJsonParser * parser;
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;
  int i;

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("0a123"))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (r_json_scan_ctx_parse_number_int (&ctx, &i, NULL), ==, R_JSON_NUMBER_NOT_PARSED);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("000.123"))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (r_json_scan_ctx_parse_number_int (&ctx, &i, NULL), ==, R_JSON_NUMBER_NOT_PARSED);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);
}
RTEST_END;

RTEST (rjson_parser, string, RTEST_FAST)
{
  RJsonParser * parser;
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;
  RStrChunk str = R_STR_CHUNK_INIT;
  rchar * endptr;

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("foo"))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_TYPE_NOT_PARSED);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("\"\""))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (ctx.data.str, ==, "\"\"");
  r_assert_cmpuint (ctx.data.size, ==, 2);
  r_assert_cmpint (r_json_scan_ctx_parse_string (&ctx, &str, &endptr), ==, R_JSON_OK);
  r_assert_cmpuint (str.size, ==, 0);
  r_assert_cmpptr (endptr, ==, str.str + 1);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);

  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("\"foo\""))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (ctx.type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (ctx.data.str, ==, "\"foo\"");
  r_assert_cmpint (r_json_scan_ctx_parse_string (&ctx, &str, &endptr), ==, R_JSON_OK);
  r_assert_cmpint (r_str_chunk_cmp (&str, R_STR_WITH_SIZE_ARGS ("foo")), ==, 0);
  r_assert_cmpptr (endptr, ==, str.str + 4);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_json_parser_unref (parser);
}
RTEST_END;

static const rchar json_array_strings[] = "[ \"foo\", \"bar\" ]";

RTEST (rjson_parser, to_value, RTEST_FAST)
{
  RJsonParser * parser;
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;
  RJsonValue * v, * av;
  RJsonResult res;

  r_assert_cmpptr ((v = r_json_scan_ctx_to_value (NULL, NULL, NULL)), ==, NULL);
  r_assert_cmpptr ((v = r_json_scan_ctx_to_value (&ctx, NULL, NULL)), ==, NULL);
  r_assert_cmpptr ((v = r_json_scan_ctx_to_value (&ctx, &res, NULL)), ==, NULL);
  r_assert_cmpint (res, ==, R_JSON_INVAL);

  /* Simple string */
  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS ("\"foo\""))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpptr ((v = r_json_scan_ctx_to_value (&ctx, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (v), ==, "foo");
  r_json_value_unref (v);
  r_json_parser_unref (parser);

  /* Array of strings */
  r_assert_cmpptr ((parser = r_json_parser_new (R_STR_WITH_SIZE_ARGS (json_array_strings))), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_start (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpptr ((v = r_json_scan_ctx_to_value (&ctx, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_json_parser_scan_end (parser, &ctx), ==, R_JSON_OK);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_ARRAY);
  r_assert_cmpuint (r_json_value_get_array_size (v), ==, 2);
  r_assert_cmpptr ((av = r_json_value_get_array_value (v, 0)), !=, NULL);
  r_assert_cmpstr (r_json_value_get_string (av), ==, "foo");
  r_assert_cmpint (av->type, ==, R_JSON_TYPE_STRING);
  r_json_value_unref (av);
  r_assert_cmpptr ((av = r_json_value_get_array_value (v, 1)), !=, NULL);
  r_assert_cmpstr (r_json_value_get_string (av), ==, "bar");
  r_assert_cmpint (av->type, ==, R_JSON_TYPE_STRING);
  r_json_value_unref (av);
  r_assert_cmpptr ((av = r_json_value_get_array_value (v, 2)), ==, NULL);
  r_json_value_unref (v);
  r_json_parser_unref (parser);
}
RTEST_END;
