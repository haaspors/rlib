#include <rlib/rlib.h>

static const rchar json_wikipedia[] =
  "{\n"
  "  \"id\": 1,\n"
  "  \"name\": \"Foo\",\n"
  "  \"price\": 123,\n"
  "  \"tags\": [\n"
  "    \"Bar\",\n"
  "    \"Eek\"\n"
  "  ],\n"
  "  \"stock\": {\n"
  "    \"warehouse\": 300,\n"
  "    \"retail\": 20\n"
  "  }\n"
  "}";

RTEST (rjson, array_of_strings, RTEST_FAST)
{
  static const rchar json_array_of_strings[] =
    " [\n"
    "   \"foo\",\n"
    "   \"bar\"\n"
    "] ";
  RJsonResult res;
  RJsonValue * v, * tmp;

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_array_of_strings), &res)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_ARRAY);
  r_assert_cmpuint (r_json_value_get_array_size (v), ==, 2);
  r_assert_cmpptr ((tmp = r_json_value_get_array_value (v, 0)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (tmp), ==, "foo");
  r_json_value_unref (tmp);
  r_assert_cmpptr ((tmp = r_json_value_get_array_value (v, 1)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (tmp), ==, "bar");
  r_json_value_unref (tmp);
  r_assert_cmpptr (r_json_value_get_array_value (v, 2), ==, NULL);
  r_json_value_unref (v);
}
RTEST_END;

RTEST (rjson, object, RTEST_FAST)
{
  static const rchar json_object_with_numbers[] =
    " {\n"
    "   \"foo\": 0.2,\n"
    "   \"bar\": 42,\n"
    "   \"bah\": null\n"
    "} ";
  RJsonResult res;
  RJsonValue * v, * tmp;

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_object_with_numbers), &res)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_OBJECT);
  r_assert_cmpuint (r_json_value_get_object_field_count (v), ==, 3);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 0), ==, "foo");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 0)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_NUMBER);
  r_assert_cmpdouble (r_json_value_get_number_double (tmp), ==, 0.2);
  r_json_value_unref (tmp);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 1), ==, "bar");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 1)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_NUMBER);
  r_assert_cmpdouble (r_json_value_get_number_double (tmp), ==, 42);
  r_json_value_unref (tmp);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 2), ==, "bah");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 2)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_NULL);
  r_assert (r_json_value_is_null (tmp));
  r_json_value_unref (tmp);

  r_assert_cmpptr ((tmp = r_json_value_get_object_field (v, "bah")), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_NULL);
  r_assert (r_json_value_is_null (tmp));
  r_json_value_unref (tmp);

  r_assert_cmpptr (r_json_value_get_object_field_name (v, 3), ==, NULL);
  r_assert_cmpptr (r_json_value_get_object_field_value (v, 3), ==, NULL);
  r_json_value_unref (v);
}
RTEST_END;

RTEST (rjson, object_array, RTEST_FAST)
{
  static const rchar json_object_including_arrays[] =
    " {\n"
    "   \"foo\": [],\n"
    "   \"bar\": 42\n"
    "} ";
  RJsonResult res;
  RJsonValue * v, * tmp;

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_object_including_arrays), &res)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_OBJECT);
  r_assert_cmpuint (r_json_value_get_object_field_count (v), ==, 2);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 0), ==, "foo");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 0)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_ARRAY);
  r_assert_cmpuint (r_json_value_get_array_size (tmp), ==, 0);
  r_json_value_unref (tmp);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 1), ==, "bar");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 1)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_NUMBER);
  r_assert_cmpdouble (r_json_value_get_number_double (tmp), ==, 42);
  r_json_value_unref (tmp);

  r_assert_cmpptr (r_json_value_get_object_field_name (v, 2), ==, NULL);
  r_assert_cmpptr (r_json_value_get_object_field_value (v, 2), ==, NULL);
  r_json_value_unref (v);
}
RTEST_END;

RTEST (rjson, object_composite_wikipedia, RTEST_FAST)
{
  RJsonResult res;
  RJsonValue * v, * tmp;

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_wikipedia), &res)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_OBJECT);
  r_assert_cmpuint (r_json_value_get_object_field_count (v), ==, 5);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 0), ==, "id");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 0)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_NUMBER);
  r_assert_cmpdouble (r_json_value_get_number_double (tmp), ==, 1);
  r_json_value_unref (tmp);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 1), ==, "name");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 1)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (tmp), ==, "Foo");
  r_json_value_unref (tmp);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 2), ==, "price");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 2)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_NUMBER);
  r_assert_cmpdouble (r_json_value_get_number_double (tmp), ==, 123);
  r_json_value_unref (tmp);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 3), ==, "tags");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 3)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_ARRAY);
  r_assert_cmpdouble (r_json_value_get_array_size (tmp), ==, 2);
  r_json_value_unref (tmp);

  r_assert_cmpstr (r_json_value_get_object_field_name (v, 4), ==, "stock");
  r_assert_cmpptr ((tmp = r_json_value_get_object_field_value (v, 4)), !=, NULL);
  r_assert_cmpint (tmp->type, ==, R_JSON_TYPE_OBJECT);
  r_assert_cmpdouble (r_json_value_get_object_field_count (tmp), ==, 2);
  r_assert_cmpstr (r_json_value_get_object_field_name (tmp, 0), ==, "warehouse");
  r_assert_cmpstr (r_json_value_get_object_field_name (tmp, 1), ==, "retail");
  r_json_value_unref (tmp);

  r_json_value_unref (v);
}
RTEST_END;

RTEST (rjson, create_object, RTEST_FAST)
{
  RJsonValue * obj, * k, * v;

  r_assert_cmpint (r_json_object_add_field (NULL, NULL, NULL), ==, R_JSON_INVAL);

  r_assert_cmpptr ((obj = r_json_object_new ()), !=, NULL);
  r_assert_cmpptr ((k = r_json_string_new_static ("foo")), !=, NULL);
  r_assert_cmpptr ((v = r_json_null_new ()), !=, NULL);
  r_assert_cmpuint (r_json_value_get_object_field_count (obj), ==, 0);

  r_assert_cmpint (r_json_object_add_field (obj, NULL, NULL), ==, R_JSON_INVAL);
  r_assert_cmpint (r_json_object_add_field (obj, k, NULL), ==, R_JSON_INVAL);
  r_assert_cmpint (r_json_object_add_field (obj, NULL, v), ==, R_JSON_INVAL);

  r_assert_cmpint (r_json_object_add_field (obj, k, v), ==, R_JSON_OK);
  r_assert_cmpuint (r_json_value_get_object_field_count (obj), ==, 1);
  r_json_value_unref (k);
  r_json_value_unref (v);

  r_json_value_unref (obj);
}
RTEST_END;

RTEST (rjson, create_array, RTEST_FAST)
{
  RJsonValue * array, * tmp;

  r_assert_cmpint (r_json_array_add_value (NULL, NULL), ==, R_JSON_INVAL);

  r_assert_cmpptr ((array = r_json_array_new ()), !=, NULL);
  r_assert_cmpuint (r_json_value_get_object_field_count (array), ==, 0);

  r_assert_cmpint (r_json_array_add_value (array, NULL), ==, R_JSON_INVAL);

  r_assert_cmpptr ((tmp = (RJsonValue *)r_json_null_new ()), !=, NULL);
  r_assert_cmpint (r_json_array_add_value (array, tmp), ==, R_JSON_OK);
  r_assert_cmpuint (r_json_value_get_array_size (array), ==, 1);
  r_json_value_unref (tmp);

  r_json_value_unref (array);
}
RTEST_END;

RTEST (rjson, value_to_buffer_array, RTEST_FAST)
{
  RJsonValue * array, * tmp;
  RBuffer * buf;
  RJsonResult res;

  r_assert_cmpptr (r_json_value_to_buffer (NULL, R_JSON_NOFLAGS, &res), ==, NULL);
  r_assert_cmpint (res, ==, R_JSON_INVAL);

  r_assert_cmpptr ((array = r_json_array_new ()), !=, NULL);

  r_assert_cmpptr ((buf = r_json_value_to_buffer (array, R_JSON_NOFLAGS, &res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, "[]");
  r_buffer_unref (buf);

  r_assert_cmpptr ((tmp = r_json_string_new_static ("foo")), !=, NULL);
  r_assert_cmpint (r_json_array_add_value (array, tmp), ==, R_JSON_OK);
  r_json_value_unref (tmp);
  r_assert_cmpptr ((tmp = r_json_string_new_static ("bar")), !=, NULL);
  r_assert_cmpint (r_json_array_add_value (array, tmp), ==, R_JSON_OK);
  r_json_value_unref (tmp);
  r_assert_cmpuint (r_json_value_get_array_size (array), ==, 2);

  r_assert_cmpptr ((buf = r_json_value_to_buffer (array, R_JSON_COMPACT, &res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, "[\"foo\",\"bar\"]");
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_json_value_to_buffer (array, R_JSON_NOFLAGS, &res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, "[\n  \"foo\",\n  \"bar\"\n]");
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_json_value_to_buffer (array, R_JSON_USE_TABS, &res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, "[\n\t\"foo\",\n\t\"bar\"\n]");
  r_buffer_unref (buf);

  r_json_value_unref (array);
}
RTEST_END;

RTEST (rjson, parse_then_value_to_buffer, RTEST_FAST)
{
  RJsonResult res;
  RJsonValue * v;
  RBuffer * buf;
  static const rchar json_wikipedia_compact[] =
    "{\"id\":1,\"name\":\"Foo\",\"price\":123,"
    "\"tags\":[\"Bar\",\"Eek\"],"
    "\"stock\":{\"warehouse\":300,\"retail\":20}"
    "}";

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_wikipedia), &res)), !=, NULL);

  r_assert_cmpptr ((buf = r_json_value_to_buffer (v, R_JSON_NOFLAGS, &res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, json_wikipedia);
  r_buffer_unref (buf);

  r_assert_cmpptr ((buf = r_json_value_to_buffer (v, R_JSON_COMPACT, &res)), !=, NULL);
  r_assert_cmpbufsstr (buf, 0, -1, ==, json_wikipedia_compact);
  r_buffer_unref (buf);

  r_json_value_unref (v);
}
RTEST_END;

RTEST (rjson, string_get_string_quoted, RTEST_FAST)
{
  RJsonValue * v;
  rchar * str;

  r_assert_cmpptr ((v = r_json_string_new ("foo", -1, NULL)), !=, NULL);
  r_assert_cmpstr ((str = r_json_value_get_string_quoted (v)), ==, "\"foo\"");
  r_free (str);
  r_json_value_unref (v);
}
RTEST_END;

RTEST (rjson, string_unescape, RTEST_FAST)
{
  static const rchar json_string[] = "\"foo\\\\foo\\b\\nbar\\t\"\n";
  static const rchar json_unicode[] = "\"\\u00a2\\u20ac\"";
  static const rchar json_unicode_ascii[] = "\"\\u002F\\u002f\"";
  static const rchar json_unicode_error[] = "\"\\u02F foo\"";
  static const rchar json_unicode_error_short[] = "\"\\u02F\"";
  RJsonValue * v;
  RJsonResult res;

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_string), NULL)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (v), ==, "foo\\foo\b\nbar\t");
  r_json_value_unref (v);

  r_assert_cmpptr (r_json_parse (R_STR_WITH_SIZE_ARGS (json_unicode_error), &res), ==, NULL);
  r_assert_cmpint (res, ==, R_JSON_FAILED_TO_UNESCAPE_STRING);

  r_assert_cmpptr (r_json_parse (R_STR_WITH_SIZE_ARGS (json_unicode_error_short), &res), ==, NULL);
  r_assert_cmpint (res, ==, R_JSON_FAILED_TO_UNESCAPE_STRING);

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_unicode_ascii), NULL)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (v), ==, "//");
  r_json_value_unref (v);

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_unicode), NULL)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (v), ==, "\xc2\xa2\xe2\x82\xac");
  r_json_value_unref (v);
}
RTEST_END;

RTEST (rjson, string_escape, RTEST_FAST)
{
  static const rchar json_string[] = "\"foo\\\\foo\\b\\nbar\\t\"\n";
  static const rchar json_unicode[] = "\"\\u00a2\\u20acfoo\"";
  RJsonValue * v;
  rchar * str;

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_string), NULL)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (v), ==, "foo\\foo\b\nbar\t");
  r_assert_cmpstr ((str = r_json_value_get_string_quoted (v)), ==, "\"foo\\\\foo\\b\\nbar\\t\"");
  r_free (str);
  r_json_value_unref (v);

  r_assert_cmpptr ((v = r_json_parse (R_STR_WITH_SIZE_ARGS (json_unicode), NULL)), !=, NULL);
  r_assert_cmpint (v->type, ==, R_JSON_TYPE_STRING);
  r_assert_cmpstr (r_json_value_get_string (v), ==, "\xc2\xa2\xe2\x82\xac""foo");
  r_assert_cmpstr ((str = r_json_value_get_string_quoted (v)), ==, json_unicode);
  r_free (str);
  r_json_value_unref (v);
}
RTEST_END;

