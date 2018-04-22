/* RLIB - Convenience library for useful things
 * Copyright (C) 2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include "rjson-private.h"
#include <rlib/rjsonparser.h>

#include <rlib/rmem.h>

RJsonValue *
r_json_parse (rconstpointer data, rsize len, RJsonResult * res)
{
  RJsonValue * ret;
  RJsonParser * parser;

  if (R_UNLIKELY (data == NULL || len == 0)) {
    if (res != NULL)
      *res = R_JSON_INVAL;
    return NULL;
  }

  if ((parser = r_json_parser_new (data, len)) != NULL) {
    ret = r_json_parser_parse_all (parser, res);
    r_json_parser_unref (parser);
  } else {
    ret = NULL;
    if (res != NULL)
      *res = R_JSON_OOM;
  }

  return ret;
}

RJsonValue *
r_json_parse_buffer (RBuffer * buf, RJsonResult * res)
{
  RJsonValue * ret;
  RJsonParser * parser;

  if (R_UNLIKELY (buf == NULL)) {
    if (res != NULL)
      *res = R_JSON_INVAL;
    return NULL;
  }

  if ((parser = r_json_parser_new_buffer (buf)) != NULL) {
    ret = r_json_parser_parse_all (parser, res);
    r_json_parser_unref (parser);
  } else {
    ret = NULL;
    if (res != NULL)
      *res = R_JSON_OOM;
  }

  return ret;
}

#if 0
RBuffer *
r_json_value_to_buffer (const RJsonValue * value)
{
  /* TODO */
  (void) value;
  return NULL;
}
#endif

static void
r_json_object_free (RJsonObject * object)
{
  r_kv_ptr_array_clear (&object->array);
  r_free (object);
}

RJsonValue *
r_json_object_new (void)
{
  RJsonObject * ret;

  if ((ret = r_mem_new0 (RJsonObject)) != NULL) {
    r_ref_init (ret, r_json_object_free);
    ret->value.type = R_JSON_TYPE_OBJECT;
    r_kv_ptr_array_init_str (&ret->array);
  }

  return &ret->value;
}

static void
r_json_array_free (RJsonArray * array)
{
  r_ptr_array_clear (&array->array);
  r_free (array);
}

RJsonValue *
r_json_array_new (void)
{
  RJsonArray * ret;

  if ((ret = r_mem_new0 (RJsonArray)) != NULL) {
    r_ref_init (ret, r_json_array_free);
    ret->value.type = R_JSON_TYPE_ARRAY;
    r_ptr_array_init (&ret->array);
  }

  return &ret->value;
}

RJsonValue *
r_json_number_new_double (rdouble value)
{
  RJsonNumber * ret;

  if ((ret = r_mem_new (RJsonNumber)) != NULL) {
    r_ref_init (ret, r_free);
    ret->value.type = R_JSON_TYPE_NUMBER;
    ret->v = value;
  }

  return &ret->value;
}

static void
r_json_string_free (RJsonString * str)
{
  r_free (str->v);
  r_free (str);
}

RJsonValue *
r_json_string_new_data (RStrChunk * value)
{
  RJsonString * ret;

  if ((ret = r_mem_new (RJsonString)) != NULL) {
    r_ref_init (ret, r_json_string_free);
    ret->value.type = R_JSON_TYPE_STRING;
    ret->v = r_json_str_chunk_unescape (value);
  }

  return &ret->value;
}

RJsonValue *
r_json_value_new (RJsonType type)
{
  RJsonValue * ret;

  if ((ret = r_mem_new (RJsonValue)) != NULL) {
    r_ref_init (ret, r_free);
    ret->type = type;
  }

  return ret;
}


rsize
r_json_value_get_object_field_count (const RJsonValue * value)
{
  if (value != NULL && value->type == R_JSON_TYPE_OBJECT) {
    const RJsonObject * object = (const RJsonObject *) value;
    return r_kv_ptr_array_size (&object->array);
  }

  return 0;
}

const rchar *
r_json_value_get_object_field_name (RJsonValue * value, rsize idx)
{
  if (value != NULL && value->type == R_JSON_TYPE_OBJECT) {
    RJsonObject * object = (RJsonObject *) value;

    return r_kv_ptr_array_get_key (&object->array, idx);
  }

  return NULL;
}

RJsonValue *
r_json_value_get_object_field_value (RJsonValue * value, rsize idx)
{
  RJsonValue * ret;

  if (value != NULL && value->type == R_JSON_TYPE_OBJECT) {
    RJsonObject * object = (RJsonObject *) value;

    if ((ret = r_kv_ptr_array_get_val (&object->array, idx)) != NULL)
      r_json_value_ref (ret);
  } else {
    ret = NULL;
  }

  return ret;
}

RJsonValue *
r_json_value_get_object_field (RJsonValue * value, const rchar * key)
{
  RJsonValue * ret;

  if (value != NULL && value->type == R_JSON_TYPE_OBJECT) {
    RJsonObject * object = (RJsonObject *) value;

    if ((ret = r_kv_ptr_array_get_val (&object->array,
            r_kv_ptr_array_find (&object->array, key))) != NULL) {
      r_json_value_ref (ret);
    }
  } else {
    ret = NULL;
  }

  return ret;
}

void
r_json_value_foreach_object_field (RJsonValue * value, RKeyValueFunc func, rpointer user)
{
  if (value != NULL && value->type == R_JSON_TYPE_OBJECT) {
    RJsonObject * object = (RJsonObject *) value;

    r_kv_ptr_array_foreach (&object->array, func, user);
  }
}

rsize
r_json_value_get_array_size (const RJsonValue * value)
{
  if (value != NULL && value->type == R_JSON_TYPE_ARRAY) {
    const RJsonArray * array = (const RJsonArray *) value;
    return r_ptr_array_size (&array->array);
  }

  return 0;
}

RJsonValue *
r_json_value_get_array_value (RJsonValue * value, rsize idx)
{
  RJsonValue * ret;

  if (value != NULL && value->type == R_JSON_TYPE_ARRAY) {
    RJsonArray * array = (RJsonArray *) value;

    if ((ret = r_ptr_array_get (&array->array, idx)) != NULL)
      r_json_value_ref (ret);
  } else {
    ret = NULL;
  }

  return ret;
}

void
r_json_value_foreach_array_value (RJsonValue * value, RFunc func, rpointer user)
{
  if (value != NULL && value->type == R_JSON_TYPE_ARRAY) {
    RJsonArray * array = (RJsonArray *) value;

    r_ptr_array_foreach (&array->array, func, user);
  }
}

int
r_json_value_get_number_int (const RJsonValue * value)
{
  if (value != NULL && value->type == R_JSON_TYPE_NUMBER) {
    const RJsonNumber * number = (const RJsonNumber *)value;
    return (int)number->v;
  }

  return 0;
}

rdouble
r_json_value_get_number_double (const RJsonValue * value)
{
  if (value != NULL && value->type == R_JSON_TYPE_NUMBER) {
    const RJsonNumber * number = (const RJsonNumber *)value;
    return number->v;
  }

  return RDOUBLE_NAN;
}

const rchar *
r_json_value_get_string (const RJsonValue * value)
{
  if (value != NULL && value->type == R_JSON_TYPE_STRING) {
    const RJsonString * string = (const RJsonString *)value;
    return string->v;
  }

  return NULL;
}

rboolean
r_json_value_is_true (const RJsonValue * value)
{
  return value != NULL && value->type == R_JSON_TYPE_TRUE;
}

rboolean
r_json_value_is_false (const RJsonValue * value)
{
  return value != NULL && value->type == R_JSON_TYPE_FALSE;
}

rboolean
r_json_value_is_null (const RJsonValue * value)
{
  return value != NULL && value->type == R_JSON_TYPE_NULL;
}

