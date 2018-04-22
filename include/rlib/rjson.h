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
#ifndef __R_JSON_H__
#define __R_JSON_H__

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/rbuffer.h>
#include <rlib/rstr.h>

R_BEGIN_DECLS

typedef enum {
  R_JSON_TYPE_NONE    = -1,
  R_JSON_TYPE_OBJECT  =  0,
  R_JSON_TYPE_ARRAY,
  R_JSON_TYPE_NUMBER,
  R_JSON_TYPE_STRING,
  R_JSON_TYPE_TRUE,
  R_JSON_TYPE_FALSE,
  R_JSON_TYPE_NULL,
  R_JSON_TYPE_COUNT
} RJsonType;

typedef enum {
  R_JSON_ITERATION_STOPPED = -3,
  R_JSON_EMPTY = -2,
  R_JSON_END = -1,
  R_JSON_OK = 0,
  R_JSON_INVAL,
  R_JSON_OOM,
  R_JSON_OUT_OF_RANGE,
  R_JSON_MAP_FAILED,
  R_JSON_TYPE_NOT_PARSED,
  R_JSON_NOT_CONTAINER,
  R_JSON_WRONG_TYPE,
  R_JSON_NUMBER_NOT_PARSED,
  R_JSON_STRING_NOT_TERMINATED,
  R_JSON_FAILED_TO_UNESCAPE_STRING,
  R_JSON_OBJECT_FIELD_NOT_PARSED,
  R_JSON_RESULT_LAST
} RJsonResult;

typedef enum {
  R_JSON_PRETTY_WHITESPACE      = (1 << 0),
} RJsonFlags;

typedef struct {
  RRef ref;

  RJsonType type;
} RJsonValue;
#define r_json_value_ref    r_ref_ref
#define r_json_value_unref  r_ref_unref

/* JSON simple value API */
R_API RJsonValue * r_json_parse (rconstpointer data, rsize len, RJsonResult * res);
R_API RJsonValue * r_json_parse_buffer (RBuffer * buf, RJsonResult * res);
R_API RBuffer * r_json_value_to_buffer (const RJsonValue * value, RJsonFlags flags);


/* RJsonValue API */
typedef struct _RJsonObject RJsonObject;
typedef struct _RJsonArray  RJsonArray;
typedef struct _RJsonNumber RJsonNumber;
typedef struct _RJsonString RJsonString;
typedef struct _RJsonTrue   RJsonTrue;
typedef struct _RJsonFalse  RJsonFalse;
typedef struct _RJsonNull   RJsonNull;

R_API RJsonValue * r_json_object_new (void);
R_API RJsonValue * r_json_array_new (void);
R_API RJsonValue * r_json_number_new_double (rdouble value);
R_API RJsonValue * r_json_string_new (const rchar * value, rssize size);
R_API RJsonValue * r_json_string_new_unescaped (const rchar * value, rssize size);
R_API RJsonValue * r_json_string_new_static (const rchar * value);
R_API RJsonValue * r_json_value_new (RJsonType type);
#define r_json_true_new() r_json_value_new (R_JSON_TYPE_TRUE)
#define r_json_false_new() r_json_value_new (R_JSON_TYPE_FALSE)
#define r_json_null_new() r_json_value_new (R_JSON_TYPE_NULL)

R_API RJsonResult r_json_object_add_field (RJsonValue * obj, RJsonValue * key, RJsonValue * value);
R_API RJsonResult r_json_array_add_value (RJsonValue * array, RJsonValue * value);

R_API rsize r_json_value_get_object_field_count (const RJsonValue * value);
R_API const rchar * r_json_value_get_object_field_name (RJsonValue * value, rsize idx);
R_API RJsonValue * r_json_value_get_object_field_value (RJsonValue * value, rsize idx);
R_API RJsonValue * r_json_value_get_object_field (RJsonValue * value, const rchar * key);
R_API void r_json_value_foreach_object_field (RJsonValue * value, RKeyValueFunc func, rpointer user);
R_API rsize r_json_value_get_array_size (const RJsonValue * value);
R_API RJsonValue * r_json_value_get_array_value (RJsonValue * value, rsize idx);
R_API void r_json_value_foreach_array_value (RJsonValue * value, RFunc func, rpointer user);
R_API int r_json_value_get_number_int (const RJsonValue * value);
R_API rdouble r_json_value_get_number_double (const RJsonValue * value);
R_API const rchar * r_json_value_get_string (const RJsonValue * value);
R_API rboolean r_json_value_is_true (const RJsonValue * value);
R_API rboolean r_json_value_is_false (const RJsonValue * value);
R_API rboolean r_json_value_is_null (const RJsonValue * value);

R_END_DECLS

#endif /* __R_JSON_H__ */

