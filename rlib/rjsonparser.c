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

#include <rlib/charset/rascii.h>
#include <rlib/rassert.h>
#include <rlib/rmem.h>
#include <rlib/rmemfile.h>

struct _RJsonParser {
  RRef ref;

  RMemMapInfo info;

  RBuffer * buf;
  RMemFile * file;
};

static void
r_json_parser_free (RJsonParser * parser)
{
  r_buffer_unmap (parser->buf, &parser->info);
  r_buffer_unref (parser->buf);

  if (parser->file != NULL)
    r_mem_file_unref (parser->file);

  r_free (parser);
}

RJsonParser *
r_json_parser_new (rconstpointer mem, rsize size)
{
  RJsonParser * ret;
  RBuffer * buf;

  if (R_UNLIKELY (mem == NULL || size == 0))
    return NULL;

  if ((buf = r_buffer_new_wrapped (R_MEM_FLAG_READONLY,
          (rpointer)mem, size, size, 0, NULL, NULL)) != NULL) {
    ret = r_json_parser_new_buffer (buf);
    r_buffer_unref (buf);
  } else {
    ret = NULL;
  }

  return ret;
}

RJsonParser *
r_json_parser_new_file (const rchar * file)
{
  RJsonParser * ret;
  RMemFile * mfile;

  if ((mfile = r_mem_file_new (file, R_MEM_PROT_READ, FALSE)) != NULL) {
    if ((ret = r_json_parser_new (r_mem_file_get_mem (mfile),
            r_mem_file_get_size (mfile))) != NULL) {
      ret->file = mfile;
    } else {
      r_mem_file_unref (mfile);
    }
  } else {
    ret = NULL;
  }

  return ret;
}

RJsonParser *
r_json_parser_new_buffer (RBuffer * buf)
{
  RJsonParser * ret;

  if (R_UNLIKELY (buf == NULL))
    return NULL;

  if ((ret = r_mem_new0 (RJsonParser)) != NULL) {
    if (r_buffer_map (buf, &ret->info, R_MEM_MAP_READ)) {
      r_ref_init (ret, r_json_parser_free);
      ret->buf = r_buffer_ref (buf);
    } else {
      r_free (ret);
      ret = NULL;
    }
  }

  return ret;
}

typedef RJsonValue * (*RJsonParseValueFunc) (const RJsonScanCtx * ctx,
    RJsonResult * res, rchar ** endptr);

static RJsonItResult
r_json_parser_object_field_cb (const RJsonParser * parser,
    const RStrChunk * name, const RJsonScanCtx * value,
    rchar ** endptr, rpointer user)
{
  RJsonObject * object = user;
  RJsonValue * v;
  RJsonResult r;
  rchar * namestr;

  if ((namestr = r_json_str_unescape_dup (name->str, name->size)) != NULL) {
    if ((v = r_json_scan_ctx_to_value (value, &r, endptr)) != NULL) {
      r_kv_ptr_array_add (&object->array, namestr, r_free, v, r_json_value_unref);
      if (endptr != NULL)
        r_assert_cmpptr (*endptr, !=, NULL);
      return R_JSON_CONTINUE;
    }

    r_free (namestr);
  } else {
    r = R_JSON_FAILED_TO_UNESCAPE_STRING;
  }

  return R_JSON_RESULT_AS_IT_RESULT (r);
}

static RJsonValue *
r_json_scan_ctx_to_object (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  RJsonValue * ret = r_json_object_new ();
  RJsonResult r;

  if (res == NULL)
    res = &r;

  if ((*res = r_json_scan_ctx_parse_object_foreach_field (ctx,
          r_json_parser_object_field_cb, ret, endptr)) == R_JSON_OK)
    return ret;

  r_json_value_unref (ret);
  return NULL;
}

static RJsonItResult
r_json_parser_value_cb (const RJsonParser * parser, const RStrChunk * name,
    const RJsonScanCtx * value, rchar ** endptr, rpointer user)
{
  RJsonArray * array = user;
  RJsonValue * v;
  RJsonResult r;

  (void) name;

  if ((v = r_json_scan_ctx_to_value (value, &r, endptr)) != NULL) {
    r_ptr_array_add (&array->array, v, r_json_value_unref);
    return R_JSON_CONTINUE;
  }

  return R_JSON_RESULT_AS_IT_RESULT (r);
}

static RJsonValue *
r_json_scan_ctx_to_array (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  RJsonValue * ret = r_json_array_new ();
  RJsonResult r;

  if (res == NULL)
    res = &r;

  if ((*res = r_json_scan_ctx_parse_array_foreach_value (ctx,
          r_json_parser_value_cb, ret, endptr)) == R_JSON_OK)
    return ret;

  r_json_value_unref (ret);
  return NULL;
}

static RJsonValue *
r_json_scan_ctx_to_number (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  rdouble number;
  RJsonResult r;

  if (res == NULL)
    res = &r;

  if ((*res = r_json_scan_ctx_parse_number_double (ctx, &number, endptr)) == R_JSON_OK)
    return (RJsonValue *)r_json_number_new_double (number);

  return NULL;
}

static RJsonValue *
r_json_scan_ctx_to_string (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  RStrChunk data;
  RJsonResult r;

  if (res == NULL)
    res = &r;

  if ((*res = r_json_scan_ctx_parse_string (ctx, &data, endptr)) == R_JSON_OK)
    return (RJsonValue *)r_json_string_new (data.str, data.size);

  return NULL;
}

static RJsonValue *
r_json_scan_ctx_to_true (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  if (res != NULL)
    *res = R_JSON_OK;
  if (endptr)
    *endptr = (rchar *)ctx->data.str + 4;

  return (RJsonValue *)r_json_true_new ();
}

static RJsonValue *
r_json_scan_ctx_to_false (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  if (res != NULL)
    *res = R_JSON_OK;
  if (endptr)
    *endptr = (rchar *)ctx->data.str + 5;

  return (RJsonValue *)r_json_false_new ();
}

static RJsonValue *
r_json_scan_ctx_to_null (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  if (res != NULL)
    *res = R_JSON_OK;
  if (endptr)
    *endptr = (rchar *)ctx->data.str + 4;

  return (RJsonValue *)r_json_null_new ();
}

RJsonValue *
r_json_parser_parse_all (RJsonParser * parser, RJsonResult * res)
{
  RJsonScanCtx ctx = R_JSON_SCAN_CTX_INIT;
  RJsonValue * ret;
  RJsonResult r;

  if ((r = r_json_parser_scan_start (parser, &ctx)) == R_JSON_OK) {
    ret = r_json_scan_ctx_to_value (&ctx, &r, NULL);
    r_json_parser_scan_end (parser, &ctx);
  } else {
    ret = NULL;
  }

  if (res != NULL)
    *res = r;

  return ret;
}

static inline const rchar *
r_json_parser_get_end (const RJsonParser * parser)
{
  return (const rchar *)parser->info.data + parser->info.size;
}

static inline void
r_json_scan_ctx_scan_whitespace (RJsonScanCtx * ctx)
{
  r_str_chunk_lwstrip (&ctx->data);
}

static RJsonResult
r_json_parser_scan_init_at (const RJsonParser * parser, RJsonScanCtx * ctx, rchar * str)
{
  RJsonResult ret = R_JSON_OK;
  const rchar * end = r_json_parser_get_end (parser);

  if (str > end)
    return R_JSON_OUT_OF_RANGE;
  else if (str == end)
    return R_JSON_END;

  ctx->parser = parser;
  ctx->type = R_JSON_TYPE_NONE;
  ctx->data.str = str;
  ctx->data.size = RPOINTER_TO_SIZE (end) - RPOINTER_TO_SIZE (str);
  r_json_scan_ctx_scan_whitespace (ctx);
  switch (ctx->data.str[0]) {
    case '{':
      ctx->type = R_JSON_TYPE_OBJECT;
      break;
    case '[':
      ctx->type = R_JSON_TYPE_ARRAY;
      break;
    case '"':
      ctx->type = R_JSON_TYPE_STRING;
      break;
    case 't':
      if (r_str_chunk_has_prefix (&ctx->data, R_STR_WITH_SIZE_ARGS ("true")))
        ctx->type = R_JSON_TYPE_TRUE;
      else
        ret = R_JSON_TYPE_NOT_PARSED;
      break;
    case 'f':
      if (r_str_chunk_has_prefix (&ctx->data, R_STR_WITH_SIZE_ARGS ("false")))
        ctx->type = R_JSON_TYPE_FALSE;
      else
        ret = R_JSON_TYPE_NOT_PARSED;
      break;
    case 'n':
      if (r_str_chunk_has_prefix (&ctx->data, R_STR_WITH_SIZE_ARGS ("null")))
        ctx->type = R_JSON_TYPE_NULL;
      else
        ret = R_JSON_TYPE_NOT_PARSED;
      break;
    case ']':
    case '}':
      ret = R_JSON_END;
      break;
    default:
      if (r_ascii_isdigit (ctx->data.str[0]) || ctx->data.str[0] == '-') {
        RStrParse res;
        r_str_to_double (ctx->data.str, NULL, &res);
        if (res == R_STR_PARSE_OK) {
          ctx->type = R_JSON_TYPE_NUMBER;
        } else {
          ctx->type = R_JSON_TYPE_NONE;
          ret = R_JSON_NUMBER_NOT_PARSED;
        }
      } else {
        ret = R_JSON_TYPE_NOT_PARSED;
      }
  }

  return ret;
}

RJsonResult
r_json_parser_scan_start (RJsonParser * parser, RJsonScanCtx * ctx)
{
  RJsonResult ret;

  if (R_UNLIKELY (parser == NULL || ctx == NULL))
    return R_JSON_INVAL;

  if ((ret = r_json_parser_scan_init_at (parser, ctx, (rchar *)parser->info.data)) == R_JSON_OK)
    r_json_parser_ref (parser);

  return ret;
}

RJsonResult
r_json_parser_scan_end (RJsonParser * parser, RJsonScanCtx * ctx)
{
  if (R_UNLIKELY (parser == NULL || ctx == NULL || parser != ctx->parser))
    return R_JSON_INVAL;

  r_json_parser_unref (parser);
  r_memclear (ctx, sizeof (RJsonScanCtx));
  return R_JSON_OK;
}

RJsonValue *
r_json_scan_ctx_to_value (const RJsonScanCtx * ctx, RJsonResult * res, rchar ** endptr)
{
  if (R_UNLIKELY (ctx == NULL || ctx->type < 0 || ctx->type >= R_JSON_TYPE_COUNT)) {
    if (res != NULL)
      *res = R_JSON_INVAL;
    return NULL;
  }

  RJsonParseValueFunc valfuncs[] = {
    r_json_scan_ctx_to_object,
    r_json_scan_ctx_to_array,
    r_json_scan_ctx_to_number,
    r_json_scan_ctx_to_string,
    r_json_scan_ctx_to_true,
    r_json_scan_ctx_to_false,
    r_json_scan_ctx_to_null,
  };

  return valfuncs[ctx->type] (ctx, res, endptr);
}

rchar *
r_json_scan_ctx_endptr (const RJsonScanCtx * ctx, RJsonResult * res)
{
  RJsonResult r;
  rchar * ret = NULL;
  RStrChunk str = R_STR_CHUNK_INIT;

  if (ctx != NULL) {
    switch (ctx->type) {
      case R_JSON_TYPE_OBJECT:
        r = r_json_scan_ctx_parse_object_foreach_field (ctx, NULL, NULL, &ret);
        break;
      case R_JSON_TYPE_ARRAY:
        r = r_json_scan_ctx_parse_array_foreach_value (ctx, NULL, NULL, &ret);
        break;
      case R_JSON_TYPE_NUMBER:
        r = r_json_scan_ctx_parse_number (ctx, &str, &ret);
        break;
      case R_JSON_TYPE_STRING:
        r = r_json_scan_ctx_parse_string (ctx, &str, &ret);
        break;
      case R_JSON_TYPE_TRUE:
      case R_JSON_TYPE_NULL:
        r = R_JSON_OK;
        ret = (rchar *)ctx->data.str + 4;
        break;
      case R_JSON_TYPE_FALSE:
        r = R_JSON_OK;
        ret = (rchar *)ctx->data.str + 5;
        break;
      default:
        r = R_JSON_WRONG_TYPE;
        break;
    }
  } else {
    r = R_JSON_INVAL;
  }

  if (res != NULL)
    *res = r;

  return ret;
}

RJsonResult
r_json_scan_ctx_scan_object_field (RJsonScanCtx * ctx,
    RStrChunk * name, RJsonScanCtx * value)
{
  RJsonResult ret;
  rchar * endptr = ctx->data.str;

  if ((ret = r_json_scan_ctx_parse_object_field (ctx, name, value, &endptr)) == R_JSON_OK) {
    ctx->data.size -= RPOINTER_TO_SIZE (endptr) - RPOINTER_TO_SIZE (ctx->data.str);
    ctx->data.str = endptr;
    r_json_scan_ctx_scan_whitespace (ctx);
  }

  return ret;
}

RJsonResult
r_json_scan_ctx_parse_object_field (const RJsonScanCtx * ctx,
    RStrChunk * name, RJsonScanCtx * value, rchar ** endptr)
{
  RJsonResult ret;

  if (R_UNLIKELY (name == NULL || value == NULL ||
        ctx == NULL || ctx->type != R_JSON_TYPE_OBJECT))
    return R_JSON_INVAL;

  if (*ctx->data.str == '{' || *ctx->data.str == ',') {
    RJsonScanCtx namectx = R_JSON_SCAN_CTX_INIT;
    rchar * eptr;

    if ((ret = r_json_parser_scan_init_at (ctx->parser, &namectx, ctx->data.str + 1)) == R_JSON_OK &&
        (ret = r_json_scan_ctx_parse_string (&namectx, name, &eptr)) == R_JSON_OK) {
      value->data.str = eptr;
      value->data.size = RPOINTER_TO_SIZE (r_json_parser_get_end (ctx->parser)) - RPOINTER_TO_SIZE (eptr);
      r_json_scan_ctx_scan_whitespace (value);

      if (*value->data.str == ':') {
        if ((ret = r_json_parser_scan_init_at (ctx->parser, value, value->data.str + 1)) == R_JSON_OK) {
          if (endptr != NULL)
            *endptr = r_json_scan_ctx_endptr (value, &ret);
        }
      } else {
        ret = R_JSON_OBJECT_FIELD_NOT_PARSED;
      }
    } else if (ret == R_JSON_END) {
      ret = R_JSON_EMPTY;
      if (endptr != NULL)
        *endptr = value->data.str + 1;
    }
  } else if (*ctx->data.str == '}') {
    ret = R_JSON_END;
    if (endptr != NULL)
      *endptr = ctx->data.str + 1;
  } else {
    ret = R_JSON_WRONG_TYPE;
  }

  return ret;
}

RJsonResult
r_json_scan_ctx_parse_object_foreach_field (const RJsonScanCtx * ctx,
    RJsonParserItFunc func, rpointer user, rchar ** endptr)
{
  RJsonScanCtx next = *ctx, val = R_JSON_SCAN_CTX_INIT;
  RStrChunk name = R_STR_CHUNK_INIT;
  RJsonResult ret;
  RJsonItResult res;
  rchar * eptr = NULL;

  while ((ret = r_json_scan_ctx_parse_object_field (&next, &name, &val, NULL)) == R_JSON_OK) {
    eptr = NULL;
    switch ((res = func (ctx->parser, &name, &val, &eptr, user))) {
      case R_JSON_CONTINUE:
        if (eptr == NULL) {
          eptr = r_json_scan_ctx_endptr (&val, &ret);
        } else if (eptr < (rchar *)ctx->parser->info.data ||
            eptr > (rchar *)ctx->parser->info.data + ctx->parser->info.size) {
          return R_JSON_OUT_OF_RANGE;
        }
        break;
      case R_JSON_STOP:
        return R_JSON_ITERATION_STOPPED;
      default:
        return (RJsonResult)res;
    }

    next.data.str = eptr;
    next.data.size = RPOINTER_TO_SIZE (r_json_parser_get_end (ctx->parser)) - RPOINTER_TO_SIZE (eptr);
    r_json_scan_ctx_scan_whitespace (&next);
  }

  if (ret == R_JSON_EMPTY) {
    next.data.str++;
    next.data.size--;
    r_json_scan_ctx_scan_whitespace (&next);
    ret = R_JSON_END;
  }

  if (ret == R_JSON_END) {
    r_assert_cmpint (*next.data.str, ==, '}');
    eptr = next.data.str + 1;
    ret = R_JSON_OK;
  }

  if (endptr != NULL)
    *endptr = eptr;

  return ret;
}

RJsonResult
r_json_scan_ctx_scan_array_value (RJsonScanCtx * ctx, RJsonScanCtx * value)
{
  RJsonResult ret;
  rchar * endptr = ctx->data.str;

  if ((ret = r_json_scan_ctx_parse_array_value (ctx, value, &endptr)) == R_JSON_OK) {
    ctx->data.size -= RPOINTER_TO_SIZE (endptr) - RPOINTER_TO_SIZE (ctx->data.str);
    ctx->data.str = endptr;
    r_json_scan_ctx_scan_whitespace (ctx);
  }

  return ret;
}

RJsonResult
r_json_scan_ctx_parse_array_value (const RJsonScanCtx * ctx,
    RJsonScanCtx * value, rchar ** endptr)
{
  RJsonResult ret;

  if (R_UNLIKELY (ctx == NULL || ctx->type != R_JSON_TYPE_ARRAY || value == NULL))
    return R_JSON_INVAL;

  if (*ctx->data.str == '[' || *ctx->data.str == ',') {
    if ((ret = r_json_parser_scan_init_at (ctx->parser, value, ctx->data.str + 1)) == R_JSON_OK) {
      if (endptr != NULL)
        *endptr = r_json_scan_ctx_endptr (value, &ret);
    } else if (ret == R_JSON_END) {
      ret = R_JSON_EMPTY;
      if (endptr != NULL)
        *endptr = value->data.str + 1;
    }
  } else if (*ctx->data.str == ']') {
    ret = R_JSON_END;
    if (endptr != NULL)
      *endptr = ctx->data.str + 1;
  } else {
    ret = R_JSON_WRONG_TYPE;
  }

  return ret;
}

RJsonResult
r_json_scan_ctx_parse_array_foreach_value (const RJsonScanCtx * ctx,
    RJsonParserItFunc func, rpointer user, rchar ** endptr)
{
  RJsonScanCtx next = *ctx, val = R_JSON_SCAN_CTX_INIT;
  RJsonResult ret;
  RJsonItResult res;
  rchar * eptr = NULL;

  while ((ret = r_json_scan_ctx_parse_array_value (&next, &val, NULL)) == R_JSON_OK) {
    eptr = NULL;
    switch ((res = func (ctx->parser, NULL, &val, &eptr, user))) {
      case R_JSON_CONTINUE:
        if (eptr == NULL) {
          eptr = r_json_scan_ctx_endptr (&val, &ret);
        } else if (eptr < (rchar *)ctx->parser->info.data ||
            eptr > (rchar *)ctx->parser->info.data + ctx->parser->info.size) {
          return R_JSON_OUT_OF_RANGE;
        }
        break;
      case R_JSON_STOP:
        return R_JSON_ITERATION_STOPPED;
      default:
        return (RJsonResult)res;
    }

    next.data.str = eptr;
    next.data.size = RPOINTER_TO_SIZE (r_json_parser_get_end (ctx->parser)) - RPOINTER_TO_SIZE (eptr);
    r_json_scan_ctx_scan_whitespace (&next);
  }

  if (ret == R_JSON_EMPTY) {
    next.data.str++;
    next.data.size--;
    r_json_scan_ctx_scan_whitespace (&next);
    ret = R_JSON_END;
  }

  if (ret == R_JSON_END) {
    r_assert_cmpint (*next.data.str, ==, ']');
    eptr = next.data.str + 1;
    ret = R_JSON_OK;
  }

  if (endptr != NULL)
    *endptr = eptr;

  return ret;
}


RJsonResult
r_json_scan_ctx_parse_number (const RJsonScanCtx * ctx, RStrChunk * str, rchar ** endptr)
{
  rchar * ptr, * end;

  if (R_UNLIKELY (ctx == NULL || str == NULL))
    return R_JSON_INVAL;

  end = (rchar *)ctx->parser->info.data + ctx->parser->info.size;
  str->str = ptr = ctx->data.str;
  str->size = 0;

  if (R_UNLIKELY (ptr >= end))
    return R_JSON_NUMBER_NOT_PARSED;

  if (*ptr == '-')
    ptr++;
  if (R_UNLIKELY (ptr >= end))
    return R_JSON_NUMBER_NOT_PARSED;

  if (r_ascii_isdigit (*ptr)) {
    if (R_UNLIKELY (end - ptr > 1 && ptr[0] == '0' && ptr[1] == '0'))
      return R_JSON_NUMBER_NOT_PARSED;

    do {
      ptr++;
    } while (ptr < end && r_ascii_isdigit (*ptr));

    if (ptr < end && *ptr == '.') {
      ptr++;
      if (ptr >= end || !r_ascii_isdigit (*ptr))
        return R_JSON_NUMBER_NOT_PARSED;
      do {
        ptr++;
      } while (ptr < end && r_ascii_isdigit (*ptr));
    }

    if (ptr < end && (*ptr == 'e' || *ptr == 'E')) {
      ptr++;
      if (ptr < end && (*ptr == '+' || *ptr == '-'))
        ptr++;

      if (ptr >= end || !r_ascii_isdigit (*ptr))
        return R_JSON_NUMBER_NOT_PARSED;
      do {
        ptr++;
      } while (ptr < end && r_ascii_isdigit (*ptr));
    }

    str->size = RPOINTER_TO_SIZE (ptr) - RPOINTER_TO_SIZE (str->str);

    while (ptr < end && r_ascii_isspace (*ptr))
      ptr++;

    if (endptr != NULL)
      *endptr = ptr;

    if (ptr == end || *ptr == ',' || *ptr == '}' || *ptr == ']')
      return R_JSON_OK;
  }

  return R_JSON_NUMBER_NOT_PARSED;
}

RJsonResult
r_json_scan_ctx_parse_number_int (const RJsonScanCtx * ctx, int * number, rchar ** endptr)
{
  RJsonResult ret;
  RStrChunk str = R_STR_CHUNK_INIT;

  if ((ret = r_json_scan_ctx_parse_number (ctx, &str, endptr)) == R_JSON_OK &&
      number != NULL) {
    RStrParse res;
    *number = r_str_to_int (str.str, NULL, 10, &res);
    if (R_UNLIKELY (res != R_STR_PARSE_OK))
      ret = R_JSON_NUMBER_NOT_PARSED;
  }

  return ret;
}

RJsonResult
r_json_scan_ctx_parse_number_double (const RJsonScanCtx * ctx, rdouble * number, rchar ** endptr)
{
  RJsonResult ret;
  RStrChunk str = R_STR_CHUNK_INIT;

  if ((ret = r_json_scan_ctx_parse_number (ctx, &str, endptr)) == R_JSON_OK &&
      number != NULL) {
    RStrParse res;
    *number = r_str_to_double (str.str, NULL, &res);
    if (R_UNLIKELY (res != R_STR_PARSE_OK))
      ret = R_JSON_NUMBER_NOT_PARSED;
  }

  return ret;
}

RJsonResult
r_json_scan_ctx_parse_string (const RJsonScanCtx * ctx, RStrChunk * str, rchar ** endptr)
{
  rssize cur;
  rsize idx = 0;

  if (R_UNLIKELY (ctx == NULL || ctx->type != R_JSON_TYPE_STRING || str == NULL))
    return R_JSON_INVAL;

  str->str = (rchar *)ctx->data.str + 1;
  str->size = ctx->data.size - 1;
  if ((cur = r_str_idx_of_c (str->str + idx, str->size - idx, '"')) >= 0) {
    do {
      idx += cur;
      if (str->str[idx - 1] != '\\') {
        str->size = idx;
        if (endptr != NULL)
          *endptr = r_str_chunk_end (str) + 1;
        return R_JSON_OK;
      }
      idx++;
    } while ((cur = r_str_idx_of_c (str->str + idx, str->size - idx, '"')) > 0);
  }

  return R_JSON_STRING_NOT_TERMINATED;
}

