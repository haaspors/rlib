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
#ifndef __R_JSON_PARSER_H__
#define __R_JSON_PARSER_H__

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/rjson.h>

R_BEGIN_DECLS

typedef struct _RJsonParser RJsonParser;

R_API RJsonParser * r_json_parser_new (rconstpointer mem, rsize size);
R_API RJsonParser * r_json_parser_new_file (const rchar * file);
R_API RJsonParser * r_json_parser_new_buffer (RBuffer * buf);
#define r_json_parser_ref   r_ref_ref
#define r_json_parser_unref r_ref_unref

R_API RJsonValue * r_json_parser_parse_all (RJsonParser * parser, RJsonResult * res);

typedef struct {
  const RJsonParser * parser;
  RJsonType type;
  RStrChunk data;
} RJsonScanCtx;
#define R_JSON_SCAN_CTX_INIT    { NULL, R_JSON_TYPE_NONE, R_STR_CHUNK_INIT }

typedef enum {
  R_JSON_STOP = R_JSON_RESULT_LAST + 1,
  R_JSON_CONTINUE,
} RJsonItResult;
#define R_JSON_RESULT_AS_IT_RESULT(r) ((RJsonItResult)(r))

typedef RJsonItResult (*RJsonParserItFunc) (const RJsonParser * parser,
    const RStrChunk * name, const RJsonScanCtx * value, rchar ** endptr, rpointer user);

R_API RJsonResult r_json_parser_scan_start (RJsonParser * parser, RJsonScanCtx * ctx);
R_API RJsonResult r_json_parser_scan_end (RJsonParser * parser, RJsonScanCtx * ctx);


R_API RJsonValue * r_json_scan_ctx_to_value (const RJsonScanCtx * ctx,
    RJsonResult * res, rchar ** endptr);
R_API rchar * r_json_scan_ctx_endptr (const RJsonScanCtx * ctx, RJsonResult * res);

/* JSON object */
R_API RJsonResult r_json_scan_ctx_scan_object_field (RJsonScanCtx * ctx,
    RStrChunk * name, RJsonScanCtx * value);
R_API RJsonResult r_json_scan_ctx_parse_object_field (const RJsonScanCtx * ctx,
    RStrChunk * name, RJsonScanCtx * value, rchar ** endptr);
R_API RJsonResult r_json_scan_ctx_parse_object_foreach_field (const RJsonScanCtx * ctx,
    RJsonParserItFunc func, rpointer user, rchar ** endptr);
/* JSON array */
R_API RJsonResult r_json_scan_ctx_scan_array_value (RJsonScanCtx * ctx,
    RJsonScanCtx * value);
R_API RJsonResult r_json_scan_ctx_parse_array_value (const RJsonScanCtx * ctx,
    RJsonScanCtx * value, rchar ** endptr);
R_API RJsonResult r_json_scan_ctx_parse_array_foreach_value (const RJsonScanCtx * ctx,
    RJsonParserItFunc func, rpointer user, rchar ** endptr);
/* JSON number */
R_API RJsonResult r_json_scan_ctx_parse_number (const RJsonScanCtx * ctx,
    RStrChunk * number, rchar ** endptr);
R_API RJsonResult r_json_scan_ctx_parse_number_int (const RJsonScanCtx * ctx,
    int * number, rchar ** endptr);
R_API RJsonResult r_json_scan_ctx_parse_number_double (const RJsonScanCtx * ctx,
    rdouble * number, rchar ** endptr);
/* JSON string */
R_API RJsonResult r_json_scan_ctx_parse_string (const RJsonScanCtx * ctx,
    RStrChunk * str, rchar ** endptr);

R_END_DECLS

#endif /* __R_JSON_PARSER_H__ */

