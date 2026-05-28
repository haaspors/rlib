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

/**
 * @file rlib/format/rjsonparser.h
 * @brief Streaming JSON parser: cursor-style scanning of objects,
 * arrays, numbers and strings without building a full value tree.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/format/rjson.h>

/**
 * @defgroup r_jsonparser Streaming JSON parser
 * @ingroup r_json
 *
 * @brief Cursor-style streaming parser; complementary to the
 * tree API in @ref r_json.
 *
 * Useful when the input is large, or only a few fields are needed.
 * Open a parser over a memory buffer / file / @c RBuffer, get the
 * top-level @ref RJsonScanCtx with @ref r_json_parser_scan_start,
 * and drill in with the per-type @c r_json_scan_ctx_* helpers.
 *
 * Numbers and strings are returned as @ref RStrChunk slices over the
 * original input — no copies and no per-value allocations.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted parser handle. */
typedef struct RJsonParser RJsonParser;

/** @brief Construct a parser over a flat memory buffer. */
R_API RJsonParser * r_json_parser_new (rconstpointer mem, rsize size);
/** @brief Construct a parser over a file (mapped on POSIX). */
R_API RJsonParser * r_json_parser_new_file (const rchar * file);
/** @brief Construct a parser over an @c RBuffer. */
R_API RJsonParser * r_json_parser_new_buffer (RBuffer * buf);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_json_parser_ref   r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_json_parser_unref r_ref_unref

/**
 * @brief Parse the whole input into a tree (equivalent to @ref
 * r_json_parse over the parser's input).
 */
R_API RJsonValue * r_json_parser_parse_all (RJsonParser * parser, RJsonResult * res);

/**
 * @brief Cursor pointing at a JSON value in the input stream.
 *
 * @c type tells you what's at the cursor; @c data is the byte range
 * the value occupies in the original input. Initialise with
 * @ref R_JSON_SCAN_CTX_INIT.
 */
typedef struct {
  const RJsonParser * parser;   /**< Owning parser. */
  RJsonType type;               /**< Type at the cursor. */
  RStrChunk data;               /**< Byte range of the value's text. */
} RJsonScanCtx;
/** @brief Static initialiser for a fresh @ref RJsonScanCtx. */
#define R_JSON_SCAN_CTX_INIT    { NULL, R_JSON_TYPE_NONE, R_STR_CHUNK_INIT }

/** @brief Iterator return value; extends @ref RJsonResult. */
typedef enum {
  R_JSON_STOP = R_JSON_RESULT_LAST + 1, /**< Stop iteration early. */
  R_JSON_CONTINUE,                       /**< Continue iteration. */
} RJsonItResult;
/** @brief Convert an @ref RJsonResult to an @ref RJsonItResult. */
#define R_JSON_RESULT_AS_IT_RESULT(r) ((RJsonItResult)(r))

/**
 * @brief Iterator callback signature for object/array foreach helpers.
 *
 * @param parser  Owning parser.
 * @param key     Field key, or @c NULL when iterating arrays.
 * @param value   Cursor pointing at the entry's value.
 * @param endptr  Optional out-pointer: caller-updated parse position.
 * @param user    Opaque user pointer passed through from the call site.
 * @return @ref R_JSON_CONTINUE to keep going, @ref R_JSON_STOP to break.
 */
typedef RJsonItResult (*RJsonParserItFunc) (const RJsonParser * parser,
    const RStrChunk * key, const RJsonScanCtx * value, rchar ** endptr, rpointer user);

/** @brief Initialise @p ctx to point at the top-level value. */
R_API RJsonResult r_json_parser_scan_start (RJsonParser * parser, RJsonScanCtx * ctx);
/** @brief Verify the top-level value was fully consumed; call after @ref r_json_parser_scan_start. */
R_API RJsonResult r_json_parser_scan_end (RJsonParser * parser, RJsonScanCtx * ctx);


/**
 * @brief Materialise the value at @p ctx into a full @ref RJsonValue tree.
 *
 * @param ctx    Cursor to materialise.
 * @param res    Optional out-pointer for the result code.
 * @param endptr Optional out-pointer: receives the end of the parsed
 *               value's byte range.
 */
R_API RJsonValue * r_json_scan_ctx_to_value (const RJsonScanCtx * ctx,
    RJsonResult * res, rchar ** endptr);
/** @brief Return a pointer to the byte just past the value at @p ctx. */
R_API rchar * r_json_scan_ctx_endptr (const RJsonScanCtx * ctx, RJsonResult * res);

/** @name Objects
 *  @{ */
/**
 * @brief Advance @p ctx to the next field; @p key and @p value are
 * filled with the field name and a cursor over its value.
 *
 * Returns @ref R_JSON_EMPTY when the object has no more fields.
 */
R_API RJsonResult r_json_scan_ctx_scan_object_field (RJsonScanCtx * ctx,
    RStrChunk * key, RJsonScanCtx * value);
/** @brief Non-advancing variant of @ref r_json_scan_ctx_scan_object_field. */
R_API RJsonResult r_json_scan_ctx_parse_object_field (const RJsonScanCtx * ctx,
    RStrChunk * key, RJsonScanCtx * value, rchar ** endptr);
/** @brief Iterate every field via @p func. */
R_API RJsonResult r_json_scan_ctx_parse_object_foreach_field (const RJsonScanCtx * ctx,
    RJsonParserItFunc func, rpointer user, rchar ** endptr);
/** @} */

/** @name Arrays
 *  @{ */
/** @brief Advance @p ctx to the next array entry; @p value receives a cursor over it. */
R_API RJsonResult r_json_scan_ctx_scan_array_value (RJsonScanCtx * ctx,
    RJsonScanCtx * value);
/** @brief Non-advancing variant of @ref r_json_scan_ctx_scan_array_value. */
R_API RJsonResult r_json_scan_ctx_parse_array_value (const RJsonScanCtx * ctx,
    RJsonScanCtx * value, rchar ** endptr);
/** @brief Iterate every array entry via @p func. */
R_API RJsonResult r_json_scan_ctx_parse_array_foreach_value (const RJsonScanCtx * ctx,
    RJsonParserItFunc func, rpointer user, rchar ** endptr);
/** @} */

/** @name Numbers
 *  @{ */
/** @brief Return the raw number literal at @p ctx as an @ref RStrChunk slice. */
R_API RJsonResult r_json_scan_ctx_parse_number (const RJsonScanCtx * ctx,
    RStrChunk * number, rchar ** endptr);
/** @brief Parse the number at @p ctx as an @c int. */
R_API RJsonResult r_json_scan_ctx_parse_number_int (const RJsonScanCtx * ctx,
    int * number, rchar ** endptr);
/** @brief Parse the number at @p ctx as @c double. */
R_API RJsonResult r_json_scan_ctx_parse_number_double (const RJsonScanCtx * ctx,
    rdouble * number, rchar ** endptr);
/** @} */

/** @name Strings
 *  @{ */
/** @brief Return the string at @p ctx as an @ref RStrChunk slice (raw, still escaped). */
R_API RJsonResult r_json_scan_ctx_parse_string (const RJsonScanCtx * ctx,
    RStrChunk * str, rchar ** endptr);
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_JSON_PARSER_H__ */

