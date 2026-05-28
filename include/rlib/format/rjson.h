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

/**
 * @file rlib/format/rjson.h
 * @brief In-memory JSON value tree: parse, build and serialise.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/rbuffer.h>
#include <rlib/rstr.h>

/**
 * @defgroup r_json JSON
 *
 * @brief In-memory JSON value tree plus a streaming parser.
 *
 * Two complementary APIs:
 *
 *  - **Tree API** (this file): parse a document into a refcounted
 *    @ref RJsonValue tree, walk it with the @c r_json_value_*
 *    accessors, optionally serialise back to bytes with
 *    @ref r_json_value_to_buffer.
 *  - **@ref r_jsonparser streaming parser** (rjsonparser.h): scan a
 *    document with a cursor-style API that doesn't build the full
 *    tree; useful when the input is large or only a few fields are
 *    needed.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief JSON value-type discriminator. */
typedef enum {
  R_JSON_TYPE_NONE    = -1, /**< Uninitialised / not yet parsed. */
  R_JSON_TYPE_OBJECT  =  0, /**< Object (key-value map). */
  R_JSON_TYPE_ARRAY,        /**< Array (ordered list). */
  R_JSON_TYPE_NUMBER,       /**< Number (integer or floating-point). */
  R_JSON_TYPE_STRING,       /**< String. */
  R_JSON_TYPE_TRUE,         /**< Boolean @c true. */
  R_JSON_TYPE_FALSE,        /**< Boolean @c false. */
  R_JSON_TYPE_NULL,         /**< @c null. */
  R_JSON_TYPE_COUNT         /**< Sentinel (number of value types). */
} RJsonType;

/** @brief Result code returned by the JSON parse / scan APIs. */
typedef enum {
  R_JSON_ITERATION_STOPPED = -3,        /**< Iterator returned @c R_JSON_STOP. */
  R_JSON_EMPTY = -2,                    /**< Container has no more entries. */
  R_JSON_END = -1,                      /**< End of input reached. */
  R_JSON_OK = 0,                        /**< Success. */
  R_JSON_INVAL,                         /**< Invalid argument. */
  R_JSON_OOM,                           /**< Allocation failed. */
  R_JSON_OUT_OF_RANGE,                  /**< Numeric overflow. */
  R_JSON_MAP_FAILED,                    /**< @c mmap of input file failed. */
  R_JSON_TYPE_NOT_PARSED,               /**< Value's type couldn't be determined. */
  R_JSON_NOT_CONTAINER,                 /**< Expected object or array. */
  R_JSON_WRONG_TYPE,                    /**< Value didn't match requested accessor. */
  R_JSON_NUMBER_NOT_PARSED,             /**< Failed to parse number literal. */
  R_JSON_STRING_NOT_TERMINATED,         /**< Unterminated string literal. */
  R_JSON_FAILED_TO_UNESCAPE_STRING,     /**< Invalid escape sequence. */
  R_JSON_OBJECT_FIELD_NOT_PARSED,       /**< Couldn't parse an object key:value field. */
  R_JSON_RESULT_LAST                    /**< Sentinel. */
} RJsonResult;

/** @brief Serialisation-format flags for @ref r_json_value_to_buffer. */
typedef enum {
  R_JSON_NOFLAGS        = 0,        /**< Pretty-print with spaces. */
  R_JSON_COMPACT        = (1 << 0), /**< Minify (no whitespace). */
  R_JSON_USE_TABS       = (1 << 1), /**< Indent with tabs instead of spaces. */
} RJsonFlags;

/**
 * @brief Refcounted JSON value (base class for all type-specific
 * variants).
 *
 * Use the @c r_json_value_get_* accessors to read values; the
 * concrete @ref RJsonObject / @ref RJsonArray / etc. struct
 * pointers are opaque.
 */
typedef struct {
  RRef ref;        /**< Refcount header (do not touch directly). */
  RJsonType type;  /**< Discriminator; pick the right accessor based on this. */
} RJsonValue;
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_json_value_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_json_value_unref  r_ref_unref

/** @name Parse and serialise
 *  @{ */
/**
 * @brief Parse a JSON document from a memory buffer into a value tree.
 * @param data Input bytes.
 * @param len  Input size in bytes.
 * @param res  Optional out-pointer: receives a @ref RJsonResult code.
 * @return New @ref RJsonValue tree, or @c NULL on failure.
 */
R_API RJsonValue * r_json_parse (rconstpointer data, rsize len, RJsonResult * res);
/** @brief Like @ref r_json_parse but takes an @c RBuffer. */
R_API RJsonValue * r_json_parse_buffer (RBuffer * buf, RJsonResult * res);
/**
 * @brief Serialise a value tree to a fresh @c RBuffer.
 * @param value Tree to serialise.
 * @param flags Bitmask of @ref RJsonFlags.
 * @param res   Optional out-pointer for the @ref RJsonResult.
 */
R_API RBuffer * r_json_value_to_buffer (const RJsonValue * value,
    RJsonFlags flags, RJsonResult * res);
/** @} */

/** @name Concrete value types (opaque)
 *
 * Pointers to these are returned by the parser and the constructors
 * below; treat as @c RJsonValue * for accessor calls.
 *  @{ */
typedef struct RJsonObject RJsonObject;  /**< Opaque object value. */
typedef struct RJsonArray  RJsonArray;   /**< Opaque array value. */
typedef struct RJsonNumber RJsonNumber;  /**< Opaque number value. */
typedef struct RJsonString RJsonString;  /**< Opaque string value. */
typedef struct RJsonTrue   RJsonTrue;    /**< Opaque @c true singleton. */
typedef struct RJsonFalse  RJsonFalse;   /**< Opaque @c false singleton. */
typedef struct RJsonNull   RJsonNull;    /**< Opaque @c null singleton. */
/** @} */

/** @name Constructors
 *  @{ */
/** @brief Construct an empty object. */
R_API RJsonValue * r_json_object_new (void);
/** @brief Construct an empty array. */
R_API RJsonValue * r_json_array_new (void);
/** @brief Construct a number from a double-precision value. */
R_API RJsonValue * r_json_number_new_double (rdouble value);
/**
 * @brief Construct a string from a not-yet-escaped UTF-8 buffer.
 * @param value Source bytes.
 * @param size  Length, or @c -1 for @c strlen.
 * @param res   Optional result code (for invalid UTF-8 / OOM).
 */
R_API RJsonValue * r_json_string_new (const rchar * value, rssize size, RJsonResult * res);
/** @brief Construct a string from an already-escaped buffer. */
R_API RJsonValue * r_json_string_new_unescaped (const rchar * value, rssize size);
/** @brief Construct a string that borrows a static, already-escaped buffer. */
R_API RJsonValue * r_json_string_new_static_unescaped (const rchar * value);
/** @brief Generic constructor; used by the singleton helpers below. */
R_API RJsonValue * r_json_value_new (RJsonType type);
/** @brief Construct the @c true singleton. */
#define r_json_true_new() r_json_value_new (R_JSON_TYPE_TRUE)
/** @brief Construct the @c false singleton. */
#define r_json_false_new() r_json_value_new (R_JSON_TYPE_FALSE)
/** @brief Construct the @c null singleton. */
#define r_json_null_new() r_json_value_new (R_JSON_TYPE_NULL)
/** @} */

/** @name Container mutators
 *  @{ */
/**
 * @brief Add a key-value pair to an object.
 * @param obj   Object value.
 * @param key   String value used as the field name.
 * @param value Value associated with @p key (takes ownership).
 */
R_API RJsonResult r_json_object_add_field (RJsonValue * obj, RJsonValue * key, RJsonValue * value);
/** @brief Append @p value to @p array (takes ownership). */
R_API RJsonResult r_json_array_add_value (RJsonValue * array, RJsonValue * value);
/** @} */

/** @name Accessors
 *  @{ */
/** @brief Number of fields in an object. */
R_API rsize r_json_value_get_object_field_count (const RJsonValue * value);
/** @brief Return the @p idx-th field name (NUL-terminated, borrowed). */
R_API const rchar * r_json_value_get_object_field_name (RJsonValue * value, rsize idx);
/** @brief Return the @p idx-th field value (borrowed reference). */
R_API RJsonValue * r_json_value_get_object_field_value (RJsonValue * value, rsize idx);
/** @brief Look up a field by name (borrowed reference, @c NULL if absent). */
R_API RJsonValue * r_json_value_get_object_field (RJsonValue * value, const rchar * key);
/** @brief Iterate every field, calling @p func with the key and value. */
R_API void r_json_value_foreach_object_field (RJsonValue * value, RKeyValueFunc func, rpointer user);
/** @brief Number of values in an array. */
R_API rsize r_json_value_get_array_size (const RJsonValue * value);
/** @brief Return the @p idx-th array entry (borrowed reference). */
R_API RJsonValue * r_json_value_get_array_value (RJsonValue * value, rsize idx);
/** @brief Iterate every array entry, calling @p func with the value. */
R_API void r_json_value_foreach_array_value (RJsonValue * value, RFunc func, rpointer user);
/** @brief Return a number-typed value rounded / truncated to @c int. */
R_API int r_json_value_get_number_int (const RJsonValue * value);
/** @brief Return a number-typed value as @c double. */
R_API rdouble r_json_value_get_number_double (const RJsonValue * value);
/** @brief Return the string's contents (NUL-terminated, borrowed). */
R_API const rchar * r_json_value_get_string (const RJsonValue * value);
/** @brief Return a fresh quoted JSON string literal (e.g. @c "\"hi\""). */
R_API rchar * r_json_value_get_string_quoted (const RJsonValue * value);
/** @brief @c TRUE if @p value is the @c true singleton. */
R_API rboolean r_json_value_is_true (const RJsonValue * value);
/** @brief @c TRUE if @p value is the @c false singleton. */
R_API rboolean r_json_value_is_false (const RJsonValue * value);
/** @brief @c TRUE if @p value is the @c null singleton. */
R_API rboolean r_json_value_is_null (const RJsonValue * value);
/** @} */

R_END_DECLS

/** @} */

#endif /* __R_JSON_H__ */

