/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2018 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_ARGPARSE_H__
#define __R_ARGPARSE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rref.h>

R_BEGIN_DECLS

typedef struct _RArgParser RArgParser;

typedef enum {
  R_ARG_OPTION_TYPE_NONE,
  R_ARG_OPTION_TYPE_BOOL = R_ARG_OPTION_TYPE_NONE,
  R_ARG_OPTION_TYPE_INT,
  R_ARG_OPTION_TYPE_INT64,
  R_ARG_OPTION_TYPE_DOUBLE,
  R_ARG_OPTION_TYPE_STRING,
  R_ARG_OPTION_TYPE_FILENAME,
  R_ARG_OPTION_TYPE_COUNT,
  R_ARG_OPTION_TYPE_ERROR = R_ARG_OPTION_TYPE_COUNT
} RArgOptionType;

typedef enum {
  R_ARG_OPTION_FLAG_NONE            = 0,
  R_ARG_OPTION_FLAG_HIDDEN          = 1 << 0,
  R_ARG_OPTION_FLAG_INVERSE         = 1 << 1,
  R_ARG_OPTION_FLAG_REQUIRED        = 1 << 2,
} RArgOptionFlags;

typedef struct {
  const rchar *   longarg;
  rchar           shortarg;
  RArgOptionType  type;
  RArgOptionFlags flags;
  const rchar *   desc;
  const rchar *   eqname;
} RArgOptionEntry;

typedef enum {
  R_ARG_PARSE_FLAG_NONE               = 0,
  R_ARG_PARSE_FLAG_DONT_EXIT          = 1 << 0,
  R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT  = 1 << 1,
  R_ARG_PARSE_FLAG_DISALE_HELP        = 1 << 2,
  R_ARG_PARSE_FLAG_ALLOW_UNKNOWN      = 1 << 3,
} RArgParseFlags;

typedef enum {
  R_ARG_PARSE_VERSION = -2,
  R_ARG_PARSE_HELP = -1,
  R_ARG_PARSE_OK = 0,
  R_ARG_PARSE_ARG_ERROR,
  R_ARG_PARSE_UNKNOWN_OPTION,
  R_ARG_PARSE_MISSING_OPTION,
  R_ARG_PARSE_VALUE_ERROR,
  R_ARG_PARSE_MISSING_COMMAND,
  R_ARG_PARSE_OOM,
  R_ARG_PARSE_ERROR,
} RArgParseResult;

typedef struct _RArgOptionGroup RArgOptionGroup;
typedef struct _RArgParseCtx RArgParseCtx;


/* RArgParser */
R_API RArgParser * r_arg_parser_new (const rchar * app, const rchar * version) R_ATTR_MALLOC;
#define r_arg_parser_ref r_ref_ref
#define r_arg_parser_unref r_ref_unref

R_API void r_arg_parser_set_summary (RArgParser * parser, const rchar * summary);
R_API void r_arg_parser_set_epilog (RArgParser * parser, const rchar * epilog);

R_API const rchar * r_arg_parser_get_summary (RArgParser * parser);
R_API const rchar * r_arg_parser_get_epilog (RArgParser * parser);

R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_arg_parser_get_help (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname) R_ATTR_MALLOC;
R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_arg_parser_get_version (RArgParser * parser) R_ATTR_MALLOC;

/* Options */
R_API rboolean r_arg_parser_add_option_entries (RArgParser * parser,
    const RArgOptionEntry * args, rsize count);
R_API rboolean r_arg_parser_add_option_entry (RArgParser * parser,
    const rchar * longarg, rchar shortarg,
    RArgOptionType type, RArgOptionFlags flags,
    const rchar * desc, const rchar * eqname);
R_API rboolean r_arg_parser_add_option_group (RArgParser * parser,
    RArgOptionGroup * group);

/* Commands */
R_ATTR_WARN_UNUSED_RESULT
R_API RArgParser * r_arg_parser_add_command (RArgParser * parser,
    const rchar * cmd, const rchar * desc);

/* Parsing, help, version  */
R_ATTR_WARN_UNUSED_RESULT
R_API RArgParseCtx * r_arg_parser_parse (RArgParser * parser, RArgParseFlags flags,
    int * argc, const rchar *** argv, RArgParseResult * res) R_ATTR_MALLOC;
R_API void r_arg_parser_print_version (RArgParser * parser, RArgParseFlags flags);
R_API int r_arg_parser_print_help (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname, int exitval);

/* RArgOptionGroup */
R_API RArgOptionGroup * r_arg_option_group_new (const rchar * name, const rchar * desc,
    const rchar * summary, rpointer user, RDestroyNotify notify);
#define r_arg_option_group_ref r_ref_ref
#define r_arg_option_group_unref r_ref_unref

R_API rboolean r_arg_option_group_add_entries (RArgOptionGroup * group,
    const RArgOptionEntry * args, rsize count);
R_API rboolean r_arg_option_group_add_entry (RArgOptionGroup * group,
    const rchar * longarg, rchar shortarg,
    RArgOptionType type, RArgOptionFlags flags,
    const rchar * desc, const rchar * eqname);

/* RArgParseCtx */
#define r_arg_parse_ctx_ref r_ref_ref
#define r_arg_parse_ctx_unref r_ref_unref

R_API rsize r_arg_parse_ctx_option_count (const RArgParseCtx * ctx);
R_API rboolean r_arg_parse_ctx_has_option (RArgParseCtx * ctx, const rchar * longarg);

R_API RArgOptionType r_arg_parse_ctx_get_option_type (RArgParseCtx * ctx, const rchar * longarg);
R_API rboolean r_arg_parse_ctx_get_option_value (RArgParseCtx * ctx,
    const rchar * longarg, RArgOptionType type, rpointer val);

R_API rboolean r_arg_parse_ctx_get_option_bool (RArgParseCtx * ctx, const rchar * longarg);
R_API int r_arg_parse_ctx_get_option_int (RArgParseCtx * ctx, const rchar * longarg);
R_API rint64 r_arg_parse_ctx_get_option_int64 (RArgParseCtx * ctx, const rchar * longarg);
R_API rdouble r_arg_parse_ctx_get_option_double (RArgParseCtx * ctx, const rchar * longarg);
R_API rchar * r_arg_parse_ctx_get_option_string (RArgParseCtx * ctx, const rchar * longarg) R_ATTR_MALLOC;
R_API rchar * r_arg_parse_ctx_get_option_filename (RArgParseCtx * ctx, const rchar * longarg) R_ATTR_MALLOC;

R_API const rchar * r_arg_parse_ctx_get_command (const RArgParseCtx * ctx);
R_API RArgParseCtx * r_arg_parse_ctx_get_command_ctx (RArgParseCtx * ctx);

R_END_DECLS

#endif /* __R_ARGPARSE_H__ */
