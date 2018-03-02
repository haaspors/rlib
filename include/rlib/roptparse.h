/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_OPTPARSE_H__
#define __R_OPTPARSE_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

R_BEGIN_DECLS

typedef enum {
  R_OPTION_TYPE_NONE,
  R_OPTION_TYPE_BOOL = R_OPTION_TYPE_NONE,
  R_OPTION_TYPE_INT,
  R_OPTION_TYPE_INT64,
  R_OPTION_TYPE_DOUBLE,
  R_OPTION_TYPE_STRING,
  R_OPTION_TYPE_FILENAME,
  R_OPTION_TYPE_COUNT
} ROptionType;

typedef enum {
  R_OPTION_FLAG_NONE            = 0,
  R_OPTION_FLAG_HIDDEN          = 1 << 0,
  R_OPTION_FLAG_INVERSE         = 1 << 1,
  R_OPTION_FLAG_REQUIRED        = 1 << 2,
} ROptionFlags;

typedef struct _ROptionParser ROptionParser;
typedef struct _ROptionGroup  ROptionGroup;
typedef struct _ROptionEntry {
  const rchar * longarg;
  rchar         shortarg;
  ROptionType   type;
  rpointer      variable;
  ROptionFlags  flags;
  const rchar * desc;
  const rchar * argname;
} ROptionEntry;

#define R_OPT_ARG(l,s,t,v,f,d,lbl)  { l, s, t, v, f, d, lbl }

typedef enum {
  R_OPTION_PARSE_VERSION = -2,
  R_OPTION_PARSE_HELP = -1,
  R_OPTION_PARSE_OK = 0,
  R_OPTION_PARSE_ARG_ERROR,
  R_OPTION_PARSE_UNKNOWN_OPTION,
  R_OPTION_PARSE_MISSING_OPTION,
  R_OPTION_PARSE_VALUE_ERROR,
  R_OPTION_PARSE_ERROR,
} ROptionParseResult;

R_API ROptionGroup * r_option_group_new (const rchar * name, const rchar * desc,
    const rchar * summary, rpointer user, RDestroyNotify notify);
#define r_option_group_ref r_ref_ref
#define r_option_group_unref r_ref_unref

R_API rboolean r_option_group_add_entries (ROptionGroup * group,
    const ROptionEntry * args, rsize count);

R_API ROptionParser * r_option_parser_new (const rchar * app, const rchar * version) R_ATTR_MALLOC;
R_API void r_option_parser_free (ROptionParser * parser);

R_API void r_option_parser_set_summary (ROptionParser * parser, const rchar * summary);
R_API void r_option_parser_set_epilog (ROptionParser * parser, const rchar * epilog);
R_API void r_option_parser_set_help_enabled (ROptionParser * parser, rboolean enabled);
R_API void r_option_parser_set_ignore_unknown_options (ROptionParser * parser, rboolean ignore_unknown);

R_API const rchar * r_option_parser_get_summary (ROptionParser * parser);
R_API const rchar * r_option_parser_get_epilog (ROptionParser * parser);
R_API rboolean r_option_parser_is_help_enabled (ROptionParser * parser);
R_API rboolean r_option_parser_is_unknown_options_ignored (ROptionParser * parser);

R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_option_parser_get_help_output (ROptionParser * parser) R_ATTR_MALLOC;
R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_option_parser_get_version_output (ROptionParser * parser) R_ATTR_MALLOC;

R_API rboolean r_option_parser_add_entries (ROptionParser * parser,
    const ROptionEntry * args, rsize count);

R_ATTR_WARN_UNUSED_RESULT
R_API ROptionParseResult r_option_parser_parse (ROptionParser * parser,
    int * argc, rchar *** argv);

R_END_DECLS

#endif /* __R_OPTPARSE_H__ */
