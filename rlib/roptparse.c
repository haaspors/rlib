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

#include "config.h"
#include "rlib-private.h"
#include <rlib/roptparse.h>

#include <rlib/charset/rascii.h>
#include <rlib/rassert.h>
#include <rlib/rref.h>
#include <rlib/data/rlist.h>
#include <rlib/data/rstring.h>
#include <rlib/rlog.h>
#include <rlib/rmem.h>
#include <rlib/os/rproc.h>
#include <rlib/rstr.h>

/* TODO: Add API to customize options usage string + (get|set)ters appname++ */
/* TODO: Add add_groups API */
/* TODO: Add commands API? */

struct _ROptionParser
{
  rchar * appname;
  rchar * options;
  rchar * version;
  rchar * summary;
  rchar * epilog;

  ruint help_enabled   : 1;
  ruint ignore_unknown : 1;

  rboolean optver, opthlp;

  ROptionGroup * entries;
  RSList * groups;

  RSList * parse_ctx;
};

typedef struct
{
  ROptionEntry opt;
  const rchar * argval;
} ROptionEntryCtx;

struct _ROptionGroup
{
  RRef ref;

  rchar * name;
  rchar * desc;
  rchar * summary;
  rpointer user;
  RDestroyNotify notify;

  ROptionEntryCtx * entries;
  rsize count;
};


static void r_option_group_free (ROptionGroup * group);

static inline ROptionGroup *
r_option_group_new_internal (const rchar * name, const rchar * desc,
    const rchar * summary, rpointer user, RDestroyNotify notify)
{
  ROptionGroup * ret = r_mem_new (ROptionGroup);
  if (R_LIKELY (ret != NULL)) {
    r_ref_init (ret, r_option_group_free);

    ret->name = r_strdup (name);
    ret->desc = r_strdup (desc);
    ret->summary = r_strdup (summary);

    ret->user = user;
    ret->notify = notify;

    ret->entries = NULL;
    ret->count = 0;
  }

  return ret;
}

ROptionGroup *
r_option_group_new (const rchar * name, const rchar * desc,
    const rchar * summary, rpointer user, RDestroyNotify notify)
{
  if (R_UNLIKELY (name == NULL || name[0] == 0))
    return NULL;

  return r_option_group_new_internal (name, desc, summary, user, notify);
}

static void
r_option_group_free (ROptionGroup * group)
{
  r_free (group->name);
  r_free (group->desc);
  r_free (group->summary);

  if (group->notify != NULL)
    group->notify (group->user);

  r_free (group->entries);

  r_free (group);
}

static rboolean
r_option_entry_ctx_init (ROptionEntryCtx * ctx, const ROptionEntry * opt)
{
  /* Hard requirements */
  if (opt->longarg == NULL)
    return FALSE;
  if (opt->type >= R_OPTION_TYPE_COUNT)
    return FALSE;

  ctx->argval = NULL;
  ctx->opt = *opt;

  /* Soft requirements */
  if (opt->shortarg == '-' || (opt->shortarg != 0 && !r_ascii_isprint (opt->shortarg))) {
    R_LOG_CAT_WARNING (&rlib_logcat,
        "ignoring incompatible short opt name for --%s", opt->longarg);
    ctx->opt.shortarg = 0;
  }
  if (opt->type != R_OPTION_TYPE_NONE && (opt->flags & R_OPTION_FLAG_INVERSE)) {
    R_LOG_CAT_WARNING (&rlib_logcat,
        "ignoring incompatible inverse flag for --%s", opt->longarg);
    ctx->opt.flags &= ~R_OPTION_FLAG_INVERSE;
  }

  if (ctx->opt.val != NULL) {
    switch (ctx->opt.type) {
      case R_OPTION_TYPE_NONE:
        *(rboolean *)ctx->opt.val = (ctx->opt.flags & R_OPTION_FLAG_INVERSE) == R_OPTION_FLAG_INVERSE;
        break;
      case R_OPTION_TYPE_INT:
        *(int *)ctx->opt.val = 0;
        break;
      case R_OPTION_TYPE_INT64:
        *(rint64 *)ctx->opt.val = 0;
        break;
      case R_OPTION_TYPE_DOUBLE:
        *(rdouble *)ctx->opt.val = .0;
        break;
      case R_OPTION_TYPE_STRING:
      case R_OPTION_TYPE_FILENAME:
        *(rpointer *)ctx->opt.val = NULL;
        break;
      default:
        r_assert_not_reached ();
        break;
    }
  }

  return TRUE;
}

static ROptionEntryCtx *
r_option_group_find_entry_by_shortarg (const ROptionGroup * group,
    rchar shortarg)
{
  rsize i;

  for (i = 0; i < group->count; i++) {
    if (group->entries[i].opt.shortarg == shortarg)
      return &group->entries[i];
  }

  return NULL;
}

static ROptionEntryCtx *
r_option_group_find_entry_by_longarg (const ROptionGroup * group,
    const rchar * longarg)
{
  rsize i, len;
  rchar * eq = r_strchr (longarg, (int)'=');

  if (eq != NULL)
    len = eq - longarg;
  else
    len = r_strlen (longarg);

  for (i = 0; i < group->count; i++) {
    if (r_strncmp (longarg, group->entries[i].opt.longarg, len) == 0)
      return &group->entries[i];
  }

  return NULL;
}

static rboolean
r_option_group_check_required (const ROptionGroup * group, RSList * ctx)
{
  rsize i;

  for (i = 0; i < group->count; i++) {
    ROptionEntry * opt = &group->entries[i].opt;
    if ((opt->flags & R_OPTION_FLAG_REQUIRED) && !r_slist_contains (ctx, opt))
      return FALSE;
  }

  return TRUE;
}

static rboolean
r_option_group_has_option (const ROptionGroup * group, const ROptionEntry * opt)
{
  rsize i;

  if (opt->shortarg != 0) {
    for (i = 0; i < group->count; i++) {
      if (group->entries[i].opt.shortarg == opt->shortarg)
        return TRUE;
      if (r_str_equals (group->entries[i].opt.longarg, opt->longarg))
        return TRUE;
    }
  } else {
    for (i = 0; i < group->count; i++) {
      if (r_str_equals (group->entries[i].opt.longarg, opt->longarg))
        return TRUE;
    }
  }

  return FALSE;
}

rboolean
r_option_group_add_entries (ROptionGroup * group,
    const ROptionEntry * entries, rsize count)
{
  rsize i;

  if (R_UNLIKELY (entries == NULL))
    return FALSE;

  if ((group->entries = r_realloc (group->entries, (group->count + count) * sizeof (ROptionEntryCtx))) == NULL)
    return FALSE;

  for (i = 0; i < count; i++) {
    if (r_option_group_has_option (group, &entries[i]) ||
        !r_option_entry_ctx_init (&group->entries[group->count], &entries[i])) {
      group->count -= i;
      return FALSE;
    }

    group->count++;
  }

  return TRUE;
}

ROptionParser *
r_option_parser_new (const rchar * app, const rchar * version)
{
  ROptionParser * ret = r_mem_new0 (ROptionParser);
  const ROptionEntry r_op_help_args[] = {
    R_OPT_ARG ("version",  0, R_OPTION_TYPE_NONE, &ret->optver,
        R_OPTION_FLAG_NONE, "Show application version number and exit", NULL),
    R_OPT_ARG ("help",   'h', R_OPTION_TYPE_NONE, &ret->opthlp,
        R_OPTION_FLAG_NONE, "Show this help message and exit", NULL),
    R_OPT_ARG ("",       '?', R_OPTION_TYPE_NONE, &ret->opthlp,
        R_OPTION_FLAG_HIDDEN, NULL, NULL),
  };

  ret->help_enabled = TRUE;
  ret->appname = app != NULL ? r_strdup (app) : r_proc_get_exe_name ();
  ret->options = r_strdup ("[options]");
  ret->version = r_strdup (version);
  ret->entries = r_option_group_new_internal (NULL, "Options", NULL, NULL, NULL);
  r_option_group_add_entries (ret->entries,
      r_op_help_args, R_N_ELEMENTS (r_op_help_args));

  return ret;
}

void
r_option_parser_free (ROptionParser * parser)
{
  if (R_LIKELY (parser != NULL)) {
    r_free (parser->appname);
    r_free (parser->options);
    r_free (parser->version);
    r_free (parser->summary);
    r_free (parser->epilog);
    r_option_group_unref (parser->entries);

    r_free (parser);
  }
}

void
r_option_parser_set_summary (ROptionParser * parser, const rchar * summary)
{
  r_free (parser->summary);
  parser->summary = r_strdup (summary);
}

void
r_option_parser_set_epilog (ROptionParser * parser, const rchar * epilog)
{
  r_free (parser->epilog);
  parser->epilog = r_strdup (epilog);
}

void
r_option_parser_set_help_enabled (ROptionParser * parser, rboolean enabled)
{
  parser->help_enabled = enabled;
}

void
r_option_parser_set_ignore_unknown_options (ROptionParser * parser, rboolean ignore_unknown)
{
  parser->ignore_unknown = ignore_unknown;
}

const rchar *
r_option_parser_get_summary (ROptionParser * parser)
{
  return parser->summary;
}

const rchar *
r_option_parser_get_epilog (ROptionParser * parser)
{
  return parser->epilog;
}

rboolean
r_option_parser_is_help_enabled (ROptionParser * parser)
{
  return parser->help_enabled;
}

rboolean
r_option_parser_is_unknown_options_ignored (ROptionParser * parser)
{
  return parser->ignore_unknown;
}

static void
r_option_entry_append_help (const ROptionEntry * opt, RString * str)
{
  int spacing = 32;

  if (opt->flags & R_OPTION_FLAG_HIDDEN)
    return;

  spacing -= r_string_append (str, "  ");

  if (opt->shortarg != 0)
    spacing -= r_string_append_printf (str, "-%c, ", opt->shortarg);

  spacing -= r_string_append_printf (str, "--%s", opt->longarg);
  if (opt->argname == NULL || *opt->argname == 0) {
    switch (opt->type) {
      case R_OPTION_TYPE_NONE:
        break;
      case R_OPTION_TYPE_FILENAME:
        spacing -= r_string_append (str, "=FILENAME");
        break;
      case R_OPTION_TYPE_STRING:
        spacing -= r_string_append (str, "=STRING");
        break;
      default:
        spacing -= r_string_append (str, "=VALUE");
        break;
    }
  } else if (opt->type != R_OPTION_TYPE_NONE) {
    spacing -= r_string_append_printf (str, "=%s", opt->argname);
  }

  while (spacing > 0)
    spacing -= r_string_append (str, " ");

  r_string_append_printf (str, " %s\n", opt->desc);
}

static void
r_option_group_append_help (const ROptionGroup * group, RString * str)
{
  rsize i;

  r_string_append (str, "\n");
  if (group->desc != NULL)
    r_string_append_printf (str, "%s:\n", group->desc);

  for (i = 0; i < group->count; i++)
    r_option_entry_append_help (&group->entries[i].opt, str);
}

rchar *
r_option_parser_get_help_output (ROptionParser * parser)
{
  RString * str;
  rsize i;

  if (R_UNLIKELY (parser == NULL))
    return NULL;

  str = r_string_new_sized (1024);
  r_string_append_printf (str, "Usage:\n  %s %s\n",
      parser->appname, parser->options);

  if (parser->summary != NULL)
    r_string_append_printf (str, "\n%s\n", parser->summary);

  r_string_append_printf (str, "\n%s:\n", parser->entries->desc);
  for (i = (parser->help_enabled) ? 0 : 3; i < parser->entries->count; i++)
    r_option_entry_append_help (&parser->entries->entries[i].opt, str);

  r_slist_foreach (parser->groups, (RFunc)r_option_group_append_help, str);

  if (parser->epilog != NULL)
    r_string_append_printf (str, "\n%s\n", parser->epilog);

  return r_string_free_keep (str);
}

rchar *
r_option_parser_get_version_output (ROptionParser * parser)
{
  const rchar * prefix, * real;

  if (R_UNLIKELY (parser == NULL))
    return NULL;

  if (parser->version != NULL) {
    prefix = "version ";
    real = parser->version;
  } else {
    prefix = "";
    real = "(\"version not specified\")";
  }

  return r_strprintf ("%s %s%s\n", parser->appname, prefix, real);
}

rboolean
r_option_parser_add_entries (ROptionParser * parser,
    const ROptionEntry * entries, rsize count)
{
  return r_option_group_add_entries (parser->entries, entries, count);
}

static ROptionEntryCtx *
r_option_parser_find_entry_by_shortarg (const ROptionParser * parser,
    rchar shortarg)
{
  ROptionEntryCtx * ret;
  RSList * it;

  ret = r_option_group_find_entry_by_shortarg (parser->entries, shortarg);
  for (it = parser->groups; it != NULL && ret == NULL; it = r_slist_next (it))
    ret = r_option_group_find_entry_by_shortarg (r_slist_data (it), shortarg);

  return ret;
}

static ROptionEntryCtx *
r_option_parser_find_entry_by_longarg (const ROptionParser * parser,
    const rchar * longarg)
{
  ROptionEntryCtx * ret;
  RSList * it;

  ret = r_option_group_find_entry_by_longarg (parser->entries, longarg);
  for (it = parser->groups; it != NULL && ret == NULL; it = r_slist_next (it))
    ret = r_option_group_find_entry_by_longarg (r_slist_data (it), longarg);

  return ret;
}

static rboolean
r_option_parser_check_required (ROptionParser * parser)
{
  rboolean ret;
  RSList * it;

  ret = r_option_group_check_required (parser->entries, parser->parse_ctx);
  for (it = parser->groups; it != NULL && ret; it = r_slist_next (it))
    ret &= r_option_group_check_required (r_slist_data (it), parser->parse_ctx);

  return ret;
}

static ROptionParseResult
r_option_entry_ctx_parse_none (const rchar ** str, rboolean * val, rboolean inv)
{
  if (str == NULL)
    return R_OPTION_PARSE_ERROR;

  if (val != NULL)
    *val = !inv ? *str != NULL : *str == NULL;

  return R_OPTION_PARSE_OK;
}

static ROptionParseResult
r_option_entry_parse_int (const rchar ** str, int * val)
{
  int value;
  RStrParse error;

  if (str == NULL || **str == 0)
    return R_OPTION_PARSE_ERROR;

  value = r_str_to_int (*str, str, 0, &error);
  if (error != R_STR_PARSE_OK || *str == 0)
    return R_OPTION_PARSE_VALUE_ERROR;

  if (val != NULL)
    *val = value;
  return R_OPTION_PARSE_OK;
}

static ROptionParseResult
r_option_entry_parse_int64 (const rchar ** str, rint64 * val)
{
  rint64 value;
  RStrParse error;

  if (str == NULL || **str == 0)
    return R_OPTION_PARSE_ERROR;

  value = r_str_to_int64 (*str, str, 0, &error);
  if (error != R_STR_PARSE_OK || *str == 0)
    return R_OPTION_PARSE_VALUE_ERROR;

  if (val != NULL)
    *val = value;
  return R_OPTION_PARSE_OK;
}

static ROptionParseResult
r_option_entry_parse_double (const rchar ** str, rdouble * val)
{
  rdouble value;
  RStrParse error;

  if (str == NULL || **str == 0)
    return R_OPTION_PARSE_ERROR;

  value = r_str_to_double (*str, str, &error);
  if (error != R_STR_PARSE_OK || *str == 0)
    return R_OPTION_PARSE_VALUE_ERROR;

  if (val != NULL)
    *val = value;
  return R_OPTION_PARSE_OK;
}

static ROptionParseResult
r_option_entry_parse_string (const rchar ** str, rchar ** val)
{
  if (str == NULL)
    return R_OPTION_PARSE_ERROR;

  if (val != NULL) {
    r_free (*val);
    *val = (*str != NULL && **str != 0) ? r_strdup (*str) : NULL;
  }

  *str += r_strlen (*str);
  return R_OPTION_PARSE_OK;
}

static ROptionParseResult
r_option_parser_parse_option_ctx (ROptionParser * parser, ROptionEntryCtx * ctx,
    const rchar ** arg, int * argc, const rchar *** argv)
{
  ROptionParseResult ret = R_OPTION_PARSE_ERROR;

  if (ctx->opt.type == R_OPTION_TYPE_NONE) {
    ctx->argval = *arg;
    ret = r_option_entry_ctx_parse_none (arg, ctx->opt.val,
        (ctx->opt.flags & R_OPTION_FLAG_INVERSE) == R_OPTION_FLAG_INVERSE);
  } else {
    const rchar * str;

    if (arg != NULL && *arg != NULL && **arg != 0) {
      str = ctx->argval = *arg;
    } else if (*argc > 0) {
      str = ctx->argval = **argv;
    } else {
      return R_OPTION_PARSE_ERROR;
    }

    switch (ctx->opt.type) {
      case R_OPTION_TYPE_INT:
        ret = r_option_entry_parse_int (&str, ctx->opt.val);
        break;
      case R_OPTION_TYPE_INT64:
        ret = r_option_entry_parse_int64 (&str, ctx->opt.val);
        break;
      case R_OPTION_TYPE_DOUBLE:
        ret = r_option_entry_parse_double (&str, ctx->opt.val);
        break;
      case R_OPTION_TYPE_STRING:
      case R_OPTION_TYPE_FILENAME:
        ret = r_option_entry_parse_string (&str, ctx->opt.val);
        break;
      default:
        r_assert_not_reached ();
        break;
    }

    if (ret == R_OPTION_PARSE_OK) {
      if (arg != NULL && *arg != NULL && **arg != 0) {
        *arg = str;
      } else {
        (*argc)--;
        (*argv)++;
      }
    }
  }

  parser->parse_ctx = r_slist_prepend (parser->parse_ctx, &ctx->opt);

  return ret;
}

static ROptionParseResult
r_option_parser_parse_short_option (ROptionParser * parser,
    const rchar ** arg, int * argc, const rchar *** argv)
{
  ROptionEntryCtx * ctx;

  if ((ctx = r_option_parser_find_entry_by_shortarg (parser, **arg)) != NULL) {
    (*arg)++;
    if (**arg == '=')
      (*arg)++;
    return r_option_parser_parse_option_ctx (parser, ctx, arg, argc, argv);
  } else if (!parser->ignore_unknown) {
    return R_OPTION_PARSE_UNKNOWN_OPTION;
  }

  (*arg)++;
  return R_OPTION_PARSE_OK;
}

static ROptionParseResult
r_option_parser_parse_long_option (ROptionParser * parser,
    const rchar ** arg, int * argc, const rchar *** argv)
{
  ROptionEntryCtx * ctx;

  if ((ctx = r_option_parser_find_entry_by_longarg (parser, *arg)) != NULL) {
    *arg += r_strlen (ctx->opt.longarg);
    if (**arg == '=')
      (*arg)++;

    return r_option_parser_parse_option_ctx (parser, ctx, arg, argc, argv);
  } else if (!parser->ignore_unknown) {
    return R_OPTION_PARSE_UNKNOWN_OPTION;
  }

  return R_OPTION_PARSE_OK;
}

ROptionParseResult
r_option_parser_parse (ROptionParser * parser,
    int * argc, rchar *** argv)
{
  ROptionParseResult ret = R_OPTION_PARSE_OK;

  if (R_UNLIKELY (argc == NULL || *argc < 1 || argv == NULL))
    return R_OPTION_PARSE_ARG_ERROR;

  if (parser->appname == NULL)
    parser->appname = r_strdup ((*argv)[0]);
  (*argv)++;
  (*argc)--;

  parser->optver = parser->opthlp = FALSE;

  while (*argc > 0 && ret == R_OPTION_PARSE_OK) {
    const rchar * arg = **argv;

    if (*arg != '-')
      break;
    arg++;

    (*argv)++;
    (*argc)--;

    if (*arg == '-') {
      arg++;
      if (*arg == 0)
        break;
      ret = r_option_parser_parse_long_option (parser, &arg, argc, (const rchar ***)argv);
    } else {
      do {
        ret = r_option_parser_parse_short_option (parser, &arg, argc, (const rchar ***)argv);
      } while (*arg != 0 && ret == R_OPTION_PARSE_OK);
    }
  }

  if (parser->optver)
    ret = R_OPTION_PARSE_VERSION;
  else if (parser->opthlp)
    ret = R_OPTION_PARSE_HELP;
  else if (!r_option_parser_check_required (parser))
    ret = R_OPTION_PARSE_MISSING_OPTION;

  r_slist_destroy (parser->parse_ctx);
  parser->parse_ctx = NULL;

  return ret;
}

rboolean
r_option_parser_get_value_by_longarg (ROptionParser * parser,
    const rchar * longarg, rpointer val, ROptionType * type)
{
  ROptionEntryCtx * ctx;

  if ((ctx = r_option_parser_find_entry_by_longarg (parser, longarg)) != NULL) {
    if (val != NULL) {
      const rchar * arg = ctx->argval;
      switch (ctx->opt.type) {
        case R_OPTION_TYPE_BOOL:
          r_option_entry_ctx_parse_none (&arg, val,
              (ctx->opt.flags & R_OPTION_FLAG_INVERSE) == R_OPTION_FLAG_INVERSE);
          break;
        case R_OPTION_TYPE_INT:
          r_option_entry_parse_int (&arg, val);
          break;
        case R_OPTION_TYPE_INT64:
          r_option_entry_parse_int64 (&arg, val);
          break;
        case R_OPTION_TYPE_DOUBLE:
          r_option_entry_parse_double (&arg, val);
          break;
        case R_OPTION_TYPE_STRING:
        case R_OPTION_TYPE_FILENAME:
          r_option_entry_parse_string (&arg, val);
          break;
        default:
          return FALSE;
      }
    }

    if (type != NULL)
      *type = ctx->opt.type;

    return TRUE;
  }

  return FALSE;
}

