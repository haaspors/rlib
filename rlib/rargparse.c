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
#include <rlib/rargparse.h>

#include <rlib/charset/rascii.h>
#include <rlib/rassert.h>
#include <rlib/rref.h>
#include <rlib/data/rdictionary.h>
#include <rlib/data/rkvptrarray.h>
#include <rlib/data/rlist.h>
#include <rlib/data/rstring.h>
#include <rlib/rlog.h>
#include <rlib/rmem.h>
#include <rlib/os/rproc.h>
#include <rlib/rstr.h>
#include <rlib/rtty.h>

/* TODO: Add API to customize options usage string + (get|set)ters appname++ */

struct _RArgParser
{
  RRef ref;

  rchar * appname;
  rchar * options;
  rchar * version;
  rchar * summary;
  rchar * epilog;

  RArgOptionGroup * main;
  RSList * groups;

  RKVPtrArray commands;
};

static RArgParseCtx *
r_arg_parser_parse_internal (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname, int * argc, const rchar *** argv,
    RArgParseResult * res);

struct _RArgParseCtx
{
  RRef ref;

  RArgParser * parser;
  RArgParseFlags flags;

  rchar * appname;
  RDictionary * options;

  rchar * command;
  RArgParseCtx * cmdctx;
};

static void
r_arg_parse_ctx_free (RArgParseCtx * ctx)
{
  if (ctx->cmdctx)
    r_arg_parse_ctx_unref (ctx->cmdctx);
  r_free (ctx->command);

  r_dictionary_unref (ctx->options);
  r_free (ctx->appname);

  r_arg_parser_unref (ctx->parser);
  r_free (ctx);
}

static inline RArgParseCtx *
r_arg_parse_ctx_new (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname)
{
  RArgParseCtx * ret;

  if ((ret = r_mem_new0 (RArgParseCtx)) != NULL) {
    r_ref_init (ret, r_arg_parse_ctx_free);

    ret->parser = r_arg_parser_ref (parser);
    ret->flags = flags;
    ret->appname = r_strdup (appname);
    ret->options = r_dictionary_new ();
  }

  return ret;
}

struct _RArgOptionGroup
{
  RRef ref;

  rchar * name;
  rchar * desc;
  rchar * summary;
  rpointer user;
  RDestroyNotify notify;

  RArgOptionEntry * entries;
  rsize count;
};


static void
r_arg_option_group_free (RArgOptionGroup * group)
{
  r_free (group->name);
  r_free (group->desc);
  r_free (group->summary);

  if (group->notify != NULL)
    group->notify (group->user);

  r_free (group->entries);

  r_free (group);
}

static inline RArgOptionGroup *
r_arg_option_group_new_internal (const rchar * name, const rchar * desc,
    const rchar * summary, rpointer user, RDestroyNotify notify)
{
  RArgOptionGroup * ret;
  if (R_LIKELY ((ret = r_mem_new0 (RArgOptionGroup)) != NULL)) {
    r_ref_init (ret, r_arg_option_group_free);

    ret->name = r_strdup (name);
    ret->desc = r_strdup (desc);
    ret->summary = r_strdup (summary);

    ret->user = user;
    ret->notify = notify;
  }

  return ret;
}

RArgOptionGroup *
r_arg_option_group_new (const rchar * name, const rchar * desc,
    const rchar * summary, rpointer user, RDestroyNotify notify)
{
  if (R_UNLIKELY (name == NULL || name[0] == 0))
    return NULL;

  return r_arg_option_group_new_internal (name, desc, summary, user, notify);
}

static rboolean
r_arg_option_entry_ctx_init (RArgOptionEntry * entry, const RArgOptionEntry * opt)
{
  /* Hard requirements */
  if (opt->longarg == NULL)
    return FALSE;
  if (opt->type >= R_ARG_OPTION_TYPE_COUNT)
    return FALSE;

  r_memcpy (entry, opt, sizeof (RArgOptionEntry));

  /* Soft requirements */
  if (opt->shortarg == '-' || (opt->shortarg != 0 && !r_ascii_isprint (opt->shortarg))) {
    R_LOG_CAT_WARNING (&rlib_logcat,
        "ignoring incompatible short opt name for --%s", opt->longarg);
    entry->shortarg = 0;
  }
  if (opt->type != R_ARG_OPTION_TYPE_NONE && (opt->flags & R_ARG_OPTION_FLAG_INVERSE)) {
    R_LOG_CAT_WARNING (&rlib_logcat,
        "ignoring incompatible inverse flag for --%s", opt->longarg);
    entry->flags &= ~R_ARG_OPTION_FLAG_INVERSE;
  }

  return TRUE;
}

static RArgOptionEntry *
r_arg_option_group_find_entry_by_shortarg (const RArgOptionGroup * group,
    rchar shortarg)
{
  rsize i;

  for (i = 0; i < group->count; i++) {
    if (group->entries[i].shortarg == shortarg)
      return &group->entries[i];
  }

  return NULL;
}

static RArgOptionEntry *
r_arg_option_group_find_entry_by_longarg (const RArgOptionGroup * group,
    const rchar * longarg)
{
  rsize i, len;
  rchar * eq = r_strchr (longarg, (int)'=');

  if (eq != NULL)
    len = eq - longarg;
  else
    len = r_strlen (longarg);

  for (i = 0; i < group->count; i++) {
    if (r_strcmp_size (longarg, len, group->entries[i].longarg, -1) == 0)
      return &group->entries[i];
  }

  return NULL;
}

static rboolean
r_arg_option_group_check_required_options (const RArgOptionGroup * group, RDictionary * options)
{
  rsize i;

  for (i = 0; i < group->count; i++) {
    RArgOptionEntry * opt = &group->entries[i];
    if ((opt->flags & R_ARG_OPTION_FLAG_REQUIRED) &&
        !r_dictionary_contains (options, opt->longarg)) {
      return FALSE;
    }
  }

  return TRUE;
}

static rboolean
r_arg_option_group_has_option (const RArgOptionGroup * group, const RArgOptionEntry * opt)
{
  rsize i;

  if (opt->shortarg != 0) {
    for (i = 0; i < group->count; i++) {
      if (group->entries[i].shortarg == opt->shortarg)
        return TRUE;
      if (r_str_equals (group->entries[i].longarg, opt->longarg))
        return TRUE;
    }
  } else {
    for (i = 0; i < group->count; i++) {
      if (r_str_equals (group->entries[i].longarg, opt->longarg))
        return TRUE;
    }
  }

  return FALSE;
}

rboolean
r_arg_option_group_add_entries (RArgOptionGroup * group,
    const RArgOptionEntry * entries, rsize count)
{
  rsize i;

  if (R_UNLIKELY (entries == NULL))
    return FALSE;

  if ((group->entries = r_realloc (group->entries, (group->count + count) * sizeof (RArgOptionEntry))) == NULL)
    return FALSE;

  for (i = 0; i < count; i++) {
    if (r_arg_option_group_has_option (group, &entries[i]) ||
        !r_arg_option_entry_ctx_init (&group->entries[group->count], &entries[i])) {
      group->count -= i;
      return FALSE;
    }

    group->count++;
  }

  return TRUE;
}

rboolean
r_arg_option_group_add_entry (RArgOptionGroup * group,
    const rchar * longarg, rchar shortarg,
    RArgOptionType type, RArgOptionFlags flags,
    const rchar * desc, const rchar * eqname)
{
  const RArgOptionEntry entry = { longarg, shortarg, type, flags, desc, eqname };
  return r_arg_option_group_add_entries (group, &entry, 1);
}

static const RArgOptionEntry r_arg_version_args[] = {
  { "version",  0, R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Show application version number and exit", NULL },
};
static const RArgOptionEntry r_arg_help_args[] = {
  { "help",   'h', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_NONE, "Show this help message and exit", NULL },
  { "",       '?', R_ARG_OPTION_TYPE_NONE, R_ARG_OPTION_FLAG_HIDDEN, NULL, NULL },
};

static void
r_arg_parser_free (RArgParser * parser)
{
  if (R_LIKELY (parser != NULL)) {
    r_free (parser->appname);
    r_free (parser->options);
    r_free (parser->version);
    r_free (parser->summary);
    r_free (parser->epilog);

    r_arg_option_group_unref (parser->main);
    r_slist_destroy_full (parser->groups, r_arg_option_group_unref);

    r_kv_ptr_array_clear (&parser->commands);
    r_free (parser);
  }
}

RArgParser *
r_arg_parser_new (const rchar * app, const rchar * version)
{
  RArgParser * ret;

  if (R_LIKELY ((ret = r_mem_new0 (RArgParser)) != NULL)) {
    r_ref_init (ret, r_arg_parser_free);

    ret->appname = app != NULL ? r_strdup (app) : r_proc_get_exe_name ();
    ret->options = r_strdup ("[options]");
    ret->version = r_strdup (version);
    ret->main = r_arg_option_group_new_internal (NULL, "Options", NULL, NULL, NULL);
    r_arg_option_group_add_entries (ret->main,
        r_arg_version_args, R_N_ELEMENTS (r_arg_version_args));
    r_arg_option_group_add_entries (ret->main,
        r_arg_help_args, R_N_ELEMENTS (r_arg_help_args));

    r_kv_ptr_array_init (&ret->commands, r_str_equal);
  }

  return ret;
}

void
r_arg_parser_set_summary (RArgParser * parser, const rchar * summary)
{
  r_free (parser->summary);
  parser->summary = r_strdup (summary);
}

void
r_arg_parser_set_epilog (RArgParser * parser, const rchar * epilog)
{
  r_free (parser->epilog);
  parser->epilog = r_strdup (epilog);
}

const rchar *
r_arg_parser_get_summary (RArgParser * parser)
{
  return parser->summary;
}

const rchar *
r_arg_parser_get_epilog (RArgParser * parser)
{
  return parser->epilog;
}

static void
r_arg_option_entry_append_help (const RArgOptionEntry * opt, RString * str)
{
  int spacing = 32;

  if (opt->flags & R_ARG_OPTION_FLAG_HIDDEN)
    return;

  spacing -= r_string_append (str, "  ");

  if (opt->shortarg != 0)
    spacing -= r_string_append_printf (str, "-%c, ", opt->shortarg);

  spacing -= r_string_append_printf (str, "--%s", opt->longarg);
  if (opt->eqname == NULL || *opt->eqname == 0) {
    switch (opt->type) {
      case R_ARG_OPTION_TYPE_NONE:
        break;
      case R_ARG_OPTION_TYPE_FILENAME:
        spacing -= r_string_append (str, "=FILENAME");
        break;
      case R_ARG_OPTION_TYPE_STRING:
        spacing -= r_string_append (str, "=STRING");
        break;
      default:
        spacing -= r_string_append (str, "=VALUE");
        break;
    }
  } else if (opt->type != R_ARG_OPTION_TYPE_NONE) {
    spacing -= r_string_append_printf (str, "=%s", opt->eqname);
  }

  while (spacing > 0)
    spacing -= r_string_append (str, " ");

  r_string_append (str, opt->desc);
  r_string_append (str, "\n");
}

static void
r_arg_option_group_append_help (const RArgOptionGroup * group, RString * str)
{
  rsize i;

  r_string_append (str, "\n");
  if (group->desc != NULL)
    r_string_append_printf (str, "%s:\n", group->desc);

  for (i = 0; i < group->count; i++)
    r_arg_option_entry_append_help (&group->entries[i], str);
}

static void
r_arg_command_append_help (rpointer key, rpointer val, rpointer user)
{
  rchar * cmd = key;
  RArgParser * parser = val;
  RString * str = user;
  int spacing = 32;

  spacing -= r_string_append_printf (str, "  %s", cmd);
  if (parser->summary != NULL) {
    while (spacing > 0)
      spacing -= r_string_append (str, " ");
    r_string_append (str, parser->summary);
  }

  r_string_append (str, "\n");
}

rchar *
r_arg_parser_get_help (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname)
{
  RString * str;
  rsize i;

  if (R_UNLIKELY (parser == NULL))
    return NULL;

  str = r_string_new_sized (1024);
  r_string_append_printf (str, "Usage:\n  %s %s",
      appname != NULL ? appname : parser->appname, parser->options);
  if (r_kv_ptr_array_size (&parser->commands) > 0)
    r_string_append (str, " <command>");
  r_string_append (str, "\n");

  if (parser->summary != NULL)
    r_string_append_printf (str, "\n%s\n", parser->summary);

  r_string_append_printf (str, "\n%s:\n", parser->main->desc);

  i = 0;
  if ((flags & R_ARG_PARSE_FLAG_DISALE_HELP) == R_ARG_PARSE_FLAG_DISALE_HELP)
    i += R_N_ELEMENTS (r_arg_version_args) + R_N_ELEMENTS (r_arg_help_args);
  for (; i < parser->main->count; i++)
    r_arg_option_entry_append_help (&parser->main->entries[i], str);

  r_slist_foreach (parser->groups, (RFunc)r_arg_option_group_append_help, str);

  if (r_kv_ptr_array_size (&parser->commands) > 0) {
    r_string_append (str, "\nCommands:\n");
    r_kv_ptr_array_foreach (&parser->commands, r_arg_command_append_help, str);
  }

  if (parser->epilog != NULL)
    r_string_append_printf (str, "\n%s\n", parser->epilog);

  return r_string_free_keep (str);
}

rchar *
r_arg_parser_get_version (RArgParser * parser)
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
r_arg_parser_add_option_entries (RArgParser * parser,
    const RArgOptionEntry * entries, rsize count)
{
  return r_arg_option_group_add_entries (parser->main, entries, count);
}

rboolean
r_arg_parser_add_option_entry (RArgParser * parser,
    const rchar * longarg, rchar shortarg,
    RArgOptionType type, RArgOptionFlags flags,
    const rchar * desc, const rchar * eqname)
{
  return r_arg_option_group_add_entry (parser->main, longarg, shortarg,
      type, flags, desc, eqname);
}

rboolean
r_arg_parser_add_option_group (RArgParser * parser, RArgOptionGroup * group)
{
  if (R_UNLIKELY (r_slist_contains (parser->groups, group)))
    return FALSE;

  parser->groups = r_slist_append (parser->groups,
      r_arg_option_group_ref (group));
  return TRUE;
}

static RArgOptionEntry *
r_arg_parser_find_entry_by_shortarg (const RArgParser * parser,
    rchar shortarg)
{
  RArgOptionEntry * ret;
  RSList * it;

  ret = r_arg_option_group_find_entry_by_shortarg (parser->main, shortarg);
  for (it = parser->groups; it != NULL && ret == NULL; it = r_slist_next (it))
    ret = r_arg_option_group_find_entry_by_shortarg (r_slist_data (it), shortarg);

  return ret;
}

static RArgOptionEntry *
r_arg_parser_find_entry_by_longarg (const RArgParser * parser,
    const rchar * longarg)
{
  RArgOptionEntry * ret;
  RSList * it;

  ret = r_arg_option_group_find_entry_by_longarg (parser->main, longarg);
  for (it = parser->groups; it != NULL && ret == NULL; it = r_slist_next (it))
    ret = r_arg_option_group_find_entry_by_longarg (r_slist_data (it), longarg);

  return ret;
}

static RArgParseResult
r_arg_option_parse_none (const rchar ** str, rboolean * val, rboolean inv)
{
  if (str == NULL)
    return R_ARG_PARSE_ERROR;

  if (val != NULL)
    *val = !inv ? *str != NULL : *str == NULL;

  return R_ARG_PARSE_OK;
}

static RArgParseResult
r_arg_option_parser_int (const rchar ** str, int * val)
{
  int value;
  RStrParse error;

  if (str == NULL || **str == 0)
    return R_ARG_PARSE_ERROR;

  value = r_str_to_int (*str, str, 0, &error);
  if (error != R_STR_PARSE_OK || *str == 0)
    return R_ARG_PARSE_VALUE_ERROR;

  if (val != NULL)
    *val = value;
  return R_ARG_PARSE_OK;
}

static RArgParseResult
r_arg_option_parser_int64 (const rchar ** str, rint64 * val)
{
  rint64 value;
  RStrParse error;

  if (str == NULL || **str == 0)
    return R_ARG_PARSE_ERROR;

  value = r_str_to_int64 (*str, str, 0, &error);
  if (error != R_STR_PARSE_OK || *str == 0)
    return R_ARG_PARSE_VALUE_ERROR;

  if (val != NULL)
    *val = value;
  return R_ARG_PARSE_OK;
}

static RArgParseResult
r_arg_option_parser_double (const rchar ** str, rdouble * val)
{
  rdouble value;
  RStrParse error;

  if (str == NULL || **str == 0)
    return R_ARG_PARSE_ERROR;

  value = r_str_to_double (*str, str, &error);
  if (error != R_STR_PARSE_OK || *str == 0)
    return R_ARG_PARSE_VALUE_ERROR;

  if (val != NULL)
    *val = value;
  return R_ARG_PARSE_OK;
}

static RArgParseResult
r_arg_option_parser_string (const rchar ** str, rchar ** val)
{
  if (str == NULL)
    return R_ARG_PARSE_ERROR;

  if (val != NULL) {
    r_free (*val);
    *val = (*str != NULL && **str != 0) ? r_strdup (*str) : NULL;
  }

  *str += r_strlen (*str);
  return R_ARG_PARSE_OK;
}

static RArgParseResult
r_arg_parser_parse_option_ctx (RArgParser * parser, RArgParseCtx * ctx,
    RArgOptionEntry * entry, const rchar ** arg, int * argc, const rchar *** argv)
{
  RArgParseResult ret = R_ARG_PARSE_ERROR;
  const rchar * str;

  if (entry->type == R_ARG_OPTION_TYPE_NONE) {
    str = *arg;
    ret = r_arg_option_parse_none (arg, NULL,
        (entry->flags & R_ARG_OPTION_FLAG_INVERSE) == R_ARG_OPTION_FLAG_INVERSE);
  } else {
    const rchar * end;
    if (arg != NULL && *arg != NULL && **arg != 0) {
      str = *arg;
    } else if (*argc > 0) {
      str = **argv;
    } else {
      return R_ARG_PARSE_ERROR;
    }

    end = str;
    switch (entry->type) {
      case R_ARG_OPTION_TYPE_INT:
        ret = r_arg_option_parser_int (&end, NULL);
        break;
      case R_ARG_OPTION_TYPE_INT64:
        ret = r_arg_option_parser_int64 (&end, NULL);
        break;
      case R_ARG_OPTION_TYPE_DOUBLE:
        ret = r_arg_option_parser_double (&end, NULL);
        break;
      case R_ARG_OPTION_TYPE_STRING:
      case R_ARG_OPTION_TYPE_FILENAME:
        ret = r_arg_option_parser_string (&end, NULL);
        break;
      default:
        r_assert_not_reached ();
        break;
    }

    if (ret == R_ARG_PARSE_OK) {
      if (arg != NULL && *arg != NULL && **arg != 0) {
        *arg = end;
      } else {
        (*argc)--;
        (*argv)++;
      }
    }
  }

  r_dictionary_insert (ctx->options, entry->longarg, (rpointer)str);

  return ret;
}

static RArgParseResult
r_arg_parser_parse_short_option (RArgParser * parser, RArgParseCtx * ctx,
    const rchar ** arg, int * argc, const rchar *** argv)
{
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_shortarg (parser, **arg)) != NULL) {
    (*arg)++;
    if (**arg == '=')
      (*arg)++;
    return r_arg_parser_parse_option_ctx (parser, ctx, entry, arg, argc, argv);
  } else if ((ctx->flags & R_ARG_PARSE_FLAG_ALLOW_UNKNOWN) == 0) {
    return R_ARG_PARSE_UNKNOWN_OPTION;
  }

  (*arg)++;
  return R_ARG_PARSE_OK;
}

static RArgParseResult
r_arg_parser_parse_long_option (RArgParser * parser, RArgParseCtx * ctx,
    const rchar ** arg, int * argc, const rchar *** argv)
{
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (parser, *arg)) != NULL) {
    *arg += r_strlen (entry->longarg);
    if (**arg == '=')
      (*arg)++;

    return r_arg_parser_parse_option_ctx (parser, ctx, entry, arg, argc, argv);
  } else if ((ctx->flags & R_ARG_PARSE_FLAG_ALLOW_UNKNOWN) == 0) {
    return R_ARG_PARSE_UNKNOWN_OPTION;
  }

  return R_ARG_PARSE_OK;
}

static rboolean
r_arg_parser_check_required_options (RArgParser * parser, RArgParseCtx * ctx)
{
  RSList * it;

  if (!r_arg_option_group_check_required_options (parser->main, ctx->options))
    return FALSE;

  for (it = parser->groups; it != NULL; it = r_slist_next (it)) {
    if (!r_arg_option_group_check_required_options (r_slist_data (it), ctx->options))
      return FALSE;
  }

  return TRUE;
}

static RArgParseResult
r_arg_parser_parse_options (RArgParser * parser, RArgParseCtx * ctx,
    int * argc, const rchar *** argv)
{
  RArgParseResult ret = R_ARG_PARSE_OK;

  while (*argc > 0 && ret == R_ARG_PARSE_OK) {
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
      ret = r_arg_parser_parse_long_option (parser, ctx, &arg, argc, (const rchar ***)argv);
    } else {
      do {
        ret = r_arg_parser_parse_short_option (parser, ctx, &arg, argc, (const rchar ***)argv);
      } while (*arg != 0 && ret == R_ARG_PARSE_OK);
    }
  }

  if (ret != R_ARG_PARSE_OK)
    return ret;

  /* Check version */
  if (r_arg_parse_ctx_get_option_bool (ctx, "version")) {
    r_arg_parser_print_version (parser, ctx->flags);
    return R_ARG_PARSE_VERSION;
  }

  /* Check help */
  if ((ctx->flags & R_ARG_PARSE_FLAG_DISALE_HELP) == 0) {
    if (r_arg_parse_ctx_get_option_bool (ctx, "help") ||
        r_arg_parse_ctx_get_option_bool (ctx, "")) {
      r_arg_parser_print_help (ctx->parser, ctx->flags, ctx->appname, 0);
      return R_ARG_PARSE_HELP;
    }
  }

  if (!r_arg_parser_check_required_options (parser, ctx))
    ret = R_ARG_PARSE_MISSING_OPTION;

  return ret;
}

static RArgParser *
r_arg_parser_add_command_internal (RArgParser * parser,
    const rchar * cmd, const rchar * desc)
{
  rchar * appname;
  RArgParser * ret;

  if ((appname = r_strjoin (" ", parser->appname, cmd, NULL)) != NULL &&
      (ret = r_arg_parser_new (appname, NULL)) != NULL) {
    ret->summary = r_strdup (desc);
    ret->main->entries[0].flags |= R_ARG_OPTION_FLAG_HIDDEN; /* hide --version */
    r_kv_ptr_array_add (&parser->commands, r_strdup (cmd), r_free,
          ret, r_arg_parser_unref);
  }

  r_free (appname);
  return ret;
}

RArgParser *
r_arg_parser_add_command (RArgParser * parser, const rchar * cmd, const rchar * desc)
{
  RArgParser * ret;

  if (R_UNLIKELY (cmd == NULL || *cmd == 0)) return NULL;

  if (r_kv_ptr_array_size (&parser->commands) == 0)
    r_arg_parser_add_command_internal (parser, r_arg_help_args[0].longarg, r_arg_help_args[0].desc);

  ret = r_arg_parser_add_command_internal (parser, cmd, desc);
  return ret != NULL ? r_arg_parser_ref (ret) : NULL;
}

static RArgParseResult
r_arg_parser_parse_command (RArgParser * parser, RArgParseFlags flags,
    RArgParseCtx * ctx, int * argc, const rchar *** argv)
{
  RArgParseResult ret;
  const rchar * cmd = (*argv)[0];
  rsize idx;

  if (r_kv_ptr_array_size (&parser->commands) == 0) {
    ret = R_ARG_PARSE_OK;
  } else if ((idx = r_kv_ptr_array_find (&parser->commands, cmd)) != R_KV_PTR_ARRAY_INVALID_IDX) {
    RArgParser * cmdparser = r_kv_ptr_array_get_val (&parser->commands, idx);
    ctx->command = r_strdup (cmd);
    (*argv)++;
    (*argc)--;
    ret = R_ARG_PARSE_OK;
    ctx->cmdctx = r_arg_parser_parse_internal (cmdparser, flags,
        cmd, argc, argv, &ret);
  } else {
    ret = R_ARG_PARSE_MISSING_COMMAND;
  }

  return ret;
}

static RArgParseCtx *
r_arg_parser_parse_internal (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname, int * argc, const rchar *** argv,
    RArgParseResult * res)
{
  RArgParseCtx * ret;
  RArgParseResult curres;

  if ((ret = r_arg_parse_ctx_new (parser, flags, appname)) != NULL) {
    if ((curres = r_arg_parser_parse_options (parser, ret, argc, argv)) == R_ARG_PARSE_OK) {
      curres = r_arg_parser_parse_command (parser, flags, ret, argc, argv);
    }

    if (curres != R_ARG_PARSE_OK) {
      r_arg_parse_ctx_unref (ret);
      ret = NULL;
    }
  } else {
    curres = R_ARG_PARSE_OOM;
  }

  if (res != NULL)
    *res = curres;
  return ret;
}

RArgParseCtx *
r_arg_parser_parse (RArgParser * parser, RArgParseFlags flags,
    int * argc, const rchar *** argv, RArgParseResult * res)
{
  const rchar * appname;

  if (R_UNLIKELY (argc == NULL || *argc < 1 || argv == NULL)) {
    if (res != NULL)
      *res = R_ARG_PARSE_ARG_ERROR;
    return NULL;
  }

  appname = (*argv)[0];
  (*argv)++;
  (*argc)--;
  return r_arg_parser_parse_internal (parser, flags, appname, argc, argv, res);
}

void
r_arg_parser_print_version (RArgParser * parser, RArgParseFlags flags)
{
  if ((flags & R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT) == 0) {
    rchar * output = r_arg_parser_get_version (parser);
    r_print ("%s", output);
    r_free (output);
  }

  if ((flags & R_ARG_PARSE_FLAG_DONT_EXIT) == 0)
    exit (0);
}

int
r_arg_parser_print_help (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname, int exitval)
{
  if ((flags & R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT) == 0) {
    rchar * output = r_arg_parser_get_help (parser, flags, appname);
    r_print ("%s", output);
    r_free (output);
  }

  if ((flags & R_ARG_PARSE_FLAG_DONT_EXIT) == 0)
    exit (exitval);

  return exitval;
}

rsize
r_arg_parse_ctx_option_count (const RArgParseCtx * ctx)
{
  return r_dictionary_size (ctx->options);
}

rboolean
r_arg_parse_ctx_has_option (RArgParseCtx * ctx, const rchar * longarg)
{
  return r_dictionary_contains (ctx->options, longarg);
}

RArgOptionType
r_arg_parse_ctx_get_option_type (RArgParseCtx * ctx, const rchar * longarg)
{
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL)
    return entry->type;

  return R_ARG_OPTION_TYPE_ERROR;
}

static rboolean
r_arg_parse_ctx_get_option_entry_value (RArgParseCtx * ctx, const RArgOptionEntry * entry,
    rpointer val)
{
  const rchar * arg;

  if ((arg = r_dictionary_lookup (ctx->options, entry->longarg)) != NULL) {
    switch (entry->type) {
      case R_ARG_OPTION_TYPE_BOOL:
        r_arg_option_parse_none (&arg, val,
            (entry->flags & R_ARG_OPTION_FLAG_INVERSE) == R_ARG_OPTION_FLAG_INVERSE);
        break;
      case R_ARG_OPTION_TYPE_INT:
        r_arg_option_parser_int (&arg, val);
        break;
      case R_ARG_OPTION_TYPE_INT64:
        r_arg_option_parser_int64 (&arg, val);
        break;
      case R_ARG_OPTION_TYPE_DOUBLE:
        r_arg_option_parser_double (&arg, val);
        break;
      case R_ARG_OPTION_TYPE_STRING:
      case R_ARG_OPTION_TYPE_FILENAME:
        r_arg_option_parser_string (&arg, val);
        break;
      default:
        return FALSE;
    }

    return TRUE;
  }

  return FALSE;
}

rboolean
r_arg_parse_ctx_get_option_value (RArgParseCtx * ctx, const rchar * longarg,
    RArgOptionType type, rpointer val)
{
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL &&
      type == entry->type && val != NULL) {
    return r_arg_parse_ctx_get_option_entry_value (ctx, entry, val);
  }

  return FALSE;
}

rboolean
r_arg_parse_ctx_get_option_bool (RArgParseCtx * ctx, const rchar * longarg)
{
  rboolean ret = FALSE;
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL) {
    if (entry->type == R_ARG_OPTION_TYPE_BOOL)
      r_arg_parse_ctx_get_option_entry_value (ctx, entry, &ret);
    else
      ret = (entry->flags & R_ARG_OPTION_FLAG_INVERSE) == R_ARG_OPTION_FLAG_INVERSE;
  }

  return ret;
}

int
r_arg_parse_ctx_get_option_int (RArgParseCtx * ctx, const rchar * longarg)
{
  int ret = 0;
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL &&
      entry->type == R_ARG_OPTION_TYPE_INT) {
    r_arg_parse_ctx_get_option_entry_value (ctx, entry, &ret);
  }

  return ret;
}

rint64
r_arg_parse_ctx_get_option_int64 (RArgParseCtx * ctx, const rchar * longarg)
{
  rint64 ret = 0;
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL &&
      entry->type == R_ARG_OPTION_TYPE_INT64) {
    r_arg_parse_ctx_get_option_entry_value (ctx, entry, &ret);
  }

  return ret;
}

rdouble
r_arg_parse_ctx_get_option_double (RArgParseCtx * ctx, const rchar * longarg)
{
  rdouble ret = 0;
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL &&
      entry->type == R_ARG_OPTION_TYPE_DOUBLE) {
    r_arg_parse_ctx_get_option_entry_value (ctx, entry, &ret);
  }

  return ret;
}

rchar *
r_arg_parse_ctx_get_option_string (RArgParseCtx * ctx, const rchar * longarg)
{
  rchar * ret = NULL;
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL &&
      entry->type == R_ARG_OPTION_TYPE_STRING) {
    r_arg_parse_ctx_get_option_entry_value (ctx, entry, &ret);
  }

  return ret;
}

rchar *
r_arg_parse_ctx_get_option_filename (RArgParseCtx * ctx, const rchar * longarg)
{
  rchar * ret = NULL;
  RArgOptionEntry * entry;

  if ((entry = r_arg_parser_find_entry_by_longarg (ctx->parser, longarg)) != NULL &&
      entry->type == R_ARG_OPTION_TYPE_FILENAME) {
    r_arg_parse_ctx_get_option_entry_value (ctx, entry, &ret);
  }

  return ret;
}

const rchar *
r_arg_parse_ctx_get_command (const RArgParseCtx * ctx)
{
  return ctx->command;
}

RArgParseCtx *
r_arg_parse_ctx_get_command_ctx (RArgParseCtx * ctx)
{
  return ctx->cmdctx != NULL ? r_arg_parse_ctx_ref (ctx->cmdctx) : NULL;
}

