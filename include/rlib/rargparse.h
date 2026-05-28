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

/**
 * @defgroup r_argparse Command-line argument parsing
 * @brief Declarative CLI option parser with grouped options, sub-
 * commands, positionals, defaults, and accumulated multi-value
 * options.
 * @{
 */

/**
 * @file rlib/rargparse.h
 * @brief Command-line argument parsing.
 *
 * Declare options as an array of @c RArgOptionEntry structs, hand
 * them to an @c RArgParser, then run @c r_arg_parser_parse against
 * @c argc / @c argv. The parse yields an @c RArgParseCtx from which
 * per-option values are retrieved via the type-specific getters.
 *
 * **Typical flow:**
 *  1. Build a parser with @c r_arg_parser_new.
 *  2. Register options via @c r_arg_parser_add_option_entries
 *     (long name, short name, type, flags, description, ...).
 *  3. Optionally add sub-commands (@c r_arg_parser_add_command)
 *     and grouped option blocks (@c r_arg_option_group_new).
 *  4. Parse with @c r_arg_parser_parse; an @c RArgParseCtx is
 *     returned (or @c NULL with a result code).
 *  5. Read values via @c r_arg_parse_ctx_get_option_bool /
 *     _int / _string / _string_array / etc.
 *  6. Release with @c r_arg_parse_ctx_unref.
 *
 * Supports automatic @c --help / @c --version handling, default
 * values, required options, positional arguments, and an inverse
 * (no-foo) flag form. @c -h, @c --help, and @c --version are
 * registered for free unless suppressed by
 * @c R_ARG_PARSE_FLAG_DISALE_HELP.
 */

R_BEGIN_DECLS

/** @brief Opaque parser handle. */
typedef struct RArgParser RArgParser;
/** @brief Opaque option-group handle (named subset of options). */
typedef struct RArgOptionGroup RArgOptionGroup;
/** @brief Opaque parse-result context returned by @c r_arg_parser_parse. */
typedef struct RArgParseCtx RArgParseCtx;

/**
 * @brief Value type carried by an @c RArgOptionEntry.
 *
 * Picks the parsing and storage strategy for an option:
 *  - @c NONE / @c BOOL: presence-only flag.
 *  - @c INT / @c INT64 / @c DOUBLE: numeric value parsed via the
 *    corresponding @c r_str_to_* family.
 *  - @c STRING / @c FILENAME: a single string; later occurrences
 *    overwrite earlier ones.
 *  - @c STRING_ARRAY: a string that accumulates across multiple
 *    occurrences; read with @c r_arg_parse_ctx_get_option_string_array.
 */
typedef enum {
  R_ARG_OPTION_TYPE_NONE,                       /**< Presence-only flag (alias for @c BOOL). */
  R_ARG_OPTION_TYPE_BOOL = R_ARG_OPTION_TYPE_NONE, /**< Boolean flag. */
  R_ARG_OPTION_TYPE_INT,                        /**< Signed @c int value. */
  R_ARG_OPTION_TYPE_INT64,                      /**< Signed @c rint64 value. */
  R_ARG_OPTION_TYPE_DOUBLE,                     /**< @c rdouble value. */
  R_ARG_OPTION_TYPE_STRING,                     /**< Single string; last occurrence wins. */
  R_ARG_OPTION_TYPE_FILENAME,                   /**< Single filename string. */
  R_ARG_OPTION_TYPE_STRING_ARRAY,               /**< Repeatable string; values accumulate in argv order. */
  R_ARG_OPTION_TYPE_COUNT,                      /**< Sentinel: number of value types (also @c ERROR). */
  R_ARG_OPTION_TYPE_ERROR = R_ARG_OPTION_TYPE_COUNT /**< Returned by getters on unknown / wrong-typed option. */
} RArgOptionType;

/** @brief Per-option behaviour flags. */
typedef enum {
  R_ARG_OPTION_FLAG_NONE            = 0,
  R_ARG_OPTION_FLAG_HIDDEN          = 1 << 0, /**< Omit from the @c --help output. */
  R_ARG_OPTION_FLAG_INVERSE         = 1 << 1, /**< Boolean inverse: @c --no-foo sets foo=FALSE. */
  R_ARG_OPTION_FLAG_REQUIRED        = 1 << 2, /**< Parser fails if the option is absent. */
  /**
   * Positional argument: bound by position in argv, not by @c --name.
   * @c longarg is the name used as the storage key and in help text;
   * @c eqname (or @c longarg uppercased) becomes the name in the
   * Usage line. @c shortarg is ignored. Cannot be combined with
   * @c TYPE_NONE since positionals always carry a value.
   * @c REQUIRED is implied when @c defval is @c NULL.
   */
  R_ARG_OPTION_FLAG_POSITIONAL      = 1 << 3,
} RArgOptionFlags;

/**
 * @brief Declarative description of one CLI option.
 *
 * Used by @c r_arg_parser_add_option_entries and friends. Typically
 * declared as a @c static array at file scope, where each row is one
 * option.
 */
typedef struct {
  const rchar *   longarg;    /**< Long-form name (no leading @c --). */
  rchar           shortarg;   /**< Short-form name (no @c -); @c 0 to disable. */
  RArgOptionType  type;       /**< Value type. */
  RArgOptionFlags flags;      /**< Behaviour flags. */
  const rchar *   desc;       /**< Help-text description. */
  const rchar *   eqname;     /**< Placeholder name in @c --foo=NAME help; @c NULL picks a default. */
  /**
   * Default value returned by the getters when the option is absent
   * from the command line. The string is parsed by the same per-type
   * parser used for the on-cmdline value; @c NULL means "no default"
   * and the getter returns the zero/empty value for the type.
   * Not meaningful for @c BOOL (presence is the value); ignored with
   * a warning if combined with @c REQUIRED.
   */
  const rchar *   defval;
} RArgOptionEntry;

/** @brief Flags controlling @c r_arg_parser_parse behaviour. */
typedef enum {
  R_ARG_PARSE_FLAG_NONE               = 0,
  R_ARG_PARSE_FLAG_DONT_EXIT          = 1 << 0, /**< Return errors instead of calling @c exit. */
  R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT  = 1 << 1, /**< Suppress automatic help / version output. */
  R_ARG_PARSE_FLAG_DISALE_HELP        = 1 << 2, /**< Don't auto-register @c --help / @c -h. */
  R_ARG_PARSE_FLAG_ALLOW_UNKNOWN      = 1 << 3, /**< Pass unknown options through instead of failing. */
} RArgParseFlags;

/** @brief Result code from @c r_arg_parser_parse. */
typedef enum {
  R_ARG_PARSE_VERSION = -2,                     /**< @c --version was requested; ctx is @c NULL. */
  R_ARG_PARSE_HELP = -1,                        /**< @c --help was requested; ctx is @c NULL. */
  R_ARG_PARSE_OK = 0,                           /**< Parse succeeded. */
  R_ARG_PARSE_ARG_ERROR,                        /**< Malformed argv. */
  R_ARG_PARSE_UNKNOWN_OPTION,                   /**< Unknown option encountered. */
  R_ARG_PARSE_MISSING_OPTION,                   /**< Required option was absent. */
  R_ARG_PARSE_VALUE_ERROR,                      /**< An option's value didn't parse. */
  R_ARG_PARSE_MISSING_COMMAND,                  /**< Sub-command parser didn't see a command. */
  R_ARG_PARSE_OOM,                              /**< Allocation failure. */
  R_ARG_PARSE_ERROR,                            /**< Generic / internal error. */
} RArgParseResult;


/**
 * @name Parser lifecycle
 * @{
 */
/**
 * @brief Create an empty parser.
 *
 * @param app      Program name shown in @c --help and the Usage line;
 *                 @c NULL falls back to @c argv[0] at parse time.
 * @param version  Version string returned by @c --version; @c NULL
 *                 omits the auto-registered @c --version option.
 * @return Newly-allocated parser; release with @c r_arg_parser_unref.
 */
R_API RArgParser * r_arg_parser_new (const rchar * app, const rchar * version) R_ATTR_MALLOC;
/** @brief Increment the parser's refcount. */
#define r_arg_parser_ref r_ref_ref
/** @brief Decrement the parser's refcount; frees when it reaches zero. */
#define r_arg_parser_unref r_ref_unref
/** @} */

/**
 * @name Parser configuration
 * @{
 */
/** @brief Set the prologue paragraph shown above option help. */
R_API void r_arg_parser_set_summary (RArgParser * parser, const rchar * summary);
/** @brief Set the epilogue paragraph shown below option help. */
R_API void r_arg_parser_set_epilog (RArgParser * parser, const rchar * epilog);
/** @brief Return the previously-set summary, or @c NULL. */
R_API const rchar * r_arg_parser_get_summary (RArgParser * parser);
/** @brief Return the previously-set epilog, or @c NULL. */
R_API const rchar * r_arg_parser_get_epilog (RArgParser * parser);
/** @} */

/**
 * @name Option registration
 * @{
 */
/**
 * @brief Register an array of @c RArgOptionEntry rows in bulk.
 *
 * @param parser Target parser.
 * @param args   Array of entries.
 * @param count  Number of entries in @p args.
 * @return @c TRUE on success; @c FALSE if any entry is invalid
 *         (no longarg, unknown type, duplicate long / short name).
 */
R_API rboolean r_arg_parser_add_option_entries (RArgParser * parser,
    const RArgOptionEntry * args, rsize count);
/**
 * @brief Register a single option by spelling out its fields.
 *
 * Equivalent to @c add_option_entries with a one-element array;
 * convenient at call sites where the description is dynamic.
 */
R_API rboolean r_arg_parser_add_option_entry (RArgParser * parser,
    const rchar * longarg, rchar shortarg,
    RArgOptionType type, RArgOptionFlags flags,
    const rchar * desc, const rchar * eqname);
/**
 * @brief Attach an option group's entries to the parser.
 *
 * Groups appear as a named subsection in @c --help; the parser
 * retains a reference to @p group.
 */
R_API rboolean r_arg_parser_add_option_group (RArgParser * parser,
    RArgOptionGroup * group);
/** @} */

/**
 * @brief Register a sub-command and return its own parser.
 *
 * The returned parser is owned by @p parser; configure it like a
 * top-level parser (add options, etc.) but don't unref it directly.
 *
 * @param parser  Parent parser.
 * @param cmd     Sub-command name as it appears in argv.
 * @param desc    Description shown in the parent's command list.
 */
R_ATTR_WARN_UNUSED_RESULT
R_API RArgParser * r_arg_parser_add_command (RArgParser * parser,
    const rchar * cmd, const rchar * desc);

/**
 * @name Help and version output
 * @{
 */
/** @brief Render the help text as a newly-allocated string. */
R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_arg_parser_get_help (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname) R_ATTR_MALLOC;
/** @brief Render the version line as a newly-allocated string. */
R_ATTR_WARN_UNUSED_RESULT
R_API rchar * r_arg_parser_get_version (RArgParser * parser) R_ATTR_MALLOC;
/**
 * @brief Print the version line to stdout.
 *
 * Honours @c R_ARG_PARSE_FLAG_DONT_PRINT_STDOUT (no-op then).
 */
R_API void r_arg_parser_print_version (RArgParser * parser, RArgParseFlags flags);
/**
 * @brief Print the help text to stdout and return @p exitval.
 *
 * Convenience for the common pattern of printing help and
 * propagating an exit code back to @c main.
 */
R_API int r_arg_parser_print_help (RArgParser * parser, RArgParseFlags flags,
    const rchar * appname, int exitval);
/** @} */

/**
 * @brief Parse @p argv against @p parser, returning a context with
 * the resolved option values.
 *
 * On success, @p argc / @p argv are advanced past consumed arguments
 * and the returned context owns the parsed values. On failure (and
 * with @c R_ARG_PARSE_FLAG_DONT_EXIT), the function returns @c NULL
 * and writes a more specific code into @p res if non-NULL.
 *
 * Without @c R_ARG_PARSE_FLAG_DONT_EXIT, the parser calls @c exit on
 * @c --help / @c --version / parse errors after printing.
 *
 * @return Owning context (release with @c r_arg_parse_ctx_unref) or
 *         @c NULL on error / help / version.
 */
R_ATTR_WARN_UNUSED_RESULT
R_API RArgParseCtx * r_arg_parser_parse (RArgParser * parser, RArgParseFlags flags,
    int * argc, const rchar *** argv, RArgParseResult * res) R_ATTR_MALLOC;

/**
 * @name Parse-context lifecycle
 * @{
 */
/** @brief Increment the context's refcount. */
#define r_arg_parse_ctx_ref r_ref_ref
/** @brief Decrement the context's refcount; frees when it reaches zero. */
#define r_arg_parse_ctx_unref r_ref_unref
/** @} */

/**
 * @name Context inspection
 * @{
 */
/** @brief Total number of options recorded in the context. */
R_API rsize r_arg_parse_ctx_option_count (const RArgParseCtx * ctx);
/** @brief Return @c TRUE if @p longarg was seen on the command line. */
R_API rboolean r_arg_parse_ctx_has_option (RArgParseCtx * ctx, const rchar * longarg);
/** @brief Return the declared @c RArgOptionType for @p longarg, or @c ERROR. */
R_API RArgOptionType r_arg_parse_ctx_get_option_type (RArgParseCtx * ctx, const rchar * longarg);
/** @} */

/**
 * @name Typed value retrieval
 *
 * Each helper reads the option named by @p longarg, using its
 * registered @c RArgOptionType. The string / filename / string_array
 * variants return freshly-allocated memory; release per their
 * @c R_ATTR_MALLOC contract.
 * @{
 */
/**
 * @brief Generic getter dispatched by declared type.
 *
 * @param ctx      Parse context.
 * @param longarg  Option long name.
 * @param type     Expected type; must match the registration.
 * @param val      Pointer to the destination variable
 *                 (e.g. @c rboolean* for @c BOOL).
 * @return @c TRUE if the option was present and parsed.
 */
R_API rboolean r_arg_parse_ctx_get_option_value (RArgParseCtx * ctx,
    const rchar * longarg, RArgOptionType type, rpointer val);
/** @brief @c BOOL value, or @c FALSE if absent. */
R_API rboolean r_arg_parse_ctx_get_option_bool (RArgParseCtx * ctx, const rchar * longarg);
/** @brief @c INT value, or 0 if absent. */
R_API int r_arg_parse_ctx_get_option_int (RArgParseCtx * ctx, const rchar * longarg);
/** @brief @c INT64 value, or 0 if absent. */
R_API rint64 r_arg_parse_ctx_get_option_int64 (RArgParseCtx * ctx, const rchar * longarg);
/** @brief @c DOUBLE value, or 0.0 if absent. */
R_API rdouble r_arg_parse_ctx_get_option_double (RArgParseCtx * ctx, const rchar * longarg);
/** @brief @c STRING value as a freshly-allocated string, or @c NULL if absent. */
R_API rchar * r_arg_parse_ctx_get_option_string (RArgParseCtx * ctx, const rchar * longarg) R_ATTR_MALLOC;
/** @brief @c FILENAME value as a freshly-allocated string, or @c NULL if absent. */
R_API rchar * r_arg_parse_ctx_get_option_filename (RArgParseCtx * ctx, const rchar * longarg) R_ATTR_MALLOC;
/**
 * @brief @c STRING_ARRAY accumulated values as a freshly-allocated
 * NULL-terminated @c rchar** (r_strv).
 *
 * Release with @c r_strv_free. Returns @c NULL if the option was
 * absent.
 */
R_API rchar ** r_arg_parse_ctx_get_option_string_array (RArgParseCtx * ctx, const rchar * longarg) R_ATTR_MALLOC;
/** @} */

/**
 * @name Sub-command access
 * @{
 */
/** @brief Sub-command consumed from argv, or @c NULL. */
R_API const rchar * r_arg_parse_ctx_get_command (const RArgParseCtx * ctx);
/** @brief Sub-command's own parse context (borrowed), or @c NULL. */
R_API RArgParseCtx * r_arg_parse_ctx_get_command_ctx (RArgParseCtx * ctx);
/** @} */

/**
 * @name Option groups
 *
 * Option groups bundle a related subset of options under a named
 * heading in the help output. Build a group with
 * @c r_arg_option_group_new, fill it via @c r_arg_option_group_add_entries,
 * then attach it to the parser with @c r_arg_parser_add_option_group.
 * @{
 */
/**
 * @brief Create an option group.
 *
 * @param name     Heading shown in @c --help.
 * @param desc     One-line description shown under the heading.
 * @param summary  Optional longer paragraph above the entries.
 * @param user     Opaque user pointer attached to the group.
 * @param notify   Destructor for @p user; called on group destroy.
 */
R_API RArgOptionGroup * r_arg_option_group_new (const rchar * name, const rchar * desc,
    const rchar * summary, rpointer user, RDestroyNotify notify);
/** @brief Increment the group's refcount. */
#define r_arg_option_group_ref r_ref_ref
/** @brief Decrement the group's refcount; frees when it reaches zero. */
#define r_arg_option_group_unref r_ref_unref

/** @brief Register a bulk array of @c RArgOptionEntry rows on the group. */
R_API rboolean r_arg_option_group_add_entries (RArgOptionGroup * group,
    const RArgOptionEntry * args, rsize count);
/** @brief Register a single option entry by spelling out its fields. */
R_API rboolean r_arg_option_group_add_entry (RArgOptionGroup * group,
    const rchar * longarg, rchar shortarg,
    RArgOptionType type, RArgOptionFlags flags,
    const rchar * desc, const rchar * eqname);
/** @} */

R_END_DECLS

/** @} */ /* r_argparse group */

#endif /* __R_ARGPARSE_H__ */
