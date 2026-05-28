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
#ifndef __R_LOG_H__
#define __R_LOG_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

/**
 * @file rlib/rlog.h
 * @brief Categorised structured logging with per-category thresholds,
 * level-gated macros, hex / buffer dump helpers and a swappable
 * sink.
 */

#include <rlib/rtypes.h>
#include <rlib/concurrency/ratomic.h>
#include <rlib/rbuffer.h>
#include <rlib/rclr.h>
#include <stdarg.h>

/**
 * @defgroup r_log Logging
 *
 * @brief Categorised logging with per-category thresholds, severity
 * levels, dump helpers and a single swappable output sink.
 *
 * Define a category once with @ref R_LOG_CATEGORY_DEFINE, then log
 * through it with @ref R_LOG_CAT_ERROR ... @ref R_LOG_CAT_TRACE.
 * Each message is filtered against both the global @c _r_log_level_min
 * (fast atomic gate) and the per-category @c threshold; messages
 * below either are eliminated before the @c r_log call ever runs.
 *
 * Output flows through the single installed @ref RLogFunc sink (set
 * via @ref r_log_override_default_handler). The default handler
 * writes coloured, level-tagged lines to stderr; replace it to ship
 * logs into syslog, journald, an in-process buffer or wherever.
 *
 * The @ref RLogKeepLastCtx machinery captures the most recent message
 * matching a filter; used internally by @c r_assert_logs_* and
 * available to callers via @ref r_log_keep_last_begin /
 * @ref r_log_keep_last_end.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Severity levels (higher = more verbose). */
typedef enum
{
  R_LOG_LEVEL_NONE              = 0,    /**< Sentinel: never logged. */
  R_LOG_LEVEL_ERROR             = 1,    /**< Hard failures. */
  R_LOG_LEVEL_CRITICAL          = 2,    /**< Recoverable but serious. */
  R_LOG_LEVEL_WARNING           = 3,    /**< Unexpected but tolerable. */
  R_LOG_LEVEL_FIXME             = 4,    /**< Known-broken paths. */
  R_LOG_LEVEL_INFO              = 5,    /**< High-level progress. */
  R_LOG_LEVEL_DEBUG             = 6,    /**< Developer-facing detail. */
  R_LOG_LEVEL_TRACE             = 7,    /**< Per-event spam. */

  R_LOG_LEVEL_COUNT                     /**< Sentinel (1 past max). */
} RLogLevel;

/** @brief Default per-category threshold; override at compile time. */
#ifndef R_LOG_LEVEL_DEFAULT
#define R_LOG_LEVEL_DEFAULT     R_LOG_LEVEL_CRITICAL
#endif
/** @brief Compile-out cap; messages above this level vanish at preprocess time. */
#ifndef R_LOG_LEVEL_MAX
#define R_LOG_LEVEL_MAX         R_LOG_LEVEL_COUNT
#endif
/** @brief Process-wide atomic minimum level; the fast pre-filter gate. */
R_API extern rauint             _r_log_level_min;

/** @brief Return the string name of @p lvl ("ERROR", "INFO", ...). */
R_API const rchar * r_log_level_get_name (RLogLevel lvl);
/** @brief Set the default threshold applied to newly-registered categories. */
R_API void r_log_set_default_level (RLogLevel lvl);
/** @brief Return the default threshold set by @ref r_log_set_default_level. */
R_API RLogLevel r_log_get_default_level (void);

/**
 * @brief Logging category descriptor.
 *
 * Declare with @ref R_LOG_CATEGORY_DEFINE at file scope. @c threshold
 * may be tuned at runtime via @ref r_log_category_set_threshold.
 */
typedef struct
{
  RLogLevel       threshold;    /**< Per-category gate. */
  const rchar *   name;         /**< Short identifier (also used for lookup). */
  const rchar *   desc;         /**< Human-readable description. */
  ruint16         clr;          /**< @ref RColorFlags for the category tag colour. */
} RLogCategory;

/** @brief Register @p cat so it can be looked up by name. */
R_API rboolean r_log_category_register (RLogCategory * cat);
/** @brief Inverse of @ref r_log_category_register. */
R_API rboolean r_log_category_unregister (RLogCategory * cat);
/** @brief Look up a previously-registered category by name. */
R_API RLogCategory * r_log_category_find (const rchar * name);

/** @brief Define an @ref RLogCategory at file scope. */
#define R_LOG_CATEGORY_DEFINE(cat, name, desc, clr)                         \
  RLogCategory cat = { R_LOG_LEVEL_DEFAULT, (name), (desc), (clr) }
/** @brief @c static-storage variant of @ref R_LOG_CATEGORY_DEFINE. */
#define R_LOG_CATEGORY_DEFINE_STATIC(cat, name, desc, clr)                  \
  static R_LOG_CATEGORY_DEFINE (cat, name, desc, clr)
/** @brief Forward-declare a category defined in another translation unit. */
#define R_LOG_CATEGORY_DEFINE_EXTERN(cat) extern RLogCategory cat

/** @brief Update @p cat's threshold at runtime. */
R_API void r_log_category_set_threshold (RLogCategory * cat, RLogLevel lvl);
/** @brief Read @p cat's current threshold. */
#define r_log_category_get_threshold(cat)       (cat)->threshold

/** @brief Built-in category used by assertion failures. */
R_API R_LOG_CATEGORY_DEFINE_EXTERN (_r_log_cat_assert);
/** @brief Pointer to @c _r_log_cat_assert, suitable for @c r_log_keep_last filters. */
#define R_LOG_CAT_ASSERT &_r_log_cat_assert

/**
 * @brief Sink function signature.
 *
 * Installed via @ref r_log_override_default_handler; receives every
 * fully-formatted message that passes the gates.
 */
typedef void (*RLogFunc) (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg, rpointer user_data);

/** @brief Low-level @c printf-style log entry; usually reached via the @c R_LOG_* macros. */
R_API void r_log (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, ...) R_ATTR_PRINTF (6, 7);
/** @brief @c va_list variant of @ref r_log. */
R_API void r_logv (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, va_list args) R_ATTR_PRINTF(6, 0);
/** @brief Log a pre-formatted message (no @c printf substitution). */
R_API void r_log_msg (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg);
/** @brief Hex-dump @p str; @p bytesperline controls the row width. */
R_API void r_log_str_dump (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * str, rssize size, rsize bytesperline);
/** @brief Hex-dump a raw memory region. */
R_API void r_log_mem_dump (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    rconstpointer ptr, rsize size, rsize bytesperline);
/** @brief Hex-dump the contents of an @ref RBuffer. */
R_API void r_log_buf_dump (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    RBuffer * buf, rsize bytesperline);

/** @name Gated log macros
 *  Run-time threshold + compile-time @ref R_LOG_LEVEL_MAX gate; the
 *  formatted call is only made when the gate is open.
 *  @{ */
/** @brief Build a per-category, per-level log macro body. */
#define R_LOG_CAT_LEVEL(cat,lvl,...) R_STMT_START {                           \
  _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);               \
  if (R_UNLIKELY (lvl <= R_LOG_LEVEL_MAX && (int)lvl<=(int)_r_log_level_min)) \
    r_log ((cat), (lvl), __FILE__, __LINE__, R_STRFUNC, __VA_ARGS__);         \
} R_STMT_END

#define R_LOG_CAT_ERROR(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_ERROR,    __VA_ARGS__) /**< @brief Log @c ERROR in @p cat. */
#define R_LOG_CAT_CRITICAL(cat,...) R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_CRITICAL, __VA_ARGS__) /**< @brief Log @c CRITICAL in @p cat. */
#define R_LOG_CAT_WARNING(cat,...)  R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_WARNING,  __VA_ARGS__) /**< @brief Log @c WARNING in @p cat. */
#define R_LOG_CAT_FIXME(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_FIXME,    __VA_ARGS__) /**< @brief Log @c FIXME in @p cat. */
#define R_LOG_CAT_INFO(cat,...)     R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_INFO,     __VA_ARGS__) /**< @brief Log @c INFO in @p cat. */
#define R_LOG_CAT_DEBUG(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_DEBUG,    __VA_ARGS__) /**< @brief Log @c DEBUG in @p cat. */
#define R_LOG_CAT_TRACE(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_TRACE,    __VA_ARGS__) /**< @brief Log @c TRACE in @p cat. */

#define R_LOG_ERROR(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR,    __VA_ARGS__) /**< @brief Log @c ERROR in the default category. */
#define R_LOG_CRITICAL(...) R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_CRITICAL, __VA_ARGS__) /**< @brief Log @c CRITICAL in the default category. */
#define R_LOG_WARNING(...)  R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_WARNING,  __VA_ARGS__) /**< @brief Log @c WARNING in the default category. */
#define R_LOG_FIXME(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_FIXME,    __VA_ARGS__) /**< @brief Log @c FIXME in the default category. */
#define R_LOG_INFO(...)     R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_INFO,     __VA_ARGS__) /**< @brief Log @c INFO in the default category. */
#define R_LOG_DEBUG(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_DEBUG,    __VA_ARGS__) /**< @brief Log @c DEBUG in the default category. */
#define R_LOG_TRACE(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_TRACE,    __VA_ARGS__) /**< @brief Log @c TRACE in the default category. */
/** @} */


/** @name Hex / buffer dump macros
 *  Same gating as the message macros above.
 *  @{ */
/** @brief Gated @c r_log_str_dump call (per-category, per-level). */
#define R_LOG_CAT_LEVEL_STR_DUMP(cat,lvl,str,size) R_STMT_START {             \
  _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);               \
  if (R_UNLIKELY (lvl <= R_LOG_LEVEL_MAX && (int)lvl<=(int)_r_log_level_min)) \
    r_log_str_dump ((cat), (lvl), __FILE__, __LINE__, R_STRFUNC, str, size, 68);\
} R_STMT_END
/** @brief @ref R_LOG_CAT_LEVEL_STR_DUMP against the default category. */
#define R_LOG_STR_DUMP(lvl,str,size)  R_LOG_CAT_LEVEL_STR_DUMP (R_LOG_CAT_DEFAULT, lvl, str, size)
/** @brief Gated @c r_log_mem_dump call. */
#define R_LOG_CAT_LEVEL_MEM_DUMP(cat,lvl,ptr,size) R_STMT_START {             \
  _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);               \
  if (R_UNLIKELY (lvl <= R_LOG_LEVEL_MAX && (int)lvl<=(int)_r_log_level_min)) \
    r_log_mem_dump ((cat), (lvl), __FILE__, __LINE__, R_STRFUNC, ptr, size, 16);\
} R_STMT_END
/** @brief @ref R_LOG_CAT_LEVEL_MEM_DUMP against the default category. */
#define R_LOG_MEM_DUMP(lvl,ptr,size)  R_LOG_CAT_LEVEL_MEM_DUMP (R_LOG_CAT_DEFAULT, lvl, ptr, size)
/** @brief Gated @c r_log_buf_dump call. */
#define R_LOG_CAT_LEVEL_BUF_DUMP(cat,lvl,buf) R_STMT_START {             \
  _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);               \
  if (R_UNLIKELY (lvl <= R_LOG_LEVEL_MAX && (int)lvl<=(int)_r_log_level_min)) \
    r_log_buf_dump ((cat), (lvl), __FILE__, __LINE__, R_STRFUNC, buf, 16);\
} R_STMT_END
/** @brief @ref R_LOG_CAT_LEVEL_BUF_DUMP against the default category. */
#define R_LOG_BUF_DUMP(lvl,buf)       R_LOG_CAT_LEVEL_BUF_DUMP (R_LOG_CAT_DEFAULT, lvl, buf)
/** @} */

/** @brief Built-in default sink (coloured, level-tagged stderr output). */
R_API void r_log_default_handler (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg, rpointer user_data);

/**
 * @brief Swap the active sink; pass @c NULL to restore the default.
 * @return The previously-installed @ref RLogFunc.
 */
R_API RLogFunc r_log_override_default_handler (RLogFunc func, rpointer data,
    rpointer * old);

/**
 * @brief State for the "keep last log message" capture mode.
 *
 * Used by @c r_assert_logs_* to verify that a specific log message
 * was emitted during a tested call. Begin a capture window with
 * @ref r_log_keep_last_begin, finish with @ref r_log_keep_last_end.
 *
 * Internally swaps the global @ref RLogFunc for the duration, so
 * any logging done between begin / end is intercepted — be aware
 * of side effects in code under capture.
 */
typedef struct {
  RLogFunc oldfunc;             /**< Previously-installed sink (restored on @c end). */
  rpointer olddata;             /**< Previously-installed user data. */

  RLogCategory * cat;           /**< Category filter; @c NULL matches all. */

  struct {
    RLogCategory * cat;         /**< Category of the captured message. */
    RLogLevel lvl;              /**< Level of the captured message. */
    ruint line;                 /**< Source line. */
    const rchar * file;         /**< Source file. */
    const rchar * func;         /**< Source function. */
    rchar * msg;                /**< Formatted message body. */
  } last;
} RLogKeepLastCtx;

/** @brief Convenience: begin capture, ignoring per-category thresholds. */
#define r_log_keep_last_begin(ctx, cat)                                       \
  r_log_keep_last_begin_full (ctx, cat, TRUE)
/** @brief Begin capture of messages in @p cat; opt-in to ignore the threshold. */
R_API void r_log_keep_last_begin_full (RLogKeepLastCtx * ctx, RLogCategory * cat,
    rboolean ignore_threshold);
/**
 * @brief End capture and restore the previous sink.
 * @param ctx     Capture context.
 * @param fwdlast If @c TRUE, also forward the captured @c last message
 *                to the previously-installed sink.
 * @param reset   If @c TRUE, clear @c ctx->last before returning.
 */
R_API void r_log_keep_last_end (RLogKeepLastCtx * ctx, rboolean fwdlast, rboolean reset);
/** @brief Clear @c ctx->last in the middle of a capture window. */
R_API void r_log_keep_last_reset (RLogKeepLastCtx * ctx);

/**
 * @brief Internal: mark a source position so the test runner can
 * pin assertion failures to the right line. Defined as a no-op
 * inside @c RLIB_COMPILATION.
 */
R_API rboolean _r_test_mark_position (const rchar * file, ruint line,
    const rchar * func, rboolean assert);

#ifdef RLIB_COMPILATION
#define _r_test_mark_position(...)
#endif

R_END_DECLS

/** @} */

#endif /* __R_LOG_H__ */

