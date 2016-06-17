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

#include <rlib/rtypes.h>
#include <rlib/ratomic.h>
#include <rlib/rclr.h>
#include <stdarg.h>

R_BEGIN_DECLS

typedef enum
{
  R_LOG_LEVEL_NONE              = 0,
  R_LOG_LEVEL_ERROR             = 1,
  R_LOG_LEVEL_CRITICAL          = 2,
  R_LOG_LEVEL_WARNING           = 3,
  R_LOG_LEVEL_FIXME             = 4,
  R_LOG_LEVEL_INFO              = 5,
  R_LOG_LEVEL_DEBUG             = 6,
  R_LOG_LEVEL_TRACE             = 7,

  R_LOG_LEVEL_COUNT
} RLogLevel;

#ifndef R_LOG_LEVEL_DEFAULT
#define R_LOG_LEVEL_DEFAULT     R_LOG_LEVEL_CRITICAL
#endif
#ifndef R_LOG_LEVEL_MAX
#define R_LOG_LEVEL_MAX         R_LOG_LEVEL_COUNT
#endif
R_API extern rauint             _r_log_level_min;

R_API const rchar * r_log_level_get_name (RLogLevel lvl);
R_API void r_log_set_default_level (RLogLevel lvl);
R_API RLogLevel r_log_get_default_level (void);

typedef struct
{
  RLogLevel       threshold;
  const rchar *   name;
  const rchar *   desc;
  ruint16         clr;
} RLogCategory;

R_API rboolean r_log_category_register (RLogCategory * cat);
R_API rboolean r_log_category_unregister (RLogCategory * cat);
R_API RLogCategory * r_log_category_find (const rchar * name);

#define R_LOG_CATEGORY_DEFINE(cat, name, desc, clr)                         \
  RLogCategory cat = { R_LOG_LEVEL_DEFAULT, (name), (desc), (clr) }
#define R_LOG_CATEGORY_DEFINE_STATIC(cat, name, desc, clr)                  \
  static R_LOG_CATEGORY_DEFINE (cat, name, desc, clr)
#define R_LOG_CATEGORY_DEFINE_EXTERN(cat) extern RLogCategory cat

R_API void r_log_category_set_threshold (RLogCategory * cat, RLogLevel lvl);
#define r_log_category_get_threshold(cat)       (cat)->threshold

R_API R_LOG_CATEGORY_DEFINE_EXTERN (_r_log_cat_assert);
#define R_LOG_CAT_ASSERT &_r_log_cat_assert

typedef void (*RLogFunc) (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg, rpointer user_data);

R_API void r_log (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, ...) R_ATTR_PRINTF (6, 7);
R_API void r_logv (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * fmt, va_list args) R_ATTR_PRINTF(6, 0);
R_API void r_log_msg (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg);
R_API void r_log_mem_dump (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const ruint8 * ptr, rsize size, rsize bytesperline);

#define R_LOG_CAT_LEVEL(cat,lvl,...) R_STMT_START {                           \
  _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);               \
  if (R_UNLIKELY (lvl <= R_LOG_LEVEL_MAX && (int)lvl<=(int)_r_log_level_min)) \
    r_log ((cat), (lvl), __FILE__, __LINE__, R_STRFUNC, __VA_ARGS__);         \
} R_STMT_END

#define R_LOG_CAT_ERROR(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_ERROR,    __VA_ARGS__)
#define R_LOG_CAT_CRITICAL(cat,...) R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_CRITICAL, __VA_ARGS__)
#define R_LOG_CAT_WARNING(cat,...)  R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_WARNING,  __VA_ARGS__)
#define R_LOG_CAT_FIXME(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_FIXME,    __VA_ARGS__)
#define R_LOG_CAT_INFO(cat,...)     R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_INFO,     __VA_ARGS__)
#define R_LOG_CAT_DEBUG(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_DEBUG,    __VA_ARGS__)
#define R_LOG_CAT_TRACE(cat,...)    R_LOG_CAT_LEVEL (cat, R_LOG_LEVEL_TRACE,    __VA_ARGS__)

#define R_LOG_ERROR(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_ERROR,    __VA_ARGS__)
#define R_LOG_CRITICAL(...) R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_CRITICAL, __VA_ARGS__)
#define R_LOG_WARNING(...)  R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_WARNING,  __VA_ARGS__)
#define R_LOG_FIXME(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_FIXME,    __VA_ARGS__)
#define R_LOG_INFO(...)     R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_INFO,     __VA_ARGS__)
#define R_LOG_DEBUG(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_DEBUG,    __VA_ARGS__)
#define R_LOG_TRACE(...)    R_LOG_CAT_LEVEL (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_TRACE,    __VA_ARGS__)


#define R_LOG_CAT_LEVEL_MEM_DUMP(cat,lvl,ptr,size) R_STMT_START {             \
  _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);               \
  if (R_UNLIKELY (lvl <= R_LOG_LEVEL_MAX && (int)lvl<=(int)_r_log_level_min)) \
    r_log_mem_dump ((cat), (lvl), __FILE__, __LINE__, R_STRFUNC, ptr, size, 16);\
} R_STMT_END
#define R_LOG_MEM_DUMP(lvl,ptr,size)  R_LOG_CAT_LEVEL_MEM_DUMP (R_LOG_CAT_DEFAULT, lvl, ptr, size)

R_API void r_log_default_handler (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg, rpointer user_data);

R_API RLogFunc r_log_override_default_handler (RLogFunc func, rpointer data,
    rpointer * old);

/* RLogKeepLast API uses r_log_override_default_handler() so be careful with
 * what you do between begin() and end().
 *
 * RLogKeepLast API also opts in for logging all, which might mean that more
 * logging will flow through the RLog framework. Be aware and careful.
 */
typedef struct {
  RLogFunc oldfunc;
  rpointer olddata;

  RLogCategory * cat;

  struct {
    RLogCategory * cat;
    RLogLevel lvl;
    ruint line;
    const rchar * file;
    const rchar * func;
    rchar * msg;
  } last;
} RLogKeepLastCtx;

#define r_log_keep_last_begin(ctx, cat)                                       \
  r_log_keep_last_begin_full (ctx, cat, TRUE)
R_API void r_log_keep_last_begin_full (RLogKeepLastCtx * ctx, RLogCategory * cat,
    rboolean ignore_threshold);
R_API void r_log_keep_last_end (RLogKeepLastCtx * ctx, rboolean fwdlast, rboolean reset);
R_API void r_log_keep_last_reset (RLogKeepLastCtx * ctx);

/* Internal API used for marking last position for rtests */
R_API rboolean _r_test_mark_position (const rchar * file, ruint line,
    const rchar * func, rboolean assrt);

R_END_DECLS

#endif /* __R_LOG_H__ */

