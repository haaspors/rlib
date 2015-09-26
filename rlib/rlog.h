/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
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
#define R_LOG_LEVEL_DEFAULT     R_LOG_LEVEL_NONE
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
R_API RLogCategory * _r_log_find_category (const rchar * name);

#define R_LOG_CATEGORY_DEFINE(cat, name, desc, clr)                         \
  RLogCategory cat = { R_LOG_LEVEL_DEFAULT, (name), (desc), (clr) }
#define R_LOG_CATEGORY_DEFINE_STATIC(cat, name, desc, clr)                  \
  static R_LOG_CATEGORY_DEFINE (cat, name, desc, clr)
#define R_LOG_CATEGORY_DEFINE_EXTERN(cat) extern RLogCategory cat

#define R_LOG_CATEGORY_FIND(cat, name)  R_STMT_START {                      \
  if ((cat = _r_log_find_category (name)) == NULL)                          \
    cat = R_LOG_CAT_DEFAULT;                                                \
} R_STMT_END
#define r_log_category_set_threshold(cat, lvl)  (cat)->threshold = lvl
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

#define R_LOG_CAT_LEVEL(cat,lvl,...) R_STMT_START {                           \
  if (R_UNLIKELY (lvl <= R_LOG_LEVEL_MAX && lvl <= _r_log_level_min))         \
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


R_API void r_log_default_handler (RLogCategory * cat, RLogLevel lvl,
    const rchar * file, ruint line, const rchar * func,
    const rchar * msg, rpointer user_data);

#if 1
R_API RLogFunc r_log_override_default_handler (RLogFunc func, rpointer * data);
#else
R_API void r_log_add_handler_full (RLogFunc func, rpointer data, RDestroyNotify notify);
#define r_log_add_handler_full(func, data)        \
  r_log_add_handler_full (func, data, NULL);
void r_log_remove_handler (RLogFunc func);
void r_log_remove_handler_by_data (rpointer data);
#endif

R_END_DECLS

#endif /* __R_LOG_H__ */

