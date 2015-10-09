/* RLIB - Convenience library for useful things
 * Copyright (C) 2015  Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the MIT License.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_ASSERT_INTERNAL_H__
#define __R_ASSERT_INTERNAL_H__

#ifndef __R_ASSERT_H__
#error "#include <rlib.h> pelase."
#endif

#include <rlib/rlog.h>
#include <string.h>

/* Assert helper macros */
#define R_ASSERT_VA(...) r_test_assertion (R_LOG_CAT_ASSERT, __FILE__, __LINE__, R_STRFUNC, __VA_ARGS__)
#if defined(RLIB_COMPILATION)
#define R_ASSERT_STMT(CMPEXPR, REPR, REAL, ...) if (!(CMPEXPR)) abort ()
#define R_ASSERT_STMT_MEM(m1, cmp, m2, s, REPR, REAL, ...)                    \
  if (!(__m1 && __m2 && memcmp (__m1, __m2, s) cmp 0)) abort ()
#else
#define R_ASSERT_STMT(CMPEXPR, REPR, REAL, ...)                               \
  if (CMPEXPR) R_LOG_CAT_TRACE (R_LOG_CAT_ASSERT, "%s ("REPR"): ("REAL")", "passed", __VA_ARGS__); \
  else R_ASSERT_VA ("%s ("REPR"): ("REAL")", "*** assertion", __VA_ARGS__)
#define R_ASSERT_STMT_MEM(m1, cmp, m2, size, REPR, REAL, ...)                 \
  if (m1 && m2 && memcmp (m1, m2, size) cmp 0) {                              \
    R_LOG_CAT_TRACE (R_LOG_CAT_ASSERT, "%s ("REPR"): ("REAL")", "passed", __VA_ARGS__);\
  } else {                                                                    \
    if (m1) r_log_mem_dump (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR,              \
        __FILE__, __LINE__, R_STRFUNC, m1, size, 16);                         \
    if (m2) r_log_mem_dump (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR,              \
        __FILE__, __LINE__, R_STRFUNC, m2, size, 16);                         \
    R_ASSERT_VA ("%s ("REPR"): ("REAL")", "*** mem assertion", __VA_ARGS__);  \
  }
#endif
#define R_ASSERT_CMP(a1, cmp, a2, TYPE, FMT, r1, r2) R_STMT_START {           \
  TYPE __a1 = (TYPE)(a1), __a2 = (TYPE)(a2);                                  \
  R_ASSERT_STMT (__a1 cmp __a2, "%s %s %s", FMT" %s "FMT,                     \
      r1, #cmp, r2, __a1, #cmp, __a2);                                        \
} R_STMT_END
#define R_ASSERT_CMPSTR(s1, cmp, s2, r1, r2)   R_STMT_START {                 \
  const rchar * __s1 = (s1), * __s2 = (s2);                                   \
  R_ASSERT_STMT (r_strcmp (__s1, __s2) cmp 0, "%s %s %s", "\"%s\" %s \"%s\"", \
      r1, #cmp, r2, __s1, #cmp, __s2);                                        \
} R_STMT_END
#define R_ASSERT_CMPMEM(m1, cmp, m2, s, r1, r2)   R_STMT_START {              \
  const ruint8 * __m1 = (const ruint8 *)(m1), * __m2 = (const ruint8 *)(m2);  \
  R_ASSERT_STMT_MEM (__m1, cmp, __m2, s,                                      \
      "%s %s %s", "\"%p\" %s \"%p\"", r1, #cmp, r2, __m1, #cmp, __m2);        \
} R_STMT_END

#endif /* __R_ASSERT_INTERNAL_H__ */

