/* RLIB - Convenience library for useful things
 * Copyright (C) 2015-2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
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
#ifndef __R_ASSERT_INTERNAL_H__
#define __R_ASSERT_INTERNAL_H__

#ifndef __R_ASSERT_H__
#error "#include <rlib.h> pelase."
#endif

#include <rlib/rlog.h>

#if defined(__GNUC__)
#define __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                    \
  _Pragma ("GCC diagnostic push")                                             \
  _Pragma ("GCC diagnostic ignored \"-Waddress\"")
#define __R_GCC_DISABLE_WARN_ADDRESS_END  _Pragma ("GCC diagnostic pop")
#else
#define __R_GCC_DISABLE_WARN_ADDRESS_BEGIN
#define __R_GCC_DISABLE_WARN_ADDRESS_END
#endif

/* Assert helper macros */
#define _R_ASSERT_VA(...) r_test_assertion (R_LOG_CAT_ASSERT, __FILE__, __LINE__, R_STRFUNC, __VA_ARGS__)
#if defined(RLIB_COMPILATION)
#define _R_ASSERT_STMT(CMPEXPR, REPR, REAL, ...)                              \
  __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                          \
  if (!(CMPEXPR)) abort ();                                                   \
  __R_GCC_DISABLE_WARN_ADDRESS_END
#define _R_ASSERT_STMT_CMPMEM(m1, cmp, m2, s, REPR, REAL, ...)                \
  __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                          \
  if (!(r_memcmp (m1, m2, s) cmp 0)) abort ();                                \
  __R_GCC_DISABLE_WARN_ADDRESS_END
#define _R_ASSERT_STMT_CMPMEMSIZE(m1, s1, cmp, m2, s2, REPR, REAL, ...)       \
  __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                          \
  if (!((s1 == s2 && r_memcmp (m1, m2, s1) cmp 0) || s1 cmp s2)) abort ();    \
  __R_GCC_DISABLE_WARN_ADDRESS_END
#else
#define _R_ASSERT_STMT(CMPEXPR, REPR, REAL, ...)                              \
  __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                          \
  if (CMPEXPR) R_LOG_CAT_TRACE (R_LOG_CAT_ASSERT, "%s ("REPR"): ("REAL")", "passed", __VA_ARGS__); \
  else _R_ASSERT_VA ("%s ("REPR"): ("REAL")", "*** assertion", __VA_ARGS__);  \
  __R_GCC_DISABLE_WARN_ADDRESS_END
#define _R_ASSERT_STMT_CMPMEM(m1, cmp, m2, size, REPR, REAL, ...)             \
  __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                          \
  if (r_memcmp (m1, m2, size) cmp 0) {                                        \
    R_LOG_CAT_TRACE (R_LOG_CAT_ASSERT, "%s ("REPR"): ("REAL")", "passed", __VA_ARGS__);\
  } else {                                                                    \
    if (m1) r_log_mem_dump (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR,              \
        __FILE__, __LINE__, R_STRFUNC, m1, size, 16);                         \
    if (m2) r_log_mem_dump (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR,              \
        __FILE__, __LINE__, R_STRFUNC, m2, size, 16);                         \
    _R_ASSERT_VA ("%s ("REPR"): ("REAL")", "*** mem assertion", __VA_ARGS__); \
  }                                                                           \
  __R_GCC_DISABLE_WARN_ADDRESS_END
#define _R_ASSERT_STMT_CMPMEMSIZE(m1, s1, cmp, m2, s2, REPR, REAL, ...)       \
  __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                          \
  if ((s1 == s2 && r_memcmp (m1, m2, s1) cmp 0) || s1 cmp s2) {               \
    R_LOG_CAT_TRACE (R_LOG_CAT_ASSERT, "%s ("REPR"): ("REAL")", "passed", __VA_ARGS__);\
  } else {                                                                    \
    if (m1) r_log_mem_dump (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR,              \
        __FILE__, __LINE__, R_STRFUNC, m1, s1, 16);                           \
    if (m2) r_log_mem_dump (R_LOG_CAT_ASSERT, R_LOG_LEVEL_ERROR,              \
        __FILE__, __LINE__, R_STRFUNC, m2, s2, 16);                           \
    _R_ASSERT_VA ("%s ("REPR"): ("REAL")", "*** mem assertion", __VA_ARGS__); \
  }                                                                           \
  __R_GCC_DISABLE_WARN_ADDRESS_END
#endif
#define _R_ASSERT(expr) R_STMT_START {                                        \
  rboolean __res = (rboolean)(expr);                                          \
  _R_ASSERT_STMT (__res, "%s", "%u", #expr, __res)                            \
} R_STMT_END
#define _R_ASSERT_CMP(a1, cmp, a2, TYPE, FMT, r1, r2) R_STMT_START {          \
  TYPE __a1 = (TYPE)(a1), __a2 = (TYPE)(a2);                                  \
  _R_ASSERT_STMT (__a1 cmp __a2, "%s %s %s", FMT" %s "FMT,                    \
      r1, #cmp, r2, __a1, #cmp, __a2);                                        \
} R_STMT_END
#define _R_ASSERT_CMPSTR(s1, cmp, s2, r1, r2)   R_STMT_START {                \
  const rchar * __s1 = (s1), * __s2 = (s2);                                   \
  _R_ASSERT_STMT (r_strcmp (__s1, __s2) cmp 0,                                \
      "%s %s %s", "\"%s\" %s \"%s\"", r1, #cmp, r2, __s1, #cmp, __s2);        \
} R_STMT_END
#define _R_ASSERT_CMPSTRN(s1, cmp, s2, s, r1, r2)   R_STMT_START {            \
  const rchar * __s1 = (s1), * __s2 = (s2);                                   \
  rsize __s = s;                                                              \
  _R_ASSERT_STMT (r_strncmp (__s1, __s2, __s) cmp 0,                          \
      "%s %s %s (%s)", "\"%.*s\" %s \"%.*s\"",                                \
      r1, #cmp, r2, #s, (int)__s, __s1, #cmp, (int)__s, __s2);                \
} R_STMT_END
#define _R_ASSERT_CMPSTRSIZE(s1, l1, cmp, s2, l2, r1, r2)   R_STMT_START {    \
  const rchar * __s1 = (s1), * __s2 = (s2);                                   \
  rssize __l1 = (l1), __l2 = (l2);                                            \
  if (__l1 < 0) __l1 = r_strlen (__s1);                                       \
  if (__l2 < 0) __l2 = r_strlen (__s2);                                       \
  if (__l1 == __l2) {                                                         \
    _R_ASSERT_STMT (r_strncmp (__s1, __s2, __l1) cmp 0,                       \
        "%s (%s) %s %s (%s)", "\"%.*s\" %s \"%.*s\"",                         \
        r1, #l1, #cmp, r2, #l2, (int)__l1, __s1, #cmp, (int)__l2, __s2);      \
  } else {                                                                    \
    _R_ASSERT_STMT (__l1 cmp __l2,                                            \
        "%s (%s) %s %s (%s)", "\"%.*s\" %s \"%.*s\"",                         \
        r1, #l1, #cmp, r2, #l2, (int)__l1, __s1, #cmp, (int)__l2, __s2);      \
  }                                                                           \
} R_STMT_END
#define _R_ASSERT_CMPMEM(m1, cmp, m2, s, r1, r2)   R_STMT_START {             \
  const ruint8 * __m1 = (const ruint8 *)(m1), * __m2 = (const ruint8 *)(m2);  \
  rsize __s = (s);                                                            \
  _R_ASSERT_STMT_CMPMEM (__m1, cmp, __m2, __s,                                \
      "%s %s %s [%s]", "\"%p [%"RSIZE_FMT"]\" %s \"%p [%"RSIZE_FMT"]\"",      \
      r1, #cmp, r2, #s, __m1, __s, #cmp, __m2, __s);                          \
} R_STMT_END
#define _R_ASSERT_CMPMEMSIZE(m1, s1, cmp, m2, s2, r1, r2)   R_STMT_START {    \
  const ruint8 * __m1 = (const ruint8 *)(m1), * __m2 = (const ruint8 *)(m2);  \
  rsize __s1 = (s1), __s2 = (s2);                                             \
  _R_ASSERT_STMT_CMPMEMSIZE (__m1, __s1, cmp, __m2, __s2,                     \
      "%s [%s] %s %s [%s]", "%p [%"RSIZE_FMT"] %s %p [%"RSIZE_FMT"]",         \
      r1, #s1, #cmp, r2, #s2, __m1, __s1, #cmp, __m2, __s2);                  \
} R_STMT_END
#define _R_ASSERT_CMPBUFSIZE(b1, o1, s1, cmp, b2, o2, s2, r1, r2)   R_STMT_START {\
  RMemMapInfo i1 = R_MEM_MAP_INFO_INIT, i2 = R_MEM_MAP_INFO_INIT;             \
  rsize __o1 = (o1), __o2 = (o2);                                             \
  rssize __s1 = (s1), __s2 = (s2);                                            \
  _R_ASSERT_STMT (r_buffer_map_byte_range (b1, __o1, __s1, &i1, R_MEM_MAP_READ),\
      "%s@%s [%s] %s %s@%s [%s]",                                             \
      "failed to map 1.buf %p@%"RSIZE_FMT" [%"RSSIZE_FMT"] [size: %"RSIZE_FMT"]",\
      r1, #o1, #s1, #cmp, r2, #o2, #s2,                                       \
      b1, __o1, __s1, r_buffer_get_size (b1));                                \
  _R_ASSERT_STMT (r_buffer_map_byte_range (b2, __o2, __s2, &i2, R_MEM_MAP_READ),\
      "%s@%s [%s] %s %s@%s [%s]",                                             \
      "failed to map 2.buf %p@%"RSIZE_FMT" [%"RSSIZE_FMT"] [size: %"RSIZE_FMT"]",\
      r1, #o1, #s1, #cmp, r2, #o2, #s2,                                       \
      b2, __o2, __s2, r_buffer_get_size (b2));                                \
  _R_ASSERT_STMT_CMPMEMSIZE (i1.data, i1.size, cmp, i2.data, i2.size,         \
      "%s@%s [%s] %s %s@%s [%s]",                                             \
      "buf:%p [%"RSIZE_FMT"] (mem:%p)@%"RSIZE_FMT" [%"RSSIZE_FMT"] %s "       \
      "buf:%p [%"RSIZE_FMT"] (mem:%p)@%"RSIZE_FMT" [%"RSSIZE_FMT"]",          \
      r1, #o1, #s1, #cmp, r2, #o2, #s2,                                       \
      b1, r_buffer_get_size (b1), i1.data, __o1, __s1, #cmp,                  \
      b2, r_buffer_get_size (b2), i2.data, __o2, __s2);                       \
  r_buffer_unmap (b1, &i1);                                                   \
  r_buffer_unmap (b2, &i2);                                                   \
} R_STMT_END
#define _R_ASSERT_CMPBUFMEM(b, o, s, cmp, m, ms, r1, r2)   R_STMT_START {     \
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;                                     \
  rsize __o = (o), __ms = (ms);                                               \
  rssize __s = (s);                                                           \
  _R_ASSERT_STMT (r_buffer_map_byte_range (b, __o, __s, &info, R_MEM_MAP_READ),\
      "%s@%s [%s] %s %s [%s]",                                                \
      "failed to map buf %p@%"RSIZE_FMT" [%"RSSIZE_FMT"] [size: %"RSIZE_FMT"]",\
      r1, #o, #s, #cmp, r2, #ms,                                              \
      b, __o, __s, r_buffer_get_size (b));                                    \
  _R_ASSERT_STMT_CMPMEMSIZE (info.data, info.size, cmp, m, __ms,              \
      "%s@%s [%s] %s %s [%s]",                                                \
      "buf:%p [%"RSIZE_FMT"] (mem:%p)@%"RSIZE_FMT" [%"RSSIZE_FMT"] %s "       \
      "mem:%p [%"RSIZE_FMT"]",                                                \
      r1, #o, #s, #cmp, r2, #ms,                                              \
      b, r_buffer_get_size (b), info.data, __o, info.size, #cmp, m, __ms);    \
  r_buffer_unmap (b, &info);                                                  \
} R_STMT_END
#define _R_ASSERT_LOG(expr, CAT, LVL, MSG) R_STMT_START {                     \
  __R_GCC_DISABLE_WARN_ADDRESS_BEGIN                                          \
  RLogKeepLastCtx ctx;                                                        \
  r_log_keep_last_begin (&ctx, CAT);                                          \
  { expr; };                                                                  \
  r_log_keep_last_end (&ctx, FALSE, FALSE); /* Call _reset() later! */        \
  if (CAT != NULL)                                                            \
    _R_ASSERT_CMP (CAT,==,ctx.last.cat,rpointer,"%p","cat","<last log cat>"); \
  if (LVL != R_LOG_LEVEL_NONE)                                                \
    _R_ASSERT_CMP (LVL,==,ctx.last.lvl,ruint,"%u","lvl","<last log level>");  \
  if (MSG != NULL)                                                            \
    _R_ASSERT_CMPSTR (MSG,==,ctx.last.msg,"msg","<last log msg>");            \
  r_log_keep_last_reset (&ctx);                                               \
  __R_GCC_DISABLE_WARN_ADDRESS_END                                            \
} R_STMT_END

#endif /* __R_ASSERT_INTERNAL_H__ */

