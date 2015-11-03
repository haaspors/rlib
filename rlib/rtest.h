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
#ifndef __R_TEST_H__
#define __R_TEST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rtest-internal.h>
#include <rlib/rtime.h>
#include <stdio.h>

R_BEGIN_DECLS

#ifndef RTEST_TIMEOUT
#define RTEST_TIMEOUT   (4*R_SECOND)
#endif
#define RTEST_TYPE_TIMEOUT(type)    (((type) & R_TEST_TYPE_MASK) * RTEST_TIMEOUT)

typedef struct _RTest RTest;
typedef void (*RTestFunc) (); /* YES - non-void argument list */
typedef void (*RTestFixtureFunc) (rpointer fixture);
typedef rboolean (*RTestFilterFunc) (const RTest * test, rsize __i, rpointer data);

typedef enum {
  R_TEST_TYPE_NONE      = 0x00000000,

  /* Test type */
  R_TEST_TYPE_FAST      = 0x00000001, /* Fast unit-test */
  R_TEST_TYPE_SLOW      = 0x00000002, /* Slow unit-test */
  R_TEST_TYPE_FASTSLOW  = 0x00000003, /* Neither/Both Fast or Slow unit-test */
  R_TEST_TYPE_INTEGR    = 0x00000004, /* Integration-test */
  R_TEST_TYPE_SYSTEM    = 0x00000008, /* System-test */
  R_TEST_TYPE_MASK      = 0x0000000F,

  /* Flags                              Used for tests:             */
  R_TEST_FLAG_STRESS    = 0x01000000, /*  that are run continously  */
  R_TEST_FLAG_LOOP      = 0x02000000, /*  that are run x iterations */
  R_TEST_FLAG_PERF      = 0x20000000, /*  measuring performance     */
  R_TEST_FLAG_FUZZY     = 0x40000000, /*  with random input         */
  R_TEST_FLAG_NOFORK    = 0x80000000, /*  which shouldn't fork      */
  R_TEST_FLAG_MASK      = 0xFF000000,
  R_TEST_ALL_MASK       = 0xFFFFFFFF
} RTestType;

#define RLIB_SIZEOF_RTEST   128

struct R_ATTR_ALIGN (RLIB_SIZEOF_RTEST) _RTest {
    ruint32 magic;
    ruint32 skip;
    const rchar * suite;
    const rchar * name;
    RTestType type;
    RClockTime timeout;

    RTestFunc func;
    rsize loop_start;
    rsize loop_end;

    rpointer fdata;
    RTestFixtureFunc setup;
    RTestFixtureFunc teardown;
};

typedef enum {
  R_TEST_RUN_STATE_NONE       = 0,
  R_TEST_RUN_STATE_RUNNING    = 1,
  R_TEST_RUN_STATE_SKIP       = 2,
  R_TEST_RUN_STATE_SUCCESS    = 3,
  R_TEST_RUN_STATE_FAILED     = 4,
  R_TEST_RUN_STATE_ERROR      = 5,
  R_TEST_RUN_STATE_TIMEOUT    = 6
} RTestRunState;

typedef struct {
  RClockTime ts;
  const rchar * file;
  const rchar * func;
  ruint line;
  rboolean assrt;
} RTestLastPos;

typedef struct {
  const RTest * test;
  RTestRunState state;
  rsize __i;

  RTestLastPos lastpos;
  RTestLastPos failpos;

  RClockTime start;
  RClockTime end;
} RTestRun;

typedef struct {
  rsize total;
  rsize run, skip;
  rsize success, fail, error;

  RClockTime start;
  RClockTime end;

  RTestRun runs[];
} RTestReport;

#define RTEST_FAST      R_TEST_TYPE_FAST
#define RTEST_SLOW      R_TEST_TYPE_SLOW
#define RTEST_FASTSLOW  R_TEST_TYPE_FASTSLOW
#define RTEST_INTEGR    R_TEST_TYPE_INTEGR
#define RTEST_SYSTEM    R_TEST_TYPE_SYSTEM

/* Start your test using one of these macros */
#define RTEST(suite, name, type)                  RTEST_DEFINE_TEST (suite, name, 0, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
#define RTEST_F(suite, name, type)                RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 0, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
#define RTEST_STRESS(suite, name, type)           RTEST_DEFINE_TEST (suite, name, 0, (type) | R_TEST_FLAG_STRESS, R_CLOCK_TIME_NONE, 0, 1)
#define RTEST_STRESS_F(suite, name,type)          RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 0, (type) | R_TEST_FLAG_STRESS, R_CLOCK_TIME_NONE, 0, 1)
#define RTEST_LOOP(suite, name, type, s,e)        RTEST_DEFINE_TEST (suite, name, 0, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
#define RTEST_LOOP_F(suite, name,type, s,e)       RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 0, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/* Or easily prefix with SKIP to easy disable it temporarily */
#define SKIP_RTEST(suite, name, type)             RTEST_DEFINE_TEST (suite, name, 1, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
#define SKIP_RTEST_F(suite, name, type)           RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 1, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
#define SKIP_RTEST_STRESS(suite, name, type)      RTEST_DEFINE_TEST (suite, name, 1, (type) | R_TEST_FLAG_STRESS, R_CLOCK_TIME_NONE, 0, 1)
#define SKIP_RTEST_STRESS_F(suite, name,type)     RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 1, (type) | R_TEST_FLAG_STRESS, R_CLOCK_TIME_NONE, 0, 1)
#define SKIP_RTEST_LOOP(suite, name, type, s,e)   RTEST_DEFINE_TEST (suite, name, 1, type, RTEST_TYPE_TIMEOUT(type), s, e)
#define SKIP_RTEST_LOOP_F(suite, name,type, s,e)  RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 1, type, RTEST_TYPE_TIMEOUT(type), s, e)
/* End your test with this macro! */
#define RTEST_END _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE); }

/* Used for fixtures*/
#define RTEST_FIXTURE_STRUCT(suite)               _RTEST_FIXTURE_STRUCT (suite)
#define RTEST_FIXTURE_SETUP(suite)                                            \
  static void _RTEST_FIXTURE_SETUP_NAME (suite) (_RTEST_FIXTURE_ARG (suite))
#define RTEST_FIXTURE_TEARDOWN(suite)                                         \
  static void _RTEST_FIXTURE_TEARDOWN_NAME (suite) (_RTEST_FIXTURE_ARG (suite))


/* Instead of defining main() yourself, just use RTEST_MAIN()
 * Usually at the bottom of your main test runner .c file.
 * TODO: Parse arguments
 */
#define RTEST_MAIN()                                                          \
  int main (int argc, rchar ** argv) {                                      \
  int ret;                                                                   \
  RTestReport * report;                                                       \
  (void) argc; (void) argv;                                                   \
                                                                              \
  report = r_test_run_local_tests (R_TEST_ALL_MASK, FALSE);                   \
  if (report == NULL)                                                         \
    return -1;                                                                \
  ret = report->fail + report->error;                                         \
  r_test_report_print (report, FALSE, stdout);                                \
  r_test_report_free (report);                                                \
  return ret;                                                                 \
}

R_API rsize r_test_get_local_test_count (rsize * runs);
R_API const RTest * r_test_get_local_tests (rsize * tests, rsize * runs);

R_API RTestRunState r_test_run_fork (const RTest * test, rsize __i,
    RClockTime timeout, RTestLastPos * lastpos, RTestLastPos * failpos);
R_API RTestRunState r_test_run_nofork (const RTest * test, rsize __i,
    RClockTime timeout, RTestLastPos * lastpos, RTestLastPos * failpos);
R_API RTestReport * r_test_run_local_tests_full (RTestFilterFunc filter, rpointer data);
R_API RTestReport * r_test_run_local_tests (RTestType type, rboolean ignore_skip);

R_API void r_test_report_print (RTestReport * report, rboolean verbose, FILE * f);
#define r_test_report_free(report)  r_free (report)

R_END_DECLS

#endif /* __R_TEST_H__ */

