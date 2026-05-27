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
#ifndef __R_TEST_H__
#define __R_TEST_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>
#include <rlib/rtest-internal.h>

#include <rlib/data/rlist.h>
#include <rlib/rmodule.h>
#include <rlib/rtime.h>

#include <stdio.h>

/**
 * @defgroup r_test Unit testing
 * @brief In-process unit-test framework: register tests with the
 * @c RTEST family of macros, ship the binary, run with @c RTEST_MAIN.
 * @{
 */

/**
 * @file rlib/rtest.h
 * @brief In-process unit-test framework.
 *
 * Tests are declared with one of the @c RTEST* macros at file scope -
 * each one expands to a self-registering @c RTest descriptor that
 * the runner picks up via @c r_test_get_module_tests. The framework
 * forks per test (Unix) or runs an isolating thread (Windows) so that
 * a crashing test reports as @c R_TEST_RUN_STATE_ERROR without taking
 * the suite down.
 *
 * **Picking a macro:**
 *  - @c RTEST / @c RTEST_F - default unit test, with or without a fixture.
 *  - @c RTEST_LOOP / @c RTEST_LOOP_F - run the body @c [start, end)
 *    times; the loop counter is exposed as @c __i.
 *  - @c RTEST_STRESS / @c RTEST_STRESS_F - long-running concurrency
 *    test, capped by @c RTEST_STRESS_TIMEOUT.
 *  - @c RTEST_BENCH / @c RTEST_BENCH_F - benchmark; no timeout.
 *  - @c SKIP_RTEST_* / @c HEAVY_RTEST_* / @c BROKEN_RTEST_* - the same
 *    macros but gated out of the default run. See @c RTestSkipReason
 *    for the difference between the three categories.
 *
 * **Type and flag classification (@c RTestType):** every test carries
 * one of the @c R_TEST_TYPE_* base types (FAST, SLOW, INTEGR, SYSTEM)
 * - which doubles as a per-test timeout multiplier - plus optional
 * @c R_TEST_FLAG_* bits (LOOP, STRESS, BENCH, etc.).
 *
 * **Wire-up:** put @c RTEST_MAIN(version_str) at the bottom of your
 * test runner source file; it expands to a @c main that parses the
 * standard CLI options (@c -f, @c -p, @c --heavy, etc.) and prints
 * a summary via @c r_test_report_print.
 */

R_BEGIN_DECLS

/**
 * @brief Default per-test timeout (multiplied by the test's base
 * @c R_TEST_TYPE_* value to scale with FAST / SLOW / INTEGR / SYSTEM).
 * Override at compile time by @c \#define-ing before including rlib.
 */
#ifndef RTEST_TIMEOUT
#define RTEST_TIMEOUT   (4*R_SECOND)
#endif
/**
 * @brief Derive a per-test timeout from a test's @c RTestType.
 *
 * Used by the @c RTEST* macros; rarely needed in user code.
 */
#define RTEST_TYPE_TIMEOUT(type)    (((type) & R_TEST_TYPE_MASK) * RTEST_TIMEOUT)

/**
 * @brief Hard cap for @c RTEST_STRESS.
 *
 * Stress tests get this fixed budget rather than the type-derived one
 * so deadlocked stress tests get reported by rtest's own per-test
 * timer instead of hanging the suite until meson's outer timeout
 * kills the runner. Override at compile time if a stress test
 * legitimately needs longer.
 */
#ifndef RTEST_STRESS_TIMEOUT
#define RTEST_STRESS_TIMEOUT  (30*R_SECOND)
#endif

/** @brief Opaque descriptor for a registered test. */
typedef struct _RTest RTest;
/**
 * @brief Test body signature.
 *
 * @param __i      Loop iteration (0 for non-LOOP tests).
 * @param fixture  Fixture-struct pointer; @c NULL for tests without
 *                 @c RTEST_FIXTURE_*.
 */
typedef void (*RTestFunc) (rsize __i, rpointer fixture);
/** @brief Fixture setup / teardown signature. */
typedef void (*RTestFixtureFunc) (rpointer fixture);
/**
 * @brief Filter callback for @c r_test_run_tests_full.
 *
 * Return @c TRUE to keep the test, @c FALSE to skip it.
 */
typedef rboolean (*RTestFilterFunc) (const RTest * test, rsize __i, rpointer data);

/**
 * @brief Test classification: base type (FAST / SLOW / INTEGR / SYSTEM)
 * plus orthogonal behaviour flags (STRESS, LOOP, BENCH, ...).
 *
 * The base type doubles as the per-test timeout multiplier
 * (@c RTEST_TYPE_TIMEOUT); flags compose with it. The runner's
 * @c -f / type-mask filter accepts a bitwise-OR of base-type bits.
 */
typedef enum {
  R_TEST_TYPE_NONE      = 0x00000000,

  R_TEST_TYPE_FAST      = 0x00000001, /**< Fast unit-test. */
  R_TEST_TYPE_SLOW      = 0x00000002, /**< Slow unit-test. */
  R_TEST_TYPE_FASTSLOW  = 0x00000003, /**< Either fast or slow. */
  R_TEST_TYPE_INTEGR    = 0x00000004, /**< Integration test. */
  R_TEST_TYPE_SYSTEM    = 0x00000008, /**< System test. */
  R_TEST_TYPE_MASK      = 0x0000000F, /**< Mask covering the base types. */

  R_TEST_FLAG_STRESS    = 0x01000000, /**< Long-running concurrency test. */
  R_TEST_FLAG_LOOP      = 0x02000000, /**< Body runs N iterations. */
  R_TEST_FLAG_BENCH     = 0x20000000, /**< Performance measurement, no timeout. */
  R_TEST_FLAG_FUZZY     = 0x40000000, /**< Random input fuzz test. */
  R_TEST_FLAG_NOFORK    = 0x80000000, /**< Run in-process; do not fork. */
  R_TEST_FLAG_MASK      = 0xFF000000, /**< Mask covering the flag bits. */
  R_TEST_ALL_MASK       = 0xFFFFFFFF  /**< Match every test. */
} RTestType;

/** @brief Wire size of @c RTest; used by the registration linker section. */
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

/** @brief Outcome of a single test run. */
typedef enum {
  R_TEST_RUN_STATE_NONE       = 0, /**< Not yet attempted. */
  R_TEST_RUN_STATE_RUNNING    = 1, /**< Currently in flight. */
  R_TEST_RUN_STATE_SKIP       = 2, /**< Skipped (gated or filtered). */
  R_TEST_RUN_STATE_SUCCESS    = 3, /**< Body returned without assertion failure. */
  R_TEST_RUN_STATE_FAILED     = 4, /**< Body hit an @c r_assert*. */
  R_TEST_RUN_STATE_ERROR      = 5, /**< Body crashed / killed / unknown exit. */
  R_TEST_RUN_STATE_TIMEOUT    = 6  /**< Body exceeded the test's timeout. */
} RTestRunState;

/**
 * @brief Why a test isn't in the default run.
 *
 * Stored on @c RTest by the source-level @c SKIP_RTEST_* /
 * @c HEAVY_RTEST_* / @c BROKEN_RTEST_* macros so the runner can keep
 * the three buckets separate in the final tally and let callers opt
 * into each category independently via the matching
 * @c R_TEST_RUN_FLAG_INCLUDE_* flag.
 */
typedef enum {
  R_TEST_NO_SKIP     = 0, /**< Test runs in the default suite. */
  R_TEST_SKIP_TEMP   = 1, /**< @c SKIP_RTEST_* - temporarily disabled. */
  R_TEST_SKIP_HEAVY  = 2, /**< @c HEAVY_RTEST_* - too expensive for default. */
  R_TEST_SKIP_BROKEN = 3, /**< @c BROKEN_RTEST_* - known broken, not under repair. */
} RTestSkipReason;

/**
 * @brief Runtime opt-in flags for @c r_test_run_tests / _full.
 *
 * One @c INCLUDE_* bit per gated category; clearing the bit keeps
 * that category out. Each bucket is independent (e.g. the nightly
 * sweep can opt HEAVY in without dragging BROKEN along, which would
 * fail by definition). To run all three, pass all three.
 */
typedef enum {
  R_TEST_RUN_FLAG_NONE           = 0,
  R_TEST_RUN_FLAG_INCLUDE_SKIP   = 1 << 0, /**< Run @c SKIP_RTEST_* tests. */
  R_TEST_RUN_FLAG_PRINT          = 1 << 1, /**< Print a status line per run. */
  R_TEST_RUN_FLAG_INCLUDE_HEAVY  = 1 << 2, /**< Run @c HEAVY_RTEST_* tests. */
  R_TEST_RUN_FLAG_INCLUDE_BROKEN = 1 << 3, /**< Run @c BROKEN_RTEST_* tests. */
} RTestRunFlag;

/**
 * @brief Source-position snapshot recorded around an assertion or
 * other rtest milestone.
 *
 * Populated by @c r_assert* and the diagnostic signal handlers; used
 * by the report to point at the last point reached before a failure.
 */
typedef struct {
  RClockTime ts;          /**< Monotonic timestamp when captured. */
  const rchar * file;     /**< Source file. */
  const rchar * func;     /**< Function name. */
  ruint line;             /**< Source line. */
  rboolean assert;        /**< @c TRUE if the position came from an assertion. */
} RTestLastPos;

/** @brief Per-test row in @c RTestReport.runs. */
typedef struct {
  const RTest * test;       /**< Test descriptor. */
  RTestRunState state;      /**< Outcome. */
  rsize __i;                /**< Loop iteration (0 for non-LOOP tests). */
  int pid;                  /**< Forked child PID, or 0 on no-fork paths. */
  int exitcode;             /**< Child exit code; meaningful on FAILED / ERROR. */

  RTestLastPos lastpos;     /**< Most recently marked source position. */
  RTestLastPos failpos;     /**< Position of the assertion that triggered FAILED. */

  RClockTime start;         /**< Monotonic timestamp when the body started. */
  RClockTime end;           /**< Monotonic timestamp when it finished. */
} RTestRun;

/** @brief Format flags for @c r_test_report_print. */
typedef enum {
  R_TEST_REPORT_FLAG_NONE         = 0,
  R_TEST_REPORT_FLAG_VERBOSE      = (1 << 0), /**< Print every run, not just failures. */
} RTestReportFlag;

/**
 * @brief Aggregate report for one @c r_test_run_tests invocation.
 *
 * Counter relationships:
 *  - @c run + @c skip + @c filtered + @c error == @c total.
 *  - @c success + @c fail + @c error == number of tests actually run.
 *  - @c skip is the grand total of gated tests; subtract @c skip_heavy
 *    and @c skip_broken to recover the @c SKIP_RTEST_* (temporarily
 *    disabled) count.
 *  - @c filtered is the count of tests excluded by the -f filter or
 *    a type mask that weren't already gated. The @c filtered_pattern
 *    and @c filtered_type sub-buckets are populated only when the
 *    default filter is in use (i.e. via @c r_test_run_tests); custom
 *    filters via @c r_test_run_tests_full leave them at zero and only
 *    the @c filtered total is meaningful.
 */
typedef struct {
  rsize total;            /**< Number of tests considered. */
  rsize run, skip;        /**< Run / gated counts (see note above). */
  rsize skip_heavy;       /**< Subcount of @c skip - @c HEAVY_RTEST_* tests. */
  rsize skip_broken;      /**< Subcount of @c skip - @c BROKEN_RTEST_* tests. */
  rsize filtered;         /**< Tests excluded by -f / type mask. */
  rsize filtered_pattern; /**< Subcount of @c filtered rejected by -f. */
  rsize filtered_type;    /**< Subcount of @c filtered rejected by the type mask. */
  rsize success;          /**< Passed runs. */
  rsize fail;             /**< Failed runs (assertion). */
  rsize error;            /**< Errored runs (crash / timeout / unknown). */

  RClockTime start;       /**< Monotonic timestamp at suite start. */
  RClockTime end;         /**< Monotonic timestamp at suite end. */

  RTestRun runs[];        /**< Per-test results, @c total entries. */
} RTestReport;

/** @brief Short alias for @c R_TEST_TYPE_FAST. */
#define RTEST_FAST      R_TEST_TYPE_FAST
/** @brief Short alias for @c R_TEST_TYPE_SLOW. */
#define RTEST_SLOW      R_TEST_TYPE_SLOW
/** @brief Short alias for @c R_TEST_TYPE_FASTSLOW. */
#define RTEST_FASTSLOW  R_TEST_TYPE_FASTSLOW
/** @brief Short alias for @c R_TEST_TYPE_INTEGR. */
#define RTEST_INTEGR    R_TEST_TYPE_INTEGR
/** @brief Short alias for @c R_TEST_TYPE_SYSTEM. */
#define RTEST_SYSTEM    R_TEST_TYPE_SYSTEM

/**
 * @name Test definition macros
 *
 * Each macro declares a self-registering @c RTest descriptor and
 * opens a function body; close it with @c RTEST_END. The @c _F
 * variants take a fixture - declare its struct via
 * @c RTEST_FIXTURE_STRUCT and lifecycle via @c RTEST_FIXTURE_SETUP
 * and @c RTEST_FIXTURE_TEARDOWN. The @c LOOP variants run the body
 * for @c __i in @c [s,e); the iteration is visible inside the body
 * as @c __i.
 * @{
 */
/** @brief Define a unit test. */
#define RTEST(suite, name, type)                  RTEST_DEFINE_TEST (suite, name, 0, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief Define a unit test that takes a fixture. */
#define RTEST_F(suite, name, type)                RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 0, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief Define a unit test that runs @c [s,e) iterations. */
#define RTEST_LOOP(suite, name, type, s,e)        RTEST_DEFINE_TEST (suite, name, 0, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @brief Define a fixture-using unit test that runs @c [s,e) iterations. */
#define RTEST_LOOP_F(suite, name, type, s,e)      RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 0, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @brief Define a stress test (capped by @c RTEST_STRESS_TIMEOUT). */
#define RTEST_STRESS(suite, name, type)           RTEST_DEFINE_TEST (suite, name, 0, (type) | R_TEST_FLAG_STRESS, RTEST_STRESS_TIMEOUT, 0, 1)
/** @brief Define a fixture-using stress test. */
#define RTEST_STRESS_F(suite, name,type)          RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 0, (type) | R_TEST_FLAG_STRESS, RTEST_STRESS_TIMEOUT, 0, 1)
/** @brief Define a benchmark (no timeout). */
#define RTEST_BENCH(suite, name, type)            RTEST_DEFINE_TEST (suite, name, 0, (type) | R_TEST_FLAG_BENCH, R_CLOCK_TIME_NONE, 0, 1)
/** @brief Define a fixture-using benchmark. */
#define RTEST_BENCH_F(suite, name, type)          RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 0, (type) | R_TEST_FLAG_BENCH, R_CLOCK_TIME_NONE, 0, 1)
/** @} */

/**
 * @name Gated test definition macros
 *
 * Same shape as the @c RTEST* macros but the test is excluded from
 * the default run; opt back in with the matching
 * @c --include-skip / @c --heavy / @c --broken CLI flag.
 *
 * Pick the macro that says why the test isn't in the default suite:
 *  - @c SKIP_RTEST_*  - temporarily disabled, expected to come back soon
 *                       (work-in-progress, debugging, etc.).
 *  - @c HEAVY_RTEST_* - works correctly but too expensive for the
 *                       default budget (Wycheproof corpora, slow
 *                       prime generation, anything gated to the
 *                       nightly / on-demand sweep).
 *  - @c BROKEN_RTEST_* - known-failing or known-flaky and not under
 *                       active repair. Carrying it in the source
 *                       keeps the regression visible without
 *                       polluting the default pass / fail tally.
 * @{
 */
/** @brief @c RTEST gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST(suite, name, type)             RTEST_DEFINE_TEST (suite, name, 1, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief @c RTEST_F gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST_F(suite, name, type)           RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 1, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief @c RTEST_LOOP gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST_LOOP(suite, name, type, s,e)   RTEST_DEFINE_TEST (suite, name, 1, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @brief @c RTEST_LOOP_F gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST_LOOP_F(suite, name,type, s,e)  RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 1, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @brief @c RTEST_STRESS gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST_STRESS(suite, name, type)      RTEST_DEFINE_TEST (suite, name, 1, (type) | R_TEST_FLAG_STRESS, RTEST_STRESS_TIMEOUT, 0, 1)
/** @brief @c RTEST_STRESS_F gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST_STRESS_F(suite, name, type)    RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 1, (type) | R_TEST_FLAG_STRESS, RTEST_STRESS_TIMEOUT, 0, 1)
/** @brief @c RTEST_BENCH gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST_BENCH(suite, name, type)       RTEST_DEFINE_TEST (suite, name, 1, (type) | R_TEST_FLAG_BENCH, R_CLOCK_TIME_NONE, 0, 1)
/** @brief @c RTEST_BENCH_F gated as @c R_TEST_SKIP_TEMP. */
#define SKIP_RTEST_BENCH_F(suite, name, type)     RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, 1, (type) | R_TEST_FLAG_BENCH, R_CLOCK_TIME_NONE, 0, 1)
/** @brief @c RTEST gated as @c R_TEST_SKIP_HEAVY. */
#define HEAVY_RTEST(suite, name, type)             RTEST_DEFINE_TEST (suite, name, R_TEST_SKIP_HEAVY, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief @c RTEST_F gated as @c R_TEST_SKIP_HEAVY. */
#define HEAVY_RTEST_F(suite, name, type)           RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, R_TEST_SKIP_HEAVY, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief @c RTEST_LOOP gated as @c R_TEST_SKIP_HEAVY. */
#define HEAVY_RTEST_LOOP(suite, name, type, s,e)   RTEST_DEFINE_TEST (suite, name, R_TEST_SKIP_HEAVY, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @brief @c RTEST_LOOP_F gated as @c R_TEST_SKIP_HEAVY. */
#define HEAVY_RTEST_LOOP_F(suite, name,type, s,e)  RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, R_TEST_SKIP_HEAVY, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @brief @c RTEST gated as @c R_TEST_SKIP_BROKEN. */
#define BROKEN_RTEST(suite, name, type)            RTEST_DEFINE_TEST (suite, name, R_TEST_SKIP_BROKEN, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief @c RTEST_F gated as @c R_TEST_SKIP_BROKEN. */
#define BROKEN_RTEST_F(suite, name, type)          RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, R_TEST_SKIP_BROKEN, type, RTEST_TYPE_TIMEOUT(type), 0, 1)
/** @brief @c RTEST_LOOP gated as @c R_TEST_SKIP_BROKEN. */
#define BROKEN_RTEST_LOOP(suite, name, type, s,e)  RTEST_DEFINE_TEST (suite, name, R_TEST_SKIP_BROKEN, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @brief @c RTEST_LOOP_F gated as @c R_TEST_SKIP_BROKEN. */
#define BROKEN_RTEST_LOOP_F(suite, name,type,s,e)  RTEST_DEFINE_TEST_WITH_FIXTURE (suite, name, R_TEST_SKIP_BROKEN, (type) | R_TEST_FLAG_LOOP, RTEST_TYPE_TIMEOUT(type), s, e)
/** @} */

/**
 * @brief Close a test body opened by any @c RTEST* macro.
 *
 * Required; the macro emits the closing brace plus a final source
 * position marker so the reporter can point at "end of body".
 */
#define RTEST_END _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE); }

/**
 * @name Fixtures
 *
 * Declare a per-test fixture so the body can carry state without
 * relying on global variables. @c RTEST_FIXTURE_STRUCT declares the
 * struct (use the suite name); @c RTEST_FIXTURE_SETUP and
 * @c RTEST_FIXTURE_TEARDOWN open function bodies that the runner
 * calls before / after each test using @c RTEST_F / @c RTEST_LOOP_F.
 * @{
 */
/** @brief Open a @c struct definition for a suite's fixture. */
#define RTEST_FIXTURE_STRUCT(suite)               _RTEST_FIXTURE_STRUCT (suite)
/** @brief Open the fixture setup function body for a suite. */
#define RTEST_FIXTURE_SETUP(suite)                                            \
  static void _RTEST_FIXTURE_SETUP_NAME (suite) (_RTEST_FIXTURE_ARG (suite))
/** @brief Open the fixture teardown function body for a suite. */
#define RTEST_FIXTURE_TEARDOWN(suite)                                         \
  static void _RTEST_FIXTURE_TEARDOWN_NAME (suite) (_RTEST_FIXTURE_ARG (suite))
/** @} */


/**
 * @brief Define a @c main() that parses the standard rlibtest CLI
 * options, runs all registered tests, prints the summary, and
 * returns the failure + error count as the process exit code.
 *
 * Use at the bottom of your test runner source file; @p version_str
 * is reported by @c --version.
 */
#define RTEST_MAIN(version_str)                                                 \
int main (int argc, rchar ** argv) {                                            \
  RArgParser * parser = r_arg_parser_new (NULL, version_str);                   \
  RArgParseCtx * ctx;                                                           \
  RTestReport * report;                                                         \
  int ret = -1;                                                                 \
                                                                                \
  const RArgOptionEntry entries[] = {                                           \
    { "verbose",     'v', R_ARG_OPTION_TYPE_BOOL,     R_ARG_OPTION_FLAG_NONE,   \
      "Print verbose info", NULL, NULL },                                       \
    { "print",       'p', R_ARG_OPTION_TYPE_BOOL,     R_ARG_OPTION_FLAG_NONE,   \
      "Print all tests which ran", NULL, NULL },                                \
    { "include-skip", 'i', R_ARG_OPTION_TYPE_BOOL,    R_ARG_OPTION_FLAG_NONE,   \
      "Also run SKIP_RTEST_* tests (temporarily disabled)", NULL, NULL },       \
    { "heavy",       'H', R_ARG_OPTION_TYPE_BOOL,     R_ARG_OPTION_FLAG_NONE,   \
      "Also run HEAVY_RTEST_* tests (slow but not broken)", NULL, NULL },       \
    { "broken",      'B', R_ARG_OPTION_TYPE_BOOL,     R_ARG_OPTION_FLAG_NONE,   \
      "Also run BROKEN_RTEST_* tests (likely to fail)", NULL, NULL },           \
    { "filter",      'f', R_ARG_OPTION_TYPE_STRING,   R_ARG_OPTION_FLAG_NONE,   \
      "Filter on test path - default is * (\"/<suite>/<name>\")", NULL, NULL }, \
    { "output",      'o', R_ARG_OPTION_TYPE_FILENAME, R_ARG_OPTION_FLAG_NONE,   \
      "File to print results to, use - for stdout [default]", NULL, NULL },     \
  };                                                                            \
  r_arg_parser_add_option_entries (parser, entries, R_N_ELEMENTS (entries));    \
                                                                                \
  if ((ctx = r_arg_parser_parse (parser, R_ARG_PARSE_FLAG_NONE,                 \
      &argc, (const rchar ***)&argv, NULL)) != NULL) {                          \
    const RTest * tests;                                                        \
    rsize count;                                                                \
    FILE * f = stdout;                                                          \
    RTestReportFlag report_flags = R_TEST_REPORT_FLAG_NONE;                     \
    RTestRunFlag run_flags = R_TEST_RUN_FLAG_NONE;                              \
    rchar * output, * filter = NULL;                                            \
                                                                                \
    if (r_arg_parse_ctx_get_option_bool (ctx, "verbose"))                       \
      report_flags |= R_TEST_REPORT_FLAG_VERBOSE;                               \
    if (r_arg_parse_ctx_get_option_bool (ctx, "print"))                         \
      run_flags |= R_TEST_RUN_FLAG_PRINT;                                       \
    if (r_arg_parse_ctx_get_option_bool (ctx, "include-skip"))                  \
      run_flags |= R_TEST_RUN_FLAG_INCLUDE_SKIP;                                \
    if (r_arg_parse_ctx_get_option_bool (ctx, "heavy"))                         \
      run_flags |= R_TEST_RUN_FLAG_INCLUDE_HEAVY;                               \
    if (r_arg_parse_ctx_get_option_bool (ctx, "broken"))                        \
      run_flags |= R_TEST_RUN_FLAG_INCLUDE_BROKEN;                              \
                                                                                \
    if ((output = r_arg_parse_ctx_get_option_string (ctx, "output")) != NULL && \
        !r_str_equals (output, "-")) {                                          \
      f = r_fopen (output, "w");                                                \
      r_free (output);                                                          \
    }                                                                           \
                                                                                \
    filter = r_arg_parse_ctx_get_option_string (ctx, "filter");                 \
    if ((tests = r_test_get_module_tests (NULL, &count)) != NULL &&             \
        (report = r_test_run_tests (tests, count, run_flags, f,                 \
            R_TEST_ALL_MASK, filter)) != NULL) {                                \
      r_test_report_print (report, report_flags, f);                            \
      ret = (int) (report->fail + report->error);                              \
      r_test_report_free (report);                                              \
    }                                                                           \
    if (f != stdout)                                                            \
      fclose (f);                                                               \
                                                                                \
    r_free (filter);                                                            \
    r_arg_parse_ctx_unref (ctx);                                                \
  } else {                                                                      \
    ret = r_arg_parser_print_help (parser, R_ARG_PARSE_FLAG_DONT_EXIT, NULL, 1);\
  }                                                                             \
                                                                                \
  r_arg_parser_unref (parser);                                                  \
  return ret;                                                                   \
}

/**
 * @brief Build the @c /\<suite\>/\<name\> path of a test as a fresh string.
 *
 * @return Newly-allocated string; free with @c r_free.
 */
R_API rchar * r_test_dup_path (const RTest * test) R_ATTR_MALLOC;
/**
 * @brief Write the @c /\<suite\>/\<name\> path of a test into a caller
 * buffer.
 *
 * @param test  Test descriptor.
 * @param path  Destination buffer.
 * @param size  Capacity of @p path in bytes (including NUL).
 * @return @c TRUE if the path fit in @p size, @c FALSE if truncated.
 */
R_API rboolean r_test_fill_path (const RTest * test, rchar * path, rsize size);

/**
 * @brief Enumerate tests registered by a module's linker section.
 *
 * @param mod    Module handle, or @c NULL for the running binary.
 * @param count  Out: number of tests in the returned array.
 * @return Pointer to the array, owned by the loader (no free).
 */
R_API const RTest * r_test_get_module_tests (RMODULE mod, rsize * count);

/**
 * @brief Run a single test in a forked child (Unix) / isolated
 * thread (Windows), with the body's outcome reported via the pipe.
 *
 * Driver-level entry; user code typically calls @c r_test_run_tests.
 */
R_API RTestRunState r_test_run_fork (const RTest * test, rsize __i,
    rboolean notimeout, RTestLastPos * lastpos, RTestLastPos * failpos,
    int * pid, int * exitcode);
/**
 * @brief Run a single test in the current process. Used when
 * @c RNOFORK is set in the environment or a debugger is attached;
 * a crashing test takes the suite down.
 */
R_API RTestRunState r_test_run_nofork (const RTest * test, rsize __i,
    rboolean notimeout, RTestLastPos * lastpos, RTestLastPos * failpos,
    int * pid, int * exitcode);
/**
 * @brief Run a suite of tests filtered by an arbitrary callback.
 *
 * @param tests    Array of tests (typically from @c r_test_get_module_tests).
 * @param count    Number of entries in @p tests.
 * @param flags    Run-time opt-in flags (@c R_TEST_RUN_FLAG_*).
 * @param f        Output FILE for live status lines.
 * @param filter   Per-test predicate; @c NULL runs every test.
 * @param data     Opaque cookie forwarded to @p filter.
 * @return Heap-allocated report; free with @c r_test_report_free.
 */
R_API RTestReport * r_test_run_tests_full (const RTest * tests, rsize count,
    RTestRunFlag flags, FILE * f, RTestFilterFunc filter, rpointer data);
/**
 * @brief Convenience wrapper around @c r_test_run_tests_full that
 * filters by a type bitmask and a @c r_str_match_simple_pattern-
 * compatible path glob.
 *
 * @param tests   Array of tests (typically from @c r_test_get_module_tests).
 * @param count   Number of entries in @p tests.
 * @param flags   Run-time opt-in flags (@c R_TEST_RUN_FLAG_*).
 * @param f       Output FILE for live status lines.
 * @param type    Bitmask of @c R_TEST_TYPE_* base types to include;
 *                use @c R_TEST_ALL_MASK to accept everything.
 * @param filter  Wildcard pattern matched against @c /\<suite\>/\<name\>;
 *                @c NULL accepts every path.
 */
R_API RTestReport * r_test_run_tests (const RTest * tests, rsize count,
    RTestRunFlag flags, FILE * f, RTestType type, const rchar * filter);
/** @brief Release a report returned by @c r_test_run_tests / _full. */
#define r_test_report_free(report)  r_free (report)

/**
 * @brief Print the per-run details and aggregate summary to @p f.
 *
 * @param report  Report returned by @c r_test_run_tests / _full.
 * @param flags   @c R_TEST_REPORT_FLAG_VERBOSE prints every run;
 *                otherwise only failures appear in the per-run block.
 * @param f       Destination FILE.
 */
R_API void r_test_report_print (RTestReport * report, RTestReportFlag flags, FILE * f);

R_END_DECLS

/** @} */ /* r_test group */

#endif /* __R_TEST_H__ */

