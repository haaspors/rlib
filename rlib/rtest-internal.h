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
#ifndef __R_TEST_INTERNAL_H__
#define __R_TEST_INTERNAL_H__

#ifndef __R_TEST_H__
#error "#include <rlib.h> pelase."
#endif


#define _RTEST_MAGIC                          0x42424242
#define _RTEST_SYM_                           _r_test_sym
#define _RTEST_DATA_NAME(suite, test)         __rtest_##suite##_##test##_data
#define _RTEST_FUNC_NAME(suite, test)         __rtest_##suite##_##test##_func
#define _RTEST_FIXTURE_DATA_NAME(suite)       __rtest_##suite##_data
#define _RTEST_FIXTURE_SETUP_NAME(suite)      __rtest_##suite##_setup
#define _RTEST_FIXTURE_TEARDOWN_NAME(suite)   __rtest_##suite##_teardown
#define _RTEST_FIXTURE_STRUCT(suite)          struct suite##_data
#define _RTEST_FIXTURE_ARG(suite)  R_ATTR_UNUSED _RTEST_FIXTURE_STRUCT(suite) * fixture

#define __RTEST(suite, test, skip, type, timeout, start, end, setup, teardown, fdata)\
  R_ATTR_UNUSED R_ATTR_DATA_SECTION (".rtest")                                \
  const RTest _RTEST_DATA_NAME (suite, test) = { _RTEST_MAGIC, skip,          \
    #suite, #test, type, timeout, _RTEST_FUNC_NAME(suite, test), start, end,  \
    fdata, (RTestFixtureFunc)setup, (RTestFixtureFunc)teardown };  \
  R_API_EXPORT R_ATTR_WEAK \
  const RTest * R_PASTE (_RTEST_SYM_, __COUNTER__) = &_RTEST_DATA_NAME (suite, test)

#define RTEST_DEFINE_TEST(suite, test, skip, type, timeout, start, end)       \
  static void _RTEST_FUNC_NAME (suite, test) (R_ATTR_UNUSED rsize __i);       \
  __RTEST (suite, test, skip, type, timeout, start, end, NULL, NULL, NULL);   \
  static void _RTEST_FUNC_NAME (suite, test) (R_ATTR_UNUSED rsize __i) {      \
    _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);

#define RTEST_DEFINE_TEST_WITH_FIXTURE(suite, test, skip, type, timeout, start, end)\
  /* Fwd declarations */                                                      \
  static _RTEST_FIXTURE_STRUCT (suite) _RTEST_FIXTURE_DATA_NAME (suite);      \
  static void _RTEST_FUNC_NAME (suite, test) (R_ATTR_UNUSED rsize __i, _RTEST_FIXTURE_ARG (suite));\
  /* Internal test structure as a symbol into .rtest section */               \
  __RTEST (suite, test, skip, type, timeout, start, end,                      \
      _RTEST_FIXTURE_SETUP_NAME (suite), _RTEST_FIXTURE_TEARDOWN_NAME (suite),\
      &_RTEST_FIXTURE_DATA_NAME (suite));                                     \
  /* Now for the real test function */                                        \
  static void _RTEST_FUNC_NAME (suite, test) (R_ATTR_UNUSED rsize __i, _RTEST_FIXTURE_ARG (suite)) {\
    _r_test_mark_position (__FILE__, __LINE__, R_STRFUNC, FALSE);


#endif /* __R_TEST_INTERNAL_H__ */

