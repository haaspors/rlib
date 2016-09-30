#include <rlib/rlib.h>

RTEST (rtime, is_leap_year, RTEST_FAST)
{
  r_assert (!r_time_is_leap_year (0));
  r_assert (!r_time_is_leap_year (1800));
  r_assert (r_time_is_leap_year (1804));
  r_assert (r_time_is_leap_year (2000));
  r_assert (!r_time_is_leap_year (1900));
  r_assert (r_time_is_leap_year (2016));
  r_assert (!r_time_is_leap_year (2100));
}
RTEST_END;

RTEST (rtime, leap_years, RTEST_FAST)
{
  static struct {
    ruint16 from, to, expected;
  } cases[] = {
    { 1996, 1996, 0 },
    { 1996, 1997, 1 },
    { 1997, 1997, 0 },
    { 1997, 1998, 0 },
    { 1997, 1998, 0 },
    { 1997, 1999, 0 },
    { 1997, 2000, 0 },
    { 1997, 2001, 1 },
    { 2000, 2001, 1 },
    { 1996, 2001, 2 },
    { 1996, 2013, 5 },
    { 1996, 2027, 8 },
    { 1898, 1899, 0 },
    { 1898, 1900, 0 },
    { 1898, 1901, 0 },
    { 1898, 1903, 0 },
    { 1898, 1905, 1 },
    { 1970, 2016, 11 },
  };
  rsize i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    r_assert_cmpuint (cases[i].expected, ==,
        r_time_leap_years (cases[i].from, cases[i].to));
  }
}
RTEST_END;

RTEST (rtime, create_unix_time, RTEST_FAST)
{
  static struct {
    ruint16 y;
    ruint8 m, d;
    ruint8 h, min, s;
    ruint64 expected;
  } cases[] = {
    { 1970,  1,  1,  0,  0,  0,          0 },
    { 2016,  9, 26, 21, 27,  1, 1474925221 },
    { 2004,  4, 30, 14, 25, 34, 1083335134 },
    { 2005,  4, 30, 14, 25, 34, 1114871134 },
    { 2019,  7, 30, 15,  5, 20, 1564499120 },
    { 2023,  3, 15, 12,  9, 12, 1678882152 },
    { 2024,  7, 16,  1, 16, 20, 1721092580 },
    { 2012,  2, 12,  5, 29, 35, 1329024575 },
    { 2018,  8,  5,  9, 48, 50, 1533462530 },
    { 1994,  9, 17, 20, 56,  0,  779835360 },
    { 2007, 10, 24,  7, 36, 23, 1193211383 },
    { 2008,  6, 17, 16, 29, 50, 1213720190 },
    { 1995,  6,  6, 23, 32, 26,  802481546 },
    { 2025,  8, 25, 12, 27, 50, 1756124870 },
    { 2021,  8,  6, 11, 50, 37, 1628250637 },
    { 2024,  3,  3, 22, 13, 50, 1709504030 },
    { 2013,  6, 30, 20, 25, 41, 1372623941 },
    { 2012, 11, 15, 15, 31, 15, 1352993475 },
    { 2009,  7,  8, 23,  5,  6, 1247094306 },
    { 2009,  8, 26,  7, 29, 53, 1251271793 },
    { 1950,  1,  1,  0,  0,  0,          0 },
  };

  rsize i;

  for (i = 0; i < R_N_ELEMENTS (cases); i++) {
    r_assert_cmpuint (cases[i].expected, ==,
        r_time_create_unix_time (cases[i].y, cases[i].m, cases[i].d,
          cases[i].h, cases[i].min, cases[i].s));
  }
}
RTEST_END;

