#include <rlib/rlib.h>


static const rchar * r_crc_test_vec = "123456789";
static const rsize   r_crc_test_vec_size = 9;

RTEST (rcrc, crc32, RTEST_FAST)
{
  r_assert_cmphex (r_crc32 (r_crc_test_vec, 0), ==, 0);
  r_assert_cmphex (r_crc32 (r_crc_test_vec, r_crc_test_vec_size), ==, 0xcbf43926);
}
RTEST_END;

RTEST (rcrc, crc32c, RTEST_FAST)
{
  r_assert_cmphex (r_crc32c (r_crc_test_vec, 0), ==, 0);
  r_assert_cmphex (r_crc32c (r_crc_test_vec, r_crc_test_vec_size), ==, 0xe3069283);
}
RTEST_END;

RTEST (rcrc, crc32bzip, RTEST_FAST)
{
  ruint8 zeros[32] = { 0 };
  ruint8 ramp[256];
  ruint i;
  for (i = 0; i < sizeof (ramp); i++) ramp[i] = (ruint8)i;

  r_assert_cmphex (r_crc32bzip2 (r_crc_test_vec, 0), ==, 0);
  r_assert_cmphex (r_crc32bzip2 (r_crc_test_vec, r_crc_test_vec_size), ==, 0xfc891918);
  r_assert_cmphex (r_crc32bzip2 (zeros, sizeof (zeros)), ==, 0xb5aa5098);
  r_assert_cmphex (r_crc32bzip2 (ramp, sizeof (ramp)), ==, 0xb6b5ee95);
}
RTEST_END;

