#include <rlib/rlib.h>

RTEST (rbitops, popcount, RTEST_FAST)
{
  r_assert_cmpuint (RUINT8_POPCOUNT  (0), ==, 0);
  r_assert_cmpuint (RUINT16_POPCOUNT (0), ==, 0);
  r_assert_cmpuint (RUINT32_POPCOUNT (0), ==, 0);
  r_assert_cmpuint (RUINT64_POPCOUNT (0), ==, 0);
  r_assert_cmpuint (RUINT8_POPCOUNT  (RUINT8_MAX), ==,  8);
  r_assert_cmpuint (RUINT16_POPCOUNT (RUINT16_MAX), ==, 16);
  r_assert_cmpuint (RUINT32_POPCOUNT (RUINT32_MAX), ==, 32);
  r_assert_cmpuint (RUINT64_POPCOUNT (RUINT64_MAX), ==, 64);

  r_assert_cmpuint (RUINT8_POPCOUNT  (0x40), ==, 1);
  r_assert_cmpuint (RUINT16_POPCOUNT (0x4040), ==, 2);
  r_assert_cmpuint (RUINT32_POPCOUNT (0x40404040), ==, 4);
  r_assert_cmpuint (RUINT64_POPCOUNT (RUINT64_CONSTANT (0x4040404040404040)), ==, 8);
}
RTEST_END;

RTEST (rbitops, parity, RTEST_FAST)
{
  r_assert_cmpuint (RUINT8_PARITY  (0), ==, 0);
  r_assert_cmpuint (RUINT16_PARITY (0), ==, 0);
  r_assert_cmpuint (RUINT32_PARITY (0), ==, 0);
  r_assert_cmpuint (RUINT64_PARITY (0), ==, 0);
  r_assert_cmpuint (RUINT8_PARITY  (RUINT8_MAX), ==,  0);
  r_assert_cmpuint (RUINT16_PARITY (RUINT16_MAX), ==, 0);
  r_assert_cmpuint (RUINT32_PARITY (RUINT32_MAX), ==, 0);
  r_assert_cmpuint (RUINT64_PARITY (RUINT64_MAX), ==, 0);

  r_assert_cmpuint (RUINT8_PARITY  (0x40), ==, 1);
  r_assert_cmpuint (RUINT8_PARITY  (0x44), ==, 0);
  r_assert_cmpuint (RUINT16_PARITY (0x4000), ==, 1);
  r_assert_cmpuint (RUINT16_PARITY (0x4040), ==, 0);
  r_assert_cmpuint (RUINT32_PARITY (0x40400040), ==, 1);
  r_assert_cmpuint (RUINT32_PARITY (0x40404040), ==, 0);
  r_assert_cmpuint (RUINT64_PARITY (RUINT64_CONSTANT (0x4040404040004040)), ==, 1);
  r_assert_cmpuint (RUINT64_PARITY (RUINT64_CONSTANT (0x4040404040404040)), ==, 0);
}
RTEST_END;

RTEST (rbitops, clz, RTEST_FAST)
{
  r_assert_cmpuint (RUINT8_CLZ  (0), ==, 8);
  r_assert_cmpuint (RUINT16_CLZ (0), ==, 16);
  r_assert_cmpuint (RUINT32_CLZ (0), ==, 32);
  r_assert_cmpuint (RUINT64_CLZ (0), ==, 64);
  r_assert_cmpuint (RUINT8_CLZ  (RUINT8_MAX), ==,  0);
  r_assert_cmpuint (RUINT16_CLZ (RUINT16_MAX), ==, 0);
  r_assert_cmpuint (RUINT32_CLZ (RUINT32_MAX), ==, 0);
  r_assert_cmpuint (RUINT64_CLZ (RUINT64_MAX), ==, 0);

  r_assert_cmpuint (RUINT8_CLZ  (0x10), ==, 3);
  r_assert_cmpuint (RUINT16_CLZ (0x0100), ==, 7);
  r_assert_cmpuint (RUINT32_CLZ (0x00001000), ==, 19);
  r_assert_cmpuint (RUINT64_CLZ (RUINT64_CONSTANT (0x0000000010000000)), ==, 35);
}
RTEST_END;

RTEST (rbitops, ctz, RTEST_FAST)
{
  r_assert_cmpuint (RUINT8_CTZ  (0), ==, 8);
  r_assert_cmpuint (RUINT16_CTZ (0), ==, 16);
  r_assert_cmpuint (RUINT32_CTZ (0), ==, 32);
  r_assert_cmpuint (RUINT64_CTZ (0), ==, 64);
  r_assert_cmpuint (RUINT8_CTZ  (RUINT8_MAX), ==,  0);
  r_assert_cmpuint (RUINT16_CTZ (RUINT16_MAX), ==, 0);
  r_assert_cmpuint (RUINT32_CTZ (RUINT32_MAX), ==, 0);
  r_assert_cmpuint (RUINT64_CTZ (RUINT64_MAX), ==, 0);

  r_assert_cmpuint (RUINT8_CTZ  (0x10), ==, 4);
  r_assert_cmpuint (RUINT16_CTZ (0x0100), ==, 8);
  r_assert_cmpuint (RUINT32_CTZ (0x00001000), ==, 12);
  r_assert_cmpuint (RUINT64_CTZ (RUINT64_CONSTANT (0x0000000010000000)), ==, 28);
}
RTEST_END;

