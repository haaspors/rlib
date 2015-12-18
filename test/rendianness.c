#include <rlib/rlib.h>

RTEST (rendianness, bswap, RTEST_FAST)
{
  ruint16 v16 = 0x00FF;
  ruint32 v32 = 0x44332211;
  ruint64 v64 = RUINT64_CONSTANT (0x1122334455667788);

  /* 16bit */
  r_assert_cmpuint (RUINT16_BSWAP (v16),                 ==, 0xFF00);
  r_assert_cmpuint (RUINT16_BSWAP (RUINT16_BSWAP (v16)), ==, 0x00FF);
  r_assert_cmpuint (RUINT16_BSWAP (v32),                 ==, 0x1122);

  /* 32bit */
  r_assert_cmpuint (RUINT32_BSWAP (v32),                 ==, 0x11223344);
  r_assert_cmpuint (RUINT32_BSWAP (RUINT32_BSWAP (v32)), ==, 0x44332211);
  r_assert_cmpuint (RUINT32_BSWAP (v16),                 ==, 0xFF000000);
  r_assert_cmpuint (RUINT32_BSWAP (v64),                 ==, 0x88776655);

  /* 64bit */
  r_assert_cmpuint (RUINT64_BSWAP (v64),                 ==, RUINT64_CONSTANT (0x8877665544332211));
  r_assert_cmpuint (RUINT64_BSWAP (RUINT64_BSWAP (v64)), ==, RUINT64_CONSTANT (0x1122334455667788));
  r_assert_cmpuint (RUINT64_BSWAP (v16),                 ==, RUINT64_CONSTANT (0xFF00000000000000));
  r_assert_cmpuint (RUINT64_BSWAP (v32),                 ==, RUINT64_CONSTANT (0x1122334400000000));
}
RTEST_END;

RTEST (rendianness, macros, RTEST_FAST)
{
  ruint16 v16 = 0x1122;
  ruint32 v32 = 0x44332211;
  ruint64 v64 = RUINT64_CONSTANT (0x1122334455667788);

#if R_BYTE_ORDER == R_LITTLE_ENDIAN
  r_assert_cmpuint (RUINT16_TO_LE (v16), ==, 0x1122);
  r_assert_cmpuint (RUINT16_TO_BE (v16), ==, 0x2211);
  r_assert_cmpuint (RUINT32_TO_LE (v32), ==, 0x44332211);
  r_assert_cmpuint (RUINT32_TO_BE (v32), ==, 0x11223344);
  r_assert_cmpuint (RUINT64_TO_LE (v64), ==, RUINT64_CONSTANT (0x1122334455667788));
  r_assert_cmpuint (RUINT64_TO_BE (v64), ==, RUINT64_CONSTANT (0x8877665544332211));
#elif R_BYTE_ORDER == R_BIG_ENDIAN
  r_assert_cmpuint (RUINT16_TO_BE (v16), ==, 0x1122);
  r_assert_cmpuint (RUINT16_TO_LE (v16), ==, 0x2211);
  r_assert_cmpuint (RUINT32_TO_BE (v32), ==, 0x44332211);
  r_assert_cmpuint (RUINT32_TO_LE (v32), ==, 0x11223344);
  r_assert_cmpuint (RUINT64_TO_BE (v64), ==, RUINT64_CONSTANT (0x1122334455667788));
  r_assert_cmpuint (RUINT64_TO_LE (v64), ==, RUINT64_CONSTANT (0x8877665544332211));
#endif
}
RTEST_END;

