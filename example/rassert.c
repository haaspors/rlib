#include <rlib/rlib.h>

#define FOOBAR 12

#ifdef R_OS_WIN32
#define R_DIRSEP_STR "\\"
#define R_DIRSEP_CHR '\\'
#define R_EXE_SUFFIX ".exe"
#else
#define R_DIRSEP_STR "/"
#define R_DIRSEP_CHR '/'
#define R_EXE_SUFFIX ""
#endif

int
main (int argc, char ** argv)
{
  static const rchar * test = "fooooo";
  rchar ** strv;
  (void)argv;

  r_assert_cmpint (argc, >=, 1);
  r_assert_cmpstr (test, !=, "bar");
  r_assert_cmpstr (__FILE__, !=, "bar");

  r_assert_cmpint (FOOBAR, ==, 12);

  strv = r_strsplit (__FILE__, R_DIRSEP_STR, 10);
  r_assert_cmpuint (r_strv_len (strv), >, 0);
  r_assert_cmpstr (strv[r_strv_len (strv)-1], ==, "rassert.c");
  r_strv_free (strv);

  strv = r_strsplit (*argv, R_DIRSEP_STR, 10);
  r_assert_cmpuint (r_strv_len (strv), >, 0);
  r_assert_cmpstr (strv[r_strv_len (strv)-1], ==, "rassert"R_EXE_SUFFIX);
  r_strv_free (strv);

  r_assert_cmpfloat (0.999f, ==, 0.999f);
  r_assert_cmpdouble (0.999, ==, 0.999);
  r_assert_cmpuint ((10 * 1 * 1 * 2 / 20) - 1, ==, 0);
  r_assert_not_reached ();
}

