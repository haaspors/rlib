#include <rlib/rlib.h>

R_LOG_CATEGORY_DEFINE_STATIC (rlogtestcat, "logtest", "Logging for testing",
    R_CLR_BG_GREEN);
#define R_LOG_CAT_DEFAULT &rlogtestcat

RTEST_FIXTURE_STRUCT (rlog)
{
  RLogKeepLastCtx ctx;
};

RTEST_FIXTURE_SETUP (rlog)
{
  r_log_keep_last_begin_full (&fixture->ctx, R_LOG_CAT_DEFAULT, FALSE);
}

RTEST_FIXTURE_TEARDOWN (rlog)
{
  r_log_keep_last_end (&fixture->ctx, TRUE, TRUE);
}

RTEST (rlog, register, RTEST_FAST)
{
  R_LOG_CATEGORY_DEFINE (tmp, "foobar", "foobar category", R_CLR_BG_RED);

  r_assert_cmpptr (r_log_category_find ("foobar"), ==, NULL);
  r_assert (!r_log_category_unregister (&tmp));
  r_assert (r_log_category_register (&tmp));
  r_assert_cmpptr (r_log_category_find ("foobar"), !=, NULL);

  r_assert (!r_log_category_register (&tmp));
  r_assert (r_log_category_unregister (&tmp));
}
RTEST_END;

RTEST_F (rlog, logging, RTEST_FAST)
{
  r_log_category_set_threshold (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_TRACE);

  R_LOG_TRACE ("foobar");
  r_assert_cmpuint (fixture->ctx.last.line, ==, __LINE__ - 1);
  r_assert_cmpstr (fixture->ctx.last.file, ==, __FILE__);
  r_assert_cmpstr (fixture->ctx.last.func, ==, R_STRFUNC);
  r_assert_cmpstr (fixture->ctx.last.msg, ==, "foobar");
  r_assert_cmpptr (fixture->ctx.last.cat, ==, R_LOG_CAT_DEFAULT);
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_TRACE);

  R_LOG_DEBUG ("foobar");
  r_assert_cmpptr (fixture->ctx.last.cat, ==, R_LOG_CAT_DEFAULT);
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_DEBUG);
  r_assert_cmpstr (fixture->ctx.last.msg, ==, "foobar");

  R_LOG_INFO ("foobar");
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_INFO);

  R_LOG_FIXME ("foobar");
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_FIXME);

  R_LOG_WARNING ("foobar %s", r_log_level_get_name (R_LOG_LEVEL_WARNING));
  r_assert_cmpptr (fixture->ctx.last.cat, ==, R_LOG_CAT_DEFAULT);
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_WARNING);
  r_assert_cmpstr (fixture->ctx.last.msg, ==, "foobar WARNING");

  R_LOG_CRITICAL ("foobar");
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_CRITICAL);

  R_LOG_ERROR ("foobar");
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_ERROR);
}
RTEST_END;

RTEST_F (rlog, threshold, RTEST_FAST)
{
  r_log_category_set_threshold (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_NONE);
  R_LOG_TRACE ("this should not be sent to log handler due to threshold");
  r_assert_cmpptr (fixture->ctx.last.cat, ==, NULL);
  r_assert_cmpptr (fixture->ctx.last.file, ==, NULL);
  r_assert_cmpptr (fixture->ctx.last.func, ==, NULL);
  r_assert_cmpptr (fixture->ctx.last.msg, ==, NULL);

  r_log_category_set_threshold (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_TRACE);
  R_LOG_TRACE ("this is trace");
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_TRACE);

  r_log_keep_last_reset (&fixture->ctx);
  r_log_category_set_threshold (R_LOG_CAT_DEFAULT, R_LOG_LEVEL_NONE);

  R_LOG_ERROR ("this is error");
  r_assert_cmpptr (fixture->ctx.last.cat, ==, NULL);
  r_assert_cmpptr (fixture->ctx.last.file, ==, NULL);
  r_assert_cmpptr (fixture->ctx.last.func, ==, NULL);
  r_assert_cmpuint (fixture->ctx.last.line, ==, 0);
  r_assert_cmpuint (fixture->ctx.last.lvl, ==, R_LOG_LEVEL_NONE);
}
RTEST_END;

