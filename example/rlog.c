#include <rlib/rlib.h>

R_LOG_CATEGORY_DEFINE_STATIC (test_log, "testlog", "Simple test logger",
    R_CLR_FMT_BOLD | R_CLR_BG_BLUE | R_CLR_FMT_UNDERLINE);
#define R_LOG_CAT_DEFAULT &test_log

int
main (int argc, char ** argv)
{
  r_log_category_register (&test_log);
  R_LOG_ERROR ("Info from binary %s with %d arguments", argv[0], argc - 1);
  R_LOG_CRITICAL ("Info from binary %s with %d arguments", argv[0], argc - 1);
  R_LOG_WARNING ("Info from binary %s with %d arguments", argv[0], argc - 1);
  R_LOG_FIXME ("Info from binary %s with %d arguments", argv[0], argc - 1);
  R_LOG_INFO ("Info from binary %s with %d arguments", argv[0], argc - 1);
  R_LOG_DEBUG ("Info from binary %s with %d arguments", argv[0], argc - 1);
  R_LOG_TRACE ("Info from binary %s with %d arguments", argv[0], argc - 1);
  {
    ruint64 uptime = r_time_get_uptime ();
    ruint days = uptime / (60 * 60 * 24);
    ruint hours = (uptime / (60 * 60)) % 24;
    ruint mins = (uptime / 60) % 60;
    ruint seconds = uptime % 60;
    R_LOG_TRACE ("boot time: %"RUINT64_FMT" - %u days, %u hours, %u mins, %us",
        uptime, days, hours, mins, seconds);
  }

  {
    rchar * tmp = "TEST \x15 10101";
    ruint8  mem[160+7];
    rsize i;
    for (i = 0; i < sizeof (mem); i++)
      mem[i] = (ruint8)(rand () % 0xFF);

    R_LOG_MEM_DUMP (R_LOG_LEVEL_DEBUG, (rpointer)tmp, 12);
    R_LOG_MEM_DUMP (R_LOG_LEVEL_INFO, mem, sizeof (mem));
  }

  return 0;
}

