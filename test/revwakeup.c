#include <rlib/rev.h>

RTEST (revwakeup, new, RTEST_FAST)
{
  REvLoop * loop;
  REvWakeup * wakeup;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((wakeup = r_ev_wakeup_new (loop)), !=, NULL);

  /* Exercise the ref/unref aliases (r_ref_ref returns the same pointer). */
  r_assert_cmpptr (r_ev_wakeup_ref (wakeup), ==, wakeup);
  r_ev_wakeup_unref (wakeup);

  r_ev_wakeup_unref (wakeup);
  r_ev_loop_unref (loop);
}
RTEST_END;

RTEST (revwakeup, signal, RTEST_FAST)
{
  REvLoop * loop;
  REvWakeup * wakeup;

  r_assert_cmpptr ((loop = r_ev_loop_new ()), !=, NULL);
  r_assert_cmpptr ((wakeup = r_ev_wakeup_new (loop)), !=, NULL);

  r_assert (r_ev_wakeup_signal (wakeup));

  r_ev_wakeup_unref (wakeup);
  r_ev_loop_unref (loop);
}
RTEST_END;
