#include <rlib/rlib.h>

typedef struct {
  rchar buf[256];
  rsize len;
  ruint calls;
} RTtyCapture;

static rboolean
tty_capture (const rchar * str, rsize size, rpointer data)
{
  RTtyCapture * c = data;
  c->calls++;
  if (c->len + size < sizeof (c->buf)) {
    r_memcpy (c->buf + c->len, str, size);
    c->len += size;
    c->buf[c->len] = 0;
  }
  return TRUE;
}

RTEST (rtty, print_override, RTEST_FAST)
{
  RTtyCapture cap = { { 0, }, 0, 0 };
  RPrintFunc oldf = NULL;
  rpointer olddata = NULL;

  r_override_print_handler (tty_capture, &cap, &oldf, &olddata);
  r_assert_cmpint (r_print ("hello %d!", 42), ==, 9);
  r_override_print_handler (oldf, olddata, NULL, NULL);

  r_assert_cmpuint (cap.calls, ==, 1);
  r_assert_cmpuint (cap.len, ==, 9);
  r_assert_cmpstr (cap.buf, ==, "hello 42!");
}
RTEST_END;

RTEST (rtty, printerr_override, RTEST_FAST)
{
  RTtyCapture cap = { { 0, }, 0, 0 };
  RPrintFunc oldf = NULL;
  rpointer olddata = NULL;

  r_override_printerr_handler (tty_capture, &cap, &oldf, &olddata);
  r_assert_cmpint (r_printerr ("err %s", "!"), ==, 5);
  r_override_printerr_handler (oldf, olddata, NULL, NULL);

  r_assert_cmpuint (cap.calls, ==, 1);
  r_assert_cmpstr (cap.buf, ==, "err !");
}
RTEST_END;

/* The two handlers verify that the data they receive is the data that
 * was installed alongside them. If the seqlock ever handed a reader a
 * torn pair (one handler with the other's data) they abort, and
 * ThreadSanitizer additionally flags any unsynchronised access. */
static rboolean
tty_expect_a (const rchar * str, rsize size, rpointer data)
{
  (void) str; (void) size;
  if (R_UNLIKELY (data != RUINT_TO_POINTER (0xAu)))
    abort ();
  return TRUE;
}

static rboolean
tty_expect_b (const rchar * str, rsize size, rpointer data)
{
  (void) str; (void) size;
  if (R_UNLIKELY (data != RUINT_TO_POINTER (0xBu)))
    abort ();
  return TRUE;
}

static rpointer
tty_print_loop (rpointer data)
{
  ruint i;
  (void) data;
  for (i = 0; i < 4000; i++)
    r_print ("x");
  return NULL;
}

RTEST (rtty, override_concurrent, RTEST_FAST)
{
  RThread * t[3];
  RPrintFunc oldf = NULL;
  rpointer olddata = NULL;
  ruint i;

  r_override_print_handler (tty_expect_a, RUINT_TO_POINTER (0xAu), &oldf, &olddata);

  for (i = 0; i < R_N_ELEMENTS (t); i++)
    t[i] = r_thread_new ("tty-print", tty_print_loop, NULL);

  /* Swap the handler under the readers; each func must stay paired with
   * its own data, or the handlers abort the (forked) test. */
  for (i = 0; i < 2000; i++) {
    if (i & 1)
      r_override_print_handler (tty_expect_a, RUINT_TO_POINTER (0xAu), NULL, NULL);
    else
      r_override_print_handler (tty_expect_b, RUINT_TO_POINTER (0xBu), NULL, NULL);
  }

  for (i = 0; i < R_N_ELEMENTS (t); i++)
    r_thread_join (t[i]);

  r_override_print_handler (oldf, olddata, NULL, NULL);
}
RTEST_END;
