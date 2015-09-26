#include <rlib/rlib.h>

#define THRS 16

static ROnce g__myonce = R_ONCE_INIT;

R_INITIALIZER (myctor)
{
  r_print ("%p: Hello from %s\n", r_thread_current (), R_STRFUNC);
}

R_DEINITIALIZER (mydtor)
{
  r_print ("%p: Goodbye from %s\n", r_thread_current (), R_STRFUNC);
}

static rpointer
myonce_func (rpointer data)
{
  r_print ("%p: %s %p\n", r_thread_current (), R_STRFUNC, data);
  return RINT_TO_POINTER (42);
}

static rpointer
once_thread_func (rpointer data)
{
  rpointer ret;
  r_print ("%p: Entering thread before once\n", r_thread_current ());
  ret = r_call_once (&g__myonce, myonce_func, data);
  r_print ("%p: Ending thread after once %"RSIZE_FMT"\n", r_thread_current (), RPOINTER_TO_SIZE (ret));
  return NULL;
}

int
main (int argc, char ** argv)
{
  RThread * th[THRS];
  int i;

  (void)argc;
  (void)argv;

  r_print ("%p: starting threads\n", r_thread_current ());
  for (i = 0; i < THRS; i++)
    th[i] = r_thread_new (NULL, once_thread_func, NULL);

  for (i = 0; i < THRS; i++)
    r_thread_join (th[i]);

  r_print ("%p: ending app\n", r_thread_current ());
  return 0;
}

