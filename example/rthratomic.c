#include <rlib/rlib.h>


#define THRS    10000
#define ITERS   10000

static rpointer
thr_add (rpointer data)
{
  ruint * counter = data;
  int i;

  for (i = 0; i < ITERS; i++)
    (*counter)++;

  return NULL;
}
static rpointer
thr_add_atomic (rpointer data)
{
  rauint * counter = data;
  int i;

  for (i = 0; i < ITERS; i++)
    r_atomic_uint_fetch_add (counter, 1);

  return NULL;
}

int
main (int argc, char ** argv)
{
  int i;
  rauint counter = 0;
  RThread * thrs[THRS];

  (void)argc;
  (void)argv;

  for (i = 0; i < THRS; i++) {
    thrs[i] = r_thread_new (NULL,
        getenv("NOATOMICS") ? thr_add : thr_add_atomic,
        (rpointer)&counter);
  }

  for (i = 0; i < THRS; i++) {
    r_thread_join (thrs[i]);
  }

  r_print ("Ran %d threads each of %d iterations yielding: %u\n",
      THRS, ITERS, counter);

  return 0;
}

