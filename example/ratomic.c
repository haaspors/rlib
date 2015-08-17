#include <rlib/rlib.h>

int
main (int argc, char ** argv)
{
  raptr a = (ruintptr) RINT_TO_POINTER (argc);
  rpointer b;

  (void)argv;

  r_atomic_ptr_store (&a, (ruintptr) (100));
  b = r_atomic_ptr_fetch_add (&a, (ruintptr) (42));
  b = r_atomic_ptr_fetch_sub (&a, (ruintptr) (42));
  b = r_atomic_ptr_fetch_and (&a, (ruintptr) (0xFF00FF));
  b = r_atomic_ptr_fetch_or (&a, (ruintptr) (0xFF00FF));
  b = r_atomic_ptr_fetch_xor (&a, (ruintptr) (0xFF00FF));

  b = r_atomic_ptr_exchange (&a, (ruintptr) (1));
  b = r_atomic_ptr_load (&a);
  if (r_atomic_ptr_cmp_xchg_weak (&a, &b, (ruintptr) (100))) {
    b = r_atomic_ptr_load (&a);
    r_atomic_ptr_cmp_xchg_strong (&a, &b, (ruintptr) (0));
  }

  return RPOINTER_TO_INT (r_atomic_ptr_load (&a));
}

