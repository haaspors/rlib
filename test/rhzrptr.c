#include <rlib/rlib.h>

RTEST (rhzrptr, rec, RTEST_FAST)
{
  RHzrPtrRec * rec = r_hzr_ptr_rec_new ();
  r_assert_cmpptr (rec, !=, NULL);
  r_hzr_ptr_rec_free (rec);
}
RTEST_END;

RTEST (rhzrptr, read, RTEST_FAST)
{
  rhzrptr hp = R_HZR_PTR_INIT (NULL);
  rpointer ptr;

  ptr = r_hzr_ptr_aqcuire (&hp, NULL);
  r_assert_cmpptr (ptr, ==, NULL);
  r_hzr_ptr_release (&hp, NULL);
}
RTEST_END;

RTEST (rhzrptr, replace, RTEST_FAST)
{
  rhzrptr hp = R_HZR_PTR_INIT (NULL);
  rpointer ptr;

  ptr = r_hzr_ptr_aqcuire (&hp, NULL);
  r_assert_cmpptr (ptr, ==, NULL);
  r_hzr_ptr_release (&hp, NULL);

  r_hzr_ptr_replace (&hp, RUINT_TO_POINTER (0xCAFEBABE));

  ptr = r_hzr_ptr_aqcuire (&hp, NULL);
  r_assert_cmpptr (ptr, ==, RUINT_TO_POINTER (0xCAFEBABE));
  r_hzr_ptr_release (&hp, NULL);
}
RTEST_END;

typedef struct {
  int i;
  rpointer ptr;
} TestHP;

RTEST (rhzrptr, read_replace, RTEST_FAST)
{
  rhzrptr hp = R_HZR_PTR_INIT (r_free);
  TestHP * ptr;

  r_hzr_ptr_replace (&hp, r_mem_new0 (TestHP));

  ptr = r_hzr_ptr_aqcuire (&hp, NULL);
  r_assert_cmpptr (ptr, !=, NULL);
  r_hzr_ptr_replace (&hp, NULL);

  /* hp is set to NULL, but ptr should still be addressable */
  r_assert_cmpint (ptr->i, ==, 0);
  r_assert_cmpptr (ptr->ptr, ==, NULL);

  r_hzr_ptr_release (&hp, NULL);

  ptr = r_hzr_ptr_aqcuire (&hp, NULL);
  r_assert_cmpptr (ptr, ==, NULL);
  r_hzr_ptr_release (&hp, NULL);
}
RTEST_END;

