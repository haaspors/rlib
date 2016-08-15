#include <rlib/rlib.h>

#define PTR_CAFEBABE    RINT_TO_POINTER (0xCAFEBABE)
#define PTR_DEADBEEF    RINT_TO_POINTER (0xDEADBEEF)
#define PTR_BAADFOOD    RINT_TO_POINTER (0xBAADF00D)

RTEST (rcbrlist, basic, RTEST_FAST)
{
  RCBRList * lst = NULL;

  r_assert_cmpuint (r_cbrlist_len (lst), ==, 0);
  r_assert_cmpptr ((lst = r_cbrlist_prepend (lst, NULL, PTR_CAFEBABE, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpuint (r_cbrlist_len (lst), ==, 1);
  r_assert_cmpptr ((lst = r_cbrlist_prepend (lst, NULL, PTR_DEADBEEF, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpuint (r_cbrlist_len (lst), ==, 2);

  r_assert (!r_cbrlist_contains (lst, NULL, PTR_BAADFOOD));
  r_assert (r_cbrlist_contains (lst, NULL, PTR_CAFEBABE));

  r_cbrlist_destroy (lst);
}
RTEST_END;

static rboolean
add_data_to_user_lst (rpointer data, rpointer user)
{
  RSList ** lst = user;
  *lst = r_slist_prepend (*lst, data);

  return FALSE;
}

RTEST (rcbrlist, call, RTEST_FAST)
{
  RCBRList * lst = NULL;
  RSList * usr = NULL;

  r_assert_cmpptr ((lst = r_cbrlist_prepend (lst, add_data_to_user_lst, PTR_CAFEBABE, &usr)), !=, NULL);
  r_assert_cmpptr ((lst = r_cbrlist_prepend (lst, add_data_to_user_lst, PTR_DEADBEEF, &usr)), !=, NULL);

  r_assert_cmpptr (usr, ==, NULL);
  lst = r_cbrlist_call (lst);
  r_assert_cmpptr (usr, !=, NULL);
  r_assert_cmpuint (r_slist_len (usr), ==, 2);
  r_assert (r_slist_contains (usr, PTR_CAFEBABE));
  r_assert (r_slist_contains (usr, PTR_DEADBEEF));
  r_assert (!r_slist_contains (usr, PTR_BAADFOOD));
  r_slist_destroy (usr);

  r_assert_cmpptr ((lst = r_cbrlist_prepend (lst, NULL, PTR_BAADFOOD, PTR_BAADFOOD)), !=, NULL);
  r_cbrlist_destroy (lst);
}
RTEST_END;

