#include <rlib/rlib.h>

#define PTR_CAFEBABE    RINT_TO_POINTER (0xCAFEBABE)
#define PTR_DEADBEEF    RINT_TO_POINTER (0xDEADBEEF)
#define PTR_BAADFOOD    RINT_TO_POINTER (0xBAADF00D)

RTEST (rcblist, basic, RTEST_FAST)
{
  RCBList * lst = NULL;

  r_assert_cmpuint (r_cblist_len (lst), ==, 0);
  r_assert_cmpptr ((lst = r_cblist_prepend (lst, NULL, PTR_CAFEBABE, PTR_CAFEBABE)), !=, NULL);
  r_assert_cmpuint (r_cblist_len (lst), ==, 1);
  r_assert_cmpptr ((lst = r_cblist_prepend (lst, NULL, PTR_DEADBEEF, PTR_DEADBEEF)), !=, NULL);
  r_assert_cmpuint (r_cblist_len (lst), ==, 2);

  r_assert (!r_cblist_contains (lst, NULL, PTR_BAADFOOD));
  r_assert (r_cblist_contains (lst, NULL, PTR_CAFEBABE));

  r_cblist_destroy (lst);
}
RTEST_END;

static void
add_data_to_user_lst (rpointer data, rpointer user)
{
  RSList ** lst = user;
  *lst = r_slist_prepend (*lst, data);
}

RTEST (rcblist, call, RTEST_FAST)
{
  RCBList * lst = NULL;
  RSList * usr = NULL;

  r_assert_cmpptr ((lst = r_cblist_prepend (lst, add_data_to_user_lst, PTR_CAFEBABE, &usr)), !=, NULL);
  r_assert_cmpptr ((lst = r_cblist_prepend (lst, add_data_to_user_lst, PTR_DEADBEEF, &usr)), !=, NULL);

  r_assert_cmpptr (usr, ==, NULL);
  r_cblist_call (lst);
  r_assert_cmpptr (usr, !=, NULL);
  r_assert_cmpuint (r_slist_len (usr), ==, 2);
  r_assert (r_slist_contains (usr, PTR_CAFEBABE));
  r_assert (r_slist_contains (usr, PTR_DEADBEEF));
  r_assert (!r_slist_contains (usr, PTR_BAADFOOD));
  r_slist_destroy (usr);

  r_cblist_destroy (lst);
}
RTEST_END;

