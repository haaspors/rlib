#include <rlib/rlib.h>

RTEST (rrsa, pub_key_init, RTEST_FAST)
{
  rmpint n, e;
  RCryptoKey * key;

  r_mpint_init_str (&n, "988672111837205085526346618740053", 0, 10);
  r_mpint_init_str (&e, "65537", 0, 10);
  r_assert_cmpptr ((key = r_rsa_pub_key_new (NULL, &e)), ==, NULL);
  r_assert_cmpptr ((key = r_rsa_pub_key_new (&n, NULL)), ==, NULL);

  r_assert_cmpptr ((key = r_rsa_pub_key_new (&n, &e)), !=, NULL);
  r_mpint_clear (&n);
  r_mpint_clear (&e);

  r_crypto_key_unref (key);
}
RTEST_END;

