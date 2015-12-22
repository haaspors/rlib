#include <rlib/rlib.h>

RTEST (rhash, md5, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_md5 ();
  ruint8 data[32];
  rsize size = sizeof (data);
  rchar * hex;

  r_assert_cmpuint (r_hash_size (hash),       ==, 128 / 8);
  r_assert_cmpuint (r_hash_blocksize (hash),  ==, 512 / 8);
  r_assert (r_hash_update (hash, "foobar", 6));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpmem (data, ==,
      "\x38\x58\xf6\x22\x30\xac\x3c\x91\x5f\x30\x0c\x66\x43\x12\xc6\x3f", size);
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "3858f62230ac3c915f300c664312c63f");
  r_assert (!r_hash_update (hash, "foobar", 6));

  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

