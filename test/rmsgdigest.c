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
  r_assert (r_hash_update (hash, "foobar", 6));

  r_assert (r_hash_finish (hash));
  r_assert (!r_hash_update (hash, "foobar", 6));

  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

RTEST (rhash, sha1, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_sha1 ();
  ruint8 data[32];
  rsize size = sizeof (data);
  rchar * hex;

  r_assert_cmpuint (r_hash_size (hash),       ==, 160 / 8);
  r_assert_cmpuint (r_hash_blocksize (hash),  ==, 512 / 8);
  r_assert (r_hash_update (hash, "foobar", 6));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpmem (data, ==,
      "\x88\x43\xd7\xf9\x24\x16\x21\x1d\xe9\xeb\xb9\x63\xff\x4c\xe2\x81\x25\x93\x28\x78", size);
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "8843d7f92416211de9ebb963ff4ce28125932878");
  r_free (hex);
  r_assert_cmpstr ((hex = r_hash_get_hex_full (hash, ":", 1)), ==,
      "88:43:d7:f9:24:16:21:1d:e9:eb:b9:63:ff:4c:e2:81:25:93:28:78");
  r_assert (r_hash_update (hash, "foobar", 6));

  r_assert (r_hash_finish (hash));
  r_assert (!r_hash_update (hash, "foobar", 6));

  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

RTEST (rhash, sha256, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_sha256 ();
  ruint8 data[32];
  rsize size = sizeof (data);
  rchar * hex;

  r_assert_cmpuint (r_hash_size (hash),       ==, 256 / 8);
  r_assert_cmpuint (r_hash_blocksize (hash),  ==, 512 / 8);
  r_assert (r_hash_update (hash, "foobar", 6));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpmem (data, ==,
      "\xc3\xab\x8f\xf1\x37\x20\xe8\xad\x90\x47\xdd\x39\x46\x6b\x3c\x89"
      "\x74\xe5\x92\xc2\xfa\x38\x3d\x4a\x39\x60\x71\x4c\xae\xf0\xc4\xf2", size);
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2");
  r_assert (r_hash_update (hash, "foobar", 6));

  r_assert (r_hash_finish (hash));
  r_assert (!r_hash_update (hash, "foobar", 6));

  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

RTEST (rhash, sha512, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_sha512 ();
  ruint8 data[64];
  rsize size = sizeof (data);
  rchar * hex;

  r_assert_cmpuint (r_hash_size (hash),       ==, 512 / 8);
  r_assert_cmpuint (r_hash_blocksize (hash),  ==, 1024 / 8);
  r_assert (r_hash_update (hash, "foobar", 6));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpmem (data, ==,
      "\x0a\x50\x26\x1e\xbd\x1a\x39\x0f\xed\x2b\xf3\x26\xf2\x67\x3c\x14"
      "\x55\x82\xa6\x34\x2d\x52\x32\x04\x97\x3d\x02\x19\x33\x7f\x81\x61"
      "\x6a\x80\x69\xb0\x12\x58\x7c\xf5\x63\x5f\x69\x25\xf1\xb5\x6c\x36"
      "\x02\x30\xc1\x9b\x27\x35\x00\xee\x01\x3e\x03\x06\x01\xbf\x24\x25", size);
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f8161"
      "6a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425");
  r_assert (r_hash_update (hash, "foobar", 6));

  r_assert (r_hash_finish (hash));
  r_assert (!r_hash_update (hash, "foobar", 6));

  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

RTEST (rhash, md5_fill_block, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_md5 ();
  ruint8 data[32];
  rsize i, size = sizeof (data);
  rchar * hex;

  for (i = 0; i < r_hash_blocksize (hash); i += 8)
    r_assert (r_hash_update (hash, "foobar64", 8));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "57c58653b9d1fe7485d4754c24ae50ef");
  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

RTEST (rhash, sha1_fill_block, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_sha1 ();
  ruint8 data[32];
  rsize i, size = sizeof (data);
  rchar * hex;

  for (i = 0; i < r_hash_blocksize (hash); i += 8)
    r_assert (r_hash_update (hash, "foobar64", 8));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "44ad860c45a831da1edf9ceb0d3c259d52efe68e");
  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

RTEST (rhash, sha256_fill_block, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_sha256 ();
  ruint8 data[32];
  rsize i, size = sizeof (data);
  rchar * hex;

  for (i = 0; i < r_hash_blocksize (hash); i += 8)
    r_assert (r_hash_update (hash, "foobar64", 8));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "c937e19346c302d51371e5df65cea11ed71c6f58678adc27fe1a55ace8167aa6");
  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

RTEST (rhash, sha512_fill_block, R_TEST_TYPE_FAST)
{
  RHash * hash = r_hash_new_sha512 ();
  ruint8 data[64];
  rsize i, size = sizeof (data);
  rchar * hex;

  for (i = 0; i < r_hash_blocksize (hash); i += 8)
    r_assert (r_hash_update (hash, "foobar64", 8));
  r_assert (r_hash_get_data (hash, data, &size));
  r_assert_cmpuint (size, ==, r_hash_size (hash));
  r_assert_cmpstr ((hex = r_hash_get_hex (hash)), ==,
      "265927b8379557541f940d2dd259ee89a55381804514b758be3dab33f981e8389"
      "27e08ffc73ae538d581b65a2eb706459817ff51172742a9e1cf832b0727cc66");
  r_free (hex);
  r_hash_free (hash);
}
RTEST_END;

