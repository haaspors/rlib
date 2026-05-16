#include <rlib/rasn1.h>

static const ruint32 asn1[] = { 1, 2, 840, 113549, 1, 1, 1 };

RTEST (rasn1oid, to_dot, RTEST_FAST)
{
  rchar * dot;

  r_assert_cmpptr (r_asn1_oid_to_dot (NULL, 0), ==, NULL);
  r_assert_cmpptr (r_asn1_oid_to_dot (asn1, 0), ==, NULL);

  r_assert_cmpstr ((dot = r_asn1_oid_to_dot (asn1, R_N_ELEMENTS (asn1))), ==,
      "1.2.840.113549.1.1.1");
  r_free (dot);
}
RTEST_END;

RTEST (rasn1oid, from_dot, RTEST_FAST)
{
  ruint32 * res;
  rsize len;

  r_assert_cmpptr (r_asn1_oid_from_dot (NULL, 0, NULL), ==, NULL);
  r_assert_cmpptr (r_asn1_oid_from_dot ("1.2.840", 0, NULL), ==, NULL);
  r_assert_cmpptr (r_asn1_oid_from_dot ("1.2.840", 1, NULL), ==, NULL);
  r_assert_cmpptr (r_asn1_oid_from_dot ("1.2.840", 4, NULL), ==, NULL);

  r_assert_cmpptr ((res = r_asn1_oid_from_dot ("1.2.840.113549.1.1.1", -1, &len)),
      !=, NULL);
  r_assert_cmpuint (len, ==, R_N_ELEMENTS (asn1));
  r_assert_cmpmem (asn1, ==, res, sizeof (asn1));

  r_free (res);
}
RTEST_END;

RTEST (rasn1oid, is_dot, RTEST_FAST)
{
  r_assert (!r_asn1_oid_is_dot (NULL, 0, NULL, 0));
  r_assert (!r_asn1_oid_is_dot (asn1, 0, NULL, 0));
  r_assert (!r_asn1_oid_is_dot (asn1, R_N_ELEMENTS (asn1), NULL, 0));
  r_assert (!r_asn1_oid_is_dot (asn1, R_N_ELEMENTS (asn1), "1.2.840", -1));
  r_assert (!r_asn1_oid_is_dot (asn1, R_N_ELEMENTS (asn1), "1.2.840.113549.1.1.1", 0));
  r_assert ( r_asn1_oid_is_dot (asn1, R_N_ELEMENTS (asn1), "1.2.840.113549.1.1.1", -1));
}
RTEST_END;

RTEST (rasn1oid, has_dot_prefix, RTEST_FAST)
{
  r_assert (!r_asn1_oid_has_dot_prefix (NULL, 0, NULL, 0));
  r_assert (!r_asn1_oid_has_dot_prefix (asn1, 0, NULL, 0));
  r_assert (!r_asn1_oid_has_dot_prefix (asn1, R_N_ELEMENTS (asn1), NULL, 0));
  r_assert ( r_asn1_oid_has_dot_prefix (asn1, R_N_ELEMENTS (asn1), "1.2.840", -1));
  r_assert (!r_asn1_oid_has_dot_prefix (asn1, R_N_ELEMENTS (asn1), "1.1.840", -1));
}
RTEST_END;

RTEST (rasn1oid, from_dot_single_arc, RTEST_FAST)
{
  /* A valid OID has at least two arcs. "123" is a single arc and
   * must be rejected. */
  r_assert_cmpptr (r_asn1_oid_from_dot ("123", -1, NULL), ==, NULL);
  r_assert_cmpptr (r_asn1_oid_from_dot ("12345", -1, NULL), ==, NULL);
}
RTEST_END;

RTEST (rasn1oid, from_dot_non_null_terminated, RTEST_FAST)
{
  /* Heap-allocated buffer with NO NUL terminator: r_str_to_uint32
   * inside r_asn1_oid_from_dot must not read past oidsize. */
  static const rchar src[] = "1.2.840";
  rchar * buf = r_memdup (src, r_strlen (src));   /* no trailing NUL */
  rsize len;
  ruint32 * res;

  r_assert_cmpptr ((res = r_asn1_oid_from_dot (buf, r_strlen (src), &len)),
      !=, NULL);
  r_assert_cmpuint (len, ==, 3);
  r_free (res);
  r_free (buf);
}
RTEST_END;

