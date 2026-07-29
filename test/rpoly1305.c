#include <rlib/rcrypto.h>
#include <rlib/rstr.h>

typedef struct {
  const rchar * key;
  const rchar * msg;
  const rchar * tag;
} RPoly1305TestData;

/* Poly1305 known-answer vectors from RFC 8439 (sec 2.5.2 and the
 * additional A.3 test vectors). Messages are given as hex. */
static const RPoly1305TestData mac_test_data[] = {
  { /* RFC 8439 sec 2.5.2 - "Cryptographic Forum Research Group" */
    "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
    "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
    "a8061dc1305136c6c22b8baf0c0127a9" },
  { /* RFC 8439 A.3 #1 - all-zero key over a 64-byte all-zero message
     * yields an all-zero tag (r == 0 and s == 0). */
    "0000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000" },
  { /* RFC 8439 A.3 #2 - r == 0, so h stays zero and the tag is exactly
     * the s half of the key regardless of the message. */
    "0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e",
    "416e79207375626d697373696f6e20746f207468652049455446",
    "36e5f6b5c5e06070f0efca96227a863e" },
  { /* RFC 8439 A.3 #5 - the partial product 2*(2^129-1) = 2^130-2 exceeds
     * the prime, forcing the final conditional subtraction of p. */
    "0200000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff",
    "03000000000000000000000000000000" },
  { /* RFC 8439 A.3 #6 - s = 2^128-1 exercises the carry out of the h + s
     * final addition. */
    "02000000000000000000000000000000ffffffffffffffffffffffffffffffff",
    "02000000000000000000000000000000",
    "03000000000000000000000000000000" },
  { /* RFC 8439 A.3 #7 - reduction accumulated across three blocks. */
    "0100000000000000000000000000000000000000000000000000000000000000",
    "ffffffffffffffffffffffffffffffff"
    "f0ffffffffffffffffffffffffffffff"
    "11000000000000000000000000000000",
    "05000000000000000000000000000000" },
};

RTEST_LOOP (rpoly1305, mac, RTEST_FAST, 0, R_N_ELEMENTS (mac_test_data))
{
  const RPoly1305TestData * data = &mac_test_data[__i];
  ruint8 key[R_POLY1305_KEY_SIZE];
  ruint8 tag[R_POLY1305_TAG_SIZE];
  ruint8 expected[R_POLY1305_TAG_SIZE];
  ruint8 * msg;
  rsize msgsize;

  msgsize = r_strlen (data->msg) / 2;
  msg = r_malloc (msgsize);

  r_assert_cmpuint (r_str_hex_to_binary (data->key, key, sizeof (key)),
      ==, sizeof (key));
  r_assert_cmpuint (r_str_hex_to_binary (data->tag, expected, sizeof (expected)),
      ==, sizeof (expected));
  r_assert_cmpuint (r_str_hex_to_binary (data->msg, msg, msgsize), ==, msgsize);

  r_poly1305_mac (tag, msg, msgsize, key);
  r_assert_cmpmem (tag, ==, expected, sizeof (expected));

  r_free (msg);
}
RTEST_END;
