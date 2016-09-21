#include <rlib/rlib.h>

static const ruint8 pkt_wrong_msglen[] = {
  0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0x78, 0x49, 0x61, 0x51, 0x33, 0x73, 0x6a, 0x33,
  0x77, 0x39, 0x74, 0x50
};
static const ruint8 pkt_wrong_magic[] = {
  0x00, 0x01, 0x00, 0x00, 0xa4, 0x42, 0x21, 0x00, 0x78, 0x49, 0x61, 0x51, 0x33, 0x73, 0x6a, 0x33,
  0x77, 0x39, 0x74, 0x50
};
static const ruint8 pkt_req_binding[] = {
  0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 0x46, 0x76, 0x41, 0x31, 0x65, 0x6d, 0x75, 0x49,
  0x73, 0x6b, 0x4e, 0x59
};
static const ruint8 pkt_success_resp_binding[] = {
  0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42, 0x46, 0x76, 0x41, 0x31, 0x65, 0x6d, 0x75, 0x49,
  0x73, 0x6b, 0x4e, 0x59, 0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xfc, 0x72, 0x12, 0xbd, 0xc5, 0x84
};
static const ruint8 pkt_req_binding_attrib[] = {
  0x00, 0x01, 0x00, 0x68, 0x21, 0x12, 0xa4, 0x42, 0x78, 0x49, 0x61, 0x51, 0x33, 0x73, 0x6a, 0x33,
  0x77, 0x39, 0x74, 0x50, 0x00, 0x06, 0x00, 0x21, 0x34, 0x66, 0x35, 0x50, 0x71, 0x69, 0x74, 0x38,
  0x30, 0x49, 0x2f, 0x47, 0x57, 0x71, 0x6a, 0x70, 0x3a, 0x32, 0x31, 0x37, 0x6d, 0x62, 0x4b, 0x6f,
  0x4e, 0x54, 0x4a, 0x4b, 0x7a, 0x70, 0x45, 0x44, 0x70, 0x00, 0x00, 0x00, 0xc0, 0x57, 0x00, 0x04,
  0x00, 0x01, 0x00, 0x00, 0x80, 0x2a, 0x00, 0x08, 0x66, 0x9f, 0xb6, 0xf6, 0x5a, 0xf7, 0x69, 0x44,
  0x00, 0x25, 0x00, 0x00, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x7f, 0x1e, 0xff, 0x00, 0x08, 0x00, 0x14,
  0x09, 0xa1, 0x66, 0x76, 0xde, 0x71, 0x19, 0x9d, 0x0b, 0x46, 0x36, 0xdf, 0xaa, 0x47, 0x35, 0xa9,
  0xbd, 0x91, 0xe1, 0x50, 0x80, 0x28, 0x00, 0x04, 0x93, 0x7c, 0xe8, 0xd8
};
static const ruint8 pkt_req_alloc[] = {
  0x00, 0x03, 0x00, 0x08, 0x21, 0x12, 0xa4, 0x42, 0x4b, 0x49, 0x72, 0x72, 0x33, 0x58, 0x5a, 0x38,
  0x46, 0x59, 0x58, 0x64, 0x00, 0x19, 0x00, 0x04, 0x11, 0x00, 0x00, 0x00
};
static const ruint8 pkt_error_resp_alloc[] = {
  0x01, 0x13, 0x00, 0x34, 0x21, 0x12, 0xa4, 0x42, 0x4b, 0x49, 0x72, 0x72, 0x33, 0x58, 0x5a, 0x38,
  0x46, 0x59, 0x58, 0x64, 0x00, 0x09, 0x00, 0x04, 0x00, 0x00, 0x04, 0x01, 0x00, 0x15, 0x00, 0x10,
  0x0c, 0x03, 0x5c, 0x43, 0x07, 0x8e, 0x94, 0x63, 0x9c, 0x0c, 0x0d, 0x04, 0x27, 0x25, 0x6e, 0x54,
  0x00, 0x14, 0x00, 0x11, 0x73, 0x74, 0x75, 0x6e, 0x2e, 0x6c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
  0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x00
};
static const ruint8 pkt_success_resp_alloc[] = {
  0x01, 0x03, 0x00, 0x38, 0x21, 0x12, 0xa4, 0x42, 0x43, 0x42, 0x46, 0x73, 0x55, 0x6f, 0x55, 0x55,
  0x6c, 0x57, 0x7a, 0x71, 0x00, 0x16, 0x00, 0x08, 0x00, 0x01, 0x55, 0xa5, 0x6b, 0x6f, 0x83, 0x40,
  0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xfd, 0x38, 0xb5, 0x68, 0x0b, 0x68, 0x00, 0x0d, 0x00, 0x04,
  0x00, 0x00, 0x00, 0x78, 0x00, 0x08, 0x00, 0x14, 0xb8, 0x89, 0xee, 0x67, 0x65, 0x03, 0x35, 0x30,
  0x34, 0x88, 0xc9, 0xe2, 0x40, 0x2f, 0x03, 0x1e, 0x8e, 0x68, 0x1d, 0xc4
};


RTEST (rstun, is_valid_msg, RTEST_FAST)
{
  r_assert (!r_stun_is_valid_msg (NULL, 0));
  r_assert (!r_stun_is_valid_msg (pkt_wrong_msglen, sizeof (pkt_wrong_msglen)));
  r_assert (!r_stun_is_valid_msg (pkt_wrong_magic, sizeof (pkt_wrong_magic)));

  r_assert (!r_stun_is_valid_msg (pkt_req_binding, 0));
  r_assert (!r_stun_is_valid_msg (pkt_req_binding_attrib, 20));
  r_assert (!r_stun_is_valid_msg (pkt_req_binding_attrib, sizeof (pkt_req_binding_attrib) - 1));

  r_assert (r_stun_is_valid_msg (pkt_req_binding, sizeof (pkt_req_binding)));
  r_assert_cmpuint (r_stun_msg_len (pkt_req_binding), ==, 0);
  r_assert (r_stun_is_valid_msg (pkt_req_binding_attrib, sizeof (pkt_req_binding_attrib)));
  r_assert_cmpuint (r_stun_msg_len (pkt_req_binding_attrib), ==, 104);
}
RTEST_END;

RTEST (rstun, request_binding, RTEST_FAST)
{
  static const ruint8 transaction_id[] = {
    0x46, 0x76, 0x41, 0x31, 0x65, 0x6d, 0x75, 0x49, 0x73, 0x6b, 0x4e, 0x59
  };

  r_assert (r_stun_is_valid_msg (pkt_req_binding, sizeof (pkt_req_binding)));
  r_assert (r_stun_msg_is_request (pkt_req_binding));
  r_assert (r_stun_msg_method_is_binding (pkt_req_binding));
  r_assert_cmpuint (r_stun_msg_len (pkt_req_binding), ==, 0);
  r_assert_cmpmem (r_stun_msg_transaction_id (pkt_req_binding), ==,
      transaction_id, sizeof (transaction_id));
  r_assert_cmpuint (r_stun_msg_attribute_count (pkt_req_binding), ==, 0);
}
RTEST_END;

RTEST (rstun, success_response_binding, RTEST_FAST)
{
  static const ruint8 transaction_id[] = {
    0x46, 0x76, 0x41, 0x31, 0x65, 0x6d, 0x75, 0x49, 0x73, 0x6b, 0x4e, 0x59
  };
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;

  r_assert (r_stun_is_valid_msg (pkt_success_resp_binding, sizeof (pkt_success_resp_binding)));
  r_assert (r_stun_msg_is_success_resp (pkt_success_resp_binding));
  r_assert (r_stun_msg_method_is_binding (pkt_success_resp_binding));
  r_assert_cmpuint (r_stun_msg_len (pkt_success_resp_binding), ==, 12);
  r_assert_cmpmem (r_stun_msg_transaction_id (pkt_success_resp_binding), ==,
      transaction_id, sizeof (transaction_id));
  r_assert_cmpuint (r_stun_msg_attribute_count (pkt_success_resp_binding), ==, 1);
  r_assert (r_stun_attr_tlv_first (pkt_success_resp_binding, &tlv));
  r_assert_cmpuint (tlv.type, ==, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS);
  r_assert_cmpuint (tlv.len, ==, 8);
}
RTEST_END;

RTEST (rstun, attributes, RTEST_FAST)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;
  RSocketAddress * addr;
  rchar * ipstr;

  r_assert (r_stun_is_valid_msg (pkt_req_binding_attrib, sizeof (pkt_req_binding_attrib)));
  r_assert_cmpuint (r_stun_msg_attribute_count (pkt_req_binding_attrib), ==, 7);

  r_assert (r_stun_attr_tlv_first (pkt_req_binding_attrib, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_USERNAME);
  r_assert_cmpuint (tlv.len, ==, 33);
  r_assert_cmpmem (tlv.value, ==, "4f5Pqit80I/GWqjp:217mbKoNTJKzpEDp", tlv.len);

  r_assert (r_stun_attr_tlv_next (pkt_req_binding_attrib, &tlv));
  r_assert_cmphex (tlv.type, ==, 0xc057);
  r_assert_cmpuint (tlv.len, ==, 4);

  r_assert (r_stun_attr_tlv_next (pkt_req_binding_attrib, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_ICE_CONTROLLING);
  r_assert_cmpuint (tlv.len, ==, 8);

  r_assert (r_stun_attr_tlv_next (pkt_req_binding_attrib, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_USE_CANDIDATE);
  r_assert_cmpuint (tlv.len, ==, 0);

  r_assert (r_stun_attr_tlv_next (pkt_req_binding_attrib, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_PRIORITY);
  r_assert_cmpuint (tlv.len, ==, 4);

  r_assert (r_stun_attr_tlv_next (pkt_req_binding_attrib, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY);
  r_assert_cmpuint (tlv.len, ==, 20);

  r_assert (r_stun_attr_tlv_next (pkt_req_binding_attrib, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_FINGERPRINT);
  r_assert_cmpuint (tlv.len, ==, 4);

  r_assert (!r_stun_attr_tlv_next (pkt_req_binding_attrib, &tlv));


  r_assert (r_stun_attr_tlv_first (pkt_success_resp_binding, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS);
  r_assert_cmpuint (tlv.len, ==, 8);
  r_assert_cmpptr ((addr = r_stun_attr_tlv_parse_xor_address (pkt_success_resp_binding, &tlv)), !=, NULL);
  r_assert_cmpuint (r_socket_address_get_family (addr), ==, R_SOCKET_FAMILY_IPV4);
  r_assert_cmpstr ((ipstr = r_socket_address_ipv4_to_str (addr, FALSE)), ==, "51.175.97.198");
  r_assert_cmpuint (r_socket_address_ipv4_get_port (addr), ==, 56672);

  r_free (ipstr);
  r_socket_address_unref (addr);
}
RTEST_END;

RTEST (rstun, req_alloc, RTEST_FAST)
{
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;

  r_assert (r_stun_is_valid_msg (pkt_req_alloc, sizeof (pkt_req_alloc)));
  r_assert (r_stun_msg_is_request (pkt_req_alloc));
  r_assert (r_stun_msg_method_is_allocate (pkt_req_alloc));
  r_assert (r_stun_attr_tlv_first (pkt_req_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_REQUESTED_TRANSPORT);
  r_assert_cmphex (r_stun_attr_tlv_parse_reqested_transport_protocol (pkt_req_alloc, &tlv), ==, 0x11); /* UDP */
  r_assert (!r_stun_attr_tlv_next (pkt_req_alloc, &tlv));

  r_assert (r_stun_is_valid_msg (pkt_error_resp_alloc, sizeof (pkt_error_resp_alloc)));
  r_assert (r_stun_msg_is_err_resp (pkt_error_resp_alloc));
  r_assert (r_stun_msg_method_is_allocate (pkt_error_resp_alloc));
  r_assert (r_stun_attr_tlv_first (pkt_error_resp_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_ERROR_CODE);
  r_assert_cmpuint (r_stun_attr_tlv_parse_error_code (pkt_error_resp_alloc, &tlv), ==, 401);
  r_assert (r_stun_attr_tlv_next (pkt_error_resp_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_NONCE);
  r_assert_cmphex (tlv.len, ==, 16);
  r_assert (r_stun_attr_tlv_next (pkt_error_resp_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_REALM);
  r_assert_cmphex (tlv.len, ==, 17);
  r_assert_cmpmem (tlv.value, ==, "stun.l.google.com", tlv.len);
  r_assert (!r_stun_attr_tlv_next (pkt_error_resp_alloc, &tlv));

  r_assert_cmpmem (r_stun_msg_transaction_id (pkt_req_alloc), ==,
      r_stun_msg_transaction_id (pkt_error_resp_alloc), R_STUN_TRANSACTION_ID_SIZE);

  r_assert (r_stun_is_valid_msg (pkt_success_resp_alloc, sizeof (pkt_success_resp_alloc)));
  r_assert (r_stun_msg_is_success_resp (pkt_success_resp_alloc));
  r_assert (r_stun_msg_method_is_allocate (pkt_success_resp_alloc));
  r_assert (r_stun_attr_tlv_first (pkt_success_resp_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_XOR_RELAYED_ADDRESS);
  r_assert (r_stun_attr_tlv_next (pkt_success_resp_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_XOR_MAPPED_ADDRESS);
  r_assert (r_stun_attr_tlv_next (pkt_success_resp_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_LIFETIME);
  r_assert_cmpuint (r_stun_att_tlv_parse_lifetime (pkt_success_resp_alloc, &tlv), ==, 120);
  r_assert (r_stun_attr_tlv_next (pkt_success_resp_alloc, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY);
  r_assert (!r_stun_attr_tlv_next (pkt_success_resp_alloc, &tlv));
}
RTEST_END;

RTEST (rstun, message_integrity_fingerprint, RTEST_FAST)
{
  /* Software name:  "STUN test client" (without quotes)  */
  /* Username:  "evtj:h6vY" (without quotes)              */
  /* Password:  "VOkJxbRl1RmTxUk/WvJxBt" (without quotes) */
  const ruint8 pkt_rfc5769_2_1[] = {
    0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86,
    0xfa, 0x87, 0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73,
    0x74, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff,
    0x80, 0x29, 0x00, 0x08, 0x93, 0x2f, 0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09,
    0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76, 0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14,
    0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e, 0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49,
    0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf
  };
  const rchar * pwd = "VOkJxbRl1RmTxUk/WvJxBt";
  RStunAttrTLV tlv = R_STUN_ATTR_TLV_INIT;

  r_assert (r_stun_is_valid_msg (pkt_rfc5769_2_1, sizeof (pkt_rfc5769_2_1)));
  r_assert (r_stun_msg_is_request (pkt_rfc5769_2_1));
  r_assert (r_stun_msg_method_is_binding (pkt_rfc5769_2_1));

  r_assert (r_stun_attr_tlv_first (pkt_rfc5769_2_1, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_SOFTWARE);
  r_assert_cmpuint (r_strlen ("STUN test client"), ==, tlv.len);
  r_assert_cmpmem (tlv.value, ==, "STUN test client", tlv.len);
  r_assert (r_stun_attr_tlv_next (pkt_rfc5769_2_1, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_PRIORITY);
  r_assert_cmphex (r_stun_att_tlv_parse_lifetime (pkt_rfc5769_2_1, &tlv), ==, 0x6e0001ff);
  r_assert (r_stun_attr_tlv_next (pkt_rfc5769_2_1, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_ICE_CONTROLLED);
  r_assert (r_stun_attr_tlv_next (pkt_rfc5769_2_1, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_USERNAME);
  r_assert_cmpuint (r_strlen ("evtj:h6vY"), ==, tlv.len);
  r_assert_cmpmem (tlv.value, ==, "evtj:h6vY", tlv.len);
  r_assert (r_stun_attr_tlv_next (pkt_rfc5769_2_1, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_MESSAGE_INTEGRITY);
  r_assert (r_stun_msg_check_integrity_short_cred (pkt_rfc5769_2_1, &tlv,
        pwd, r_strlen (pwd)));
  r_assert (r_stun_attr_tlv_next (pkt_rfc5769_2_1, &tlv));
  r_assert_cmphex (tlv.type, ==, R_STUN_ATTR_TYPE_FINGERPRINT);
  r_assert (r_stun_msg_check_fingerprint (pkt_rfc5769_2_1, &tlv));
  r_assert (!r_stun_attr_tlv_next (pkt_rfc5769_2_1, &tlv));
}
RTEST_END;


