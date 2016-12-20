#include <rlib/rlib.h>

const rchar testcertpem[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIC8TCCAdmgAwIBAgIJALoi/+XOQDHjMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV\r\n"
  "BAMMBHJsaWIwHhcNMTYxMTE1MTMzNjI0WhcNMTcxMTE1MTMzNjI0WjAPMQ0wCwYD\r\n"
  "VQQDDARybGliMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwjolUmQU\r\n"
  "r9Q2FZ7O3qau+Z6+VvuJROvxzjt1aIQLLO/hF0Ya56BZCZD5aKyqQM//fTm97VTb\r\n"
  "CQYBaNg03D20XPDIWmr7EdHxYK+YI+jz7DrWqhM4jwSvvteXXXWD7bVdCq+RyveD\r\n"
  "NrgoGZqL5UCiWS1BWkB9nS/KQtgxrT3hWSOlG1xRh6hfeIy4H2CB3Qk/Q3PHjMcH\r\n"
  "7CKhCj+ctbqR3r2K3BLL3fgZKnfQdCPsZplN8Ey4hSOc/67NQK/yn/S0JgeHmjb8\r\n"
  "D5xbaDiOloOHJJg6dm1QU0UuEpiK2Uda0VR6TGu9Ci05h5U3HoV9CbyAGQhmFSem\r\n"
  "NreAELYv89sMgwIDAQABo1AwTjAdBgNVHQ4EFgQUXFVr3x4Bcglp/MP0ZFEk/Ntz\r\n"
  "wJYwHwYDVR0jBBgwFoAUXFVr3x4Bcglp/MP0ZFEk/NtzwJYwDAYDVR0TBAUwAwEB\r\n"
  "/zANBgkqhkiG9w0BAQsFAAOCAQEAL4ZKyDRXP3+Jr/GN+p6WbFW3tHuhxWxy8rMy\r\n"
  "W7OHX/sHASzJiaEmjtIlPx/7uFFowktEmXyybEmBvYp64UZ2mo2v+CCm+236wPTS\r\n"
  "gGfpcp9nP2RI0VFdJLHuqWapa5CQJZISRAO/tj7UqflOWBohm04EvmJe53JGEq+4\r\n"
  "Dk41kC+z3jVPGHG+jR3uYOw7JCmFT+bt4P5EDxGAKe9eoweLHBJ8vlJ7cUdHhBv1\r\n"
  "BUCMVR86kPZFzHKVQtWNXt26H/khgz7RA/qUSJA17Nk2h0h60b1AbkljkduWWIMZ\r\n"
  "5B2DUz4MEDUHjppHF9+A2q5ZN+25eOYbrkS5Dq50VPNrvd8dSQ==\r\n"
  "-----END CERTIFICATE-----\r\n";

const rchar testpkpem[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDCOiVSZBSv1DYV\r\n"
  "ns7epq75nr5W+4lE6/HOO3VohAss7+EXRhrnoFkJkPlorKpAz/99Ob3tVNsJBgFo\r\n"
  "2DTcPbRc8MhaavsR0fFgr5gj6PPsOtaqEziPBK++15dddYPttV0Kr5HK94M2uCgZ\r\n"
  "movlQKJZLUFaQH2dL8pC2DGtPeFZI6UbXFGHqF94jLgfYIHdCT9Dc8eMxwfsIqEK\r\n"
  "P5y1upHevYrcEsvd+Bkqd9B0I+xmmU3wTLiFI5z/rs1Ar/Kf9LQmB4eaNvwPnFto\r\n"
  "OI6Wg4ckmDp2bVBTRS4SmIrZR1rRVHpMa70KLTmHlTcehX0JvIAZCGYVJ6Y2t4AQ\r\n"
  "ti/z2wyDAgMBAAECggEABJZzAzsx8eVFUcVqhX/SajsBq/RNDb+0+nYVE97qlKkl\r\n"
  "2/Lf99ClycAO5BYP/2/qTP7sKYrzkYb+yYcx2HHsrLVTRi94trcKyIndQhvihxXs\r\n"
  "tB+4Gki2Df/xp1d7QkYiaHo1K2IlS0mWSOSJoWShcRHMlWEolmnmkSWiJsFrbTuL\r\n"
  "sxB/6lVmD6Bbez/ob5JzK4QBAEREd0QbUCQiDssFvf0nlDmtKrxosLFuu86z0nIR\r\n"
  "3OKyr9n6IW64r7x7Ccv/5pY3Cmkg0/knF4bi60ssm2byY2TW3wnOT0inVrp0UUQP\r\n"
  "ex9Dse3izVyMLaeqLh6GCQhLFROE85qslLmOYb56YQKBgQD7HHWdsrNDtkHkXvyz\r\n"
  "TWi8dPVMVk4/X/G3vPr2nBRHj9MzXX/ZgoFpklMsR/EtKh9LBBh9vY9YnXhIGUrc\r\n"
  "vwt1PSUIsjUuHBfhxnHxcZEu2ROw18LJmSRp6duZADFcH8ApPFg1dVZ2APyHyS4J\r\n"
  "tTL/DIeQ6ASq0EENjuO5VgM5PwKBgQDGAiz9c3/1OPZNiENyCYbrqOzduzkoisX7\r\n"
  "yGYFiJpLdsmrRsztqJktwiDEYYrJoV+AHmKa79Iexp6vvq9gQFN3XvFw6U1XXF5D\r\n"
  "RtLHHqWgoj9yFIpmVXfcdFICfNdPcVn7NAE0CQBRNgBJGSvRoSeTpOyjVmF9Mu18\r\n"
  "h2wUK0L3vQKBgBms7kXCmNvKjfA42iPHPXdPiilVBckrGT8NPqfqi5RJm3G8FK97\r\n"
  "zZmq0YBMltdkYDC+aXap5DdOWpccpu/tRNGm/9tkxVVCoBqAvPPQBeVBYucJGKye\r\n"
  "UP/XXpHFWEawJGjS9733knCcZzXHF0L82QsFD/N8FcYVZyFow9YWelvnAoGAIj8o\r\n"
  "FuIOJJSojPpfZ+7b5hB+f08tcKSn34dmldhtj1XJRZVmRkidzbtAvZZ9UahWgys+\r\n"
  "NLv75JTHx2+8l3IovYGvUq8XUF/Kcepi9EuJrAHD5XBGC7MGmxuHP6Tl/HiHbpot\r\n"
  "Bxnzcxha7kmrOYOc+71PrGR5UhUn3Bz0BX0CBSUCgYAKxDbgtJ1NZgf33yMQb1BG\r\n"
  "vgLQWiysO9t1dXFN9YiPsZ1Rkyj9iOdROG47T1ifcrCw45mqBF71COM23zplWz64\r\n"
  "wUg8Baom8FExrgLtVDeyQO7qkiOoP96r9Fm34Y4Sgv1/oiO9f5KYckMcSig9zCQA\r\n"
  "VFwqM04nD9RsYGRKy6NhrA==\r\n"
  "-----END PRIVATE KEY-----\r\n";


RTEST_FIXTURE_STRUCT (rtlsserver)
{
  RTLSServer * server;
  rboolean hs_done;

  RClock * clock;
  REvLoop * evloop;
  RPrng * prng;

  RQueue qout;
  RQueue qapp;
};

static void
r_tlsserver_test_hs_done (rpointer ctx, RTLSServer * server)
{
  RTEST_FIXTURE_STRUCT (rtlsserver) * fixture = ctx;
  (void) server;
  fixture->hs_done = TRUE;
}

static rboolean
r_tlsserver_test_buffer_out (rpointer ctx, RBuffer * buf, RTLSServer * server)
{
  RTEST_FIXTURE_STRUCT (rtlsserver) * fixture = ctx;
  (void) server;

  return r_queue_push (&fixture->qout, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsserver_test_buffer_appdata (rpointer ctx, RBuffer * buf, RTLSServer * server)
{
  RTEST_FIXTURE_STRUCT (rtlsserver) * fixture = ctx;
  (void) server;

  return r_queue_push (&fixture->qapp, r_buffer_ref (buf)) != NULL;
}

RTEST_FIXTURE_SETUP (rtlsserver)
{
  static RTLSCallbacks cbs = {
    NULL,
    r_tlsserver_test_hs_done,
    r_tlsserver_test_buffer_out,
    r_tlsserver_test_buffer_appdata,
  };
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((fixture->evloop = r_ev_loop_new_full (fixture->clock, NULL)), !=, NULL);
  fixture->hs_done = FALSE;

  r_queue_init (&fixture->qout);
  r_queue_init (&fixture->qapp);
  r_assert_cmpptr ((fixture->server = r_tls_server_new (&cbs, fixture, NULL)), !=, NULL);

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_server_set_cert (fixture->server, cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
}

RTEST_FIXTURE_TEARDOWN (rtlsserver)
{
  r_tls_server_unref (fixture->server);

  r_queue_clear (&fixture->qout, r_buffer_unref);
  r_queue_clear (&fixture->qapp, r_buffer_unref);
  r_ev_loop_unref (fixture->evloop);
  r_clock_unref (fixture->clock);
  r_prng_unref (fixture->prng);
}

static RBuffer *
r_test_tls_server_queue_agg (RQueue * q)
{
  RBuffer * ret, * cur;

  if (R_UNLIKELY (q == NULL)) return NULL;
  if (R_UNLIKELY (r_queue_is_empty (q))) return NULL;

  if ((ret = r_buffer_new ()) != NULL) {
    while ((cur = r_queue_pop (q)) != NULL) {
      r_buffer_append_mem_from_buffer (ret, cur);
      r_buffer_unref (cur);
    }
  }

  return ret;
}

#define r_test_tls_server_incoming_data(b) R_STMT_START {                     \
  RBuffer * buf;                                                              \
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,              \
          (rpointer)(b), sizeof (b), sizeof (b), 0, NULL, NULL)), !=, NULL);  \
  r_assert (r_tls_server_incoming_data (fixture->server, buf));               \
  r_buffer_unref (buf);                                                       \
} R_STMT_END

static const ruint8 pkt_dtls_client_hallo[] = {
  0x16, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9a, 0x01, 0x00, 0x00,
  0x8e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8e, 0xfe, 0xfd, 0x0e, 0x49, 0x7a, 0xe5, 0x2a,
  0x41, 0xa1, 0xfe, 0x3a, 0x13, 0x53, 0x11, 0x37, 0xf8, 0x97, 0xa7, 0x79, 0xa6, 0xab, 0xb1, 0x6c,
  0xdd, 0x9e, 0x4b, 0xf1, 0x2b, 0xbd, 0x5b, 0xa1, 0xe1, 0x3f, 0xf0, 0x00, 0x00, 0x00, 0x22, 0xc0,
  0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x09, 0xc0,
  0x13, 0x00, 0x33, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0x00, 0x9c, 0x00, 0x2f, 0x00, 0x35, 0x00,
  0x0a, 0x01, 0x00, 0x00, 0x42, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x23,
  0x00, 0x00, 0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
  0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01, 0x00, 0x0e, 0x00, 0x07, 0x00, 0x04,
  0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x08, 0x00,
  0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18
};

static const ruint8 pkt_dtls_client_finished[] = {
  0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x0e, 0x10, 0x00, 0x01,
  0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x76, 0x56, 0x2e, 0x83, 0xb6,
  0x97, 0x71, 0x7d, 0x95, 0xe0, 0xaf, 0x93, 0xb7, 0xa7, 0x89, 0x34, 0x9d, 0xa4, 0x14, 0xf9, 0xbf,
  0xe9, 0xfe, 0x16, 0xee, 0xaf, 0xb0, 0x08, 0x5c, 0x31, 0x05, 0xfc, 0xf8, 0xff, 0x54, 0x03, 0x05,
  0xaf, 0x63, 0x82, 0xed, 0x0e, 0xae, 0x6b, 0x96, 0x9d, 0x81, 0xfb, 0x67, 0x98, 0xfd, 0x96, 0x71,
  0x52, 0x53, 0x5f, 0x60, 0xc1, 0xac, 0x21, 0x5d, 0xc3, 0xaf, 0x1a, 0x1b, 0x39, 0x18, 0xb5, 0x10,
  0xa7, 0x4f, 0xb8, 0x1b, 0xbe, 0xcf, 0xba, 0xbe, 0x57, 0x85, 0xbf, 0xce, 0xd0, 0x70, 0x50, 0x25,
  0xaa, 0xe5, 0x75, 0x9c, 0x47, 0x8b, 0xc1, 0x28, 0x88, 0x07, 0xe1, 0x8a, 0x47, 0x4e, 0x14, 0x8a,
  0x55, 0x7e, 0xb9, 0x0b, 0x81, 0x34, 0x12, 0x27, 0x5b, 0x03, 0x4c, 0x62, 0xfd, 0x95, 0x52, 0x8d,
  0x75, 0x3a, 0xfd, 0x21, 0x00, 0xc3, 0xd7, 0xef, 0x21, 0xeb, 0x26, 0x36, 0xe2, 0xf0, 0x4a, 0x86,
  0xc7, 0x73, 0x57, 0xb9, 0xea, 0xb7, 0xf2, 0x6b, 0x08, 0x5a, 0x2a, 0xb3, 0xbc, 0x61, 0x8f, 0xfa,
  0xd7, 0x26, 0x1e, 0xaf, 0xf3, 0x2b, 0x8a, 0x5d, 0xa2, 0xa9, 0x14, 0xc7, 0x5b, 0x57, 0x40, 0xa1,
  0x81, 0x72, 0x82, 0xe9, 0x79, 0x52, 0xb8, 0x04, 0x7a, 0x98, 0x1e, 0x92, 0x7e, 0x00, 0xb3, 0x24,
  0x99, 0x6d, 0x66, 0x00, 0x2f, 0x7f, 0x97, 0x55, 0x9c, 0x80, 0xc7, 0xa4, 0x36, 0x0b, 0xff, 0xcf,
  0x61, 0xce, 0x1c, 0x78, 0xfd, 0xba, 0x36, 0x6d, 0x31, 0x12, 0x45, 0xd9, 0xa7, 0x1e, 0xe3, 0x53,
  0x0d, 0x99, 0x38, 0x45, 0x81, 0x1f, 0x76, 0x19, 0x9d, 0xc3, 0x76, 0x73, 0x44, 0xda, 0x84, 0xf4,
  0x6a, 0xd2, 0x7e, 0xbb, 0xfb, 0x6b, 0x7d, 0x90, 0x5e, 0x13, 0xa2, 0xff, 0xb4, 0x33, 0x18, 0xd6,
  0x03, 0xd3, 0xef, 0x02, 0x57, 0x80, 0xcb, 0x70, 0x49, 0x5f, 0x65, 0x14, 0xfe, 0xfd, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x01, 0x16, 0xfe, 0xfd, 0x00, 0x01, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x4b, 0xe7, 0x61, 0xd6, 0x94, 0x4f, 0xcf, 0x54, 0x22, 0x00,
  0x04, 0x78, 0x59, 0xaf, 0xaf, 0x57, 0xcf, 0x49, 0x38, 0x0e, 0x7a, 0xcd, 0xb5, 0xe2, 0x6f, 0x27,
  0x9e, 0xc1, 0x6b, 0xbb, 0xaf, 0xc0, 0x4f, 0x4e, 0xae, 0x4b, 0xd0, 0xe4, 0x54, 0x2d, 0x51, 0x1c,
  0x73, 0x4e, 0x87, 0x59, 0xce, 0x2d, 0x8b, 0xdb, 0x07, 0x0d, 0x80, 0x5b, 0x98, 0xcd, 0xcf, 0x97,
  0xd0, 0x8f, 0x79, 0x2e, 0x35, 0xb5
};


RTEST_F (rtlsserver, dtls_srtp_valid_handshake, RTEST_FAST)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RCryptoCipher * cipher;
  RHmac * hmac;
  RBuffer * buf;
  RTLSHandshakeType hs;
  ruint32 l;
  ruint16 msgseq;
  const RTLSCipherSuiteInfo * csinfo;
  static const ruint8 dtls_server_random[] = {
    0x58, 0x49, 0x81, 0x6a, 0x57, 0xc3, 0x49, 0x00, 0x29, 0x52, 0x8f, 0xac, 0xc7, 0x48, 0x57, 0x9e,
    0x26, 0x41, 0x87, 0xa6, 0xde, 0xd2, 0xe6, 0x72, 0x1a, 0x38, 0x08, 0x72, 0xdb, 0xd2, 0x09, 0x94
  };
  static const ruint8 server_enc_key[] = {
    0xba, 0x51, 0x90, 0x79, 0xa1, 0x0c, 0xa4, 0xce, 0x41, 0x0b, 0x37, 0xa2, 0x2c, 0x79, 0xca, 0x01
  };
  static const ruint8 server_mac_key[] = {
    0x6b, 0x29, 0x8f, 0x66, 0x8e, 0xbc, 0x51, 0x7d, 0x81, 0xbb, 0x6d, 0xd8, 0x08, 0x93, 0x59, 0x56,
    0x1e, 0xcf, 0x67, 0x21
  };

  r_assert_cmpptr ((cipher = r_cipher_aes_128_cbc_new (server_enc_key)), !=, NULL);
  r_assert_cmpptr ((hmac = r_hmac_new (R_HASH_TYPE_SHA1, server_mac_key, sizeof (server_mac_key))), !=, NULL);

  r_assert_cmpint (r_tls_server_set_random (fixture->server, dtls_server_random),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert (!fixture->hs_done);

  r_test_tls_server_incoming_data (pkt_dtls_client_hallo);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);

  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpuint (parser.epoch, ==, 0);
  r_assert_cmpuint (parser.seqno, ==, 0);
  r_assert_cmpuint (parser.fragment.size, ==, 66);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO);
  r_assert_cmpuint (msgseq, ==, 0);
  r_assert_cmpuint (l, ==, 54);
  {
    RTLSHelloMsg msg;

    r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_parser_parse_hello (&parser, &msg));
    r_assert_cmpuint (msg.version, ==, R_TLS_VERSION_DTLS_1_2);
    r_assert_cmpuint (msg.sidlen, ==, 0);
    r_assert_cmpuint (msg.cookielen, ==, 0);
    r_assert_cmpuint (msg.complen, ==, 1);
    r_assert_cmpuint (msg.cslen, ==, 2);
    r_assert_cmpuint (msg.extlen, >, 0);
  }

  {
    RTLSCertificate tlscert = R_TLS_CERTIFICATE_INIT;

    r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
    r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_2);
    r_assert_cmpuint (parser.epoch, ==, 0);
    r_assert_cmpuint (parser.seqno, ==, 1);
    r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
          &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
    r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_CERTIFICATE);
    r_assert_cmpuint (msgseq, ==, 1);
    r_assert_cmpuint (l, >, 0);

    r_assert_cmpint (r_tls_parser_parse_certificate_next (&parser, &tlscert), ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (tlscert.len, ==, 757);
  }

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpuint (parser.epoch, ==, 0);
  r_assert_cmpuint (parser.seqno, ==, 2);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE);
  r_assert_cmpuint (msgseq, ==, 2);
  r_assert_cmpuint (l, ==, 0);

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_EOB);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  /* ClientKeyExchange, ChangeCipherSpec & Finished */
  r_assert (!fixture->hs_done);
  r_test_tls_server_incoming_data (pkt_dtls_client_finished);
  r_assert (fixture->hs_done);

  r_assert_cmphex (r_tls_server_get_version (fixture->server), ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpptr ((csinfo = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpstr (csinfo->str, ==, "TLS-RSA-WITH-AES-128-CBC-SHA");
  r_assert_cmphex (r_tls_server_get_dtls_srtp_profile (fixture->server), ==,
      R_SRTP_CS_AES_128_CM_HMAC_SHA1_80);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpuint (parser.epoch, ==, 0);
  r_assert_cmpuint (parser.seqno, ==, 3);
  r_assert_cmpuint (parser.fragment.size, ==, 1);
  r_assert_cmpuint (parser.fragment.data[0], ==, 1);

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpuint (parser.epoch, ==, 1);
  r_assert_cmpuint (parser.seqno, ==, 0);

  /* Finished struct is encrypted! */
  r_assert_cmpint (r_tls_parser_decrypt (&parser, cipher, hmac), ==, R_TLS_ERROR_OK);
  {
    const ruint8 * verify_data;
    rsize verify_size;

    r_assert_cmpint (r_tls_parser_parse_finished (&parser, &verify_data, &verify_size),
        ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (verify_size, ==, 12);
  }

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_EOB);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);
}
RTEST_END;

