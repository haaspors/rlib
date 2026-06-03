#include <rlib/rnet.h>
#include <rlib/rcrypto.h>

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
  rboolean got_error;
  RTLSAlertType last_alert;

  RClock * clock;
  REvLoop * evloop;
  RPrng * prng;

  RQueue qout;
  RQueue qapp;
};

static void
r_tlsserver_test_hs_done (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsserver) * fixture = ctx;
  (void) session;
  fixture->hs_done = TRUE;
}

static void
r_tlsserver_test_error (rpointer ctx, RTLSAlertType alert, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsserver) * fixture = ctx;
  (void) session;
  fixture->got_error = TRUE;
  fixture->last_alert = alert;
}

static rboolean
r_tlsserver_test_buffer_out (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsserver) * fixture = ctx;
  (void) session;

  return r_queue_push (&fixture->qout, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsserver_test_buffer_appdata (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsserver) * fixture = ctx;
  (void) session;

  return r_queue_push (&fixture->qapp, r_buffer_ref (buf)) != NULL;
}

RTEST_FIXTURE_SETUP (rtlsserver)
{
  static RTLSCallbacks cbs = {
    NULL,
    r_tlsserver_test_hs_done,
    r_tlsserver_test_buffer_out,
    r_tlsserver_test_buffer_appdata,
    r_tlsserver_test_error,
    NULL,
  };
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((fixture->evloop = r_ev_loop_new_full (fixture->clock, NULL)), !=, NULL);
  fixture->hs_done = FALSE;
  fixture->got_error = FALSE;
  fixture->last_alert = R_TLS_ALERT_TYPE_CLOSE_NOTIFY;

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

/* Wrap a raw byte range in a buffer and feed it to the server. */
static void
r_test_tls_server_feed (RTLSServer * server, const ruint8 * data, rsize size)
{
  RBuffer * buf;

  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)data, size, size, 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_incoming_data (server, buf));
  r_buffer_unref (buf);
}

/* Absorb one (D)TLS record's handshake fragment into a transcript hash,
 * exactly as the server does, so a test client can reproduce the
 * handshake hashes. */
static void
r_test_tls_hash_record (RMsgDigest * md, const ruint8 * data, rsize size)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RBuffer * buf;

  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)data, size, size, 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}

/* Build a minimal DTLS 1.2 ClientHello (RSA-AES128-CBC-SHA, null
 * compression) into @out; returns its length. @scsv adds the
 * TLS_EMPTY_RENEGOTIATION_INFO_SCSV cipher; @renego_ext appends a
 * renegotiation_info extension carrying a @renegolen-byte
 * renegotiated_connection; @ems appends the extended_master_secret
 * extension; @etm appends the encrypt_then_mac extension. */
static rsize
r_test_tls_build_dtls_client_hello (RPrng * prng, ruint8 * out, rsize outsz,
    rboolean ems, rboolean etm, rboolean scsv, rboolean renego_ext,
    const ruint8 * renego, ruint8 renegolen)
{
  ruint8 body[256];
  ruint8 * p = body;
  ruint8 * extlenp;
  rsize bodylen, hs, nsuites;

  *p++ = 0xfe; *p++ = 0xfd;                  /* client_version DTLS 1.2 */
  r_prng_fill (prng, p, R_TLS_HELLO_RANDOM_BYTES); p += R_TLS_HELLO_RANDOM_BYTES;
  *p++ = 0;                                  /* session id length */
  *p++ = 0;                                  /* cookie length (DTLS) */
  nsuites = scsv ? 2 : 1;
  r_store_be16 (p, (ruint16)(nsuites * sizeof (ruint16))); p += 2;
  r_store_be16 (p, (ruint16)R_TLS_CS_RSA_WITH_AES_128_CBC_SHA); p += 2;
  if (scsv) {
    r_store_be16 (p, (ruint16)R_TLS_CS_EMPTY_RENEGOTIATION_INFO_SCSV); p += 2;
  }
  *p++ = 1; *p++ = 0;                        /* compression: null */
  extlenp = p; p += 2;                       /* extensions length placeholder */
  if (renego_ext) {
    r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_RENEGOTIATION_INFO); p += 2;
    r_store_be16 (p, (ruint16)(1 + renegolen)); p += 2;
    *p++ = renegolen;
    if (renegolen > 0) { r_memcpy (p, renego, renegolen); p += renegolen; }
  }
  if (ems) {
    r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET); p += 2;
    r_store_be16 (p, 0); p += 2;
  }
  if (etm) {
    r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC); p += 2;
    r_store_be16 (p, 0); p += 2;
  }
  r_store_be16 (extlenp, (ruint16)(p - (extlenp + 2)));
  bodylen = (rsize)(p - body);

  r_assert_cmpint (r_dtls_write_handshake (out, outsz, &hs,
        R_TLS_VERSION_DTLS_1_2, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
        (ruint16)bodylen, 0, 0, 0, 0, (ruint32)bodylen), ==, R_TLS_ERROR_OK);
  r_memcpy (out + hs, body, bodylen);
  return hs + bodylen;
}

/* Minimal DTLS 1.2 RSA client completing a handshake against the server
 * under test. It mirrors the server's transcript hashing by feeding the
 * same handshake-message fragments, derives the master secret per RFC 7627
 * when the ServerHello negotiated extended master secret (else the legacy
 * client+server-random seed), then sends ClientKeyExchange,
 * ChangeCipherSpec and an encrypted Finished. The handshake completing
 * therefore proves the server derived the same master secret. The negotiated
 * server write keys are returned via @srv_cipher / @srv_hmac so the caller
 * can decrypt the server's Finished. */
static void
r_test_tls_dtls_client_complete (RTLSServer * server, RPrng * prng,
    const ruint8 * ch, rsize chlen, const ruint8 * srvflight, rsize srvlen,
    rboolean ems, rboolean etm, RCryptoCipher ** srv_cipher, RHmac ** srv_hmac)
{
  RCryptoKey * pk;
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RMsgDigest * md;
  ruint8 crand[R_TLS_HELLO_RANDOM_BYTES], srand[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 pms[48], ms[48], kb[128], vd[12], iv[16];
  ruint8 sh[64];
  ruint8 enc[512];
  ruint8 ckebuf[512], finbuf[64], ccsbuf[32];
  rsize enclen = sizeof (enc), shlen, ckehs, ckelen, finhs, ccslen;
  RCryptoCipher * cipher;
  RHmac * hmac;
  RBuffer * plain, * encbuf;
  rboolean seen_ems = FALSE, seen_etm = FALSE;
  RTLSError e;

  /* The server's RSA key: rlib's r_crypto_key_encrypt drives the public
   * operation off the private key object (only the public exponent is used),
   * which is exactly what a client encrypting to the cert's key needs. */
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);

  /* transcript += ClientHello, and capture the client random */
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)ch, chlen, chlen, 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_memcpy (crand, hello.random, sizeof (crand));
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  /* transcript += server flight; capture server random and EMS negotiation */
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)srvflight, srvlen, srvlen, 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_memcpy (srand, hello.random, sizeof (srand));
  {
    RTLSHelloExt ext;
    for (e = r_tls_hello_msg_extension_first (&hello, &ext); e == R_TLS_ERROR_OK;
        e = r_tls_hello_msg_extension_next (&hello, &ext)) {
      if (ext.type == R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET)
        seen_ems = TRUE;
      else if (ext.type == R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC)
        seen_etm = TRUE;
    }
  }
  while (r_tls_parser_init_next (&parser, NULL) == R_TLS_ERROR_OK)
    r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
  r_assert_cmpint (seen_ems, ==, ems);
  r_assert_cmpint (seen_etm, ==, etm);

  /* ClientKeyExchange: RSA-encrypt a 48-byte pre-master secret */
  pms[0] = 0xfe; pms[1] = 0xfd;
  r_prng_fill (prng, pms + 2, sizeof (pms) - 2);
  r_assert_cmpint (r_crypto_key_encrypt (pk, prng, pms, sizeof (pms), enc, &enclen),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_dtls_write_handshake (ckebuf, sizeof (ckebuf), &ckehs,
        R_TLS_VERSION_DTLS_1_2, R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
        (ruint16)(2 + enclen), 0, 1, 1, 0, (ruint32)(2 + enclen)), ==, R_TLS_ERROR_OK);
  r_store_be16 (ckebuf + ckehs, (ruint16)enclen);
  r_memcpy (ckebuf + ckehs + 2, enc, enclen);
  ckelen = ckehs + 2 + enclen;
  r_test_tls_hash_record (md, ckebuf, ckelen);

  /* session hash (transcript through ClientKeyExchange) drives EMS */
  shlen = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, sh, shlen, NULL));

  if (ems)
    r_assert_cmpint (r_tls_1_2_prf_sha256 (ms, sizeof (ms), pms, sizeof (pms),
          R_STR_WITH_SIZE_ARGS ("extended master secret"), sh, shlen, NULL),
        ==, R_TLS_ERROR_OK);
  else
    r_assert_cmpint (r_tls_1_2_prf_sha256 (ms, sizeof (ms), pms, sizeof (pms),
          R_STR_WITH_SIZE_ARGS ("master secret"),
          crand, sizeof (crand), srand, sizeof (srand), NULL), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_1_2_prf_sha256 (kb, sizeof (kb), ms, sizeof (ms),
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        srand, sizeof (srand), crand, sizeof (crand), NULL), ==, R_TLS_ERROR_OK);
  /* keyblock: client MAC | server MAC | client key | server key */
  r_assert_cmpint (r_tls_1_2_prf_sha256 (vd, sizeof (vd), ms, sizeof (ms),
        R_STR_WITH_SIZE_ARGS ("client finished"), sh, shlen, NULL), ==, R_TLS_ERROR_OK);

  /* encrypted Finished (epoch 1) */
  r_assert_cmpint (r_dtls_write_handshake (finbuf, sizeof (finbuf), &finhs,
        R_TLS_VERSION_DTLS_1_2, R_TLS_HANDSHAKE_TYPE_FINISHED, sizeof (vd),
        1, 0, 2, 0, sizeof (vd)), ==, R_TLS_ERROR_OK);
  r_memcpy (finbuf + finhs, vd, sizeof (vd));
  r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, finbuf,
          finhs + sizeof (vd), finhs + sizeof (vd), 0, NULL, NULL)), !=, NULL);
  r_assert_cmpptr ((cipher = r_cipher_aes_128_cbc_new (kb + 40)), !=, NULL);
  r_assert_cmpptr ((hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb, 20)), !=, NULL);
  r_prng_fill (prng, iv, sizeof (iv));
  r_assert_cmpptr ((encbuf = r_dtls_encrypt_buffer (plain, cipher, iv, hmac, etm)), !=, NULL);
  r_buffer_unref (plain);
  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);

  /* ChangeCipherSpec (epoch 0) */
  r_assert_cmpint (r_dtls_write_change_cipher (ccsbuf, sizeof (ccsbuf), &ccslen,
        R_TLS_VERSION_DTLS_1_2, 0, 2), ==, R_TLS_ERROR_OK);

  /* server write keys, for the caller to decrypt the server Finished */
  r_assert_cmpptr ((*srv_cipher = r_cipher_aes_128_cbc_new (kb + 56)), !=, NULL);
  r_assert_cmpptr ((*srv_hmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb + 20, 20)), !=, NULL);

  /* send the client flight */
  r_test_tls_server_feed (server, ckebuf, ckelen);
  r_test_tls_server_feed (server, ccsbuf, ccslen);
  r_assert (r_tls_server_incoming_data (server, encbuf));
  r_buffer_unref (encbuf);

  r_memclear_secure (pms, sizeof (pms));
  r_memclear_secure (ms, sizeof (ms));
  r_memclear_secure (kb, sizeof (kb));
  r_msg_digest_free (md);
  r_crypto_key_unref (pk);
}


/* Drive the server through a full DTLS handshake using the captured
 * ClientHello (which offers extended_master_secret and use_srtp) and the
 * in-test client, then verify the negotiated state and decrypt the server
 * Finished. Exercises EMS end to end: the handshake only completes if the
 * server derived the same RFC 7627 master secret as the client. */
RTEST_F (rtlsserver, dtls_srtp_valid_handshake, RTEST_FAST)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RCryptoCipher * cipher = NULL;
  RHmac * hmac = NULL;
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSHandshakeType hs;
  ruint32 l;
  ruint16 msgseq;
  rboolean seen_ems;
  const RTLSCipherSuiteInfo * csinfo;
  static const ruint8 dtls_server_random[] = {
    0x58, 0x49, 0x81, 0x6a, 0x57, 0xc3, 0x49, 0x00, 0x29, 0x52, 0x8f, 0xac, 0xc7, 0x48, 0x57, 0x9e,
    0x26, 0x41, 0x87, 0xa6, 0xde, 0xd2, 0xe6, 0x72, 0x1a, 0x38, 0x08, 0x72, 0xdb, 0xd2, 0x09, 0x94
  };

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
  /* 66 bytes pre-EMS; the echoed extended_master_secret extension adds 4 */
  r_assert_cmpuint (parser.fragment.size, ==, 70);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO);
  r_assert_cmpuint (msgseq, ==, 0);
  r_assert_cmpuint (l, ==, 58);
  {
    RTLSHelloMsg msg;
    RTLSHelloExt ext;
    RTLSError e;

    r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_parser_parse_hello (&parser, &msg));
    r_assert_cmpuint (msg.version, ==, R_TLS_VERSION_DTLS_1_2);
    r_assert_cmpuint (msg.sidlen, ==, 0);
    r_assert_cmpuint (msg.cookielen, ==, 0);
    r_assert_cmpuint (msg.complen, ==, 1);
    r_assert_cmpuint (msg.cslen, ==, 2);
    r_assert_cmpuint (msg.extlen, >, 0);

    seen_ems = FALSE;
    for (e = r_tls_hello_msg_extension_first (&msg, &ext); e == R_TLS_ERROR_OK;
        e = r_tls_hello_msg_extension_next (&msg, &ext)) {
      if (ext.type == R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET) {
        seen_ems = TRUE;
        r_assert_cmpuint (ext.len, ==, 0);
      }
    }
    r_assert (seen_ems);
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

  /* Complete the handshake with the in-test client over the server flight. */
  r_assert (!fixture->hs_done);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_test_tls_dtls_client_complete (fixture->server, fixture->prng,
      pkt_dtls_client_hallo, sizeof (pkt_dtls_client_hallo), info.data, info.size,
      TRUE, FALSE, &cipher, &hmac);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);
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

  /* The server Finished is encrypted; decrypt it with the keys the client
   * derived from the shared (EMS) master secret. */
  r_assert_cmpint (r_tls_parser_decrypt (&parser, cipher, hmac, FALSE), ==, R_TLS_ERROR_OK);
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

/* A ClientHello that does not offer extended_master_secret must complete on
 * the legacy client+server-random master secret, and the ServerHello must
 * not echo the extension. */
RTEST_F (rtlsserver, dtls_handshake_without_ems, RTEST_FAST)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RCryptoCipher * cipher = NULL;
  RHmac * hmac = NULL;
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint8 ch[256];
  rsize chlen;
  RTLSHelloMsg msg;
  RTLSHelloExt ext;
  RTLSError e;
  rboolean seen_ems = FALSE;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, FALSE, FALSE, TRUE, NULL, 0);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &msg), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&msg, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&msg, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET)
      seen_ems = TRUE;
  }
  r_assert (!seen_ems);
  r_tls_parser_clear (&parser);

  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_test_tls_dtls_client_complete (fixture->server, fixture->prng,
      ch, chlen, info.data, info.size, FALSE, FALSE, &cipher, &hmac);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);

  r_assert (fixture->hs_done);

  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);
}
RTEST_END;

/* RFC 7366: a ClientHello offering encrypt_then_mac (with a CBC suite) must
 * have the extension echoed and the handshake complete with encrypt-then-MAC
 * record protection in both directions. */
RTEST_F (rtlsserver, dtls_encrypt_then_mac_handshake, RTEST_FAST)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RCryptoCipher * cipher = NULL;
  RHmac * hmac = NULL;
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSHelloMsg msg;
  RTLSHelloExt ext;
  RTLSError e;
  ruint8 ch[256];
  rsize chlen;
  rboolean seen_etm = FALSE;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, TRUE, FALSE, TRUE, NULL, 0);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &msg), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&msg, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&msg, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_ENCRYPT_THEN_MAC) {
      seen_etm = TRUE;
      r_assert_cmpuint (ext.len, ==, 0);
    }
  }
  r_assert (seen_etm);
  r_tls_parser_clear (&parser);

  /* Complete the handshake; the in-test client uses EtM record protection.
   * hs_done implies the server accepted the EtM-protected client Finished. */
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_test_tls_dtls_client_complete (fixture->server, fixture->prng,
      ch, chlen, info.data, info.size, FALSE, TRUE, &cipher, &hmac);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);
  r_assert (fixture->hs_done);

  /* The server Finished must be EtM-protected: decrypt it with EtM. */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);
  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.epoch, ==, 1);
  r_assert_cmpint (r_tls_parser_decrypt (&parser, cipher, hmac, TRUE), ==, R_TLS_ERROR_OK);
  {
    const ruint8 * verify_data;
    rsize verify_size;

    r_assert_cmpint (r_tls_parser_parse_finished (&parser, &verify_data, &verify_size),
        ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (verify_size, ==, 12);
  }

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);
}
RTEST_END;


RTEST_F (rtlsserver, dtls_handshake_error_alert, RTEST_FAST)
{
  /* A DTLS handshake record whose type is neither ClientHello nor
   * ServerHello (0x0b = Certificate) is unexpected in the hello state. */
  static const ruint8 pkt_bad_hs[] = {
    0x16, 0xfe, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c,
    0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  r_test_tls_server_incoming_data (pkt_bad_hs);

  /* The error callback fired with the alert that was sent. */
  r_assert (fixture->got_error);
  r_assert_cmpuint (fixture->last_alert, ==, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
  r_assert (!fixture->hs_done);

  /* A fatal alert record was emitted to the peer. */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST_F (rtlsserver, tls_handshake_error_alert, RTEST_FAST)
{
  /* As above but over a (non-DTLS) TLS 1.2 record, exercising the
   * r_tls_write_alert framing path. 0x0b = Certificate, unexpected in
   * the hello state. */
  static const ruint8 pkt_bad_hs[] = {
    0x16, 0x03, 0x03, 0x00, 0x04, 0x0b, 0x00, 0x00, 0x00
  };
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  r_test_tls_server_incoming_data (pkt_bad_hs);

  r_assert (fixture->got_error);
  r_assert_cmpuint (fixture->last_alert, ==, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
  r_assert (!fixture->hs_done);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert (!r_tls_parser_is_dtls (&parser));
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;

/* RFC 5746: a non-empty renegotiated_connection in the initial ClientHello
 * (rlib does not renegotiate) must abort with a fatal handshake_failure. */
RTEST_F (rtlsserver, dtls_renegotiation_info_not_empty, RTEST_FAST)
{
  static const ruint8 renego[] = { 0xde, 0xad, 0xbe, 0xef };
  ruint8 ch[256];
  rsize chlen;
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, FALSE, FALSE, TRUE, renego, sizeof (renego));
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_assert (fixture->got_error);
  r_assert_cmpuint (fixture->last_alert, ==, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
  r_assert (!fixture->hs_done);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;

/* RFC 5746 3.6: TLS_EMPTY_RENEGOTIATION_INFO_SCSV signals secure
 * renegotiation like an empty renegotiation_info extension, so the
 * ServerHello must echo a renegotiation_info extension. */
RTEST_F (rtlsserver, dtls_renegotiation_info_scsv, RTEST_FAST)
{
  ruint8 ch[256];
  rsize chlen;
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg msg;
  RTLSHelloExt ext;
  RTLSError e;
  rboolean seen_renego = FALSE;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, FALSE, TRUE, FALSE, NULL, 0);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_assert (!fixture->got_error);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &msg), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&msg, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&msg, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_RENEGOTIATION_INFO) {
      seen_renego = TRUE;
      r_assert_cmpuint (ext.len, ==, 1);  /* empty renegotiated_connection */
      r_assert_cmpuint (ext.data[0], ==, 0);
    }
  }
  r_assert (seen_renego);

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;

/* A ClientHello whose trailing extension declares a body that isn't present
 * must be parsed without reading past the extensions block: the extension
 * iterator stops at the truncated entry and the handshake proceeds from the
 * valid ones. (Regression for the missing body-bounds check in
 * r_tls_hello_msg_extension_next.) */
RTEST_F (rtlsserver, dtls_clienthello_truncated_extension, RTEST_FAST)
{
  ruint8 body[128];
  ruint8 * p = body;
  ruint8 * extlenp;
  ruint8 ch[256];
  rsize bodylen, hs, chlen;
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;

  *p++ = 0xfe; *p++ = 0xfd;                  /* client_version DTLS 1.2 */
  r_prng_fill (fixture->prng, p, R_TLS_HELLO_RANDOM_BYTES); p += R_TLS_HELLO_RANDOM_BYTES;
  *p++ = 0;                                  /* session id length */
  *p++ = 0;                                  /* cookie length */
  r_store_be16 (p, 2); p += 2;
  r_store_be16 (p, (ruint16)R_TLS_CS_RSA_WITH_AES_128_CBC_SHA); p += 2;
  *p++ = 1; *p++ = 0;                        /* compression: null */
  extlenp = p; p += 2;
  /* valid empty renegotiation_info */
  r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_RENEGOTIATION_INFO); p += 2;
  r_store_be16 (p, 1); p += 2; *p++ = 0;
  /* trailing renegotiation_info declaring 10 bytes with none present */
  r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_RENEGOTIATION_INFO); p += 2;
  r_store_be16 (p, 10); p += 2;
  r_store_be16 (extlenp, (ruint16)(p - (extlenp + 2)));
  bodylen = (rsize)(p - body);

  r_assert_cmpint (r_dtls_write_handshake (ch, sizeof (ch), &hs,
        R_TLS_VERSION_DTLS_1_2, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
        (ruint16)bodylen, 0, 0, 0, 0, (ruint32)bodylen), ==, R_TLS_ERROR_OK);
  r_memcpy (ch + hs, body, bodylen);
  chlen = hs + bodylen;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  /* Handled without an over-read: the truncated extension is dropped and the
   * server answers from the valid first extension. */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;

/* After the handshake the server can encrypt and emit application data via
 * r_tls_server_send_appdata; the record decrypts back to the sent bytes. */
RTEST_F (rtlsserver, dtls_send_appdata, RTEST_FAST)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RCryptoCipher * cipher = NULL;
  RHmac * hmac = NULL;
  RBuffer * buf, * app;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint8 ch[256];
  rsize chlen;
  static const ruint8 appdata[] = {
    'h', 'e', 'l', 'l', 'o', ' ', 'a', 'p', 'p', 'd', 'a', 't', 'a'
  };

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, FALSE, FALSE, TRUE, NULL, 0);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_test_tls_dtls_client_complete (fixture->server, fixture->prng,
      ch, chlen, info.data, info.size, FALSE, FALSE, &cipher, &hmac);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);
  r_assert (fixture->hs_done);

  /* Drop the server's ChangeCipherSpec + Finished flight. */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_buffer_unref (buf);

  /* Send application data and recover it from the emitted record. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)appdata, sizeof (appdata), sizeof (appdata), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_APPLICATION_DATA);
  r_assert_cmpuint (parser.epoch, ==, 1);
  r_assert_cmpint (r_tls_parser_decrypt (&parser, cipher, hmac, FALSE), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.fragment.size, ==, sizeof (appdata));
  r_assert_cmpint (r_memcmp (parser.fragment.data, appdata, sizeof (appdata)), ==, 0);

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);
}
RTEST_END;

/* Over a (non-DTLS) TLS connection the record sequence number is implicit and
 * must advance per record: the client Finished is read seqno 0, the first
 * application_data record is seqno 1. A regression where the server MAC'd
 * every TLS record with seqno 0 completed the handshake (Finished is 0) but
 * dropped the first appdata record. Drive a full TLS RSA handshake with an
 * in-test client, then send one appdata record and assert it is delivered. */
RTEST_F (rtlsserver, tls_appdata_second_record_seqno, RTEST_FAST)
{
  RCryptoKey * pk;
  RMsgDigest * md;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RBuffer * buf, * plain, * enc;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RCryptoCipher * ccipher;
  RHmac * chmac;
  ruint8 chbody[128], ch[256];
  ruint8 crand[R_TLS_HELLO_RANDOM_BYTES], srand[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 pms[48], ms[48], kb[128], vd[12], iv[16], sh[64];
  ruint8 encpms[512], cke[512], fin[64], ccs[16];
  rsize chlen, chbodylen, hs, enclen = sizeof (encpms), ckelen, finhs, ccslen, shlen;
  ruint8 * p = chbody;
  ruint8 * extlenp;
  static const ruint8 appdata[] = { 'p', 'i', 'n', 'g' };

  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);

  /* TLS 1.2 ClientHello (RSA-AES128-CBC-SHA, null compression, empty
   * renegotiation_info; no extended_master_secret -> legacy key derivation). */
  *p++ = 0x03; *p++ = 0x03;
  r_prng_fill (fixture->prng, p, R_TLS_HELLO_RANDOM_BYTES);
  r_memcpy (crand, p, R_TLS_HELLO_RANDOM_BYTES); p += R_TLS_HELLO_RANDOM_BYTES;
  *p++ = 0;                                  /* session id length */
  r_store_be16 (p, 2); p += 2;
  r_store_be16 (p, (ruint16)R_TLS_CS_RSA_WITH_AES_128_CBC_SHA); p += 2;
  *p++ = 1; *p++ = 0;                        /* compression: null */
  extlenp = p; p += 2;
  r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_RENEGOTIATION_INFO); p += 2;
  r_store_be16 (p, 1); p += 2; *p++ = 0;
  r_store_be16 (extlenp, (ruint16)(p - (extlenp + 2)));
  chbodylen = (rsize)(p - chbody);

  r_assert_cmpint (r_tls_write_handshake (ch, sizeof (ch), &hs, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO, (ruint16)chbodylen), ==, R_TLS_ERROR_OK);
  r_memcpy (ch + hs, chbody, chbodylen);
  chlen = hs + chbodylen;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (fixture->server, ch, chlen);
  r_test_tls_hash_record (md, ch, chlen);

  /* server flight: ServerHello (capture server random) + Certificate + HelloDone */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_memcpy (srand, hello.random, sizeof (srand));
  while (r_tls_parser_init_next (&parser, NULL) == R_TLS_ERROR_OK)
    r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  /* ClientKeyExchange */
  pms[0] = 0x03; pms[1] = 0x03;
  r_prng_fill (fixture->prng, pms + 2, sizeof (pms) - 2);
  r_assert_cmpint (r_crypto_key_encrypt (pk, fixture->prng, pms, sizeof (pms), encpms, &enclen),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_tls_write_handshake (cke, sizeof (cke), &hs, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, (ruint16)(2 + enclen)), ==, R_TLS_ERROR_OK);
  r_store_be16 (cke + hs, (ruint16)enclen);
  r_memcpy (cke + hs + 2, encpms, enclen);
  ckelen = hs + 2 + enclen;
  r_test_tls_hash_record (md, cke, ckelen);

  /* legacy master secret + key block (client MAC | server MAC | client key | ...) */
  shlen = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, sh, shlen, NULL));
  r_assert_cmpint (r_tls_1_2_prf_sha256 (ms, sizeof (ms), pms, sizeof (pms),
        R_STR_WITH_SIZE_ARGS ("master secret"),
        crand, sizeof (crand), srand, sizeof (srand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_1_2_prf_sha256 (kb, sizeof (kb), ms, sizeof (ms),
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        srand, sizeof (srand), crand, sizeof (crand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_1_2_prf_sha256 (vd, sizeof (vd), ms, sizeof (ms),
        R_STR_WITH_SIZE_ARGS ("client finished"), sh, shlen, NULL), ==, R_TLS_ERROR_OK);

  r_assert_cmpptr ((ccipher = r_cipher_aes_128_cbc_new (kb + 40)), !=, NULL);
  r_assert_cmpptr ((chmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb, 20)), !=, NULL);

  /* encrypted Finished (client write seqno 0) */
  r_assert_cmpint (r_tls_write_handshake (fin, sizeof (fin), &finhs, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_FINISHED, sizeof (vd)), ==, R_TLS_ERROR_OK);
  r_memcpy (fin + finhs, vd, sizeof (vd));
  r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, fin,
          finhs + sizeof (vd), finhs + sizeof (vd), 0, NULL, NULL)), !=, NULL);
  r_prng_fill (fixture->prng, iv, sizeof (iv));
  r_assert_cmpptr ((enc = r_tls_encrypt_buffer (plain, 0, ccipher, iv, chmac, FALSE)), !=, NULL);
  r_buffer_unref (plain);

  /* ChangeCipherSpec + Finished */
  r_assert_cmpint (r_tls_write_change_cipher (ccs, sizeof (ccs), &ccslen,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (fixture->server, cke, ckelen);
  r_test_tls_server_feed (fixture->server, ccs, ccslen);
  r_assert (r_buffer_map (enc, &info, R_MEM_MAP_READ));
  r_test_tls_server_feed (fixture->server, info.data, info.size);
  r_buffer_unmap (enc, &info);
  r_buffer_unref (enc);

  r_assert (fixture->hs_done);

  /* application_data record at client write seqno 1 — the regression dropped it */
  {
    ruint8 app[64];
    rsize applen;
    r_assert_cmpint (r_tls_write_application_data (app, sizeof (app), &applen,
          R_TLS_VERSION_TLS_1_2, appdata, sizeof (appdata)), ==, R_TLS_ERROR_OK);
    r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, app, applen, applen,
            0, NULL, NULL)), !=, NULL);
    r_prng_fill (fixture->prng, iv, sizeof (iv));
    r_assert_cmpptr ((enc = r_tls_encrypt_buffer (plain, 1, ccipher, iv, chmac, FALSE)), !=, NULL);
    r_buffer_unref (plain);
    r_assert (r_buffer_map (enc, &info, R_MEM_MAP_READ));
    r_test_tls_server_feed (fixture->server, info.data, info.size);
    r_buffer_unmap (enc, &info);
    r_buffer_unref (enc);
  }

  /* the appdata callback must have received the decrypted bytes */
  r_assert_cmpptr ((buf = r_queue_pop (&fixture->qapp)), !=, NULL);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, sizeof (appdata));
  r_assert_cmpint (r_memcmp (info.data, appdata, sizeof (appdata)), ==, 0);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);

  r_hmac_free (chmac);
  r_crypto_cipher_unref (ccipher);
  r_memclear_secure (pms, sizeof (pms));
  r_memclear_secure (ms, sizeof (ms));
  r_memclear_secure (kb, sizeof (kb));
  r_msg_digest_free (md);
  r_crypto_key_unref (pk);
}
RTEST_END;
