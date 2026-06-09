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
  RTLSSessionTicketKeys * ticket_keys;
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

  /* Shared key store the ticket-issuing / resuming tests attach to a server;
   * the fixture leaves it detached so the default server issues no tickets. */
  r_assert_cmpptr ((fixture->ticket_keys = r_tls_session_ticket_keys_new ()), !=, NULL);
}

RTEST_FIXTURE_TEARDOWN (rtlsserver)
{
  r_tls_session_ticket_keys_unref (fixture->ticket_keys);
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
 * extension; @etm appends the encrypt_then_mac extension; @session_ticket
 * appends an empty session_ticket extension. */
static rsize
r_test_tls_build_dtls_client_hello (RPrng * prng, ruint8 * out, rsize outsz,
    rboolean ems, rboolean etm, rboolean scsv, rboolean renego_ext,
    const ruint8 * renego, ruint8 renegolen, rboolean session_ticket)
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
  if (session_ticket) {
    r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_SESSION_TICKET); p += 2;
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
 * can decrypt the server's Finished. When @hs_md is non-NULL the transcript
 * hash (folded through the client Finished) and the master secret are handed
 * back via @hs_md / @ms_out so the caller can fold any trailing handshake
 * messages and verify the server Finished; the caller then owns @hs_md. */
static void
r_test_tls_dtls_client_complete (RTLSServer * server, RPrng * prng,
    const ruint8 * ch, rsize chlen, const ruint8 * srvflight, rsize srvlen,
    rboolean ems, rboolean etm, RCryptoCipher ** srv_cipher, RHmac ** srv_hmac,
    RMsgDigest ** hs_md, ruint8 * ms_out)
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
  /* The client Finished joins the transcript that the server's Finished is
   * computed over (the caller folds any messages the server emits after it). */
  r_test_tls_hash_record (md, finbuf, finhs + sizeof (vd));
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
  r_memclear_secure (kb, sizeof (kb));
  if (hs_md != NULL) {
    *hs_md = md;                /* transfer the transcript hash to the caller */
    r_memcpy (ms_out, ms, sizeof (ms));
  } else {
    r_msg_digest_free (md);
  }
  r_memclear_secure (ms, sizeof (ms));
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
  rboolean seen_ems, seen_session_ticket;
  const RTLSCipherSuiteInfo * csinfo;
  RMsgDigest * hs_md = NULL;
  ruint8 ms[48], expected_vd[12];
  static const ruint8 dtls_server_random[] = {
    0x58, 0x49, 0x81, 0x6a, 0x57, 0xc3, 0x49, 0x00, 0x29, 0x52, 0x8f, 0xac, 0xc7, 0x48, 0x57, 0x9e,
    0x26, 0x41, 0x87, 0xa6, 0xde, 0xd2, 0xe6, 0x72, 0x1a, 0x38, 0x08, 0x72, 0xdb, 0xd2, 0x09, 0x94
  };

  r_assert_cmpint (r_tls_server_set_random (fixture->server, dtls_server_random),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
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
  /* 66 bytes pre-extension; the echoed extended_master_secret and
   * session_ticket extensions add 4 each */
  r_assert_cmpuint (parser.fragment.size, ==, 74);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO);
  r_assert_cmpuint (msgseq, ==, 0);
  r_assert_cmpuint (l, ==, 62);
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
    seen_session_ticket = FALSE;
    for (e = r_tls_hello_msg_extension_first (&msg, &ext); e == R_TLS_ERROR_OK;
        e = r_tls_hello_msg_extension_next (&msg, &ext)) {
      if (ext.type == R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET) {
        seen_ems = TRUE;
        r_assert_cmpuint (ext.len, ==, 0);
      } else if (ext.type == R_TLS_EXT_TYPE_SESSION_TICKET) {
        seen_session_ticket = TRUE;
        r_assert_cmpuint (ext.len, ==, 0);
      }
    }
    r_assert (seen_ems);
    r_assert (seen_session_ticket);
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
      TRUE, FALSE, &cipher, &hmac, &hs_md, ms);
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

  /* The session_ticket the client offered draws a NewSessionTicket carrying a
   * non-empty (encrypted) ticket ahead of the ChangeCipherSpec. */
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpuint (parser.epoch, ==, 0);
  r_assert_cmpuint (parser.seqno, ==, 3);
  /* The NewSessionTicket is part of the server Finished's transcript hash. */
  r_msg_digest_update (hs_md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET);
  r_assert_cmpuint (msgseq, ==, 3);
  {
    ruint32 lifetime;
    const ruint8 * ticket;
    ruint16 ticketsize;

    r_assert_cmpint (r_tls_parser_parse_new_session_ticket (&parser, &lifetime,
          &ticket, &ticketsize), ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (lifetime, ==, R_TLS_SESSION_TICKET_LIFETIME);
    r_assert_cmpuint (ticketsize, >, 0);
  }

  /* Expected server verify_data over the full transcript (now including the
   * NewSessionTicket); compared against the decrypted server Finished below. */
  {
    ruint8 hash[64];
    rsize hashsize = r_msg_digest_size (hs_md);

    r_assert (r_msg_digest_get_data (hs_md, hash, hashsize, NULL));
    r_assert_cmpint (r_tls_1_2_prf_sha256 (expected_vd, sizeof (expected_vd),
          ms, sizeof (ms), R_STR_WITH_SIZE_ARGS ("server finished"),
          hash, hashsize, NULL), ==, R_TLS_ERROR_OK);
  }

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);
  r_assert_cmpuint (parser.version, ==, R_TLS_VERSION_DTLS_1_2);
  r_assert_cmpuint (parser.epoch, ==, 0);
  r_assert_cmpuint (parser.seqno, ==, 4);
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
    r_assert_cmpint (r_memcmp (verify_data, expected_vd, verify_size), ==, 0);
  }

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_EOB);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  r_msg_digest_free (hs_md);
  r_memclear_secure (ms, sizeof (ms));
  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);
}
RTEST_END;

/* Search the ServerHello in the server's first flight for a session_ticket
 * extension; assert it is present (when @expect) or absent, and empty when
 * present. */
static void
r_test_tls_assert_session_ticket_ext (RQueue * qout, rboolean expect)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RBuffer * buf;
  RTLSHelloMsg msg;
  RTLSHelloExt ext;
  RTLSError e;
  rboolean seen = FALSE;

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &msg), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&msg, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&msg, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_SESSION_TICKET) {
      seen = TRUE;
      r_assert_cmpuint (ext.len, ==, 0);
    }
  }
  r_assert_cmpint (seen, ==, expect);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}

/* A ClientHello that offers the session_ticket extension must draw an empty
 * session_ticket extension in the ServerHello (the "a NewSessionTicket will
 * follow" signal). */
RTEST_F (rtlsserver, dtls_session_ticket_extension_echoed, RTEST_FAST)
{
  ruint8 ch[256];
  rsize chlen;

  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, FALSE, FALSE, TRUE, NULL, 0, TRUE);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_test_tls_assert_session_ticket_ext (&fixture->qout, TRUE);
}
RTEST_END;

/* With no key store configured the server cannot seal a ticket, so even a
 * ClientHello that offers session_ticket must not draw the extension. */
RTEST_F (rtlsserver, dtls_session_ticket_no_keys_no_echo, RTEST_FAST)
{
  ruint8 ch[256];
  rsize chlen;

  /* deliberately no r_tls_server_set_session_ticket_keys */
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, FALSE, FALSE, TRUE, NULL, 0, TRUE);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_test_tls_assert_session_ticket_ext (&fixture->qout, FALSE);
}
RTEST_END;

/* A ClientHello that does not offer the session_ticket extension must not draw
 * one in the ServerHello. */
RTEST_F (rtlsserver, dtls_session_ticket_extension_absent, RTEST_FAST)
{
  ruint8 ch[256];
  rsize chlen;

  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  chlen = r_test_tls_build_dtls_client_hello (fixture->prng, ch, sizeof (ch),
      FALSE, FALSE, FALSE, TRUE, NULL, 0, FALSE);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_test_tls_assert_session_ticket_ext (&fixture->qout, FALSE);
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
      FALSE, FALSE, FALSE, TRUE, NULL, 0, FALSE);
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
      ch, chlen, info.data, info.size, FALSE, FALSE, &cipher, &hmac, NULL, NULL);
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
      FALSE, TRUE, FALSE, TRUE, NULL, 0, FALSE);
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
      ch, chlen, info.data, info.size, FALSE, TRUE, &cipher, &hmac, NULL, NULL);
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
      FALSE, FALSE, FALSE, TRUE, renego, sizeof (renego), FALSE);
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
      FALSE, FALSE, TRUE, FALSE, NULL, 0, FALSE);
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
      FALSE, FALSE, FALSE, TRUE, NULL, 0, FALSE);
  r_test_tls_server_feed (fixture->server, ch, chlen);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_test_tls_dtls_client_complete (fixture->server, fixture->prng,
      ch, chlen, info.data, info.size, FALSE, FALSE, &cipher, &hmac, NULL, NULL);
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

/* A non-DTLS TLS handshake that offers the session_ticket extension must draw a
 * NewSessionTicket ahead of the server ChangeCipherSpec, and the server
 * Finished must verify over a transcript that includes it. Covers the TLS
 * (non-DTLS) ticket-emission path and its transcript fold. */
RTEST_F (rtlsserver, tls_session_ticket_issued, RTEST_FAST)
{
  RCryptoKey * pk;
  RMsgDigest * md;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RBuffer * buf, * plain, * enc;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RCryptoCipher * ccipher, * scipher;
  RHmac * chmac, * shmac;
  RTLSHandshakeType hs;
  ruint32 l;
  ruint16 msgseq;
  ruint8 chbody[128], ch[256];
  ruint8 crand[R_TLS_HELLO_RANDOM_BYTES], srand[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 pms[48], ms[48], kb[128], vd[12], iv[16], sh[64], expected_vd[12];
  ruint8 encpms[512], cke[512], fin[64], ccs[16];
  rsize chlen, chbodylen, hssz, enclen = sizeof (encpms), ckelen, finhs, ccslen, shlen;
  ruint8 * p = chbody;
  ruint8 * extlenp;

  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);

  /* TLS 1.2 ClientHello: RSA-AES128-CBC-SHA, null compression, empty
   * renegotiation_info and an empty session_ticket extension. */
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
  r_store_be16 (p, (ruint16)R_TLS_EXT_TYPE_SESSION_TICKET); p += 2;
  r_store_be16 (p, 0); p += 2;
  r_store_be16 (extlenp, (ruint16)(p - (extlenp + 2)));
  chbodylen = (rsize)(p - chbody);

  r_assert_cmpint (r_tls_write_handshake (ch, sizeof (ch), &hssz, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO, (ruint16)chbodylen), ==, R_TLS_ERROR_OK);
  r_memcpy (ch + hssz, chbody, chbodylen);
  chlen = hssz + chbodylen;

  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (fixture->server, ch, chlen);
  r_test_tls_hash_record (md, ch, chlen);

  /* server flight: ServerHello + Certificate + HelloDone */
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
  r_assert_cmpint (r_tls_write_handshake (cke, sizeof (cke), &hssz, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, (ruint16)(2 + enclen)), ==, R_TLS_ERROR_OK);
  r_store_be16 (cke + hssz, (ruint16)enclen);
  r_memcpy (cke + hssz + 2, encpms, enclen);
  ckelen = hssz + 2 + enclen;
  r_test_tls_hash_record (md, cke, ckelen);

  /* legacy master secret + key block (client MAC | server MAC | client key | server key) */
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
  r_assert_cmpptr ((scipher = r_cipher_aes_128_cbc_new (kb + 56)), !=, NULL);
  r_assert_cmpptr ((shmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb + 20, 20)), !=, NULL);

  /* encrypted client Finished (client write seqno 0), folded into the transcript */
  r_assert_cmpint (r_tls_write_handshake (fin, sizeof (fin), &finhs, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_FINISHED, sizeof (vd)), ==, R_TLS_ERROR_OK);
  r_memcpy (fin + finhs, vd, sizeof (vd));
  r_test_tls_hash_record (md, fin, finhs + sizeof (vd));
  r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, fin,
          finhs + sizeof (vd), finhs + sizeof (vd), 0, NULL, NULL)), !=, NULL);
  r_prng_fill (fixture->prng, iv, sizeof (iv));
  r_assert_cmpptr ((enc = r_tls_encrypt_buffer (plain, 0, ccipher, iv, chmac, FALSE)), !=, NULL);
  r_buffer_unref (plain);

  r_assert_cmpint (r_tls_write_change_cipher (ccs, sizeof (ccs), &ccslen,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (fixture->server, cke, ckelen);
  r_test_tls_server_feed (fixture->server, ccs, ccslen);
  r_assert (r_buffer_map (enc, &info, R_MEM_MAP_READ));
  r_test_tls_server_feed (fixture->server, info.data, info.size);
  r_buffer_unmap (enc, &info);
  r_buffer_unref (enc);
  r_assert (fixture->hs_done);

  /* server 2nd flight: NewSessionTicket (plaintext, pre-CCS), ChangeCipherSpec,
   * then the encrypted Finished. */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET);
  {
    ruint32 lifetime;
    const ruint8 * ticket;
    ruint16 ticketsize;

    r_assert_cmpint (r_tls_parser_parse_new_session_ticket (&parser, &lifetime,
          &ticket, &ticketsize), ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (lifetime, ==, R_TLS_SESSION_TICKET_LIFETIME);
    r_assert_cmpuint (ticketsize, >, 0);
  }

  /* expected server verify_data over the transcript including the NST */
  {
    ruint8 hash[64];
    rsize hashsize = r_msg_digest_size (md);

    r_assert (r_msg_digest_get_data (md, hash, hashsize, NULL));
    r_assert_cmpint (r_tls_1_2_prf_sha256 (expected_vd, sizeof (expected_vd),
          ms, sizeof (ms), R_STR_WITH_SIZE_ARGS ("server finished"),
          hash, hashsize, NULL), ==, R_TLS_ERROR_OK);
  }

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_decrypt (&parser, scipher, shmac, FALSE), ==, R_TLS_ERROR_OK);
  {
    const ruint8 * verify_data;
    rsize verify_size;

    r_assert_cmpint (r_tls_parser_parse_finished (&parser, &verify_data, &verify_size),
        ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (verify_size, ==, 12);
    r_assert_cmpint (r_memcmp (verify_data, expected_vd, verify_size), ==, 0);
  }

  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  r_hmac_free (chmac);
  r_hmac_free (shmac);
  r_crypto_cipher_unref (ccipher);
  r_crypto_cipher_unref (scipher);
  r_memclear_secure (pms, sizeof (pms));
  r_memclear_secure (ms, sizeof (ms));
  r_memclear_secure (kb, sizeof (kb));
  r_msg_digest_free (md);
  r_crypto_key_unref (pk);
}
RTEST_END;

/* Build a TLS 1.2 ClientHello offering @suite, empty renegotiation_info, and a
 * session_ticket extension carrying @ticket (empty when @ticketlen is 0). The
 * client random is captured into @crand. Returns the record length. */
static rsize
r_test_tls_build_client_hello (RPrng * prng, ruint8 * ch, rsize chcap,
    RTLSCipherSuite suite, const ruint8 * ticket, rsize ticketlen, ruint8 * crand)
{
  ruint8 body[512];
  ruint8 * p = body;
  ruint8 * extlenp;
  rsize bodylen, hssz;

  *p++ = 0x03; *p++ = 0x03;
  r_prng_fill (prng, p, R_TLS_HELLO_RANDOM_BYTES);
  r_memcpy (crand, p, R_TLS_HELLO_RANDOM_BYTES); p += R_TLS_HELLO_RANDOM_BYTES;
  *p++ = 0;                                  /* session id length */
  r_store_be16 (p, 2); p += 2;               /* cipher-suites length */
  r_store_be16 (p, (ruint16) suite); p += 2;
  *p++ = 1; *p++ = 0;                        /* compression: null */
  extlenp = p; p += 2;
  r_store_be16 (p, (ruint16) R_TLS_EXT_TYPE_RENEGOTIATION_INFO); p += 2;
  r_store_be16 (p, 1); p += 2; *p++ = 0;
  r_store_be16 (p, (ruint16) R_TLS_EXT_TYPE_SESSION_TICKET); p += 2;
  r_store_be16 (p, (ruint16) ticketlen); p += 2;
  if (ticketlen > 0) { r_memcpy (p, ticket, ticketlen); p += ticketlen; }
  r_store_be16 (extlenp, (ruint16) (p - (extlenp + 2)));
  bodylen = (rsize) (p - body);

  r_assert_cmpint (r_tls_write_handshake (ch, chcap, &hssz, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO, (ruint16) bodylen), ==, R_TLS_ERROR_OK);
  r_memcpy (ch + hssz, body, bodylen);
  return hssz + bodylen;
}

/* Create a server configured like the fixture's (same callbacks bound to @ctx,
 * same cert), for the second connection in a resumption test. */
static RTLSServer *
r_test_tls_server_new_cfg (rpointer ctx)
{
  static const RTLSCallbacks cbs = {
    NULL, r_tlsserver_test_hs_done, r_tlsserver_test_buffer_out,
    r_tlsserver_test_buffer_appdata, r_tlsserver_test_error, NULL,
  };
  RTLSServer * srv;
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((srv = r_tls_server_new (&cbs, ctx, NULL)), !=, NULL);
  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (R_TLS_ERROR_OK, ==, r_tls_server_set_cert (srv, cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  return srv;
}

/* Drive a full TLS 1.2 RSA handshake against @server to completion, returning
 * the negotiated master secret in @ms and a malloc'd copy of the issued ticket
 * in @ticket_out / @ticketlen_out (caller frees). */
static void
r_test_tls_client_issue (RTLSServer * server, RPrng * prng, RQueue * qout,
    ruint8 ms[48], ruint8 ** ticket_out, rsize * ticketlen_out)
{
  RCryptoKey * pk;
  RMsgDigest * md;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RBuffer * buf, * plain, * enc;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RCryptoCipher * ccipher;
  RHmac * chmac;
  RTLSHandshakeType hs;
  ruint32 l;
  ruint16 msgseq;
  ruint8 ch[256];
  ruint8 crand[R_TLS_HELLO_RANDOM_BYTES], srand[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 pms[48], kb[128], vd[12], iv[16], sh[64];
  ruint8 encpms[512], cke[512], fin[64], ccs[16];
  rsize chlen, hssz, enclen = sizeof (encpms), ckelen, finhs, ccslen, shlen;

  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);

  chlen = r_test_tls_build_client_hello (prng, ch, sizeof (ch),
      R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, NULL, 0, crand);
  r_test_tls_server_feed (server, ch, chlen);
  r_test_tls_hash_record (md, ch, chlen);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_memcpy (srand, hello.random, sizeof (srand));
  while (r_tls_parser_init_next (&parser, NULL) == R_TLS_ERROR_OK)
    r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  pms[0] = 0x03; pms[1] = 0x03;
  r_prng_fill (prng, pms + 2, sizeof (pms) - 2);
  r_assert_cmpint (r_crypto_key_encrypt (pk, prng, pms, sizeof (pms), encpms, &enclen),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_tls_write_handshake (cke, sizeof (cke), &hssz, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, (ruint16)(2 + enclen)), ==, R_TLS_ERROR_OK);
  r_store_be16 (cke + hssz, (ruint16)enclen);
  r_memcpy (cke + hssz + 2, encpms, enclen);
  ckelen = hssz + 2 + enclen;
  r_test_tls_hash_record (md, cke, ckelen);

  shlen = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, sh, shlen, NULL));
  r_assert_cmpint (r_tls_1_2_prf_sha256 (ms, 48, pms, sizeof (pms),
        R_STR_WITH_SIZE_ARGS ("master secret"),
        crand, sizeof (crand), srand, sizeof (srand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_1_2_prf_sha256 (kb, sizeof (kb), ms, 48,
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        srand, sizeof (srand), crand, sizeof (crand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_1_2_prf_sha256 (vd, sizeof (vd), ms, 48,
        R_STR_WITH_SIZE_ARGS ("client finished"), sh, shlen, NULL), ==, R_TLS_ERROR_OK);

  r_assert_cmpptr ((ccipher = r_cipher_aes_128_cbc_new (kb + 40)), !=, NULL);
  r_assert_cmpptr ((chmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb, 20)), !=, NULL);

  r_assert_cmpint (r_tls_write_handshake (fin, sizeof (fin), &finhs, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_FINISHED, sizeof (vd)), ==, R_TLS_ERROR_OK);
  r_memcpy (fin + finhs, vd, sizeof (vd));
  r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, fin,
          finhs + sizeof (vd), finhs + sizeof (vd), 0, NULL, NULL)), !=, NULL);
  r_prng_fill (prng, iv, sizeof (iv));
  r_assert_cmpptr ((enc = r_tls_encrypt_buffer (plain, 0, ccipher, iv, chmac, FALSE)), !=, NULL);
  r_buffer_unref (plain);

  r_assert_cmpint (r_tls_write_change_cipher (ccs, sizeof (ccs), &ccslen,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (server, cke, ckelen);
  r_test_tls_server_feed (server, ccs, ccslen);
  r_assert (r_buffer_map (enc, &info, R_MEM_MAP_READ));
  r_test_tls_server_feed (server, info.data, info.size);
  r_buffer_unmap (enc, &info);
  r_buffer_unref (enc);

  /* server 2nd flight: NewSessionTicket, CCS, Finished -- capture the ticket */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET);
  {
    ruint32 lifetime;
    const ruint8 * ticket;
    ruint16 ticketsize;

    r_assert_cmpint (r_tls_parser_parse_new_session_ticket (&parser, &lifetime,
          &ticket, &ticketsize), ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (ticketsize, >, 0);
    *ticket_out = r_memdup (ticket, ticketsize);
    *ticketlen_out = ticketsize;
  }
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  r_hmac_free (chmac);
  r_crypto_cipher_unref (ccipher);
  r_memclear_secure (pms, sizeof (pms));
  r_memclear_secure (kb, sizeof (kb));
  r_msg_digest_free (md);
  r_crypto_key_unref (pk);
}

/* Present @ticket to @server (which must share the issuing key store) and drive
 * the abbreviated handshake to completion: verify the server Finished over
 * H(CH||SH), then send the client Finished over H(CH||SH||serverFinished). */
static void
r_test_tls_client_resume (RTLSServer * server, RPrng * prng, RQueue * qout,
    const ruint8 ms[48], const ruint8 * ticket, rsize ticketlen)
{
  RMsgDigest * md;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RBuffer * buf, * plain, * enc;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RCryptoCipher * ccipher, * scipher;
  RHmac * chmac, * shmac;
  ruint8 ch[512];
  ruint8 crand[R_TLS_HELLO_RANDOM_BYTES], srand[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 kb[128], vd[12], iv[16], hash[64], svd[12];
  ruint8 fin[64], ccs[16];
  rsize chlen, finhs, ccslen, hashsize;
  const ruint8 * verify_data;
  rsize verify_size;

  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);

  chlen = r_test_tls_build_client_hello (prng, ch, sizeof (ch),
      R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, ticket, ticketlen, crand);
  r_test_tls_server_feed (server, ch, chlen);
  r_test_tls_hash_record (md, ch, chlen);

  /* resumed server flight: ServerHello, CCS, encrypted Finished (no Certificate) */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (hello.sidlen, >, 0);     /* a session id signals resumption */
  r_memcpy (srand, hello.random, sizeof (srand));
  {
    /* No fresh ticket is issued on resume, so the ServerHello must not promise
     * one with a session_ticket extension (RFC 5077 3.4). */
    RTLSHelloExt ext;
    RTLSError e;
    for (e = r_tls_hello_msg_extension_first (&hello, &ext); e == R_TLS_ERROR_OK;
        e = r_tls_hello_msg_extension_next (&hello, &ext))
      r_assert_cmpuint (ext.type, !=, R_TLS_EXT_TYPE_SESSION_TICKET);
  }

  /* key block from the resumed master secret and the fresh randoms */
  r_assert_cmpint (r_tls_1_2_prf_sha256 (kb, sizeof (kb), ms, 48,
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        srand, sizeof (srand), crand, sizeof (crand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((ccipher = r_cipher_aes_128_cbc_new (kb + 40)), !=, NULL);
  r_assert_cmpptr ((chmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb, 20)), !=, NULL);
  r_assert_cmpptr ((scipher = r_cipher_aes_128_cbc_new (kb + 56)), !=, NULL);
  r_assert_cmpptr ((shmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb + 20, 20)), !=, NULL);

  /* server verify_data is over the transcript through ServerHello */
  hashsize = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, hash, hashsize, NULL));
  r_assert_cmpint (r_tls_1_2_prf_sha256 (svd, sizeof (svd), ms, 48,
        R_STR_WITH_SIZE_ARGS ("server finished"), hash, hashsize, NULL), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_decrypt (&parser, scipher, shmac, FALSE), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_finished (&parser, &verify_data, &verify_size),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (verify_size, ==, 12);
  r_assert_cmpint (r_memcmp (verify_data, svd, verify_size), ==, 0);
  /* fold the server Finished so the client Finished covers it */
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  hashsize = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, hash, hashsize, NULL));
  r_assert_cmpint (r_tls_1_2_prf_sha256 (vd, sizeof (vd), ms, 48,
        R_STR_WITH_SIZE_ARGS ("client finished"), hash, hashsize, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_write_handshake (fin, sizeof (fin), &finhs, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_FINISHED, sizeof (vd)), ==, R_TLS_ERROR_OK);
  r_memcpy (fin + finhs, vd, sizeof (vd));
  r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, fin,
          finhs + sizeof (vd), finhs + sizeof (vd), 0, NULL, NULL)), !=, NULL);
  r_prng_fill (prng, iv, sizeof (iv));
  r_assert_cmpptr ((enc = r_tls_encrypt_buffer (plain, 0, ccipher, iv, chmac, FALSE)), !=, NULL);
  r_buffer_unref (plain);

  r_assert_cmpint (r_tls_write_change_cipher (ccs, sizeof (ccs), &ccslen,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (server, ccs, ccslen);
  r_assert (r_buffer_map (enc, &info, R_MEM_MAP_READ));
  r_test_tls_server_feed (server, info.data, info.size);
  r_buffer_unmap (enc, &info);
  r_buffer_unref (enc);

  r_hmac_free (chmac);
  r_hmac_free (shmac);
  r_crypto_cipher_unref (ccipher);
  r_crypto_cipher_unref (scipher);
  r_memclear_secure (kb, sizeof (kb));
  r_msg_digest_free (md);
}

/* Feed a resume ClientHello (offering @suite + @ticket) and assert the server
 * runs a full handshake -- a Certificate follows the ServerHello rather than a
 * ChangeCipherSpec -- i.e. it declined to resume. */
static void
r_test_tls_client_resume_assert_full (RTLSServer * server, RPrng * prng,
    RQueue * qout, RTLSCipherSuite suite, const ruint8 * ticket, rsize ticketlen)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RBuffer * buf;
  RTLSHandshakeType hs;
  ruint32 l;
  ruint16 msgseq;
  ruint8 ch[512], crand[R_TLS_HELLO_RANDOM_BYTES];
  rsize chlen;

  chlen = r_test_tls_build_client_hello (prng, ch, sizeof (ch),
      suite, ticket, ticketlen, crand);
  r_test_tls_server_feed (server, ch, chlen);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_CERTIFICATE);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}

/* End-to-end resumption: issue a ticket via a full handshake, then present it
 * to a second server sharing the same key store and complete the abbreviated
 * handshake, with the negotiated parameters preserved. */
RTEST_F (rtlsserver, tls_session_resume, RTEST_FAST)
{
  RTLSServer * srv2;
  ruint8 ms[48], * ticket = NULL;
  rsize ticketlen = 0;
  const RTLSCipherSuiteInfo * csinfo;

  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_test_tls_client_issue (fixture->server, fixture->prng, &fixture->qout,
      ms, &ticket, &ticketlen);
  r_assert (fixture->hs_done);
  r_assert_cmpuint (ticketlen, >, 0);

  fixture->hs_done = FALSE;
  r_queue_clear (&fixture->qout, r_buffer_unref);
  r_assert_cmpptr ((srv2 = r_test_tls_server_new_cfg (fixture)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (srv2, fixture->ticket_keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (srv2, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  r_test_tls_client_resume (srv2, fixture->prng, &fixture->qout, ms, ticket, ticketlen);
  r_assert (fixture->hs_done);
  r_assert_cmphex (r_tls_server_get_version (srv2), ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpptr ((csinfo = r_tls_server_get_cipher_suite (srv2)), !=, NULL);
  r_assert_cmpstr (csinfo->str, ==, "TLS-RSA-WITH-AES-128-CBC-SHA");

  r_free (ticket);
  r_tls_server_unref (srv2);
}
RTEST_END;

/* A ClientHello carrying an unopenable ticket falls back to a full handshake. */
RTEST_F (rtlsserver, tls_session_resume_bad_ticket, RTEST_FAST)
{
  ruint8 garbage[80];

  r_memset (garbage, 0xab, sizeof (garbage));
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  r_test_tls_client_resume_assert_full (fixture->server, fixture->prng, &fixture->qout,
      R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, garbage, sizeof (garbage));
  r_assert (!fixture->hs_done);
}
RTEST_END;

/* A ticket for a suite the resuming ClientHello no longer offers must not
 * resume (RFC 5077); the server falls back to a full handshake. */
RTEST_F (rtlsserver, tls_session_resume_suite_not_offered, RTEST_FAST)
{
  RTLSServer * srv2;
  ruint8 ms[48], * ticket = NULL;
  rsize ticketlen = 0;

  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_test_tls_client_issue (fixture->server, fixture->prng, &fixture->qout,
      ms, &ticket, &ticketlen);
  r_assert (fixture->hs_done);

  fixture->hs_done = FALSE;
  r_queue_clear (&fixture->qout, r_buffer_unref);
  r_assert_cmpptr ((srv2 = r_test_tls_server_new_cfg (fixture)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (srv2, fixture->ticket_keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (srv2, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  /* the ticket is for RSA-AES128-CBC-SHA; this ClientHello offers only SHA256 */
  r_test_tls_client_resume_assert_full (srv2, fixture->prng, &fixture->qout,
      R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256, ticket, ticketlen);

  r_free (ticket);
  r_tls_server_unref (srv2);
}
RTEST_END;

/* Build a DTLS 1.2 ClientHello (message_seq 0) offering @suite, empty
 * renegotiation_info, extended_master_secret (the issuing session used it) and
 * a session_ticket extension carrying @ticket. Captures the client random. */
static rsize
r_test_tls_build_dtls_resume_hello (RPrng * prng, ruint8 * out, rsize outsz,
    RTLSCipherSuite suite, const ruint8 * ticket, rsize ticketlen, ruint8 * crand)
{
  ruint8 body[256];
  ruint8 * p = body;
  ruint8 * extlenp;
  rsize bodylen, hs;

  *p++ = 0xfe; *p++ = 0xfd;                  /* client_version DTLS 1.2 */
  r_prng_fill (prng, p, R_TLS_HELLO_RANDOM_BYTES);
  r_memcpy (crand, p, R_TLS_HELLO_RANDOM_BYTES); p += R_TLS_HELLO_RANDOM_BYTES;
  *p++ = 0;                                  /* session id length */
  *p++ = 0;                                  /* cookie length */
  r_store_be16 (p, 2); p += 2;               /* cipher-suites length */
  r_store_be16 (p, (ruint16) suite); p += 2;
  *p++ = 1; *p++ = 0;                        /* compression: null */
  extlenp = p; p += 2;
  r_store_be16 (p, (ruint16) R_TLS_EXT_TYPE_RENEGOTIATION_INFO); p += 2;
  r_store_be16 (p, 1); p += 2; *p++ = 0;
  r_store_be16 (p, (ruint16) R_TLS_EXT_TYPE_EXTENDED_MASTER_SECRET); p += 2;
  r_store_be16 (p, 0); p += 2;
  r_store_be16 (p, (ruint16) R_TLS_EXT_TYPE_SESSION_TICKET); p += 2;
  r_store_be16 (p, (ruint16) ticketlen); p += 2;
  if (ticketlen > 0) { r_memcpy (p, ticket, ticketlen); p += ticketlen; }
  r_store_be16 (extlenp, (ruint16) (p - (extlenp + 2)));
  bodylen = (rsize) (p - body);

  r_assert_cmpint (r_dtls_write_handshake (out, outsz, &hs,
        R_TLS_VERSION_DTLS_1_2, R_TLS_HANDSHAKE_TYPE_CLIENT_HELLO,
        (ruint16) bodylen, 0, 0, 0, 0, (ruint32) bodylen), ==, R_TLS_ERROR_OK);
  r_memcpy (out + hs, body, bodylen);
  return hs + bodylen;
}

/* Present @ticket to a DTLS @server sharing the issuing key store and drive the
 * abbreviated handshake to completion: verify the server Finished (epoch 1)
 * over H(CH||SH), then send the client ChangeCipherSpec + Finished. */
static void
r_test_tls_dtls_client_resume (RTLSServer * server, RPrng * prng, RQueue * qout,
    const ruint8 ms[48], const ruint8 * ticket, rsize ticketlen)
{
  RMsgDigest * md;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RBuffer * buf, * plain, * encbuf;
  RCryptoCipher * ccipher, * scipher;
  RHmac * chmac, * shmac;
  ruint8 ch[256];
  ruint8 crand[R_TLS_HELLO_RANDOM_BYTES], srand[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 kb[128], vd[12], iv[16], hash[64], svd[12];
  ruint8 finbuf[64], ccsbuf[32];
  rsize chlen, finhs, ccslen, hashsize;
  const ruint8 * verify_data;
  rsize verify_size;

  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);

  chlen = r_test_tls_build_dtls_resume_hello (prng, ch, sizeof (ch),
      R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, ticket, ticketlen, crand);
  r_test_tls_server_feed (server, ch, chlen);
  r_test_tls_hash_record (md, ch, chlen);

  /* resumed server flight: ServerHello, CCS (epoch 0), encrypted Finished
   * (epoch 1); no Certificate. */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.epoch, ==, 0);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (hello.sidlen, >, 0);     /* a session id signals resumption */
  r_memcpy (srand, hello.random, sizeof (srand));
  {
    /* No fresh ticket is issued on resume, so the ServerHello must not promise
     * one with a session_ticket extension (RFC 5077 3.4). */
    RTLSHelloExt ext;
    RTLSError e;
    for (e = r_tls_hello_msg_extension_first (&hello, &ext); e == R_TLS_ERROR_OK;
        e = r_tls_hello_msg_extension_next (&hello, &ext))
      r_assert_cmpuint (ext.type, !=, R_TLS_EXT_TYPE_SESSION_TICKET);
  }

  r_assert_cmpint (r_tls_1_2_prf_sha256 (kb, sizeof (kb), ms, 48,
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        srand, sizeof (srand), crand, sizeof (crand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((ccipher = r_cipher_aes_128_cbc_new (kb + 40)), !=, NULL);
  r_assert_cmpptr ((chmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb, 20)), !=, NULL);
  r_assert_cmpptr ((scipher = r_cipher_aes_128_cbc_new (kb + 56)), !=, NULL);
  r_assert_cmpptr ((shmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb + 20, 20)), !=, NULL);

  hashsize = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, hash, hashsize, NULL));
  r_assert_cmpint (r_tls_1_2_prf_sha256 (svd, sizeof (svd), ms, 48,
        R_STR_WITH_SIZE_ARGS ("server finished"), hash, hashsize, NULL), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC);
  r_assert_cmpuint (parser.epoch, ==, 0);

  r_assert_cmpint (r_tls_parser_init_next (&parser, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (parser.epoch, ==, 1);
  r_assert_cmpint (r_tls_parser_decrypt (&parser, scipher, shmac, FALSE), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_finished (&parser, &verify_data, &verify_size),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (verify_size, ==, 12);
  r_assert_cmpint (r_memcmp (verify_data, svd, verify_size), ==, 0);
  /* fold the server Finished so the client Finished covers it */
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  hashsize = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, hash, hashsize, NULL));
  r_assert_cmpint (r_tls_1_2_prf_sha256 (vd, sizeof (vd), ms, 48,
        R_STR_WITH_SIZE_ARGS ("client finished"), hash, hashsize, NULL), ==, R_TLS_ERROR_OK);

  /* client ChangeCipherSpec (epoch 0) + encrypted Finished (epoch 1, msg_seq 1) */
  r_assert_cmpint (r_dtls_write_change_cipher (ccsbuf, sizeof (ccsbuf), &ccslen,
        R_TLS_VERSION_DTLS_1_2, 0, 1), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_dtls_write_handshake (finbuf, sizeof (finbuf), &finhs,
        R_TLS_VERSION_DTLS_1_2, R_TLS_HANDSHAKE_TYPE_FINISHED, sizeof (vd),
        1, 0, 1, 0, sizeof (vd)), ==, R_TLS_ERROR_OK);
  r_memcpy (finbuf + finhs, vd, sizeof (vd));
  r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, finbuf,
          finhs + sizeof (vd), finhs + sizeof (vd), 0, NULL, NULL)), !=, NULL);
  r_prng_fill (prng, iv, sizeof (iv));
  r_assert_cmpptr ((encbuf = r_dtls_encrypt_buffer (plain, ccipher, iv, chmac, FALSE)), !=, NULL);
  r_buffer_unref (plain);

  r_test_tls_server_feed (server, ccsbuf, ccslen);
  r_assert (r_tls_server_incoming_data (server, encbuf));
  r_buffer_unref (encbuf);

  r_hmac_free (chmac);
  r_hmac_free (shmac);
  r_crypto_cipher_unref (ccipher);
  r_crypto_cipher_unref (scipher);
  r_memclear_secure (kb, sizeof (kb));
  r_msg_digest_free (md);
}

/* End-to-end DTLS resumption: a full DTLS handshake issues a ticket, then a
 * second server sharing the key store resumes from it through the abbreviated
 * handshake (exercises the DTLS record-header transcript fold). */
RTEST_F (rtlsserver, dtls_session_resume, RTEST_FAST)
{
  RTLSParser parser = R_TLS_PARSER_INIT;
  RCryptoCipher * cipher = NULL;
  RHmac * hmac = NULL;
  RMsgDigest * hs_md = NULL;
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSServer * srv2;
  ruint8 ms[48], * ticket = NULL;
  rsize ticketlen = 0;
  RTLSHandshakeType hs;
  ruint32 l;
  ruint16 msgseq;

  /* phase 1: full DTLS handshake issues a ticket */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server,
        fixture->ticket_keys), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_test_tls_server_incoming_data (pkt_dtls_client_hallo);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_test_tls_dtls_client_complete (fixture->server, fixture->prng,
      pkt_dtls_client_hallo, sizeof (pkt_dtls_client_hallo), info.data, info.size,
      TRUE, FALSE, &cipher, &hmac, &hs_md, ms);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);
  r_assert (fixture->hs_done);

  /* capture the issued ticket from the server's 2nd flight */
  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpint (r_tls_parser_parse_handshake_full (&parser, &hs, &l,
        &msgseq, NULL, NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmphex (hs, ==, R_TLS_HANDSHAKE_TYPE_NEW_SESSION_TICKET);
  {
    ruint32 lifetime;
    const ruint8 * tk;
    ruint16 tksz;

    r_assert_cmpint (r_tls_parser_parse_new_session_ticket (&parser, &lifetime,
          &tk, &tksz), ==, R_TLS_ERROR_OK);
    r_assert_cmpuint (tksz, >, 0);
    ticket = r_memdup (tk, tksz);
    ticketlen = tksz;
  }
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
  r_msg_digest_free (hs_md);
  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);

  /* phase 2: resume on a second server sharing the key store */
  fixture->hs_done = FALSE;
  r_queue_clear (&fixture->qout, r_buffer_unref);
  r_assert_cmpptr ((srv2 = r_test_tls_server_new_cfg (fixture)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (srv2, fixture->ticket_keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (srv2, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  r_test_tls_dtls_client_resume (srv2, fixture->prng, &fixture->qout, ms, ticket, ticketlen);
  r_assert (fixture->hs_done);
  r_assert_cmphex (r_tls_server_get_version (srv2), ==, R_TLS_VERSION_DTLS_1_2);

  r_free (ticket);
  r_tls_server_unref (srv2);
}
RTEST_END;

/* How r_test_tls_drive_bad_finished should break the client Finished. */
typedef enum {
  R_TEST_FIN_BAD_VERIFY,   /* valid record, wrong verify_data -> decrypt_error */
  R_TEST_FIN_BAD_MAC,      /* tampered ciphertext -> bad_record_mac */
} RTestFinBreak;

/* Drive a TLS 1.2 RSA handshake against @server up to the client Finished, then
 * send a deliberately broken Finished so the server emits the corresponding
 * fatal alert (asserted by the caller via the fixture's error callback). */
static void
r_test_tls_drive_bad_finished (RTLSServer * server, RPrng * prng, RQueue * qout,
    RTestFinBreak how)
{
  RCryptoKey * pk;
  RMsgDigest * md;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RBuffer * buf, * plain, * enc;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RCryptoCipher * ccipher;
  RHmac * chmac;
  ruint8 ch[256], rec[128];
  ruint8 crand[R_TLS_HELLO_RANDOM_BYTES], srand[R_TLS_HELLO_RANDOM_BYTES];
  ruint8 pms[48], ms[48], kb[128], vd[12], iv[16], sh[64];
  ruint8 encpms[512], cke[512], fin[64], ccs[16];
  rsize chlen, hssz, enclen = sizeof (encpms), ckelen, finhs, ccslen, shlen;

  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpptr ((md = r_msg_digest_new_sha256 ()), !=, NULL);

  chlen = r_test_tls_build_client_hello (prng, ch, sizeof (ch),
      R_TLS_CS_RSA_WITH_AES_128_CBC_SHA, NULL, 0, crand);
  r_test_tls_server_feed (server, ch, chlen);
  r_test_tls_hash_record (md, ch, chlen);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_memcpy (srand, hello.random, sizeof (srand));
  while (r_tls_parser_init_next (&parser, NULL) == R_TLS_ERROR_OK)
    r_msg_digest_update (md, parser.fragment.data, parser.fragment.size);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);

  pms[0] = 0x03; pms[1] = 0x03;
  r_prng_fill (prng, pms + 2, sizeof (pms) - 2);
  r_assert_cmpint (r_crypto_key_encrypt (pk, prng, pms, sizeof (pms), encpms, &enclen),
      ==, R_CRYPTO_OK);
  r_assert_cmpint (r_tls_write_handshake (cke, sizeof (cke), &hssz, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, (ruint16)(2 + enclen)), ==, R_TLS_ERROR_OK);
  r_store_be16 (cke + hssz, (ruint16)enclen);
  r_memcpy (cke + hssz + 2, encpms, enclen);
  ckelen = hssz + 2 + enclen;
  r_test_tls_hash_record (md, cke, ckelen);

  shlen = r_msg_digest_size (md);
  r_assert (r_msg_digest_get_data (md, sh, shlen, NULL));
  r_assert_cmpint (r_tls_1_2_prf_sha256 (ms, 48, pms, sizeof (pms),
        R_STR_WITH_SIZE_ARGS ("master secret"),
        crand, sizeof (crand), srand, sizeof (srand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_1_2_prf_sha256 (kb, sizeof (kb), ms, 48,
        R_STR_WITH_SIZE_ARGS ("key expansion"),
        srand, sizeof (srand), crand, sizeof (crand), NULL), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_1_2_prf_sha256 (vd, sizeof (vd), ms, 48,
        R_STR_WITH_SIZE_ARGS ("client finished"), sh, shlen, NULL), ==, R_TLS_ERROR_OK);

  /* A wrong verify_data still MACs and decrypts cleanly, so the server reaches
   * the Finished check and rejects it with decrypt_error. */
  if (how == R_TEST_FIN_BAD_VERIFY)
    vd[0] ^= 0xff;

  r_assert_cmpptr ((ccipher = r_cipher_aes_128_cbc_new (kb + 40)), !=, NULL);
  r_assert_cmpptr ((chmac = r_hmac_new (R_MSG_DIGEST_TYPE_SHA1, kb, 20)), !=, NULL);
  r_assert_cmpint (r_tls_write_handshake (fin, sizeof (fin), &finhs, R_TLS_VERSION_TLS_1_2,
        R_TLS_HANDSHAKE_TYPE_FINISHED, sizeof (vd)), ==, R_TLS_ERROR_OK);
  r_memcpy (fin + finhs, vd, sizeof (vd));
  r_assert_cmpptr ((plain = r_buffer_new_wrapped (R_MEM_FLAG_NONE, fin,
          finhs + sizeof (vd), finhs + sizeof (vd), 0, NULL, NULL)), !=, NULL);
  r_prng_fill (prng, iv, sizeof (iv));
  r_assert_cmpptr ((enc = r_tls_encrypt_buffer (plain, 0, ccipher, iv, chmac, FALSE)), !=, NULL);
  r_buffer_unref (plain);

  r_assert_cmpint (r_tls_write_change_cipher (ccs, sizeof (ccs), &ccslen,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_server_feed (server, cke, ckelen);
  r_test_tls_server_feed (server, ccs, ccslen);

  r_assert (r_buffer_map (enc, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, <=, sizeof (rec));
  r_memcpy (rec, info.data, info.size);
  /* Flipping a ciphertext byte breaks the record MAC -> bad_record_mac. */
  if (how == R_TEST_FIN_BAD_MAC)
    rec[info.size - 1] ^= 0xff;
  r_test_tls_server_feed (server, rec, info.size);
  r_buffer_unmap (enc, &info);
  r_buffer_unref (enc);

  r_hmac_free (chmac);
  r_crypto_cipher_unref (ccipher);
  r_memclear_secure (pms, sizeof (pms));
  r_memclear_secure (ms, sizeof (ms));
  r_memclear_secure (kb, sizeof (kb));
  r_msg_digest_free (md);
  r_crypto_key_unref (pk);
}

/* A client Finished that decrypts cleanly but carries the wrong verify_data is
 * a failed handshake cryptographic check -> decrypt_error (RFC 5246 7.2.2). */
RTEST_F (rtlsserver, tls_alert_finished_decrypt_error, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  r_test_tls_drive_bad_finished (fixture->server, fixture->prng, &fixture->qout,
      R_TEST_FIN_BAD_VERIFY);

  r_assert (fixture->got_error);
  r_assert (!fixture->hs_done);
  r_assert_cmpuint (fixture->last_alert, ==, R_TLS_ALERT_TYPE_DECRYPT_ERROR);
}
RTEST_END;

/* A TLS record that fails decryption / MAC is fatal: bad_record_mac. */
RTEST_F (rtlsserver, tls_alert_bad_record_mac, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  r_test_tls_drive_bad_finished (fixture->server, fixture->prng, &fixture->qout,
      R_TEST_FIN_BAD_MAC);

  r_assert (fixture->got_error);
  r_assert (!fixture->hs_done);
  r_assert_cmpuint (fixture->last_alert, ==, R_TLS_ALERT_TYPE_BAD_RECORD_MAC);
}
RTEST_END;

/* Unlike TLS, a DTLS record that fails decryption / MAC is silently discarded
 * and the association survives (RFC 6347 4.1.2.7): no alert, no error. */
RTEST_F (rtlsserver, dtls_bad_record_silently_discarded, RTEST_FAST)
{
  RCryptoCipher * cipher = NULL;
  RHmac * hmac = NULL;
  RMsgDigest * hs_md = NULL;
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint8 ms[48];
  /* DTLS application_data record, epoch 1, seqno 1, with a 32-byte body that
   * is not a valid ciphertext under the negotiated keys. */
  ruint8 rec[13 + 32];

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_test_tls_server_incoming_data (pkt_dtls_client_hallo);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_test_tls_dtls_client_complete (fixture->server, fixture->prng,
      pkt_dtls_client_hallo, sizeof (pkt_dtls_client_hallo), info.data, info.size,
      TRUE, FALSE, &cipher, &hmac, &hs_md, ms);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);
  r_assert (fixture->hs_done);
  r_msg_digest_free (hs_md);
  r_hmac_free (hmac);
  r_crypto_cipher_unref (cipher);

  /* Drain the server's flight, then feed the bogus epoch-1 record. */
  r_queue_clear (&fixture->qout, r_buffer_unref);
  r_memset (rec, 0, sizeof (rec));
  rec[0] = R_TLS_CONTENT_TYPE_APPLICATION_DATA;
  rec[1] = 0xfe; rec[2] = 0xfd;              /* DTLS 1.2 */
  rec[3] = 0x00; rec[4] = 0x01;              /* epoch 1 */
  rec[10] = 0x01;                            /* sequence number 1 (48-bit) */
  rec[11] = 0x00; rec[12] = 0x20;            /* length 32 */
  r_memset (rec + 13, 0xab, 32);             /* garbage ciphertext */
  r_test_tls_server_feed (fixture->server, rec, sizeof (rec));

  r_assert (!fixture->got_error);
  r_assert_cmpptr (r_test_tls_server_queue_agg (&fixture->qout), ==, NULL);

  r_memclear_secure (ms, sizeof (ms));
}
RTEST_END;

/* A record whose fragment length exceeds the 2^14 limit is rejected at the
 * record layer with a fatal record_overflow (RFC 5246 7.2.2). */
RTEST_F (rtlsserver, tls_alert_record_overflow, RTEST_FAST)
{
  /* TLS 1.2 handshake record header claiming a 0x4000-byte fragment. */
  static const ruint8 pkt[] = { 0x16, 0x03, 0x03, 0x40, 0x00 };
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);

  /* A record-layer framing failure is fatal, so incoming_data reports it. */
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE, (rpointer)pkt,
          sizeof (pkt), sizeof (pkt), 0, NULL, NULL)), !=, NULL);
  r_assert (!r_tls_server_incoming_data (fixture->server, buf));
  r_buffer_unref (buf);

  r_assert (fixture->got_error);
  r_assert_cmpuint (fixture->last_alert, ==, R_TLS_ALERT_TYPE_RECORD_OVERFLOW);

  r_assert_cmpptr ((buf = r_test_tls_server_queue_agg (&fixture->qout)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_RECORD_OVERFLOW);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;
