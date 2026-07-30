#include <rlib/rnet.h>
#include <rlib/rcrypto.h>

#include "rtlstestcerts.h"

/* Self-signed test certificate + matching RSA private key (CN=rlib). */
static const rchar testcertpem[] =
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

static const rchar testpkpem[] =
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

/* Self-signed P-256 ECDSA test certificate + matching PKCS#8 key (CN=rlib-ecdsa).
 * Keep the serial small (the parser stores it as a ruint64) and the validity in
 * UTCTime range (< year 2050, no GeneralizedTime) when regenerating, or the
 * certificate will not parse. */
static const rchar testcertpem_ecdsa[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBazCCARKgAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApybGliLWVj\n"
  "ZHNhMB4XDTI2MDYxMDE2MzEwNVoXDTQ4MDUwNTE2MzEwNVowFTETMBEGA1UEAwwK\n"
  "cmxpYi1lY2RzYTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHmc5lmycwenV7C+\n"
  "7Z8tpwNH4WqfCYE2ngzLa8mn0MK+UeGkAOMj30dPnRd9Y2mi7ypVo1y0aAb/HJYF\n"
  "/q6z4pijUzBRMB0GA1UdDgQWBBR6XBE2U7nNA9t9ll5AacMs4bTZazAfBgNVHSME\n"
  "GDAWgBR6XBE2U7nNA9t9ll5AacMs4bTZazAPBgNVHRMBAf8EBTADAQH/MAoGCCqG\n"
  "SM49BAMCA0cAMEQCIBbHM2jgY1m9lhDtyIUZJA1Pf8faLunxtb3ysQvorcEyAiAQ\n"
  "MI/3ana2mn80+oVJfVU6vFEOYVJ84K16whK8g3e7Fg==\n"
  "-----END CERTIFICATE-----\n";

static const rchar testpkpem_ecdsa[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoTATtTsWuzOwzu8p\n"
  "lD/YJFTfjLKmPB52UDdl6/X+V42hRANCAAR5nOZZsnMHp1ewvu2fLacDR+FqnwmB\n"
  "Np4My2vJp9DCvlHhpADjI99HT50XfWNpou8qVaNctGgG/xyWBf6us+KY\n"
  "-----END PRIVATE KEY-----\n";

/* Self-signed P-384 / P-521 ECDSA test certificates + PKCS#8 keys, for the 1.3
 * CertificateVerify schemes ecdsa_secp384r1_sha384 / ecdsa_secp521r1_sha512.
 * Same generation constraints as testcertpem_ecdsa (small serial, pre-2050). */
static const rchar testcertpem_ecdsa384[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBrzCCATWgAwIBAgIBATAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1ybGliLWVj\n"
  "ZHNhMzg0MB4XDTI2MDcyNzIwNDgyMVoXDTQ4MDYyMTIwNDgyMVowGDEWMBQGA1UE\n"
  "AwwNcmxpYi1lY2RzYTM4NDB2MBAGByqGSM49AgEGBSuBBAAiA2IABHfcO62ibiQU\n"
  "glYrb6sPqvtMNBx9hQ8PaSN0tjtDT6j06PCMz723JL6M/fqXtFFfEp7fsc9l/qWt\n"
  "ebpFUXmSGfae7V9gUcYUn0ymDmCMbhJtbhz04Yq1Yu94g4B1dYMaZaNTMFEwHQYD\n"
  "VR0OBBYEFAXcoxN3AXnLfJVUpwLdMJkCvPfkMB8GA1UdIwQYMBaAFAXcoxN3AXnL\n"
  "fJVUpwLdMJkCvPfkMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDaAAwZQIw\n"
  "el4HTsofk/B7Cp/FJWXqivsbMBj7LFB3/Kom3vjmZ6OJll+utXhd7lElP4mhSq3e\n"
  "AjEAxUsip5CG6drgL5x89Q9XcZz5hEg1UG9OZ0TnxvyKy2IqujOKcYu0KpqafmyD\n"
  "fidy\n"
  "-----END CERTIFICATE-----\n";

static const rchar testpkpem_ecdsa384[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDDCbWZwdlCAU6sPeKSD\n"
  "BRf4heZXVNP6ly9a2A/wlmO6RErkq//ezyhEV3PgqJwAUtqhZANiAAR33Dutom4k\n"
  "FIJWK2+rD6r7TDQcfYUPD2kjdLY7Q0+o9OjwjM+9tyS+jP36l7RRXxKe37HPZf6l\n"
  "rXm6RVF5khn2nu1fYFHGFJ9Mpg5gjG4SbW4c9OGKtWLveIOAdXWDGmU=\n"
  "-----END PRIVATE KEY-----\n";

static const rchar testcertpem_ecdsa521[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB+TCCAVugAwIBAgIBATAKBggqhkjOPQQDAjAYMRYwFAYDVQQDDA1ybGliLWVj\n"
  "ZHNhNTIxMB4XDTI2MDcyNzIwNDgyMVoXDTQ4MDYyMTIwNDgyMVowGDEWMBQGA1UE\n"
  "AwwNcmxpYi1lY2RzYTUyMTCBmzAQBgcqhkjOPQIBBgUrgQQAIwOBhgAEAXM0f8y9\n"
  "YmTfGEsdGKWUljQ/BpOmgPsHtgrlPrsL5CmpL6JsEMZL1Td7g5tlwKfLh8bB3r8V\n"
  "oS2Z7Rmbt1JFhsOCAIa5xsoVl42QpunyaIYMFi4TSara6eoZDJXQXV0Q2q9mY/Qk\n"
  "erTFmxh4V8vRl2+BFnNDAQ15LglOnRFvVKNnfuY6o1MwUTAdBgNVHQ4EFgQUjgHe\n"
  "cUiLJUWqs95CAU2QI7hnECswHwYDVR0jBBgwFoAUjgHecUiLJUWqs95CAU2QI7hn\n"
  "ECswDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgOBiwAwgYcCQgHGr2XEchte\n"
  "EwLZC2sD13k14Q59MbySYcBefHSm+Yw1VgM3eEgKyYP6ncLqJepTxhKiVCxTjNRS\n"
  "1Pa08NMrrl1+jAJBJ/KZxMUz/jGseAq+OSN6cF6irVc5y/yQi06ZAviKikaqRcyx\n"
  "s5z6FC1GXtKu3yjbdOk8pMJ/3XMmvIKC6iG54TI=\n"
  "-----END CERTIFICATE-----\n";

static const rchar testpkpem_ecdsa521[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIAgpoilaQNti83T+zw\n"
  "0wJL9Y3m0WLkPAmG7bb3cFi26R1Q+XLIF2t/GKwirvWSAD+v7D5OzTMxKF434kLB\n"
  "xpV5HSuhgYkDgYYABAFzNH/MvWJk3xhLHRillJY0PwaTpoD7B7YK5T67C+QpqS+i\n"
  "bBDGS9U3e4ObZcCny4fGwd6/FaEtme0Zm7dSRYbDggCGucbKFZeNkKbp8miGDBYu\n"
  "E0mq2unqGQyV0F1dENqvZmP0JHq0xZsYeFfL0ZdvgRZzQwENeS4JTp0Rb1SjZ37m\n"
  "Og==\n"
  "-----END PRIVATE KEY-----\n";

/* Self-signed Ed25519 certificate + matching PKCS#8 key (CN=rlib-ed25519), for
 * the 1.3 CertificateVerify ed25519 scheme. Same generation constraints as
 * testcertpem_ecdsa (small serial, pre-2050). */
static const rchar testcertpem_ed25519[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBLzCB4qADAgECAgEBMAUGAytlcDAXMRUwEwYDVQQDDAxybGliLWVkMjU1MTkw\n"
  "HhcNMjYwNzI3MjIwNzU4WhcNNDgwNjIxMjIwNzU4WjAXMRUwEwYDVQQDDAxybGli\n"
  "LWVkMjU1MTkwKjAFBgMrZXADIQCraKuX/GZ695ZdM5IWppcYyHKCHa0bsPum1mxl\n"
  "7Su9C6NTMFEwHQYDVR0OBBYEFEejUEmkmH4KhOFQbwqykULLE34rMB8GA1UdIwQY\n"
  "MBaAFEejUEmkmH4KhOFQbwqykULLE34rMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2Vw\n"
  "A0EA+pW3yQXXbirkFdrSS/h4ks261980uyvLB38wOrxsg8y9C2EljrtAcTWOLFQH\n"
  "2Fvt0wDLNP+pQlXYPoqsZL3vDw==\n"
  "-----END CERTIFICATE-----\n";

static const rchar testpkpem_ed25519[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MC4CAQAwBQYDK2VwBCIEIJKdC2hLiSupxcBfuOHOJo21Xs4uo1DHngILAzCzFb3D\n"
  "-----END PRIVATE KEY-----\n";

/* Self-signed Ed448 certificate + matching PKCS#8 key (CN=rlib-ed448), for the
 * 1.3 CertificateVerify ed448 scheme. Same generation constraints as
 * testcertpem_ecdsa (small serial, pre-2050). */
static const rchar testcertpem_ed448[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIBdjCB96ADAgECAgEBMAUGAytlcTAVMRMwEQYDVQQDDApybGliLWVkNDQ4MB4X\n"
  "DTI2MDcyNzIyMzgzNVoXDTQ4MDYyMTIyMzgzNVowFTETMBEGA1UEAwwKcmxpYi1l\n"
  "ZDQ0ODBDMAUGAytlcQM6ALsYJKLhoYrpXLc0/NT4FTHn3ufPTYqN9cNqHoO4G+/n\n"
  "byz7tDfnc0wUY60oV9W+ld4IuPiDnFh+gKNTMFEwHQYDVR0OBBYEFI+7lKgPHo4r\n"
  "16us3Oy20G7dAsKAMB8GA1UdIwQYMBaAFI+7lKgPHo4r16us3Oy20G7dAsKAMA8G\n"
  "A1UdEwEB/wQFMAMBAf8wBQYDK2VxA3MAw/4wBzJpHCJX9A9gGQTJ3kWNtR5q35Nu\n"
  "wC4AAgcxa3P1YVGA7WNyH4HMJkIeCXeQj2/1P9938r4AzHws10Sew1lxXLfnq+/t\n"
  "0zq0Q0xz1qzYfW0Ct/03IBoCDoHfhDx1qMdSEL4q3lRlGnE+kCFlLQ8A\n"
  "-----END CERTIFICATE-----\n";

static const rchar testpkpem_ed448[] =
  "-----BEGIN PRIVATE KEY-----\n"
  "MEcCAQAwBQYDK2VxBDsEORtAq9iHLGotJ4Nctu8X08dMYN9OVyGG7L7/uhFDrJ7q\n"
  "dLpCuWG+OY9CEHXZFz+l0DOgJkvQiK+drg==\n"
  "-----END PRIVATE KEY-----\n";

RTEST_FIXTURE_STRUCT (rtlsclient)
{
  RTLSServer * server;
  RTLSClient * client;

  rboolean srv_hs_done, cli_hs_done;
  rboolean srv_error, cli_error;
  RTLSAlertType srv_alert, cli_alert;   /* alert each side raised at its error */
  rboolean srv_closed, cli_closed;
  rboolean srv_ph_auth_called;          /* server post_handshake_auth cb fired */
  rboolean srv_ph_auth_ok;              /* its result flag */
  ruint verify_calls;
  rboolean verify_result;
  RTLSCipherSuite force_suite;   /* pin both endpoints to one suite; NONE = defaults */

  rboolean sni_cb_called;        /* server's SNI selection cb fired */
  rchar sni_seen[128];           /* SNI host the server's cb received ("" if NULL) */
  RCryptoCert * sni_cert;        /* cert the cb installs for the SNI host, or NULL */
  RCryptoKey * sni_key;

  RClock * clock;
  REvLoop * evloop;
  RPrng * prng;

  RQueue srv_out, cli_out;       /* records each side emits */
  RQueue srv_app, cli_app;       /* decrypted application data each side received */
};

static rboolean
r_tlsclient_test_prefer_ecdhe (rpointer ctx, RTLSVersion ver,
    RTLSCipherSuite * cs, rsize * count)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) ver;
  if (fixture->force_suite == R_TLS_CS_NONE)
    return FALSE;                /* follow the library defaults (ECDHE-first) */
  *count = 1;
  cs[0] = fixture->force_suite;
  return TRUE;
}

static void
r_tlsclient_test_srv_hs_done (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->srv_hs_done = TRUE;
}

static void
r_tlsclient_test_cli_hs_done (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->cli_hs_done = TRUE;
}

static void
r_tlsclient_test_srv_error (rpointer ctx, RTLSAlertType alert, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->srv_error = TRUE;
  fixture->srv_alert = alert;
}

static void
r_tlsclient_test_cli_error (rpointer ctx, RTLSAlertType alert, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->cli_error = TRUE;
  fixture->cli_alert = alert;
}

static void
r_tlsclient_test_srv_closed (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->srv_closed = TRUE;
}

static void
r_tlsclient_test_cli_closed (rpointer ctx, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->cli_closed = TRUE;
}

static rboolean
r_tlsclient_test_srv_out (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->srv_out, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_cli_out (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->cli_out, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_srv_app (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->srv_app, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_cli_app (rpointer ctx, RBuffer * buf, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  return r_queue_push (&fixture->cli_app, r_buffer_ref (buf)) != NULL;
}

static rboolean
r_tlsclient_test_verify_cert (rpointer ctx, RCryptoCert * const * chain, ruint count)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) chain; (void) count;
  fixture->verify_calls++;
  return fixture->verify_result;
}

/* Server-side SNI selection: record the requested name and, if the fixture has
 * one staged, install a per-name certificate for this connection. */
static RTLSError
r_tlsclient_test_sni (rpointer ctx, const rchar * name, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  fixture->sni_cb_called = TRUE;
  if (name != NULL)
    r_strncpy (fixture->sni_seen, name, sizeof (fixture->sni_seen));
  if (fixture->sni_cert != NULL)
    return r_tls_server_set_cert ((RTLSServer *) session,
        fixture->sni_cert, fixture->sni_key);
  return R_TLS_ERROR_OK;
}

static void
r_tlsclient_test_srv_ph_auth (rpointer ctx, rboolean ok, rpointer session)
{
  RTEST_FIXTURE_STRUCT (rtlsclient) * fixture = ctx;
  (void) session;
  fixture->srv_ph_auth_called = TRUE;
  fixture->srv_ph_auth_ok = ok;
}

static const RTLSCallbacks srvcbs = {
  r_tlsclient_test_prefer_ecdhe,
  r_tlsclient_test_srv_hs_done,
  r_tlsclient_test_srv_out,
  r_tlsclient_test_srv_app,
  r_tlsclient_test_srv_error,
  NULL,
  r_tlsclient_test_srv_closed,
  r_tlsclient_test_srv_ph_auth,
};
static const RTLSCallbacks clicbs = {
  r_tlsclient_test_prefer_ecdhe,
  r_tlsclient_test_cli_hs_done,
  r_tlsclient_test_cli_out,
  r_tlsclient_test_cli_app,
  r_tlsclient_test_cli_error,
  r_tlsclient_test_verify_cert,
  r_tlsclient_test_cli_closed,
  NULL,
};

RTEST_FIXTURE_SETUP (rtlsclient)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((fixture->prng = r_prng_new_mt ()), !=, NULL);
  r_assert_cmpptr ((fixture->clock = r_test_clock_new (FALSE)), !=, NULL);
  r_assert_cmpptr ((fixture->evloop = r_ev_loop_new_full (fixture->clock, NULL)), !=, NULL);

  fixture->srv_hs_done = fixture->cli_hs_done = FALSE;
  fixture->srv_error = fixture->cli_error = FALSE;
  fixture->srv_alert = fixture->cli_alert = R_TLS_ALERT_TYPE_CLOSE_NOTIFY;
  fixture->srv_closed = fixture->cli_closed = FALSE;
  fixture->srv_ph_auth_called = fixture->srv_ph_auth_ok = FALSE;
  fixture->verify_calls = 0;
  fixture->verify_result = TRUE;
  fixture->force_suite = R_TLS_CS_NONE;
  fixture->sni_cb_called = FALSE;
  fixture->sni_seen[0] = '\0';
  fixture->sni_cert = NULL;
  fixture->sni_key = NULL;

  r_queue_init (&fixture->srv_out);
  r_queue_init (&fixture->cli_out);
  r_queue_init (&fixture->srv_app);
  r_queue_init (&fixture->cli_app);

  r_assert_cmpptr ((fixture->server = r_tls_server_new (&srvcbs, fixture, NULL)), !=, NULL);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (R_TLS_ERROR_OK, ==,
      r_tls_server_set_cert (fixture->server, cert, pk));
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
}

RTEST_FIXTURE_TEARDOWN (rtlsclient)
{
  if (fixture->sni_cert != NULL)
    r_crypto_cert_unref (fixture->sni_cert);
  if (fixture->sni_key != NULL)
    r_crypto_key_unref (fixture->sni_key);
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);

  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);
  r_queue_clear (&fixture->srv_app, r_buffer_unref);
  r_queue_clear (&fixture->cli_app, r_buffer_unref);

  r_ev_loop_unref (fixture->evloop);
  r_clock_unref (fixture->clock);
  r_prng_unref (fixture->prng);
}

/* Shuttle records between the two endpoints until neither has anything more
 * to send. Each out callback emits one record per buffer, so feeding them
 * back individually works for both TLS and DTLS. */
static void
r_test_tls_loopback_pump (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  RBuffer * buf;
  ruint i;

  for (i = 0; i < 64; i++) {
    rboolean progress = FALSE;

    while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
      r_tls_server_incoming_data (fixture->server, buf);
      r_buffer_unref (buf);
      progress = TRUE;
    }
    while ((buf = r_queue_pop (&fixture->srv_out)) != NULL) {
      r_tls_client_incoming_data (fixture->client, buf);
      r_buffer_unref (buf);
      progress = TRUE;
    }

    if (!progress)
      break;
  }
}

/* Deliver a batch of out records with the encrypted (unified-header) ones
 * reversed, keeping the plaintext epoch-0 records (e.g. ServerHello) ahead of
 * the flight so keys are installed before the protected records arrive. This
 * reorders both whole messages and the fragments within them. */
static rboolean
r_test_deliver_reordered (RQueue * q, RTLSClient * client, RTLSServer * server)
{
  RBuffer * bufs[64];
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint n = 0, i;

  while (n < R_N_ELEMENTS (bufs) && (bufs[n] = r_queue_pop (q)) != NULL)
    n++;
  if (n == 0)
    return FALSE;

  for (i = 0; i < n; i++) {          /* plaintext records first, in order */
    rboolean unified = FALSE;
    if (r_buffer_map (bufs[i], &info, R_MEM_MAP_READ)) {
      unified = r_dtls13_is_unified_hdr (info.data[0]);
      r_buffer_unmap (bufs[i], &info);
    }
    if (!unified) {
      if (server != NULL) r_tls_server_incoming_data (server, bufs[i]);
      else                r_tls_client_incoming_data (client, bufs[i]);
      r_buffer_unref (bufs[i]);
      bufs[i] = NULL;
    }
  }
  for (i = n; i-- > 0; ) {           /* encrypted records reversed */
    if (bufs[i] == NULL)
      continue;
    if (server != NULL) r_tls_server_incoming_data (server, bufs[i]);
    else                r_tls_client_incoming_data (client, bufs[i]);
    r_buffer_unref (bufs[i]);
  }
  return TRUE;
}

static void
r_test_tls_loopback_pump_reorder (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  ruint i;

  for (i = 0; i < 64; i++) {
    rboolean progress = FALSE;
    progress |= r_test_deliver_reordered (&fixture->cli_out, NULL, fixture->server);
    progress |= r_test_deliver_reordered (&fixture->srv_out, fixture->client, NULL);
    if (!progress)
      break;
  }
}

static RBuffer *
r_test_tls_queue_agg (RQueue * q)
{
  RBuffer * ret, * cur;

  if (r_queue_is_empty (q))
    return NULL;
  if ((ret = r_buffer_new ()) != NULL) {
    while ((cur = r_queue_pop (q)) != NULL) {
      r_buffer_append_mem_from_buffer (ret, cur);
      r_buffer_unref (cur);
    }
  }
  return ret;
}

/* Assert @q delivered exactly @data. */
static void
r_test_tls_assert_appdata (RQueue * q, const ruint8 * data, rsize size)
{
  RBuffer * buf;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  r_assert_cmpptr ((buf = r_test_tls_queue_agg (q)), !=, NULL);
  r_assert (r_buffer_map (buf, &info, R_MEM_MAP_READ));
  r_assert_cmpuint (info.size, ==, size);
  r_assert_cmpint (r_memcmp (info.data, data, size), ==, 0);
  r_buffer_unmap (buf, &info);
  r_buffer_unref (buf);
}

/* Assert @buf is an alert record. The close_notify is emitted post-handshake,
 * so its body is encrypted (only the record content type is in the clear); the
 * decrypted warning/close_notify bytes are asserted in the rtlsserver suite. */
static void
r_test_tls_assert_alert_record (RBuffer * buf)
{
  RTLSParser parser = R_TLS_PARSER_INIT;

  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_tls_parser_clear (&parser);
}

/* Drive a handshake, then have one endpoint cleanly close: it emits a warning
 * close_notify, the peer auto-responds (RFC 5246 7.2.1) and reports the orderly
 * close through its closed callback, and neither side accepts further app data.
 * The initiator is not itself notified (it requested the close). */
static void
r_test_tls_close_notify (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version, rboolean server_initiates)
{
  static const ruint8 payload[] = { 'x' };
  RBuffer * buf;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);

  if (server_initiates) {
    r_assert (r_tls_server_close (fixture->server));
    r_assert (!r_tls_server_close (fixture->server));  /* idempotent: a no-op */
    /* The server queued exactly its warning close_notify; deliver it. */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->srv_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_tls_client_incoming_data (fixture->client, buf);
    r_buffer_unref (buf);
    r_assert (fixture->cli_closed);
    r_assert (!fixture->cli_error);
    r_assert (!fixture->srv_closed);                   /* initiator not notified */
    /* The client auto-responded with its own warning close_notify. */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->cli_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_buffer_unref (buf);
  } else {
    r_assert (r_tls_client_close (fixture->client));
    r_assert (!r_tls_client_close (fixture->client));  /* idempotent: a no-op */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->cli_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_tls_server_incoming_data (fixture->server, buf);
    r_buffer_unref (buf);
    r_assert (fixture->srv_closed);
    r_assert (!fixture->srv_error);
    r_assert (!fixture->cli_closed);                   /* initiator not notified */
    r_assert_cmpptr ((buf = r_queue_pop (&fixture->srv_out)), !=, NULL);
    r_test_tls_assert_alert_record (buf);
    r_buffer_unref (buf);
  }

  /* A closed session refuses application data in either direction. */
  r_assert_cmpptr ((buf = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)payload, sizeof (payload), sizeof (payload), 0, NULL, NULL)), !=, NULL);
  r_assert (!r_tls_client_send_appdata (fixture->client, buf));
  r_assert (!r_tls_server_send_appdata (fixture->server, buf));
  r_buffer_unref (buf);
}

static void
r_test_tls_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture, RTLSVersion version)
{
  static const ruint8 c2s[] = { 'h', 'e', 'l', 'l', 'o', ' ', 's', 'e', 'r', 'v', 'e', 'r' };
  static const ruint8 s2c[] = { 'h', 'i', ' ', 'c', 'l', 'i', 'e', 'n', 't' };
  RBuffer * app;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, version);
  r_assert_cmpptr (r_tls_client_get_cipher_suite (fixture->client), !=, NULL);
  /* Both endpoints default to ECDHE-first: forward secrecy out of the box. */
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_ECDHE_RSA);

  /* Application data, client -> server. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  /* Application data, server -> client. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

/* 1.3 1-RTT loopback over @version (TLS 1.3 or DTLS 1.3). The 1.3 suites have no
 * entry in the 1.2-shaped cipher-suite table, so get_cipher_suite is NULL here;
 * we assert the handshake completes, the negotiated version, the peer
 * certificate, and an application-data round-trip in both directions. */
static void
r_test_tls13_loopback_version (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version)
{
  static const ruint8 c2s[] = { 'h', 'e', 'l', 'l', 'o', ' ', '1', '.', '3' };
  static const ruint8 s2c[] = { 'h', 'i', ' ', '1', '.', '3' };
  RBuffer * app;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        version), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, version);
  /* The negotiated 1.3 suite is reported (it has a cipher-suite table entry). */
  r_assert_cmpptr (r_tls_client_get_cipher_suite (fixture->client), !=, NULL);
  if (fixture->force_suite != R_TLS_CS_NONE) {
    r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->suite,
        ==, fixture->force_suite);
  } else {
    r_assert (r_tls_client_get_cipher_suite (fixture->client)->suite ==
          R_TLS_CS_AES_128_GCM_SHA256 ||
        r_tls_client_get_cipher_suite (fixture->client)->suite ==
          R_TLS_CS_AES_256_GCM_SHA384);
  }

  /* Application data, client -> server. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  /* Application data, server -> client. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

/* The bulk of the suite drives TLS 1.3; the versioned core also serves DTLS. */
static void
r_test_tls13_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  r_test_tls13_loopback_version (fixture, R_TLS_VERSION_TLS_1_3);
}

RTEST_F (rtlsclient, tls_loopback, RTEST_FAST)
{
  r_test_tls_loopback (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

/* RSA server certificate: 1.3 CertificateVerify uses rsa_pss_rsae_sha256. */
RTEST_F (rtlsclient, tls13_loopback_rsa, RTEST_FAST)
{
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* ECDSA server certificate: 1.3 CertificateVerify uses ecdsa_secp256r1_sha256. */
RTEST_F (rtlsclient, tls13_loopback_ecdsa, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* P-384 / P-521 ECDSA server certificates: the 1.3 CertificateVerify uses
 * ecdsa_secp384r1_sha384 / ecdsa_secp521r1_sha512, so the server signs and the
 * client verifies with SHA-384 / SHA-512 -- the handshake completing exercises
 * the curve-matched scheme selection and digest on both sides. */
RTEST_F (rtlsclient, tls13_loopback_ecdsa_secp384r1, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa384, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa384, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_loopback (fixture);
}
RTEST_END;

RTEST_F (rtlsclient, tls13_loopback_ecdsa_secp521r1, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa521, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa521, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Ed25519 server certificate: the 1.3 CertificateVerify uses the ed25519 scheme,
 * so the server signs and the client verifies over the content directly (no
 * pre-hash). The handshake completing exercises the PureEdDSA sign/verify path. */
RTEST_F (rtlsclient, tls13_loopback_ed25519, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ed25519, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ed25519, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Ed448 server certificate: the 1.3 CertificateVerify uses the ed448 scheme,
 * so the server signs and the client verifies over the content directly (no
 * pre-hash). The handshake completing exercises the PureEdDSA sign/verify path. */
RTEST_F (rtlsclient, tls13_loopback_ed448, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ed448, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ed448, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Force AES_256_GCM_SHA384 to exercise the SHA-384 key schedule end to end. */
RTEST_F (rtlsclient, tls13_loopback_aes256, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_AES_256_GCM_SHA384;
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Force TLS_CHACHA20_POLY1305_SHA256 (0x1303): the ChaCha20-Poly1305 AEAD
 * drives the 1.3 record layer end to end. */
RTEST_F (rtlsclient, tls13_loopback_chacha20, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_CHACHA20_POLY1305_SHA256;
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* TLS 1.3 post-handshake KeyUpdate (RFC 8446 4.6.3). After the handshake each
 * endpoint rekeys its sending direction; the peer must track the rotation for
 * records to keep decrypting. A key_update requesting a peer update makes the
 * peer answer with its own KeyUpdate, rotating both directions. An app-data
 * round trip after each rotation proves the keys stayed in sync. */
RTEST_F (rtlsclient, tls13_key_update, RTEST_FAST)
{
  static const ruint8 a[] = { 'a', 'f', 't', 'e', 'r', '1' };
  static const ruint8 b[] = { 'a', 'f', 't', 'e', 'r', '2' };
  RBuffer * app;

  /* KeyUpdate is refused before the session is established. */
  r_assert (!r_tls_client_key_update (fixture->client, FALSE));

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);

  /* Client rekeys its sending direction; the peer need not respond. */
  r_assert (r_tls_client_key_update (fixture->client, FALSE));
  r_test_tls_loopback_pump (fixture);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* client -> server still decrypts under the client's new send key. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)a, sizeof (a), sizeof (a), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, a, sizeof (a));

  /* Server rekeys and asks the client to rekey too: the client's auto-response
   * KeyUpdate rotates the remaining direction, so both are now fresh. */
  r_assert (r_tls_server_key_update (fixture->server, TRUE));
  r_test_tls_loopback_pump (fixture);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* server -> client under the server's new send key. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)b, sizeof (b), sizeof (b), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, b, sizeof (b));

  /* client -> server under the client's twice-rotated send key. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)a, sizeof (a), sizeof (a), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, a, sizeof (a));

  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
}
RTEST_END;

/* ALPN (RFC 7301): the client offers a protocol list, the server selects by its
 * own preference from the overlap, and both endpoints report the same choice.
 * Parameterised by @version to cover the 1.2 ServerHello and the 1.3
 * EncryptedExtensions carrier. */
static void
r_test_tls_alpn_negotiated (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version)
{
  static const rchar * srv[] = { "h2", "http/1.1" };
  static const rchar * cli[] = { "http/1.1", "h2" };
  const rchar * sel;
  rsize sellen = 0;

  r_assert_cmpint (r_tls_server_set_alpn_protocols (fixture->server,
        srv, R_N_ELEMENTS (srv)), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_alpn_protocols (fixture->client,
        cli, R_N_ELEMENTS (cli)), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        version), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* Server preference wins: "h2" is the server's first choice and the client
   * offers it too, so both sides agree on "h2". */
  sel = r_tls_client_get_alpn_selected (fixture->client, &sellen);
  r_assert_cmpptr (sel, !=, NULL);
  r_assert_cmpuint (sellen, ==, 2);
  r_assert_cmpint (r_memcmp (sel, "h2", 2), ==, 0);

  sel = r_tls_server_get_alpn_selected (fixture->server, &sellen);
  r_assert_cmpptr (sel, !=, NULL);
  r_assert_cmpuint (sellen, ==, 2);
  r_assert_cmpint (r_memcmp (sel, "h2", 2), ==, 0);
}

RTEST_F (rtlsclient, tls_alpn, RTEST_FAST)
{
  r_test_tls_alpn_negotiated (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, tls13_alpn, RTEST_FAST)
{
  r_test_tls_alpn_negotiated (fixture, R_TLS_VERSION_TLS_1_3);
}
RTEST_END;

/* The client offers ALPN but the server has none configured: no protocol is
 * negotiated and the handshake still completes. Input validation of the
 * protocol list is exercised alongside. */
RTEST_F (rtlsclient, tls13_alpn_server_unconfigured, RTEST_FAST)
{
  static const rchar * cli[] = { "h2" };
  static const rchar * bad[] = { "" };
  rsize sellen = 1;

  r_assert_cmpint (r_tls_client_set_alpn_protocols (fixture->client, bad, 1),
      ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_client_set_alpn_protocols (fixture->client,
        cli, R_N_ELEMENTS (cli)), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpptr (r_tls_client_get_alpn_selected (fixture->client, &sellen), ==, NULL);
  r_assert_cmpuint (sellen, ==, 0);
}
RTEST_END;

/* The server requires secp256r1 but the client offers an x25519 key_share, so
 * the server answers with a HelloRetryRequest and the client retries with a
 * secp256r1 share. The handshake can only complete if the retry worked. */
RTEST_F (rtlsclient, tls13_loopback_hrr, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_SECP256R1), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* The client offers a key_share for x25519 but lists the other supported groups
 * too; pinning the server to each in turn forces a HelloRetryRequest and drives
 * the client's retry with that group's key_share. The handshake completing
 * exercises keygen / point / ECDH shared-secret for the group end to end -- the
 * secp521r1 case in particular covers the 66-byte secret / 133-byte point. */
RTEST_F (rtlsclient, tls13_loopback_group_secp384r1, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_SECP384R1), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback (fixture);
}
RTEST_END;

RTEST_F (rtlsclient, tls13_loopback_group_secp521r1, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_SECP521R1), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback (fixture);
}
RTEST_END;

RTEST_F (rtlsclient, tls13_loopback_group_x448, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_X448), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Finite-field (ffdhe, RFC 7919) key exchange: pinning the server to an ffdhe
 * group forces a HelloRetryRequest and the client retries with an ffdhe
 * key_share. The handshake completing exercises the DH keygen / public-value
 * encoding / shared secret. ffdhe8192 (the 1024-byte value / secret) is in the
 * heavy tier because its modular exponentiations are expensive. */
RTEST_F (rtlsclient, tls13_loopback_group_ffdhe2048, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_FFDHE2048), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback (fixture);
}
RTEST_END;

HEAVY_RTEST_F (rtlsclient, tls13_loopback_group_ffdhe8192, RTEST_SLOW)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_FFDHE8192), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback (fixture);
}
RTEST_END;

/* Drain @from, asserting every record's ciphertext fits a @limit-byte plaintext
 * cap (RFC 8449: header + inner plaintext<=limit + AEAD tag), feed each into the
 * server (@to_server) or client, and return the record count. */
static ruint
r_test_tls_relay_capped (RQueue * from, ruint16 limit,
    rboolean to_server, RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  RBuffer * rec;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  ruint n = 0;

  while ((rec = r_queue_pop (from)) != NULL) {
    r_assert (r_buffer_map (rec, &info, R_MEM_MAP_READ));
    r_assert_cmpuint (info.size, <=,
        R_TLS_RECORD_HDR_SIZE + (rsize) limit + R_TLS13_AEAD_TAG_SIZE);
    r_buffer_unmap (rec, &info);
    if (to_server)
      r_tls_server_incoming_data (fixture->server, rec);
    else
      r_tls_client_incoming_data (fixture->client, rec);
    r_buffer_unref (rec);
    n++;
  }
  return n;
}

/* record_size_limit (RFC 8449): both endpoints advertise a small receive limit;
 * the handshake completes and each direction honours the peer's cap, fragmenting
 * larger application data into multiple records that reassemble to the original.
 * The client sends toward @srv_limit (the server's advertised value), the server
 * toward @cli_limit. */
static void
r_test_tls13_record_size_limit (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    ruint16 cli_limit, ruint16 srv_limit)
{
  ruint8 payload[1000];
  RBuffer * app;
  rsize i;

  for (i = 0; i < sizeof (payload); i++)
    payload[i] = (ruint8) (i & 0xff);

  r_assert_cmpint (r_tls_client_set_record_size_limit (fixture->client, cli_limit),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_record_size_limit (fixture->server, srv_limit),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* Client -> server: the client caps each record at the server's limit. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          payload, sizeof (payload), sizeof (payload), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_assert_cmpuint (r_test_tls_relay_capped (&fixture->cli_out, srv_limit, TRUE, fixture),
      >, 1);
  r_test_tls_assert_appdata (&fixture->srv_app, payload, sizeof (payload));

  /* Server -> client: symmetrically capped at the client's limit. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          payload, sizeof (payload), sizeof (payload), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_assert_cmpuint (r_test_tls_relay_capped (&fixture->srv_out, cli_limit, FALSE, fixture),
      >, 1);
  r_test_tls_assert_appdata (&fixture->cli_app, payload, sizeof (payload));

  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
}

RTEST_F (rtlsclient, tls13_record_size_limit, RTEST_FAST)
{
  r_test_tls13_record_size_limit (fixture, 64, 100);
}
RTEST_END;

/* An incoming record whose plaintext exceeds the limit we advertised is a fatal
 * record_overflow (RFC 8449). Post-handshake application_data is AEAD-protected
 * and would fail decryption before the size guard, so a plaintext handshake-type
 * record -- which skips decryption -- exercises the guard directly. */
RTEST_F (rtlsclient, tls13_record_size_limit_incoming_overflow, RTEST_FAST)
{
  ruint8 big[R_TLS_RECORD_HDR_SIZE + 200];
  RBuffer * rec;

  r_assert_cmpint (r_tls_client_set_record_size_limit (fixture->client, 64),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_record_size_limit (fixture->server, 64),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (!fixture->cli_error);

  r_memclear (big, sizeof (big));
  big[0] = R_TLS_CONTENT_TYPE_HANDSHAKE;
  r_store_be16 (&big[1], R_TLS_VERSION_TLS_1_2);
  r_store_be16 (&big[3], 200);                /* fragment length 200 > 64 */
  r_assert_cmpptr ((rec = r_buffer_new_wrapped (R_MEM_FLAG_NONE, big,
          sizeof (big), sizeof (big), 0, NULL, NULL)), !=, NULL);
  r_tls_client_incoming_data (fixture->client, rec);
  r_buffer_unref (rec);

  r_assert (fixture->cli_error);
  r_assert_cmpuint (fixture->cli_alert, ==, R_TLS_ALERT_TYPE_RECORD_OVERFLOW);
}
RTEST_END;

/* The limit must lie in 64 .. 2^14; 0 disables the extension. */
RTEST_F (rtlsclient, tls13_record_size_limit_invalid, RTEST_FAST)
{
  r_assert_cmpint (r_tls_client_set_record_size_limit (fixture->client, 63),
      ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_client_set_record_size_limit (fixture->client,
        R_TLS_MAX_PLAINTEXT + 1), ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_client_set_record_size_limit (fixture->client, 0),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_record_size_limit (fixture->client, 64),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_record_size_limit (fixture->client,
        R_TLS_MAX_PLAINTEXT), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_set_record_size_limit (fixture->server, 63),
      ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_server_set_record_size_limit (fixture->server,
        R_TLS_MAX_PLAINTEXT + 1), ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_server_set_record_size_limit (fixture->server, 64),
      ==, R_TLS_ERROR_OK);
}
RTEST_END;

/* OCSP stapling (status_request, RFC 6066 / RFC 8446 4.4.2.1): the client offers
 * status_request and the server, with a response configured, staples it in the
 * leaf CertificateEntry; the client retrieves the identical bytes. @staplelen
 * spans small and multi-KB responses (the latter outgrows the certificate scratch
 * buffer, exercising the heap-built Certificate message). */
static void
r_test_tls13_ocsp_staple (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture, rsize staplelen)
{
  ruint8 * staple;
  const ruint8 * got;
  rsize gotlen = 0, i;

  r_assert_cmpptr ((staple = r_malloc (staplelen)), !=, NULL);
  for (i = 0; i < staplelen; i++)
    staple[i] = (ruint8) ((i * 7 + 3) & 0xff);

  r_assert_cmpint (r_tls_client_request_ocsp (fixture->client, TRUE),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_ocsp_response (fixture->server, staple, staplelen),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  got = r_tls_client_get_ocsp_response (fixture->client, &gotlen);
  r_assert_cmpptr (got, !=, NULL);
  r_assert_cmpuint (gotlen, ==, staplelen);
  r_assert_cmpmem (got, ==, staple, staplelen);

  r_free (staple);
}

RTEST_F (rtlsclient, tls13_ocsp_staple, RTEST_FAST)
{
  r_test_tls13_ocsp_staple (fixture, 128);
}
RTEST_END;

/* A multi-KB staple forces the Certificate message past the stack scratch buffer. */
RTEST_F (rtlsclient, tls13_ocsp_staple_large, RTEST_FAST)
{
  r_test_tls13_ocsp_staple (fixture, 6000);
}
RTEST_END;

/* No staple is delivered when the client did not ask, even if the server has one
 * configured; and none when the client asks but the server has none. Either way
 * the handshake completes. */
RTEST_F (rtlsclient, tls13_ocsp_not_delivered, RTEST_FAST)
{
  static const ruint8 staple[] = { 0x30, 0x03, 0x0a, 0x01, 0x00 };
  const ruint8 * got;
  rsize gotlen = 1;

  /* Server has a response, but the client never offers status_request. */
  r_assert_cmpint (r_tls_server_set_ocsp_response (fixture->server, staple,
        sizeof (staple)), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (!fixture->cli_error);

  got = r_tls_client_get_ocsp_response (fixture->client, &gotlen);
  r_assert_cmpptr (got, ==, NULL);
  r_assert_cmpuint (gotlen, ==, 0);
}
RTEST_END;

/* status_request offered, but the server stapled nothing: no OCSP delivered. */
RTEST_F (rtlsclient, tls13_ocsp_requested_server_none, RTEST_FAST)
{
  const ruint8 * got;
  rsize gotlen = 1;

  r_assert_cmpint (r_tls_client_request_ocsp (fixture->client, TRUE),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (!fixture->cli_error);

  got = r_tls_client_get_ocsp_response (fixture->client, &gotlen);
  r_assert_cmpptr (got, ==, NULL);
  r_assert_cmpuint (gotlen, ==, 0);
}
RTEST_END;

/* set_ocsp_response validates its arguments. */
RTEST_F (rtlsclient, tls13_ocsp_set_validation, RTEST_FAST)
{
  static const ruint8 der[] = { 0x30, 0x03, 0x0a, 0x01, 0x00 };

  r_assert_cmpint (r_tls_server_set_ocsp_response (fixture->server, der, 0),
      ==, R_TLS_ERROR_INVAL);          /* non-NULL der, zero len */
  r_assert_cmpint (r_tls_server_set_ocsp_response (fixture->server, NULL, 5),
      ==, R_TLS_ERROR_INVAL);          /* NULL der, non-zero len */
  r_assert_cmpint (r_tls_server_set_ocsp_response (fixture->server, der, sizeof (der)),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_ocsp_response (fixture->server, NULL, 0),
      ==, R_TLS_ERROR_OK);             /* clear */
}
RTEST_END;

/* signed_certificate_timestamp (RFC 6962): the client offers the extension and
 * the server carries the SignedCertificateTimestampList verbatim in the leaf
 * CertificateEntry; the client retrieves the identical bytes. */
RTEST_F (rtlsclient, tls13_sct, RTEST_FAST)
{
  static const ruint8 scts[] = {
    0x00, 0x12, 0x00, 0x10, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c };
  const ruint8 * got;
  rsize gotlen = 0;

  r_assert_cmpint (r_tls_client_request_sct (fixture->client, TRUE),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_sct_list (fixture->server, scts, sizeof (scts)),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);

  got = r_tls_client_get_sct_list (fixture->client, &gotlen);
  r_assert_cmpptr (got, !=, NULL);
  r_assert_cmpuint (gotlen, ==, sizeof (scts));
  r_assert_cmpmem (got, ==, scts, sizeof (scts));
}
RTEST_END;

/* OCSP staple and SCTs ride the same leaf CertificateEntry: both are delivered
 * when both are requested and configured. */
RTEST_F (rtlsclient, tls13_ocsp_and_sct, RTEST_FAST)
{
  static const ruint8 ocsp[] = { 0x30, 0x05, 0x0a, 0x01, 0x00, 0x02, 0x00 };
  static const ruint8 scts[] = { 0x00, 0x06, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd };
  const ruint8 * got;
  rsize gotlen = 0;

  r_assert_cmpint (r_tls_client_request_ocsp (fixture->client, TRUE),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_request_sct (fixture->client, TRUE),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_ocsp_response (fixture->server, ocsp, sizeof (ocsp)),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_sct_list (fixture->server, scts, sizeof (scts)),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (!fixture->cli_error);

  got = r_tls_client_get_ocsp_response (fixture->client, &gotlen);
  r_assert_cmpptr (got, !=, NULL);
  r_assert_cmpuint (gotlen, ==, sizeof (ocsp));
  r_assert_cmpmem (got, ==, ocsp, sizeof (ocsp));

  got = r_tls_client_get_sct_list (fixture->client, &gotlen);
  r_assert_cmpptr (got, !=, NULL);
  r_assert_cmpuint (gotlen, ==, sizeof (scts));
  r_assert_cmpmem (got, ==, scts, sizeof (scts));
}
RTEST_END;

/* No SCTs are delivered when the client did not ask, even with some configured. */
RTEST_F (rtlsclient, tls13_sct_not_delivered, RTEST_FAST)
{
  static const ruint8 scts[] = { 0x00, 0x06, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd };
  const ruint8 * got;
  rsize gotlen = 1;

  r_assert_cmpint (r_tls_server_set_sct_list (fixture->server, scts, sizeof (scts)),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (!fixture->cli_error);

  got = r_tls_client_get_sct_list (fixture->client, &gotlen);
  r_assert_cmpptr (got, ==, NULL);
  r_assert_cmpuint (gotlen, ==, 0);
}
RTEST_END;

/* set_sct_list validates its arguments. */
RTEST_F (rtlsclient, tls13_sct_set_validation, RTEST_FAST)
{
  static const ruint8 scts[] = { 0x00, 0x06, 0x00, 0x04, 0xaa, 0xbb, 0xcc, 0xdd };

  r_assert_cmpint (r_tls_server_set_sct_list (fixture->server, scts, 0),
      ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_server_set_sct_list (fixture->server, NULL, 5),
      ==, R_TLS_ERROR_INVAL);
  r_assert_cmpint (r_tls_server_set_sct_list (fixture->server, scts, sizeof (scts)),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_sct_list (fixture->server, NULL, 0),
      ==, R_TLS_ERROR_OK);
}
RTEST_END;

/* Drive CH1 -> HelloRetryRequest with a server that requires secp256r1 while
 * the client first offers x25519. Returns the (still-owned) HRR record and
 * leaves the client having consumed nothing yet. */
static RBuffer *
r_test_tls13_hrr_drive (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  RBuffer * ch1, * hrr;

  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_SECP256R1), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_assert_cmpptr ((ch1 = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch1);
  r_buffer_unref (ch1);
  r_assert_cmpptr ((hrr = r_queue_pop (&fixture->srv_out)), !=, NULL);
  return hrr;
}

/* A second HelloRetryRequest is illegal (RFC 8446 4.1.4): once the client has
 * answered one HRR, replaying it aborts with unexpected_message. */
RTEST_F (rtlsclient, tls13_hrr_second_rejected, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);

  /* First HRR: the client retries (CH2), no error. */
  r_tls_client_incoming_data (fixture->client, hrr);
  r_assert (!fixture->cli_error);

  /* Replaying the HRR is a second one -- reject it. */
  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);

  r_assert (fixture->cli_error);
  r_assert_cmpuint (fixture->cli_alert, ==, R_TLS_ALERT_TYPE_UNEXPECTED_MESSAGE);
  r_assert (!fixture->cli_hs_done);
}
RTEST_END;

/* After a HelloRetryRequest the ServerHello must keep the suite the HRR
 * committed to; a changed suite is illegal_parameter (RFC 8446 4.1.4). */
RTEST_F (rtlsclient, tls13_hrr_serverhello_suite_mismatch, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);
  RBuffer * ch2, * sh;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize csoff;
  ruint16 cur;

  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);

  /* CH2 -> server sends its second flight; the ServerHello is the first record. */
  r_assert_cmpptr ((ch2 = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch2);
  r_buffer_unref (ch2);
  r_assert_cmpptr ((sh = r_queue_pop (&fixture->srv_out)), !=, NULL);

  /* Rewrite the ServerHello cipher_suite to a different (valid) 1.3 suite. The
   * field sits after record hdr(5) + hs hdr(4) + version(2) + random(32) +
   * legacy_session_id (1-byte length + echo). */
  r_assert (r_buffer_map (sh, &info, R_MEM_MAP_WRITE));
  r_assert_cmpuint (info.data[0], ==, R_TLS_CONTENT_TYPE_HANDSHAKE);
  r_assert_cmpuint (info.data[5], ==, R_TLS_HANDSHAKE_TYPE_SERVER_HELLO);
  csoff = 44 + info.data[43];
  cur = r_load_be16 (info.data + csoff);
  r_store_be16 (info.data + csoff, cur == R_TLS_CS_AES_128_GCM_SHA256 ?
      (ruint16) R_TLS_CS_AES_256_GCM_SHA384 : (ruint16) R_TLS_CS_AES_128_GCM_SHA256);
  r_assert (r_buffer_unmap (sh, &info));

  r_tls_client_incoming_data (fixture->client, sh);
  r_buffer_unref (sh);

  r_assert (fixture->cli_error);
  r_assert_cmpuint (fixture->cli_alert, ==, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
  r_assert (!fixture->cli_hs_done);
}
RTEST_END;

/* The retry ClientHello must echo the HelloRetryRequest cookie verbatim; a
 * corrupted echo is rejected by the server with illegal_parameter. */
RTEST_F (rtlsclient, tls13_hrr_cookie_mismatch, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);
  RBuffer * ch2;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RTLSHelloExt ext;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  const ruint8 * cookie = NULL;
  ruint16 cookielen = 0;
  ruint8 ckcopy[64];
  rsize i, off = 0;
  rboolean found = FALSE;
  RTLSError e;

  /* Read the cookie the HRR carries. */
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, hrr), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&hello, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_COOKIE) {
      cookie = r_tls_hello_ext_cookie (&ext, &cookielen);
      r_assert_cmpuint (cookielen, >, 0);
      r_assert_cmpuint (cookielen, <=, sizeof (ckcopy));
      r_memcpy (ckcopy, cookie, cookielen);
      found = TRUE;
    }
  }
  r_assert (found);
  r_tls_parser_clear (&parser);

  /* Client retries (CH2), echoing the cookie. */
  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);
  r_assert_cmpptr ((ch2 = r_queue_pop (&fixture->cli_out)), !=, NULL);

  /* Locate the echoed cookie in CH2 and flip one of its bytes. */
  r_assert (r_buffer_map (ch2, &info, R_MEM_MAP_WRITE));
  found = FALSE;
  for (i = 0; i + cookielen <= info.size; i++) {
    if (r_memcmp (info.data + i, ckcopy, cookielen) == 0) { off = i; found = TRUE; break; }
  }
  r_assert (found);
  info.data[off] ^= 0xff;
  r_assert (r_buffer_unmap (ch2, &info));

  r_tls_server_incoming_data (fixture->server, ch2);
  r_buffer_unref (ch2);

  r_assert (fixture->srv_error);
  r_assert_cmpuint (fixture->srv_alert, ==, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

/* The retry ClientHello must carry a key_share for the group the
 * HelloRetryRequest asked for; a retry that still omits it (here its share is
 * repointed to another group) leaves the server with no usable share and it
 * aborts with handshake_failure rather than issuing a second HRR. */
RTEST_F (rtlsclient, tls13_hrr_retry_missing_share, RTEST_FAST)
{
  RBuffer * hrr = r_test_tls13_hrr_drive (fixture);
  RBuffer * ch2;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RTLSHelloExt ext;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  rsize ksoff = 0;
  rboolean found = FALSE;
  RTLSError e;

  r_tls_client_incoming_data (fixture->client, hrr);
  r_buffer_unref (hrr);
  r_assert_cmpptr ((ch2 = r_queue_pop (&fixture->cli_out)), !=, NULL);

  /* Find the first KeyShareEntry's group id -- ext.data opens with the
   * client_shares vector length(2), then group(2) -- and repoint it. */
  r_assert (r_buffer_map (ch2, &info, R_MEM_MAP_READ));
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, ch2), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  for (e = r_tls_hello_msg_extension_first (&hello, &ext); e == R_TLS_ERROR_OK;
      e = r_tls_hello_msg_extension_next (&hello, &ext)) {
    if (ext.type == R_TLS_EXT_TYPE_KEY_SHARE) {
      ksoff = (rsize) (ext.data - info.data) + 2;
      found = TRUE;
    }
  }
  r_tls_parser_clear (&parser);
  r_assert (found);
  r_assert (r_buffer_unmap (ch2, &info));

  r_assert (r_buffer_map (ch2, &info, R_MEM_MAP_WRITE));
  r_assert_cmpuint (r_load_be16 (info.data + ksoff), ==, R_TLS_SUPPORTED_GROUP_SECP256R1);
  r_store_be16 (info.data + ksoff, (ruint16) R_TLS_SUPPORTED_GROUP_X25519);
  r_assert (r_buffer_unmap (ch2, &info));

  r_tls_server_incoming_data (fixture->server, ch2);
  r_buffer_unref (ch2);

  r_assert (fixture->srv_error);
  r_assert_cmpuint (fixture->srv_alert, ==, R_TLS_ALERT_TYPE_HANDSHAKE_FAILURE);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

/* Build a fresh server pre-loaded with the test cert and @keys (shared so a
 * later connection can open a ticket the first sealed). */
static RTLSServer *
r_test_tls13_new_server (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSSessionTicketKeys * keys)
{
  RTLSServer * s = r_tls_server_new (&srvcbs, fixture, NULL);
  RCryptoCert * cert = r_pem_parse_cert_from_data (testcertpem, -1);
  RCryptoKey * pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0);
  r_assert_cmpint (r_tls_server_set_cert (s, cert, pk), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (s, keys), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
  return s;
}

/* Full 1.3 handshake yields a NewSessionTicket; a second connection resumes
 * from it with an abbreviated handshake (no certificate exchanged) that still
 * carries application data both ways. The two servers share a ticket-key store,
 * as separate server instances would in production. */
RTEST_F (rtlsclient, tls13_resumption, RTEST_FAST)
{
  static const ruint8 c2s[] = { 'r', 'e', 's', 'u', 'm', 'e' };
  static const ruint8 s2c[] = { 'o', 'k' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First (full) handshake. The server issues a NewSessionTicket. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  r_assert_cmpuint (fixture->verify_calls, ==, 1);   /* full handshake verified a cert */

  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* Fresh endpoints (sharing the key store) for the resumed handshake. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_3);
  /* Resumption authenticates via the PSK: no Certificate, so verify_cert was
   * not called again and no peer certificate was received. */
  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), ==, NULL);

  /* The resumed session carries application data both ways. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* A resumption ClientHello whose pre_shared_key binder does not match the one
 * the server recomputes over the ticket PSK is rejected: the server opens the
 * ticket, fails the binder check and aborts with a fatal decrypt_error alert
 * instead of completing the abbreviated handshake. */
RTEST_F (rtlsclient, tls13_resumption_bad_binder, RTEST_FAST)
{
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;
  RBuffer * ch, * alert;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First (full) handshake to obtain a ticket. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* Fresh endpoints sharing the key store; the ticket opens but we corrupt the
   * binder on the wire. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  fixture->cli_error = fixture->srv_error = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  /* The ClientHello ends with the binder (pre_shared_key is last); flipping its
   * final byte leaves the transcript the server hashes intact but breaks the
   * binder value. */
  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert (r_buffer_map (ch, &info, R_MEM_MAP_WRITE));
  info.data[info.size - 1] ^= 0xff;
  r_assert (r_buffer_unmap (ch, &info));

  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);

  r_assert (fixture->srv_error);
  r_assert (!fixture->srv_hs_done);

  r_assert_cmpptr ((alert = r_queue_pop (&fixture->srv_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_DECRYPT_ERROR);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* A ticket the resuming server cannot open (its key store never sealed it) is
 * silently declined: the pre_shared_key offer is ignored and the handshake
 * falls back to a full one, verifying the certificate again. */
RTEST_F (rtlsclient, tls13_resumption_ticket_declined, RTEST_FAST)
{
  RTLSSessionTicketKeys * keys, * otherkeys;
  RTLSClientSession * session;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First (full) handshake seals a ticket under @keys. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* The resuming server holds an unrelated key store, so the ticket will not
   * open. */
  r_assert_cmpptr ((otherkeys = r_tls_session_ticket_keys_new ()), !=, NULL);
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, otherkeys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  /* Full handshake ran instead: no error, a certificate was verified again and
   * a peer certificate is present. */
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_3);
  r_assert_cmpuint (fixture->verify_calls, ==, 2);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
  r_tls_session_ticket_keys_unref (otherkeys);
}
RTEST_END;

/* A first handshake against an early-data-enabled server yields a ticket that
 * permits 0-RTT; the resumed connection sends early data after the ClientHello,
 * the server accepts it (echoes early_data) and delivers it via appdata before
 * the handshake completes. */
RTEST_F (rtlsclient, tls13_early_data_accepted, RTEST_FAST)
{
  static const ruint8 early[] = { 'G', 'E', 'T', ' ', '/' };
  static const ruint8 s2c[] = { 'o', 'k' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First handshake: the server offers 0-RTT, so its ticket advertises it. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* Fresh endpoints (sharing the key store); the client offers 0-RTT data. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)early, sizeof (early), sizeof (early), 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_early_data (fixture->client, app), ==, R_TLS_ERROR_OK);
  r_buffer_unref (app);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  fixture->verify_calls = 0;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  /* Both endpoints agree 0-RTT was accepted; the certificate was not re-sent. */
  r_assert (r_tls_client_get_early_data_accepted (fixture->client));
  r_assert (r_tls_server_get_early_data_accepted (fixture->server));
  r_assert_cmpuint (fixture->verify_calls, ==, 0);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), ==, NULL);
  /* The early data reached the server as application data during the handshake. */
  r_test_tls_assert_appdata (&fixture->srv_app, early, sizeof (early));

  /* 1-RTT data still flows afterwards. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* When the resuming server declines 0-RTT (early data disabled), the client's
 * early-data records are discarded and the payload is transparently resent as
 * ordinary application data once the handshake completes. */
RTEST_F (rtlsclient, tls13_early_data_rejected, RTEST_FAST)
{
  static const ruint8 early[] = { 'P', 'I', 'N', 'G' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First handshake against an early-data-enabled server: the ticket permits
   * 0-RTT, so the client will actually put early data on the wire. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* The resuming server does NOT enable 0-RTT, so it declines the offer. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)early, sizeof (early), sizeof (early), 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_early_data (fixture->client, app), ==, R_TLS_ERROR_OK);
  r_buffer_unref (app);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
  /* Neither side saw 0-RTT accepted, yet the payload was delivered once, resent
   * as 1-RTT application data. */
  r_assert (!r_tls_client_get_early_data_accepted (fixture->client));
  r_assert (!r_tls_server_get_early_data_accepted (fixture->server));
  r_test_tls_assert_appdata (&fixture->srv_app, early, sizeof (early));

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* The resuming server accepts 0-RTT but has a smaller max_early_data_size than
 * the ticket originally advertised; a client payload that overshoots that limit
 * is rejected on the server rather than delivered (RFC 8446 4.2.10). */
RTEST_F (rtlsclient, tls13_early_data_exceeds_max, RTEST_FAST)
{
  static const ruint8 early[] = { 'T', 'O', 'O', 'M', 'U', 'C', 'H', '!' };
  RTLSSessionTicketKeys * keys;
  RTLSClientSession * session;
  RBuffer * app;

  r_assert_cmpptr ((keys = r_tls_session_ticket_keys_new ()), !=, NULL);

  /* First handshake advertises a generous limit, so the ticket permits enough
   * early data for the payload below. */
  r_assert_cmpint (r_tls_server_set_session_ticket_keys (fixture->server, keys),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 0x4000),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert_cmpptr ((session = r_tls_client_get_session (fixture->client)), !=, NULL);

  /* The resuming server now enforces a limit of 4 bytes, below the 8-byte
   * payload the client offers as 0-RTT. */
  r_tls_client_unref (fixture->client);
  r_tls_server_unref (fixture->server);
  fixture->server = r_test_tls13_new_server (fixture, keys);
  r_assert_cmpint (r_tls_server_set_max_early_data_size (fixture->server, 4),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((fixture->client = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_session (fixture->client, session), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)early, sizeof (early), sizeof (early), 0, NULL, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_early_data (fixture->client, app), ==, R_TLS_ERROR_OK);
  r_buffer_unref (app);

  fixture->cli_hs_done = fixture->srv_hs_done = FALSE;
  fixture->cli_error = fixture->srv_error = FALSE;
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  /* The server aborted the handshake on the over-long early data; the oversized
   * record was never delivered to the application. */
  r_assert (fixture->srv_error);
  r_assert (!fixture->srv_hs_done);
  r_assert_cmpuint (r_queue_size (&fixture->srv_app), ==, 0);

  r_tls_client_session_unref (session);
  r_tls_session_ticket_keys_unref (keys);
}
RTEST_END;

/* In 1.3, alerts after the handshake are AEAD-protected (RFC 8446 5): the
 * server's close_notify goes out as an application_data record, the client
 * decrypts it, reports the orderly close and auto-responds with its own
 * protected close_notify. */
RTEST_F (rtlsclient, tls13_close_notify, RTEST_FAST)
{
  RBuffer * buf;
  RTLSParser parser = R_TLS_PARSER_INIT;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);

  r_assert (r_tls_server_close (fixture->server));
  r_assert_cmpptr ((buf = r_queue_pop (&fixture->srv_out)), !=, NULL);
  /* Protected: the record carries application_data, not a cleartext alert. */
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_APPLICATION_DATA);
  r_tls_parser_clear (&parser);

  r_tls_client_incoming_data (fixture->client, buf);
  r_buffer_unref (buf);
  r_assert (fixture->cli_closed);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_closed);   /* the initiator is not itself notified */

  /* The client auto-responded with its own protected close_notify. */
  r_assert_cmpptr ((buf = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_APPLICATION_DATA);
  r_tls_parser_clear (&parser);
  r_buffer_unref (buf);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_loopback, RTEST_FAST)
{
  r_test_tls_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* DTLS 1.3 (RFC 9147) 1-RTT loopback over the unified record layer: the same
 * 1.3 handshake as TLS, reframed onto DTLS records (unified header, encrypted
 * sequence numbers, epochs). RSA server cert -> rsa_pss_rsae_sha256. */
RTEST_F (rtlsclient, dtls13_loopback_rsa, RTEST_FAST)
{
  r_test_tls13_loopback_version (fixture, R_TLS_VERSION_DTLS_1_3);
}
RTEST_END;

/* ECDSA server certificate over DTLS 1.3: CertificateVerify uses
 * ecdsa_secp256r1_sha256. */
RTEST_F (rtlsclient, dtls13_loopback_ecdsa, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_loopback_version (fixture, R_TLS_VERSION_DTLS_1_3);
}
RTEST_END;

/* DTLS 1.3 forcing the ChaCha20-Poly1305 suite: exercises the ChaCha20 variant
 * of the record sequence-number masking on both endpoints. */
RTEST_F (rtlsclient, dtls13_loopback_chacha20, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_CHACHA20_POLY1305_SHA256;
  r_test_tls13_loopback_version (fixture, R_TLS_VERSION_DTLS_1_3);
}
RTEST_END;

/* DTLS 1.3 HelloRetryRequest: the server requires secp256r1 but the client
 * offers an x25519 key_share, so the server answers with an HRR (return-
 * routability over the DTLS framing) and the client retries with a secp256r1
 * share. Completing the handshake proves the DTLS HRR path -- transcript rewrite
 * (message_hash), cookie echo, and the second ClientHello -- works. */
RTEST_F (rtlsclient, dtls13_loopback_hrr, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_key_share_group (fixture->server,
        R_TLS_SUPPORTED_GROUP_SECP256R1), ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback_version (fixture, R_TLS_VERSION_DTLS_1_3);
}
RTEST_END;

/* A replayed DTLS 1.3 record is dropped by the anti-replay window (RFC 9147
 * 4.5.1): deliver an application-data record once, then re-deliver the identical
 * record; the second copy authenticates but is not surfaced a second time. */
RTEST_F (rtlsclient, dtls13_replay_dropped, RTEST_FAST)
{
  static const ruint8 payload[] = { 'r', 'e', 'p', 'l', 'a', 'y' };
  RBuffer * app, * rec, * dup;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_DTLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);

  /* Client sends one application-data record. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer) payload, sizeof (payload), sizeof (payload), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_assert_cmpptr ((rec = r_queue_pop (&fixture->cli_out)), !=, NULL);
  dup = r_buffer_ref (rec);   /* keep an identical copy to replay */

  /* First delivery is accepted and surfaced. */
  r_tls_server_incoming_data (fixture->server, rec);
  r_buffer_unref (rec);
  r_test_tls_assert_appdata (&fixture->srv_app, payload, sizeof (payload));

  /* The replay authenticates (valid record) but the window drops it: no new
   * application data and no error. */
  r_tls_server_incoming_data (fixture->server, dup);
  r_buffer_unref (dup);
  r_assert (r_queue_is_empty (&fixture->srv_app));
  r_assert (!fixture->srv_error);
}
RTEST_END;

/* DTLS 1.3 handshake reassembly (RFC 9147 5.5): a small fragment cap splits the
 * flight (notably the Certificate) into multiple DTLS handshake fragments; the
 * handshake completes only if the peer reassembles them. */
RTEST_F (rtlsclient, dtls13_loopback_fragmented, RTEST_FAST)
{
  r_assert_cmpint (r_tls_client_set_dtls_handshake_fragment (fixture->client, 48),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_dtls_handshake_fragment (fixture->server, 48),
      ==, R_TLS_ERROR_OK);
  r_test_tls13_loopback_version (fixture, R_TLS_VERSION_DTLS_1_3);
}
RTEST_END;

/* DTLS 1.3 reassembly with reordering: the flight is fragmented and the encrypted
 * records are delivered in reverse, so the peer must buffer out-of-order messages
 * and out-of-order fragments and reassemble them in message_seq order. */
RTEST_F (rtlsclient, dtls13_reassembly_reordered, RTEST_FAST)
{
  r_assert_cmpint (r_tls_client_set_dtls_handshake_fragment (fixture->client, 48),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_dtls_handshake_fragment (fixture->server, 48),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_DTLS_1_3), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump_reorder (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_DTLS_1_3);
}
RTEST_END;

/* DTLS 1.3 flight retransmission (RFC 9147 5.8): drop the server's first flight,
 * advance the (test) clock past the retransmit timeout and run the loop so the
 * retransmit timers fire; the resent flight then completes the handshake. */
RTEST_F (rtlsclient, dtls13_retransmit_lost_flight, RTEST_FAST)
{
  RBuffer * buf;
  RClockTime now;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_DTLS_1_3), ==, R_TLS_ERROR_OK);

  /* Deliver the ClientHello; the server emits its flight and arms a retransmit. */
  while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
    r_tls_server_incoming_data (fixture->server, buf);
    r_buffer_unref (buf);
  }
  r_assert (!fixture->srv_hs_done);
  r_assert (!r_queue_is_empty (&fixture->srv_out));

  /* Lose the server's flight entirely. */
  r_queue_clear (&fixture->srv_out, r_buffer_unref);
  r_assert (!fixture->cli_hs_done);

  /* Fire the retransmit timers. */
  now = r_clock_get_time (fixture->clock);
  r_assert (r_test_clock_update_time (fixture->clock, now + 2 * R_SECOND));
  r_ev_loop_run (fixture->evloop, R_EV_LOOP_RUN_NOWAIT);

  /* The server retransmitted its flight; drive the rest to completion. */
  r_assert (!r_queue_is_empty (&fixture->srv_out));
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
}
RTEST_END;

/* DTLS silently discards records that fail to deprotect (RFC 9147 4.5.2): an
 * injected / corrupt datagram must not tear down an established session. */
RTEST_F (rtlsclient, dtls13_corrupt_record_dropped, RTEST_FAST)
{
  /* A well-formed unified header (epoch 3, 16-bit seq, length) over garbage that
   * cannot authenticate. */
  ruint8 bogus[5 + 18];
  static const ruint8 payload[] = { 'o', 'k' };
  RBuffer * rec, * app;
  rsize i;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_DTLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);

  bogus[0] = 0x2f;                       /* 001 0 1 1 11 */
  bogus[1] = 0x00; bogus[2] = 0x00;      /* sequence */
  bogus[3] = 0x00; bogus[4] = 18;        /* length */
  for (i = 0; i < 18; i++)
    bogus[5 + i] = (ruint8) (0x11 * i);
  r_assert_cmpptr ((rec = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          bogus, sizeof (bogus), sizeof (bogus), 0, NULL, NULL)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, rec);
  r_buffer_unref (rec);
  r_assert (!fixture->srv_error);        /* the connection survives */

  /* And normal application data still flows afterwards. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer) payload, sizeof (payload), sizeof (payload), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, payload, sizeof (payload));
  r_assert (!fixture->srv_error);
}
RTEST_END;

/* Implicit acknowledgment (RFC 9147 5.8.3): if the server's ACK is lost, an
 * application-epoch record still tells the client its Finished arrived, so it
 * stops retransmitting instead of eventually failing. */
RTEST_F (rtlsclient, dtls13_implicit_ack_stops_retransmit, RTEST_FAST)
{
  static const ruint8 s2c[] = { 'h', 'i' };
  RBuffer * buf, * app;
  RClockTime now;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_DTLS_1_3), ==, R_TLS_ERROR_OK);

  /* ClientHello -> server; server flight -> client; client Finished -> server. */
  while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
    r_tls_server_incoming_data (fixture->server, buf); r_buffer_unref (buf); }
  while ((buf = r_queue_pop (&fixture->srv_out)) != NULL) {
    r_tls_client_incoming_data (fixture->client, buf); r_buffer_unref (buf); }
  r_assert (fixture->cli_hs_done);
  while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
    r_tls_server_incoming_data (fixture->server, buf); r_buffer_unref (buf); }
  r_assert (fixture->srv_hs_done);

  /* Lose the server's ACK; only an implicit ack can now stop the client. */
  r_queue_clear (&fixture->srv_out, r_buffer_unref);

  /* Server application data (next epoch) implicitly acknowledges the Finished. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer) s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  while ((buf = r_queue_pop (&fixture->srv_out)) != NULL) {
    r_tls_client_incoming_data (fixture->client, buf); r_buffer_unref (buf); }
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));

  /* The retransmit timer is cancelled: advancing time retransmits nothing. */
  now = r_clock_get_time (fixture->clock);
  r_assert (r_test_clock_update_time (fixture->clock, now + 10 * R_SECOND));
  r_ev_loop_run (fixture->evloop, R_EV_LOOP_RUN_NOWAIT);
  r_assert (r_queue_is_empty (&fixture->cli_out));   /* no retransmitted Finished */
  r_assert (!fixture->cli_error);
}
RTEST_END;

/* RFC 9147 7.1: when a partial server flight is ACKed, the server drops the
 * acknowledged records and retransmits only the remainder -- not the whole
 * flight. Withhold a record from the middle of the flight so the client sees a
 * gap and ACKs what it has; the retransmit must then be strictly smaller than
 * the original flight. */
RTEST_F (rtlsclient, dtls13_partial_ack_retransmits_remainder, RTEST_FAST)
{
  RBuffer * buf;
  RClockTime now;
  rsize total, drop, idx = 0, rtx_count;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_DTLS_1_3), ==, R_TLS_ERROR_OK);

  /* ClientHello -> server; the server emits its flight and arms a retransmit. */
  while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
    r_tls_server_incoming_data (fixture->server, buf); r_buffer_unref (buf); }
  total = r_queue_size (&fixture->srv_out);
  r_assert_cmpuint (total, >, 2);
  drop = total / 2;               /* a record in the middle of the flight */

  /* Deliver every record but the middle one; the records past the gap buffer,
   * so the client cannot complete and ACKs what it received. */
  while ((buf = r_queue_pop (&fixture->srv_out)) != NULL) {
    if (idx++ != drop)
      r_tls_client_incoming_data (fixture->client, buf);
    r_buffer_unref (buf);
  }
  r_assert (!fixture->cli_hs_done);
  r_assert (!r_queue_is_empty (&fixture->cli_out));

  /* The client's ACK reaches the server, which drops the acknowledged records. */
  while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
    r_tls_server_incoming_data (fixture->server, buf); r_buffer_unref (buf); }
  r_assert (r_queue_is_empty (&fixture->srv_out));

  /* Fire the retransmit timer: only the un-acknowledged remainder goes out. */
  now = r_clock_get_time (fixture->clock);
  r_assert (r_test_clock_update_time (fixture->clock, now + 2 * R_SECOND));
  r_ev_loop_run (fixture->evloop, R_EV_LOOP_RUN_NOWAIT);
  rtx_count = r_queue_size (&fixture->srv_out);
  r_assert_cmpuint (rtx_count, >, 0);
  r_assert_cmpuint (rtx_count, <, total);

  /* The retransmitted remainder completes the handshake. */
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);
  r_assert (!fixture->cli_error && !fixture->srv_error);
}
RTEST_END;

/* DTLS 1.3 Connection ID (RFC 9146): both ends advertise a CID, so protected
 * records carry the peer's CID in the unified header. Verifies the wire framing
 * (C bit + CID bytes) and that a CID-tagged record still deprotects. */
RTEST_F (rtlsclient, dtls13_loopback_cid, RTEST_FAST)
{
  static const ruint8 climsg[] = { 'c', 'i', 'd' };
  static const ruint8 ccid[] = { 0xca, 0xfe, 0x01 };  /* the client's own CID */
  static const ruint8 scid[] = { 0xbe, 0xef };        /* the server's own CID */
  RBuffer * app, * rec;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  r_assert_cmpint (r_tls_client_set_connection_id (fixture->client, ccid, sizeof (ccid)),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_connection_id (fixture->server, scid, sizeof (scid)),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_DTLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* A client-sent record tags the server's CID with the C bit set. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer) climsg, sizeof (climsg), sizeof (climsg), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_assert_cmpptr ((rec = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert (r_buffer_map (rec, &info, R_MEM_MAP_READ));
  r_assert (r_dtls13_is_unified_hdr (info.data[0]));
  r_assert_cmphex (info.data[0] & 0x10, ==, 0x10);        /* C bit present */
  r_assert_cmpmem (info.data + 1, ==, scid, sizeof (scid));
  r_buffer_unmap (rec, &info);

  /* The server parses the CID-bearing record and surfaces the payload. */
  r_tls_server_incoming_data (fixture->server, rec);
  r_buffer_unref (rec);
  r_test_tls_assert_appdata (&fixture->srv_app, climsg, sizeof (climsg));
  r_assert (!fixture->srv_error);
}
RTEST_END;

/* The client offers SNI; the server's selection callback sees the name and
 * installs a per-name certificate, which the client then receives. */
RTEST_F (rtlsclient, sni_selects_cert, RTEST_FAST)
{
  RCryptoCert * peer;

  r_assert_cmpptr ((fixture->sni_cert =
      r_pem_parse_cert_from_data (rtest_leaf_root_pem, -1)), !=, NULL);
  r_assert_cmpptr ((fixture->sni_key =
      r_pem_parse_key_from_data (rtest_leaf_root_key_pem, -1, NULL, 0)), !=, NULL);

  r_assert_cmpint (r_tls_server_set_server_name_cb (fixture->server,
      r_tlsclient_test_sni), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client,
      "host.example.com"), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop,
      fixture->prng), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop,
      fixture->prng, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (fixture->sni_cb_called);
  r_assert_cmpstr (fixture->sni_seen, ==, "host.example.com");
  /* the server exposes the requested name, and presented the selected cert */
  r_assert_cmpstr (r_tls_server_get_server_name (fixture->server), ==,
      "host.example.com");
  r_assert_cmpptr ((peer = r_tls_client_get_peer_cert (fixture->client)), !=, NULL);
  r_assert_cmpstr (r_crypto_x509_cert_subject (peer), ==, "CN=localhost");
}
RTEST_END;

/* No SNI: the callback still fires (with a NULL name) and the default cert
 * stands; the server-name getter reports NULL. */
RTEST_F (rtlsclient, sni_absent_keeps_default, RTEST_FAST)
{
  RCryptoCert * peer;

  r_assert_cmpint (r_tls_server_set_server_name_cb (fixture->server,
      r_tlsclient_test_sni), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop,
      fixture->prng), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop,
      fixture->prng, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (fixture->sni_cb_called);
  r_assert_cmpstr (fixture->sni_seen, ==, "");
  r_assert_cmpptr (r_tls_server_get_server_name (fixture->server), ==, NULL);
  r_assert_cmpptr ((peer = r_tls_client_get_peer_cert (fixture->client)), !=, NULL);
  r_assert_cmpstr (r_crypto_x509_cert_subject (peer), ==, "CN=rlib");
}
RTEST_END;

/* An over-long SNI host is rejected (it would not fit a host name / the record);
 * a 255-byte name is accepted. */
RTEST_F (rtlsclient, sni_name_length_capped, RTEST_FAST)
{
  rchar name[300];
  rsize i;

  for (i = 0; i < sizeof (name) - 1; i++)
    name[i] = 'a';

  name[256] = '\0';   /* 256 bytes -> rejected */
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client, name), ==,
      R_TLS_ERROR_INVAL);
  name[255] = '\0';   /* 255 bytes -> accepted */
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client, name), ==,
      R_TLS_ERROR_OK);
}
RTEST_END;

/* The SNI hook runs before cipher negotiation, so installing an ECDSA cert for
 * the requested host makes the server negotiate an ECDHE_ECDSA suite (the client
 * offers both ECDSA and RSA) -- i.e. the SNI-selected cert's key type drives the
 * cipher choice. The fixture default cert is RSA, so without the early hook the
 * suite would have been chosen against the wrong key. */
RTEST_F (rtlsclient, sni_cert_key_type_drives_cipher, RTEST_FAST)
{
  r_assert_cmpptr ((fixture->sni_cert =
      r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((fixture->sni_key =
      r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);

  r_assert_cmpint (r_tls_server_set_server_name_cb (fixture->server,
      r_tlsclient_test_sni), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_server_name (fixture->client,
      "ecdsa.example.com"), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop,
      fixture->prng), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop,
      fixture->prng, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
}
RTEST_END;

RTEST_F (rtlsclient, tls_close_notify_client, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_TLS_1_2, FALSE);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_close_notify_client, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_DTLS_1_2, FALSE);
}
RTEST_END;

RTEST_F (rtlsclient, tls_close_notify_server, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_TLS_1_2, TRUE);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_close_notify_server, RTEST_FAST)
{
  r_test_tls_close_notify (fixture, R_TLS_VERSION_DTLS_1_2, TRUE);
}
RTEST_END;

/* A rejecting verify_cert aborts the handshake: the client emits a fatal
 * alert and never reports handshake_done. */
RTEST_F (rtlsclient, tls_verify_cert_reject, RTEST_FAST)
{
  fixture->verify_result = FALSE;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert_cmpuint (fixture->verify_calls, ==, 1);
  r_assert (!fixture->cli_hs_done);
  r_assert (fixture->cli_error);
}
RTEST_END;

/* RFC 8446 4.1.3 downgrade protection: a 1.3-capable server that settles on
 * TLS 1.2 stamps the downgrade sentinel into its ServerHello.random, and a
 * client that offered 1.3 but is answered with that ServerHello aborts with a
 * fatal illegal_parameter alert rather than completing the downgrade. */
RTEST_F (rtlsclient, tls_downgrade_protection, RTEST_FAST)
{
  RBuffer * ch, * sh, * alert;
  RTLSClient * victim;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSHelloMsg hello;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  /* Drive the 1.2 ClientHello into the server so it emits its flight. */
  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);

  /* The first server record is the ServerHello; its random carries the
   * "DOWNGRD\x01" sentinel because the 1.3-capable server settled on 1.2. */
  r_assert_cmpptr ((sh = r_queue_pop (&fixture->srv_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, sh), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_parser_parse_hello (&parser, &hello), ==, R_TLS_ERROR_OK);
  r_assert (r_tls13_random_is_downgrade (hello.random));
  r_assert_cmpmem (hello.random + R_TLS_HELLO_RANDOM_BYTES - 8, ==,
      "\x44\x4f\x57\x4e\x47\x52\x44\x01", 8);
  r_tls_parser_clear (&parser);

  /* A fresh client that offered 1.3 detects the downgrade in that ServerHello
   * and aborts instead of accepting 1.2. */
  r_assert_cmpptr ((victim = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_start (victim, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);   /* drop victim's ClientHello */
  fixture->cli_error = fixture->cli_hs_done = FALSE;

  r_tls_client_incoming_data (victim, sh);
  r_assert (fixture->cli_error);
  r_assert (!fixture->cli_hs_done);

  /* It signalled the peer with a fatal illegal_parameter alert. */
  r_assert_cmpptr ((alert = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_ILLEGAL_PARAMETER);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);

  r_tls_client_unref (victim);
  r_buffer_unref (sh);
}
RTEST_END;

/* The client offers both 1.3 and 1.2 in one ClientHello. Against the default
 * (1.3-capable) server it negotiates 1.3. */
RTEST_F (rtlsclient, tls_hybrid_negotiates_tls13, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_3);
  r_assert_cmpuint (r_tls_server_get_version (fixture->server), ==, R_TLS_VERSION_TLS_1_3);
}
RTEST_END;

/* Same hybrid client, but the server is capped at 1.2 -- a genuine 1.2 peer
 * that neither speaks 1.3 nor stamps the downgrade sentinel. The client falls
 * back to a full 1.2 handshake (no false downgrade abort) and data flows. */
RTEST_F (rtlsclient, tls_hybrid_falls_back_to_tls12, RTEST_FAST)
{
  static const ruint8 c2s[] = { 'f', 'a', 'l', 'l', 'b', 'a', 'c', 'k' };
  static const ruint8 s2c[] = { 'o', 'k', ' ', '1', '.', '2' };
  RBuffer * app;

  r_assert_cmpint (r_tls_server_set_version_range (fixture->server,
        R_TLS_VERSION_TLS_1_2, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpuint (r_tls_client_get_version (fixture->client), ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpuint (r_tls_server_get_version (fixture->server), ==, R_TLS_VERSION_TLS_1_2);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
  /* 1.2 with the default ECDHE-first preference: forward secrecy preserved. */
  r_assert_cmpptr (r_tls_client_get_cipher_suite (fixture->client), !=, NULL);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_ECDHE_RSA);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}
RTEST_END;

/* A server that requires 1.3 rejects a 1.2-only client with a fatal
 * protocol_version alert. */
RTEST_F (rtlsclient, tls_server_requires_tls13, RTEST_FAST)
{
  RBuffer * ch, * alert;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_set_version_range (fixture->server,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);

  r_assert (fixture->srv_error);
  r_assert (!fixture->srv_hs_done);

  r_assert_cmpptr ((alert = r_queue_pop (&fixture->srv_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_PROTOCOL_VERSION);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);
}
RTEST_END;

/* r_tls_client_set_version_range accepts the 1.2..1.3 window and rejects
 * inverted, out-of-window and DTLS bounds. */
RTEST_F (rtlsclient, tls_client_version_range_validation, RTEST_FAST)
{
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_2, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_VERSION);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_TLS_1_0, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_VERSION);
  r_assert_cmpint (r_tls_client_set_version_range (fixture->client,
        R_TLS_VERSION_DTLS_1_2, R_TLS_VERSION_DTLS_1_2), ==, R_TLS_ERROR_VERSION);
}
RTEST_END;

/* A client pinned to 1.3 (no fallback) rejects a 1.2 ServerHello as out of its
 * offered range, aborting with protocol_version rather than downgrading. A
 * pinned client offers no 1.2 suites, so a genuine 1.2 server could not answer
 * it at all; the rejection guards the case where a server (or an attacker)
 * replies 1.2 regardless. The 1.2 ServerHello is sourced from the capped server
 * answering a hybrid client. */
RTEST_F (rtlsclient, tls_client_requires_tls13, RTEST_FAST)
{
  RBuffer * ch, * sh, * alert;
  RTLSClient * victim;
  RTLSParser parser = R_TLS_PARSER_INIT;
  RTLSAlertLevel alevel;
  RTLSAlertType atype;

  r_assert_cmpint (r_tls_server_set_version_range (fixture->server,
        R_TLS_VERSION_TLS_1_2, R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  /* A hybrid client so the capped server produces a real (sentinel-free) 1.2
   * ServerHello. */
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpptr ((ch = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_tls_server_incoming_data (fixture->server, ch);
  r_buffer_unref (ch);
  r_assert_cmpptr ((sh = r_queue_pop (&fixture->srv_out)), !=, NULL);

  /* Pinned-1.3 client fed that 1.2 ServerHello aborts. */
  r_assert_cmpptr ((victim = r_tls_client_new (&clicbs, fixture, NULL)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_version_range (victim,
        R_TLS_VERSION_TLS_1_3, R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (victim, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_queue_clear (&fixture->cli_out, r_buffer_unref);   /* drop victim's ClientHello */
  fixture->cli_error = fixture->cli_hs_done = FALSE;

  r_tls_client_incoming_data (victim, sh);
  r_assert (fixture->cli_error);
  r_assert (!fixture->cli_hs_done);

  r_assert_cmpptr ((alert = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert_cmpint (r_tls_parser_init_buffer (&parser, alert), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (parser.content, ==, R_TLS_CONTENT_TYPE_ALERT);
  r_assert_cmpint (r_tls_parser_parse_alert (&parser, &alevel, &atype), ==, R_TLS_ERROR_OK);
  r_assert_cmpuint (alevel, ==, R_TLS_ALERT_LEVEL_FATAL);
  r_assert_cmpuint (atype, ==, R_TLS_ALERT_TYPE_PROTOCOL_VERSION);
  r_tls_parser_clear (&parser);
  r_buffer_unref (alert);

  r_tls_client_unref (victim);
  r_buffer_unref (sh);
}
RTEST_END;

/* Mutual TLS: the server requires a client certificate, the client presents
 * one, and the handshake completes with each side holding the other's leaf. */
static void
r_test_tls_mtls_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture, RTLSVersion version)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_cert (fixture->client, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server,
        R_TLS_CLIENT_CERT_MODE_REQUIRE), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  /* Each side validated and kept the other's leaf certificate. */
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), !=, NULL);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
}

RTEST_F (rtlsclient, tls_mtls_loopback, RTEST_FAST)
{
  r_test_tls_mtls_loopback (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_mtls_loopback, RTEST_FAST)
{
  r_test_tls_mtls_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* The server requires a client certificate but the client has none: it answers
 * with an empty Certificate and the server aborts the handshake. */
RTEST_F (rtlsclient, tls_mtls_require_no_client_cert, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server,
        R_TLS_CLIENT_CERT_MODE_REQUIRE), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (!fixture->srv_hs_done);
  r_assert (!fixture->cli_hs_done);
  r_assert (fixture->srv_error);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), ==, NULL);
}
RTEST_END;

/* ECDHE_RSA end-to-end: both endpoints offer only the ECDHE suite, so the
 * handshake exercises the ServerKeyExchange signature, the ephemeral ECDH
 * agreement, and the variable-length premaster on both sides. */
static void
r_test_tls_ecdhe_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture, RTLSVersion version)
{
  static const ruint8 c2s[] = { 'e', 'c', 'd', 'h', 'e' };
  static const ruint8 s2c[] = { 'o', 'k' };
  const RTLSCipherSuiteInfo * info;
  RBuffer * app;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  /* Forward secrecy: both sides negotiated the ephemeral-ECDH suite. */
  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_RSA);
  r_assert_cmpptr ((info = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_RSA);

  /* Application data round-trips over the established keys. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

RTEST_F (rtlsclient, tls_ecdhe_loopback, RTEST_FAST)
{
  r_test_tls_ecdhe_loopback (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdhe_loopback, RTEST_FAST)
{
  r_test_tls_ecdhe_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* A duplicated ServerKeyExchange must abort the handshake: the client accepts
 * exactly one SKE (a second would otherwise replace the ephemeral keys). */
RTEST_F (rtlsclient, tls_ecdhe_duplicate_ske, RTEST_FAST)
{
  RBuffer * buf;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  /* ClientHello -> server; then replay the server's SKE record to the client. */
  while ((buf = r_queue_pop (&fixture->cli_out)) != NULL) {
    r_tls_server_incoming_data (fixture->server, buf);
    r_buffer_unref (buf);
  }
  while ((buf = r_queue_pop (&fixture->srv_out)) != NULL) {
    RTLSParser parser = R_TLS_PARSER_INIT;
    RTLSHandshakeType type = (RTLSHandshakeType)0;
    rboolean is_ske;

    r_assert_cmpint (r_tls_parser_init_buffer (&parser, buf), ==, R_TLS_ERROR_OK);
    is_ske = r_tls_parser_parse_handshake_peek_type (&parser, &type) == R_TLS_ERROR_OK &&
        type == R_TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE;
    r_tls_parser_clear (&parser);

    r_tls_client_incoming_data (fixture->client, buf);
    if (is_ske)
      r_tls_client_incoming_data (fixture->client, buf);
    r_buffer_unref (buf);
  }

  r_assert (fixture->cli_error);
  r_assert (!fixture->cli_hs_done);
}
RTEST_END;

/* Static RSA still works end to end when pinned explicitly (the default
 * preference is ECDHE-first, so this exercises the legacy key exchange). */
RTEST_F (rtlsclient, tls_rsa_loopback, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_RSA_WITH_AES_128_CBC_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->key_exchange,
      ==, R_KEY_EXCHANGE_RSA);
}
RTEST_END;

/* AES-256-CBC exercises the wider key expansion (32-byte write keys) over a
 * full ECDHE handshake with application data. */
RTEST_F (rtlsclient, tls_ecdhe_aes256_loopback, RTEST_FAST)
{
  static const ruint8 c2s[] = { 'a', 'e', 's', '2', '5', '6' };
  RBuffer * app;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpint (r_tls_client_get_cipher_suite (fixture->client)->suite,
      ==, R_TLS_CS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
  r_assert_cmpuint (r_tls_client_get_cipher_suite (fixture->client)->cipher->keybits, ==, 256);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));
}
RTEST_END;

/* AEAD (AES-GCM) end to end for one suite/version: handshake completes, the
 * negotiated suite is the forced GCM suite, and app data round-trips through
 * the AEAD record path. The SHA-384 suites also exercise the per-suite PRF and
 * transcript hash. */
static void
r_test_tls_gcm_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version, RTLSCipherSuite suite)
{
  static const ruint8 c2s[] = { 'g', 'c', 'm', '-', 'p', 'i', 'n', 'g' };
  static const ruint8 s2c[] = { 'g', 'c', 'm', '-', 'p', 'o', 'n', 'g' };
  const RTLSCipherSuiteInfo * info;
  RBuffer * app;

  fixture->force_suite = suite;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->suite, ==, suite);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);
  r_assert_cmpptr ((info = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpint (info->suite, ==, suite);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_GCM);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

RTEST_F (rtlsclient, tls_gcm_ecdhe_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_ecdhe_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, tls_gcm_ecdhe_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_ecdhe_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, tls_gcm_rsa_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_rsa_aes128, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_RSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, tls_gcm_rsa_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_gcm_rsa_aes256_sha384, RTEST_FAST)
{
  r_test_tls_gcm_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_RSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

/* ChaCha20-Poly1305 (RFC 7905) end to end for one version: handshake completes
 * on the forced suite and app data round-trips through the AEAD record path,
 * which for RFC 7905 uses the TLS 1.3-style nonce (no explicit per-record
 * nonce) rather than the GCM salt||nonce framing. */
static void
r_test_tls_chacha20_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version)
{
  static const ruint8 c2s[] = { 'c', 'c', '2', '0', '-', 'p', 'i', 'n', 'g' };
  static const ruint8 s2c[] = { 'c', 'c', '2', '0', '-', 'p', 'o', 'n', 'g' };
  const RTLSCipherSuiteInfo * info;
  RBuffer * app;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->suite, ==, R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_POLY1305);
  r_assert_cmpptr ((info = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpint (info->suite, ==, R_TLS_CS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
  r_assert_cmpint (info->cipher->mode, ==, R_CRYPTO_CIPHER_MODE_POLY1305);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)s2c, sizeof (s2c), sizeof (s2c), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_server_send_appdata (fixture->server, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->cli_app, s2c, sizeof (s2c));
}

/* The issue's headline: ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8). */
RTEST_F (rtlsclient, tls_chacha20_ecdhe_rsa, RTEST_FAST)
{
  r_test_tls_chacha20_loopback (fixture, R_TLS_VERSION_TLS_1_2);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_chacha20_ecdhe_rsa, RTEST_FAST)
{
  r_test_tls_chacha20_loopback (fixture, R_TLS_VERSION_DTLS_1_2);
}
RTEST_END;

/* A tampered AEAD record must fail the tag check: complete a GCM handshake,
 * then flip a byte in a client application-data record before it reaches the
 * server. The server reports bad_record_mac and never surfaces the payload. */
RTEST_F (rtlsclient, gcm_tampered_record, RTEST_FAST)
{
  static const ruint8 c2s[] = { 's', 'e', 'c', 'r', 'e', 't' };
  RBuffer * app, * rec;
  RMemMapInfo info = R_MEM_MAP_INFO_INIT;

  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done && fixture->srv_hs_done);

  /* Client emits one encrypted application-data record. */
  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);

  /* Corrupt the last byte (inside the GCM tag) before delivering it. */
  r_assert_cmpptr ((rec = r_queue_pop (&fixture->cli_out)), !=, NULL);
  r_assert (r_buffer_map (rec, &info, R_MEM_MAP_RW));
  info.data[info.size - 1] ^= 0xff;
  r_buffer_unmap (rec, &info);

  r_tls_server_incoming_data (fixture->server, rec);
  r_buffer_unref (rec);

  r_assert (fixture->srv_error);
  r_assert (r_queue_is_empty (&fixture->srv_app));
}
RTEST_END;

/* Replace the fixture's default RSA server cert with the ECDSA one. */
static void
r_test_tls_use_ecdsa_server_cert (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_crypto_key_get_algo (pk), ==, R_CRYPTO_ALGO_ECDSA);
  r_assert_cmpint (r_tls_server_set_cert (fixture->server, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);
}

/* ECDHE_ECDSA end to end with an ECDSA server certificate: the handshake
 * completes, the negotiated suite authenticates with ECDSA, and app data
 * round-trips. The SHA-384 GCM suite also exercises the per-suite PRF. */
static void
r_test_tls_ecdsa_loopback (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSVersion version, RTLSCipherSuite suite)
{
  static const ruint8 c2s[] = { 'e', 'c', 'd', 's', 'a' };
  const RTLSCipherSuiteInfo * info;
  RBuffer * app;

  r_test_tls_use_ecdsa_server_cert (fixture);
  fixture->force_suite = suite;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng, version),
      ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);

  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->suite, ==, suite);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
  r_assert_cmpptr ((info = r_tls_server_get_cipher_suite (fixture->server)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);

  r_assert_cmpptr ((app = r_buffer_new_wrapped (R_MEM_FLAG_NONE,
          (rpointer)c2s, sizeof (c2s), sizeof (c2s), 0, NULL, NULL)), !=, NULL);
  r_assert (r_tls_client_send_appdata (fixture->client, app));
  r_buffer_unref (app);
  r_test_tls_loopback_pump (fixture);
  r_test_tls_assert_appdata (&fixture->srv_app, c2s, sizeof (c2s));
}

RTEST_F (rtlsclient, tls_ecdsa_gcm128, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdsa_gcm128, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, tls_ecdsa_gcm256_sha384, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdsa_gcm256_sha384, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
}
RTEST_END;

RTEST_F (rtlsclient, tls_ecdsa_cbc128_sha256, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_TLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
}
RTEST_END;

RTEST_F (rtlsclient, dtls_ecdsa_cbc128_sha256, RTEST_FAST)
{
  r_test_tls_ecdsa_loopback (fixture, R_TLS_VERSION_DTLS_1_2,
      R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
}
RTEST_END;

/* With an ECDSA certificate and no forced suite, the default negotiation must
 * pick an ECDHE_ECDSA suite (the auth gate keeps the RSA/ECDHE_RSA suites out). */
RTEST_F (rtlsclient, tls_ecdsa_default_negotiation, RTEST_FAST)
{
  const RTLSCipherSuiteInfo * info;

  r_test_tls_use_ecdsa_server_cert (fixture);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert_cmpptr ((info = r_tls_client_get_cipher_suite (fixture->client)), !=, NULL);
  r_assert_cmpint (info->key_exchange, ==, R_KEY_EXCHANGE_ECDHE_ECDSA);
}
RTEST_END;

/* Auth-type mismatch: an ECDSA cert cannot satisfy a forced ECDHE_RSA suite,
 * and the default RSA cert cannot satisfy a forced ECDHE_ECDSA suite. Either
 * way negotiation finds no common suite and the handshake aborts. */
RTEST_F (rtlsclient, tls_ecdsa_cert_rsa_suite_fails, RTEST_FAST)
{
  r_test_tls_use_ecdsa_server_cert (fixture);
  fixture->force_suite = R_TLS_CS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (!fixture->cli_hs_done);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

RTEST_F (rtlsclient, tls_rsa_cert_ecdsa_suite_fails, RTEST_FAST)
{
  fixture->force_suite = R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (!fixture->cli_hs_done);
  r_assert (!fixture->srv_hs_done);
}
RTEST_END;

/* Mutual TLS with ECDSA on both ends: server requires a client cert, both
 * present ECDSA certs, the handshake completes and each side holds the other's
 * leaf. Exercises the ECDSA CertificateVerify sign + verify path. */
RTEST_F (rtlsclient, tls_ecdsa_mutual, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_test_tls_use_ecdsa_server_cert (fixture);

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_cert (fixture->client, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server,
        R_TLS_CLIENT_CERT_MODE_REQUIRE), ==, R_TLS_ERROR_OK);
  fixture->force_suite = R_TLS_CS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_2), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), !=, NULL);
  r_assert_cmpptr (r_tls_client_get_peer_cert (fixture->client), !=, NULL);
}
RTEST_END;

/* Post-handshake client authentication (RFC 8446 4.6.2): run a TLS 1.3 handshake
 * in which the client offered post_handshake_auth, confirm no client cert was
 * requested during it, then have the server request one and drive the client's
 * answering Certificate / CertificateVerify / Finished flight. */
static void
r_test_tls13_post_handshake_auth (RTEST_FIXTURE_STRUCT (rtlsclient) * fixture,
    RTLSClientCertMode mode)
{
  r_assert_cmpint (r_tls_client_set_post_handshake_auth (fixture->client, TRUE),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server, mode),
      ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);

  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->cli_hs_done);
  r_assert (fixture->srv_hs_done);
  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), ==, NULL);

  r_assert_cmpint (r_tls_server_request_post_handshake_auth (fixture->server),
      ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
}

/* RSA client certificate: the server requests it after the handshake and the
 * flight verifies, exposing the leaf and reporting success. */
RTEST_F (rtlsclient, tls13_post_handshake_auth, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_cert (fixture->client, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_post_handshake_auth (fixture, R_TLS_CLIENT_CERT_MODE_REQUIRE);

  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert (fixture->srv_ph_auth_called);
  r_assert (fixture->srv_ph_auth_ok);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), !=, NULL);
}
RTEST_END;

/* ECDSA client certificate: exercises the ECDSA CertificateVerify sign (client)
 * and verify (server) on the post-handshake path. */
RTEST_F (rtlsclient, tls13_post_handshake_auth_ecdsa, RTEST_FAST)
{
  RCryptoCert * cert;
  RCryptoKey * pk;

  r_test_tls_use_ecdsa_server_cert (fixture);

  r_assert_cmpptr ((cert = r_pem_parse_cert_from_data (testcertpem_ecdsa, -1)), !=, NULL);
  r_assert_cmpptr ((pk = r_pem_parse_key_from_data (testpkpem_ecdsa, -1, NULL, 0)), !=, NULL);
  r_assert_cmpint (r_tls_client_set_cert (fixture->client, cert, pk), ==, R_TLS_ERROR_OK);
  r_crypto_key_unref (pk);
  r_crypto_cert_unref (cert);

  r_test_tls13_post_handshake_auth (fixture, R_TLS_CLIENT_CERT_MODE_REQUIRE);

  r_assert (!fixture->cli_error);
  r_assert (!fixture->srv_error);
  r_assert (fixture->srv_ph_auth_called);
  r_assert (fixture->srv_ph_auth_ok);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), !=, NULL);
}
RTEST_END;

/* Client offered post_handshake_auth but holds no certificate: under REQUEST it
 * answers with an empty Certificate, so the flight completes but authenticates
 * no one -- the result is reported as failure and no peer cert is exposed. */
RTEST_F (rtlsclient, tls13_post_handshake_auth_no_cert, RTEST_FAST)
{
  r_test_tls13_post_handshake_auth (fixture, R_TLS_CLIENT_CERT_MODE_REQUEST);

  r_assert (!fixture->srv_error);
  r_assert (fixture->srv_ph_auth_called);
  r_assert (!fixture->srv_ph_auth_ok);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), ==, NULL);
}
RTEST_END;

/* Client offered post_handshake_auth but holds no certificate, and the server
 * requires one: the empty answer aborts the session with a fatal alert and the
 * completion callback does not fire. */
RTEST_F (rtlsclient, tls13_post_handshake_auth_require_no_cert, RTEST_FAST)
{
  r_assert_cmpint (r_tls_client_set_post_handshake_auth (fixture->client, TRUE),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_server_set_client_cert_mode (fixture->server,
        R_TLS_CLIENT_CERT_MODE_REQUIRE), ==, R_TLS_ERROR_OK);

  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->srv_hs_done);

  r_assert_cmpint (r_tls_server_request_post_handshake_auth (fixture->server),
      ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);

  r_assert (fixture->srv_error);
  r_assert (!fixture->srv_ph_auth_called);
  r_assert_cmpptr (r_tls_server_get_peer_cert (fixture->server), ==, NULL);
}
RTEST_END;

/* The client never offered post_handshake_auth: the server cannot request a
 * post-handshake certificate and the trigger is rejected. */
RTEST_F (rtlsclient, tls13_post_handshake_auth_not_offered, RTEST_FAST)
{
  r_assert_cmpint (r_tls_server_start (fixture->server, fixture->evloop, fixture->prng),
      ==, R_TLS_ERROR_OK);
  r_assert_cmpint (r_tls_client_start (fixture->client, fixture->evloop, fixture->prng,
        R_TLS_VERSION_TLS_1_3), ==, R_TLS_ERROR_OK);
  r_test_tls_loopback_pump (fixture);
  r_assert (fixture->srv_hs_done);

  r_assert_cmpint (r_tls_server_request_post_handshake_auth (fixture->server),
      ==, R_TLS_ERROR_WRONG_STATE);
  r_assert (!fixture->srv_ph_auth_called);
}
RTEST_END;
