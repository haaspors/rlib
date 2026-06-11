#include <rlib/rcrypto.h>

#include "rtlstestcerts.h"

/* A time inside every test cert's validity window (~2026..2126). */
#define RTEST_NOW       (r_time_create_unix_time (2030, 1, 1, 0, 0, 0))
#define RTEST_TOO_LATE  (r_time_create_unix_time (2130, 1, 1, 0, 0, 0))
#define RTEST_TOO_EARLY (r_time_create_unix_time (2000, 1, 1, 0, 0, 0))

#define cert_of(pem)  r_pem_parse_cert_from_data (pem, -1)

static RTrustResult
r_test_verify (RTrustStore * store, ruint64 now, RX509ExtKeyUsage eku,
    const rchar * leaf, const rchar * a, const rchar * b)
{
  RCryptoCert * chain[3];
  ruint n = 0;
  RTrustResult res;

  r_assert_cmpptr ((chain[n++] = cert_of (leaf)), !=, NULL);
  if (a != NULL)
    r_assert_cmpptr ((chain[n++] = cert_of (a)), !=, NULL);
  if (b != NULL)
    r_assert_cmpptr ((chain[n++] = cert_of (b)), !=, NULL);

  res = r_trust_store_verify (store, chain, n, now, eku);

  while (n-- > 0)
    r_crypto_cert_unref (chain[n]);
  return res;
}

static RTrustStore *
r_test_store_with (const rchar * pem)
{
  RTrustStore * store;
  r_assert_cmpptr ((store = r_trust_store_new_certs ()), !=, NULL);
  if (pem != NULL)
    r_assert_cmpint (r_trust_store_add_pem (store, pem, -1), ==, 1);
  return store;
}

RTEST (rtruststore, verify_invalid_args, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  RCryptoCert * leaf;

  r_assert_cmpint (r_trust_store_verify (NULL, NULL, 0, RTEST_NOW, 0), ==,
      R_TRUST_INVALID);
  r_assert_cmpptr ((leaf = cert_of (rtest_leaf_root_pem)), !=, NULL);
  r_assert_cmpint (r_trust_store_verify (store, &leaf, 0, RTEST_NOW, 0), ==,
      R_TRUST_INVALID);
  r_crypto_cert_unref (leaf);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, trust_two_level, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_root_pem, NULL, NULL),
      ==, R_TRUST_OK);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, trust_three_level, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  /* leaf <- intermediate (in chain) <- root (anchor) */
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_pem, rtest_inter_pem, NULL),
      ==, R_TRUST_OK);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, trust_anchor_is_intermediate, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_inter_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_pem, NULL, NULL),
      ==, R_TRUST_OK);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, untrusted_wrong_anchor, RTEST_FAST)
{
  /* leaf_root is signed by root, but only the intermediate is anchored. */
  RTrustStore * store = r_test_store_with (rtest_inter_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_root_pem, NULL, NULL),
      ==, R_TRUST_UNTRUSTED);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, untrusted_empty_store, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (NULL);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_root_pem, NULL, NULL),
      ==, R_TRUST_UNTRUSTED);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, expired_and_not_yet_valid, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_TOO_LATE,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_root_pem, NULL, NULL),
      ==, R_TRUST_EXPIRED);
  r_assert_cmpint (r_test_verify (store, RTEST_TOO_EARLY,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_root_pem, NULL, NULL),
      ==, R_TRUST_EXPIRED);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, reject_non_ca_intermediate, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_child_notca_pem,
        rtest_midleaf_notca_pem, NULL), ==, R_TRUST_NOT_CA);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, reject_ca_without_keycertsign, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_noksign_pem,
        rtest_inter_noksign_pem, NULL), ==, R_TRUST_BAD_USAGE);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, reject_pathlen_exceeded, RTEST_FAST)
{
  /* leaf <- subinter <- intermediate(pathlen:0) <- root: the intermediate
   * permits zero CAs below it, but subinter is one. */
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_sub_pem,
        rtest_subinter_pem, rtest_inter_pem), ==, R_TRUST_PATHLEN);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, reject_leaf_without_eku, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  /* serverAuth demanded, leaf carries no extendedKeyUsage -> rejected. */
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_noeku_pem, NULL, NULL),
      ==, R_TRUST_BAD_USAGE);
  /* but with no purpose demanded it is accepted. */
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_NONE, rtest_leaf_noeku_pem, NULL, NULL),
      ==, R_TRUST_OK);
  r_trust_store_unref (store);
}
RTEST_END;

/* A leaf whose extendedKeyUsage is present but lacks serverAuth is rejected
 * when serverAuth is demanded (distinct from an absent EKU). */
RTEST (rtruststore, reject_leaf_wrong_eku, RTEST_FAST)
{
  RTrustStore * store = r_test_store_with (rtest_root_pem);
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_SERVER_AUTH, rtest_leaf_clientauth_pem, NULL, NULL),
      ==, R_TRUST_BAD_USAGE);
  /* The same leaf is fine when client auth is what's demanded. */
  r_assert_cmpint (r_test_verify (store, RTEST_NOW,
        R_X509_EXT_KEY_USAGE_CLIENT_AUTH, rtest_leaf_clientauth_pem, NULL, NULL),
      ==, R_TRUST_OK);
  r_trust_store_unref (store);
}
RTEST_END;

RTEST (rtruststore, add_pem_bundle_counts, RTEST_FAST)
{
  RTrustStore * store;
  rchar * bundle;

  r_assert_cmpptr ((store = r_trust_store_new_certs ()), !=, NULL);
  /* A bundle with two CERTIFICATE blocks adds two anchors. */
  bundle = r_strprintf ("%s%s", rtest_root_pem, rtest_inter_pem);
  r_assert_cmpint (r_trust_store_add_pem (store, bundle, -1), ==, 2);
  r_free (bundle);
  r_trust_store_unref (store);
}
RTEST_END;
