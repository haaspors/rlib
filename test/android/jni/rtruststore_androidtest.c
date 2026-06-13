/* JNI bridge for the Android instrumented trust-store test.
 *
 * Runs inside an app process (real ART VM), so r_trust_store_new_system returns
 * the JNI X509TrustManager backend and the delegation path -- which the bare
 * rlibtest run on the emulator cannot reach -- is exercised end to end. The app
 * bundles androidtest_root as a trust anchor (network_security_config.xml), so
 * leaves under it verify OK; androidtest_root_alt is untrusted.
 */
#include <jni.h>
#include <rlib/rlib.h>
#include <rlib/rcrypto.h>

#include "androidtest-certs.h"

/* Scenario ids -- kept in sync with NativeTrustTest.java. The two TRUSTED cases
 * exercise both trust-manager dispatch branches (checkServerTrusted via the
 * serverAuth leaf, checkClientTrusted via the clientAuth leaf). */
enum {
  SCENARIO_TRUSTED_SERVER = 0,  /* leaf under the bundled anchor, serverAuth */
  SCENARIO_TRUSTED_CLIENT = 1,  /* leaf under the bundled anchor, clientAuth */
  SCENARIO_UNTRUSTED      = 2,  /* leaf under the foreign (untrusted) root */
};

JNIEXPORT jint JNICALL
JNI_OnLoad (JavaVM * vm, void * reserved)
{
  (void) reserved;
  /* Hand rlib the process JavaVM the trust backend needs (see
   * r_trust_store_set_java_vm). */
  r_trust_store_set_java_vm (vm);
  return JNI_VERSION_1_6;
}

static RTrustResult
run_scenario (int scenario)
{
  const rchar * leaf;
  RX509ExtKeyUsage eku;
  RTrustStore * store;
  RCryptoCert * chain[1];
  RTrustResult res;

  switch (scenario) {
    case SCENARIO_TRUSTED_SERVER:
      leaf = at_leaf_server_pem; eku = R_X509_EXT_KEY_USAGE_SERVER_AUTH; break;
    case SCENARIO_TRUSTED_CLIENT:
      leaf = at_leaf_client_pem; eku = R_X509_EXT_KEY_USAGE_CLIENT_AUTH; break;
    case SCENARIO_UNTRUSTED:
      leaf = at_leaf_alt_pem;    eku = R_X509_EXT_KEY_USAGE_SERVER_AUTH; break;
    default:
      return R_TRUST_INVALID;
  }

  if ((store = r_trust_store_new_system ()) == NULL)
    return R_TRUST_INVALID;
  if ((chain[0] = r_pem_parse_cert_from_data (leaf, -1)) == NULL) {
    r_trust_store_unref (store);
    return R_TRUST_INVALID;
  }

  res = r_trust_store_verify (store, chain, 1, r_time_get_unix_time (), eku);

  r_crypto_cert_unref (chain[0]);
  r_trust_store_unref (store);
  return res;
}

JNIEXPORT jint JNICALL
Java_no_neat_rlib_trusttest_NativeTrustTest_run (JNIEnv * env, jclass cls,
    jint scenario)
{
  (void) env;
  (void) cls;
  return (jint) run_scenario ((int) scenario);
}
