package no.neat.rlib.trusttest;

import static org.junit.Assert.assertEquals;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Test;
import org.junit.runner.RunWith;

/**
 * Exercises rlib's Android system trust-store backend end to end. Running inside
 * an app process gives the backend a real JavaVM (registered from JNI_OnLoad),
 * so {@code r_trust_store_new_system} returns the JNI X509TrustManager verifier
 * and the delegation path -- unreachable from the bare rlibtest emulator run --
 * is covered.
 *
 * The app bundles {@code androidtest_root} as a trust anchor (see
 * network_security_config.xml), so leaves under it verify OK; the foreign root
 * is not trusted.
 */
@RunWith(AndroidJUnit4.class)
public class NativeTrustTest {

    static {
        System.loadLibrary("rtruststore_androidtest");
    }

    // Mirror of rlib's RTrustResult (include/rlib/crypto/rtruststore.h).
    private static final int R_TRUST_OK = 0;
    private static final int R_TRUST_UNTRUSTED = 1;

    // Mirror of the scenario ids in rtruststore_androidtest.c.
    private static final int TRUSTED_SERVER = 0;
    private static final int TRUSTED_CLIENT = 1;
    private static final int UNTRUSTED = 2;

    private static native int run(int scenario);

    @Test
    public void trustedServerChainVerifies() {
        assertEquals(R_TRUST_OK, run(TRUSTED_SERVER));
    }

    @Test
    public void trustedClientChainVerifies() {
        assertEquals(R_TRUST_OK, run(TRUSTED_CLIENT));
    }

    @Test
    public void untrustedRootIsRejected() {
        assertEquals(R_TRUST_UNTRUSTED, run(UNTRUSTED));
    }
}
