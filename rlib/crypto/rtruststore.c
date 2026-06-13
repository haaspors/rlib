/* RLIB - Convenience library for useful things
 * Copyright (C) 2026 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */

#include "config.h"
#include "../rlib-private.h"
#include <rlib/crypto/rtruststore.h>

#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rmsgdigest.h>
#include <rlib/crypto/rpem.h>
#include <rlib/data/rptrarray.h>
#include <rlib/file/rfile.h>
#include <rlib/file/rfs.h>
#include <rlib/format/rasn1.h>
#include <rlib/os/renv.h>
#include <rlib/rmem.h>
#include <rlib/rstr.h>

#if defined (R_OS_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#elif defined (R_OS_DARWIN)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#elif defined (R_OS_ANDROID)
#include <jni.h>
#endif

/* A path no longer than this many certificates can be built; TLS chains are
 * tiny and this also caps the index bitmask used during path-building. */
#define R_TRUST_MAX_CHAIN  16

struct RTrustStore {
  RRef ref;
  RTrustResult (*verify) (RTrustStore * store, RCryptoCert * const * chain,
      ruint count, ruint64 now, RX509ExtKeyUsage required_eku);
};

RTrustResult
r_trust_store_verify (RTrustStore * store, RCryptoCert * const * chain,
    ruint count, ruint64 now, RX509ExtKeyUsage required_eku)
{
  if (R_UNLIKELY (store == NULL || chain == NULL || count == 0))
    return R_TRUST_INVALID;
  return store->verify (store, chain, count, now, required_eku);
}

/* --- certs backend: engine-validated trust anchors ----------------------- */

typedef struct {
  RTrustStore base;
  RPtrArray * anchors;      /* RCryptoCert *, leaf-to-root path-built against */
} RTrustCerts;

static rboolean
r_trust_cert_time_valid (const RCryptoCert * cert, ruint64 now)
{
  return now >= r_crypto_cert_get_valid_from (cert) &&
      now <= r_crypto_cert_get_valid_to (cert);
}

/* TRUE if @issuer's subject matches @cert's issuer DN and signed @cert. */
static rboolean
r_trust_issued_by (const RCryptoCert * cert, const RCryptoCert * issuer)
{
  return r_strcmp (r_crypto_x509_cert_subject (issuer),
          r_crypto_x509_cert_issuer (cert)) == 0 &&
      r_crypto_x509_cert_verify_signature (cert, issuer) == R_CRYPTO_OK;
}

/* Checks a certificate that sits above the leaf as a CA in the path: validity,
 * CA flag, keyUsage and its pathLenConstraint against the CAs already below it. */
static RTrustResult
r_trust_check_ca (const RCryptoCert * ca, ruint64 now, ruint ncabelow)
{
  RX509KeyUsage ku;
  rint32 pathlen;

  if (!r_trust_cert_time_valid (ca, now))
    return R_TRUST_EXPIRED;
  if (!r_crypto_x509_cert_is_ca (ca))
    return R_TRUST_NOT_CA;
  /* A CA that declares a keyUsage must allow certificate signing. */
  ku = r_crypto_x509_cert_key_usage (ca);
  if (ku != R_X509_KEY_USAGE_NONE && !(ku & R_X509_KEY_USAGE_KEY_CERT_SIGN))
    return R_TRUST_BAD_USAGE;
  pathlen = r_crypto_x509_cert_path_len (ca);
  if (pathlen >= 0 && (ruint) pathlen < ncabelow)
    return R_TRUST_PATHLEN;
  return R_TRUST_OK;
}

static RTrustResult
r_trust_certs_verify (RTrustStore * base, RCryptoCert * const * chain,
    ruint count, ruint64 now, RX509ExtKeyUsage required_eku)
{
  RTrustCerts * store = (RTrustCerts *) base;
  const RCryptoCert * cur = chain[0];
  ruint32 used = 1u;                /* chain[0] (leaf) consumed */
  ruint ncabelow = 0, step;
  rsize na, ai;

  if (count > R_TRUST_MAX_CHAIN)
    count = R_TRUST_MAX_CHAIN;

  /* Leaf checks: validity and -- when a purpose is required -- a matching
   * extendedKeyUsage (an absent EKU is rejected when a purpose is demanded). */
  if (!r_trust_cert_time_valid (cur, now))
    return R_TRUST_EXPIRED;
  if (required_eku != R_X509_EXT_KEY_USAGE_NONE) {
    RX509ExtKeyUsage eku = r_crypto_x509_cert_ext_key_usage (cur);
    if (!(eku & (required_eku | R_X509_EXT_KEY_USAGE_ANY)))
      return R_TRUST_BAD_USAGE;
  }

  na = r_ptr_array_size (store->anchors);

  for (step = 0; step < count; step++) {
    ruint j;

    /* A trust anchor that issued cur ends the path. */
    for (ai = 0; ai < na; ai++) {
      const RCryptoCert * a = r_ptr_array_get (store->anchors, ai);
      if (r_trust_issued_by (cur, a)) {
        RTrustResult res = r_trust_check_ca (a, now, ncabelow);
        /* The anchor is trusted by inclusion, so a missing CA flag / keyUsage
         * on it is not fatal -- only its validity and pathLen bound the path. */
        if (res == R_TRUST_EXPIRED || res == R_TRUST_PATHLEN)
          return res;
        return R_TRUST_OK;
      }
    }

    /* Otherwise an intermediate from the peer chain must issue cur. */
    for (j = 1; j < count; j++) {
      const RCryptoCert * c;
      RTrustResult res;

      if (used & (1u << j))
        continue;
      c = chain[j];
      if (!r_trust_issued_by (cur, c))
        continue;

      if ((res = r_trust_check_ca (c, now, ncabelow)) != R_TRUST_OK)
        return res;
      used |= (1u << j);
      ncabelow++;
      cur = c;
      break;
    }
    if (j == count)             /* no issuer found in chain or anchors */
      return R_TRUST_UNTRUSTED;
  }

  return R_TRUST_UNTRUSTED;      /* path longer than R_TRUST_MAX_CHAIN */
}

static void
r_trust_certs_free (RTrustStore * base)
{
  RTrustCerts * store = (RTrustCerts *) base;
  r_ptr_array_unref (store->anchors);
  r_free (store);
}

RTrustStore *
r_trust_store_new_certs (void)
{
  RTrustCerts * store;

  if ((store = r_mem_new0 (RTrustCerts)) == NULL)
    return NULL;
  r_ref_init (store, r_trust_certs_free);
  store->base.verify = r_trust_certs_verify;
  if ((store->anchors = r_ptr_array_new ()) == NULL) {
    r_free (store);
    return NULL;
  }
  return &store->base;
}

rboolean
r_trust_store_add_cert (RTrustStore * base, RCryptoCert * cert)
{
  RTrustCerts * store = (RTrustCerts *) base;

  if (R_UNLIKELY (base == NULL || base->verify != r_trust_certs_verify))
    return FALSE;
  if (R_UNLIKELY (cert == NULL))
    return FALSE;

  return r_ptr_array_add (store->anchors, r_crypto_cert_ref (cert),
      r_crypto_cert_unref) != R_PTR_ARRAY_INVALID_IDX;
}

rssize
r_trust_store_add_pem (RTrustStore * base, const rchar * pem, rssize size)
{
  RPemParser * parser;
  RPemBlock * block;
  rssize added = 0;

  if (R_UNLIKELY (base == NULL || pem == NULL))
    return -1;
  if ((parser = r_pem_parser_new (pem, size)) == NULL)
    return -1;

  while ((block = r_pem_parser_next_block (parser)) != NULL) {
    if (r_pem_block_get_type (block) == R_PEM_TYPE_CERTIFICATE) {
      RCryptoCert * cert = r_pem_block_get_cert (block);
      if (cert != NULL) {
        if (r_trust_store_add_cert (base, cert))
          added++;
        r_crypto_cert_unref (cert);
      }
    }
    r_pem_block_unref (block);
  }

  r_pem_parser_unref (parser);
  return added;
}

rssize
r_trust_store_add_pem_file (RTrustStore * base, const rchar * filename)
{
  ruint8 * data;
  rsize size;
  rssize added;

  if (R_UNLIKELY (base == NULL || filename == NULL))
    return -1;
  if (!r_file_read_all (filename, &data, &size))
    return -1;

  added = r_trust_store_add_pem (base, (const rchar *) data, (rssize) size);
  r_free (data);
  return added;
}

/* --- system trust: load the OS CA bundle / directory --------------------- */

/* The file-based backend is for Unix platforms without a native verifier;
 * Darwin (Security framework) and Android (JNI) delegate to the OS below, not
 * to these probe lists. */
#if defined (R_OS_UNIX) && !defined (R_OS_DARWIN) && !defined (R_OS_ANDROID)
/* Concatenated CA bundles, probed in order (first with anchors wins). */
static const rchar * const g__r_trust_system_bundles[] = {
  "/etc/ssl/certs/ca-certificates.crt",   /* Debian, Ubuntu, Arch, ... */
  "/etc/pki/tls/certs/ca-bundle.crt",     /* RHEL, Fedora, ... */
  "/etc/ssl/cert.pem",                    /* Alpine, BSD, ... */
  "/etc/ssl/ca-bundle.pem",               /* openSUSE */
};
/* CA directories (hashed symlinks or plain PEM files), probed in order. */
static const rchar * const g__r_trust_system_dirs[] = {
  "/etc/ssl/certs",
  "/etc/pki/tls/certs",
};

/* Add every regular file under @dirpath that parses as PEM certificate(s).
 * Returns the number of anchors added, or -1 if the directory can't be read. */
static rssize
r_trust_store_add_dir (RTrustStore * store, const rchar * dirpath)
{
  RFsDir * dir;
  const rchar * name;
  rssize total = 0;

  if ((dir = r_fs_dir_open (dirpath)) == NULL)
    return -1;
  while ((name = r_fs_dir_read_next (dir)) != NULL) {
    rchar * path = r_fs_path_build (dirpath, name, NULL);
    if (path != NULL) {
      /* A non-certificate file just adds nothing; ignore the failure. */
      if (!r_fs_test_is_directory (path)) {
        rssize added = r_trust_store_add_pem_file (store, path);
        if (added > 0)
          total += added;
      }
      r_free (path);
    }
  }
  r_fs_dir_close (dir);
  return total;
}
#endif /* R_OS_UNIX && !R_OS_DARWIN */

/* The native-verifier backends below hold no anchors of their own: the OS owns
 * the trust decision, so verify hands the presented chain to the platform. */
#if defined (R_OS_WIN32) || defined (R_OS_DARWIN) || defined (R_OS_ANDROID)
static void
r_trust_system_free (RTrustStore * store)
{
  r_free (store);
}
#endif

#if defined (R_OS_WIN32)
/* Map the required leaf EKU to the CryptoAPI usage OID (NULL = any). */
static LPCSTR
r_trust_win32_eku_oid (RX509ExtKeyUsage eku)
{
  switch (eku) {
    case R_X509_EXT_KEY_USAGE_CLIENT_AUTH: return szOID_PKIX_KP_CLIENT_AUTH;
    case R_X509_EXT_KEY_USAGE_SERVER_AUTH: return szOID_PKIX_KP_SERVER_AUTH;
    default:                               return NULL;
  }
}

static RTrustResult
r_trust_system_verify_win32 (RTrustStore * base, RCryptoCert * const * chain,
    ruint count, ruint64 now, RX509ExtKeyUsage required_eku)
{
  HCERTSTORE extra;
  PCCERT_CONTEXT leaf = NULL;
  PCCERT_CHAIN_CONTEXT chainctx = NULL;
  CERT_CHAIN_PARA chainpara;
  LPCSTR ekuoid = r_trust_win32_eku_oid (required_eku);
  LPSTR usageoids[1];
  FILETIME ft;
  ruint64 ticks;
  ruint i;
  RTrustResult ret = R_TRUST_UNTRUSTED;
  (void) base;

  if ((extra = CertOpenStore (CERT_STORE_PROV_MEMORY, X509_ASN_ENCODING,
          (HCRYPTPROV_LEGACY) NULL, 0, NULL)) == NULL)
    return R_TRUST_INVALID;

  /* Load the presented chain (leaf first) into an in-memory store; the leaf is
   * the certificate to build a chain for, the rest are candidate intermediates. */
  for (i = 0; i < count; i++) {
    rsize derlen;
    ruint8 * der = r_crypto_cert_dup_data (chain[i], &derlen);
    PCCERT_CONTEXT ctx = NULL;
    if (der == NULL)
      continue;
    if (CertAddEncodedCertificateToStore (extra, X509_ASN_ENCODING, der,
          (DWORD) derlen, CERT_STORE_ADD_ALWAYS, (i == 0) ? &leaf : &ctx) &&
        ctx != NULL)
      CertFreeCertificateContext (ctx);
    r_free (der);
  }
  if (leaf == NULL) {
    CertCloseStore (extra, 0);
    return R_TRUST_INVALID;
  }

  /* now (Unix seconds) -> FILETIME (100ns ticks since 1601; epoch gap 11644473600s). */
  ticks = ((ruint64) now + 11644473600ULL) * 10000000ULL;
  ft.dwLowDateTime = (DWORD) (ticks & 0xffffffffULL);
  ft.dwHighDateTime = (DWORD) (ticks >> 32);

  ZeroMemory (&chainpara, sizeof (chainpara));
  chainpara.cbSize = sizeof (chainpara);
  chainpara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
  if (ekuoid != NULL) {
    usageoids[0] = (LPSTR) ekuoid;
    chainpara.RequestedUsage.Usage.cUsageIdentifier = 1;
    chainpara.RequestedUsage.Usage.rgpszUsageIdentifier = usageoids;
  }

  /* No revocation: the rlib and macOS backends don't do it, and it would add a
   * network round-trip. Hostname is the application's concern, so the SSL policy
   * runs with no server name. */
  if (CertGetCertificateChain (NULL, leaf, &ft, extra, &chainpara, 0, NULL,
        &chainctx)) {
    DWORD err = chainctx->TrustStatus.dwErrorStatus;
    if (err == CERT_TRUST_NO_ERROR) {
      CERT_CHAIN_POLICY_PARA polpara;
      CERT_CHAIN_POLICY_STATUS polstatus;
      SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslpara;

      ZeroMemory (&sslpara, sizeof (sslpara));
      sslpara.cbSize = sizeof (sslpara);
      sslpara.dwAuthType = (required_eku == R_X509_EXT_KEY_USAGE_CLIENT_AUTH)
          ? AUTHTYPE_CLIENT : AUTHTYPE_SERVER;
      ZeroMemory (&polpara, sizeof (polpara));
      polpara.cbSize = sizeof (polpara);
      polpara.pvExtraPolicyPara = &sslpara;
      ZeroMemory (&polstatus, sizeof (polstatus));
      polstatus.cbSize = sizeof (polstatus);

      if (CertVerifyCertificateChainPolicy (CERT_CHAIN_POLICY_SSL, chainctx,
            &polpara, &polstatus))
        ret = (polstatus.dwError == 0) ? R_TRUST_OK : R_TRUST_UNTRUSTED;
      else
        ret = R_TRUST_INVALID;
    } else if (err & (CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_CTL_IS_NOT_TIME_VALID)) {
      ret = R_TRUST_EXPIRED;
    } else if (err & CERT_TRUST_IS_NOT_VALID_FOR_USAGE) {
      ret = R_TRUST_BAD_USAGE;
    } else {
      ret = R_TRUST_UNTRUSTED;
    }
    CertFreeCertificateChain (chainctx);
  } else {
    ret = R_TRUST_INVALID;
  }

  CertFreeCertificateContext (leaf);
  CertCloseStore (extra, 0);
  return ret;
}

static RTrustStore *
r_trust_system_new_win32 (void)
{
  RTrustStore * store;

  if ((store = r_mem_new0 (RTrustStore)) == NULL)
    return NULL;
  r_ref_init (store, r_trust_system_free);
  store->verify = r_trust_system_verify_win32;
  return store;
}
#endif /* R_OS_WIN32 */

#if defined (R_OS_DARWIN)
static RTrustResult
r_trust_system_verify_darwin (RTrustStore * base, RCryptoCert * const * chain,
    ruint count, ruint64 now, RX509ExtKeyUsage required_eku)
{
  CFMutableArrayRef certs;
  SecPolicyRef policy;
  SecTrustRef trust = NULL;
  CFErrorRef err = NULL;
  CFDateRef date;
  OSStatus st;
  RTrustResult ret = R_TRUST_UNTRUSTED;
  ruint i;
  (void) base;

  if ((certs = CFArrayCreateMutable (NULL, (CFIndex) count,
          &kCFTypeArrayCallBacks)) == NULL)
    return R_TRUST_INVALID;

  /* The chain is leaf first; SecTrust takes the leaf as element 0. */
  for (i = 0; i < count; i++) {
    rsize derlen;
    ruint8 * der = r_crypto_cert_dup_data (chain[i], &derlen);
    CFDataRef data;
    SecCertificateRef cert;
    if (der == NULL)
      continue;
    data = CFDataCreate (NULL, der, (CFIndex) derlen);
    r_free (der);
    if (data == NULL)
      continue;
    cert = SecCertificateCreateWithData (NULL, data);
    CFRelease (data);
    if (cert != NULL) {
      CFArrayAppendValue (certs, cert);
      CFRelease (cert);
    }
  }
  if (CFArrayGetCount (certs) == 0) {
    CFRelease (certs);
    return R_TRUST_INVALID;
  }

  /* The SSL policy's server flag selects the server-auth EKU (client otherwise);
   * no hostname (the application's concern). NONE -> basic X.509 (any EKU). */
  if (required_eku == R_X509_EXT_KEY_USAGE_NONE)
    policy = SecPolicyCreateBasicX509 ();
  else
    policy = SecPolicyCreateSSL (
        required_eku != R_X509_EXT_KEY_USAGE_CLIENT_AUTH, NULL);
  if (policy == NULL) {
    CFRelease (certs);
    return R_TRUST_INVALID;
  }

  st = SecTrustCreateWithCertificates (certs, policy, &trust);
  CFRelease (policy);
  CFRelease (certs);
  if (st != errSecSuccess || trust == NULL)
    return R_TRUST_INVALID;

  /* Pin the evaluation time (CFAbsoluteTime is seconds since 2001-01-01). */
  date = CFDateCreate (NULL,
      (CFAbsoluteTime) ((double) now - kCFAbsoluteTimeIntervalSince1970));
  if (date != NULL) {
    SecTrustSetVerifyDate (trust, date);
    CFRelease (date);
  }

  /* The native verifier is coarse: trusted or not. */
  if (SecTrustEvaluateWithError (trust, &err))
    ret = R_TRUST_OK;
  else if (err != NULL)
    CFRelease (err);

  CFRelease (trust);
  return ret;
}

static RTrustStore *
r_trust_system_new_darwin (void)
{
  RTrustStore * store;

  if ((store = r_mem_new0 (RTrustStore)) == NULL)
    return NULL;
  r_ref_init (store, r_trust_system_free);
  store->verify = r_trust_system_verify_darwin;
  return store;
}
#endif /* R_OS_DARWIN */

#if defined (R_OS_ANDROID)
/* The app must hand rlib its JavaVM (typically from JNI_OnLoad) before the
 * system trust store can be used: Android exposes trust only through the Java
 * X509TrustManager, reached over JNI. */
static JavaVM * g__r_trust_jvm = NULL;

void
r_trust_store_set_java_vm (rpointer vm)
{
  g__r_trust_jvm = (JavaVM *) vm;
}

/* Wrap @der (DER bytes, @len long) as a java.security.cert.X509Certificate via
 * CertificateFactory; returns a local ref or NULL (with a pending exception). */
static jobject
r_trust_android_make_cert (JNIEnv * env, jobject cf, jmethodID gen,
    jclass bais_cls, jmethodID bais_ctor, const ruint8 * der, rsize len)
{
  jbyteArray bytes;
  jobject bais, cert;

  if ((bytes = (*env)->NewByteArray (env, (jsize) len)) == NULL)
    return NULL;
  (*env)->SetByteArrayRegion (env, bytes, 0, (jsize) len, (const jbyte *) der);
  if ((bais = (*env)->NewObject (env, bais_cls, bais_ctor, bytes)) == NULL) {
    (*env)->DeleteLocalRef (env, bytes);
    return NULL;
  }
  cert = (*env)->CallObjectMethod (env, cf, gen, bais);
  (*env)->DeleteLocalRef (env, bytes);
  (*env)->DeleteLocalRef (env, bais);
  return cert;
}

/* Delegate validation to the platform default X509TrustManager, which applies
 * the app's trust policy: the system anchors always, plus user / enterprise
 * anchors when the app's network security config opts in. The verify date can't
 * be pinned through this API, so @now is not honoured and the verdict is coarse
 * (trusted or not). A structural JNI failure fails closed. */
static RTrustResult
r_trust_system_verify_android (RTrustStore * base, RCryptoCert * const * chain,
    ruint count, ruint64 now, RX509ExtKeyUsage required_eku)
{
  JavaVM * vm = g__r_trust_jvm;
  JNIEnv * env = NULL;
  rboolean attached = FALSE;
  RTrustResult ret = R_TRUST_INVALID;
  jclass cf_cls, x509_cls, bais_cls, tmf_cls, x509tm_cls;
  jmethodID m, bais_ctor;
  jobject cf, tmf, x509tm = NULL;
  jobjectArray jchain, tms;
  jstring s;
  ruint i;
  jsize n, j;
  (void) base;
  (void) now;

  if (vm == NULL)
    return R_TRUST_INVALID;
  if ((*vm)->GetEnv (vm, (void **) &env, JNI_VERSION_1_6) == JNI_EDETACHED) {
    if ((*vm)->AttachCurrentThread (vm, &env, NULL) != JNI_OK)
      return R_TRUST_INVALID;
    attached = TRUE;
  }
  if (env == NULL)
    return R_TRUST_INVALID;
  if ((*env)->PushLocalFrame (env, (jsize) (count + 24)) != 0) {
    if ((*env)->ExceptionCheck (env)) (*env)->ExceptionClear (env);
    goto detach;
  }

  /* CertificateFactory cf = CertificateFactory.getInstance("X.509"); */
  if ((cf_cls = (*env)->FindClass (env, "java/security/cert/CertificateFactory")) == NULL) goto pop;
  if ((m = (*env)->GetStaticMethodID (env, cf_cls, "getInstance",
          "(Ljava/lang/String;)Ljava/security/cert/CertificateFactory;")) == NULL) goto pop;
  s = (*env)->NewStringUTF (env, "X.509");
  cf = (*env)->CallStaticObjectMethod (env, cf_cls, m, s);
  if ((*env)->ExceptionCheck (env) || cf == NULL) goto fail;
  if ((m = (*env)->GetMethodID (env, cf_cls, "generateCertificate",
          "(Ljava/io/InputStream;)Ljava/security/cert/Certificate;")) == NULL) goto pop;

  /* X509Certificate[] chain, leaf first, built from the DER inputs. */
  if ((x509_cls = (*env)->FindClass (env, "java/security/cert/X509Certificate")) == NULL) goto pop;
  if ((bais_cls = (*env)->FindClass (env, "java/io/ByteArrayInputStream")) == NULL) goto pop;
  if ((bais_ctor = (*env)->GetMethodID (env, bais_cls, "<init>", "([B)V")) == NULL) goto pop;
  if ((jchain = (*env)->NewObjectArray (env, (jsize) count, x509_cls, NULL)) == NULL) goto pop;
  for (i = 0; i < count; i++) {
    rsize derlen;
    ruint8 * der = r_crypto_cert_dup_data (chain[i], &derlen);
    jobject cert;
    if (der == NULL) goto pop;
    cert = r_trust_android_make_cert (env, cf, m, bais_cls, bais_ctor, der, derlen);
    r_free (der);
    if ((*env)->ExceptionCheck (env) || cert == NULL) goto fail;
    (*env)->SetObjectArrayElement (env, jchain, (jsize) i, cert);
    (*env)->DeleteLocalRef (env, cert);
  }

  /* The default TrustManagerFactory's first X509TrustManager carries the app's
   * trust policy (null KeyStore = platform default). */
  if ((tmf_cls = (*env)->FindClass (env, "javax/net/ssl/TrustManagerFactory")) == NULL) goto pop;
  if ((m = (*env)->GetStaticMethodID (env, tmf_cls, "getDefaultAlgorithm",
          "()Ljava/lang/String;")) == NULL) goto pop;
  s = (*env)->CallStaticObjectMethod (env, tmf_cls, m);
  if ((*env)->ExceptionCheck (env) || s == NULL) goto fail;
  if ((m = (*env)->GetStaticMethodID (env, tmf_cls, "getInstance",
          "(Ljava/lang/String;)Ljavax/net/ssl/TrustManagerFactory;")) == NULL) goto pop;
  tmf = (*env)->CallStaticObjectMethod (env, tmf_cls, m, s);
  if ((*env)->ExceptionCheck (env) || tmf == NULL) goto fail;
  if ((m = (*env)->GetMethodID (env, tmf_cls, "init", "(Ljava/security/KeyStore;)V")) == NULL) goto pop;
  (*env)->CallVoidMethod (env, tmf, m, NULL);
  if ((*env)->ExceptionCheck (env)) goto fail;
  if ((m = (*env)->GetMethodID (env, tmf_cls, "getTrustManagers",
          "()[Ljavax/net/ssl/TrustManager;")) == NULL) goto pop;
  tms = (*env)->CallObjectMethod (env, tmf, m);
  if ((*env)->ExceptionCheck (env) || tms == NULL) goto fail;
  if ((x509tm_cls = (*env)->FindClass (env, "javax/net/ssl/X509TrustManager")) == NULL) goto pop;
  n = (*env)->GetArrayLength (env, tms);
  for (j = 0; j < n; j++) {
    jobject tm = (*env)->GetObjectArrayElement (env, tms, j);
    if (tm != NULL && (*env)->IsInstanceOf (env, tm, x509tm_cls)) { x509tm = tm; break; }
    (*env)->DeleteLocalRef (env, tm);
  }
  if (x509tm == NULL) goto pop;

  /* checkServerTrusted / checkClientTrusted throws on an untrusted chain. The
   * authType is a placeholder (we are not in a handshake; the platform uses it
   * only for legacy chain cleaning). */
  if ((m = (*env)->GetMethodID (env, x509tm_cls,
          (required_eku == R_X509_EXT_KEY_USAGE_CLIENT_AUTH) ? "checkClientTrusted" : "checkServerTrusted",
          "([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V")) == NULL) goto pop;
  s = (*env)->NewStringUTF (env, "RSA");
  (*env)->CallVoidMethod (env, x509tm, m, jchain, s);
  ret = (*env)->ExceptionCheck (env) ? R_TRUST_UNTRUSTED : R_TRUST_OK;
  goto pop;

fail:
  ret = R_TRUST_UNTRUSTED;
pop:
  if ((*env)->ExceptionCheck (env))
    (*env)->ExceptionClear (env);
  (*env)->PopLocalFrame (env, NULL);
detach:
  if (attached)
    (*vm)->DetachCurrentThread (vm);
  return ret;
}

static RTrustStore *
r_trust_system_new_android (void)
{
  RTrustStore * store;

  /* Without a JavaVM there is no way to reach the trust manager; fail here, as
   * documented, rather than return a store that rejects every chain at verify. */
  if (g__r_trust_jvm == NULL)
    return NULL;

  if ((store = r_mem_new0 (RTrustStore)) == NULL)
    return NULL;
  r_ref_init (store, r_trust_system_free);
  store->verify = r_trust_system_verify_android;
  return store;
}
#endif /* R_OS_ANDROID */

RTrustStore *
r_trust_store_new_system (void)
{
#if defined (R_OS_WIN32)
  return r_trust_system_new_win32 ();
#elif defined (R_OS_DARWIN)
  return r_trust_system_new_darwin ();
#elif defined (R_OS_ANDROID)
  return r_trust_system_new_android ();
#elif defined (R_OS_UNIX)
  RTrustStore * store;
  const rchar * env;
  rssize added = 0;
  rsize i;

  if ((store = r_trust_store_new_certs ()) == NULL)
    return NULL;

  if ((env = r_getenv ("SSL_CERT_FILE")) != NULL) {
    added = r_trust_store_add_pem_file (store, env);
  } else if ((env = r_getenv ("SSL_CERT_DIR")) != NULL) {
    added = r_trust_store_add_dir (store, env);
  } else {
    for (i = 0; i < R_N_ELEMENTS (g__r_trust_system_bundles) && added <= 0; i++)
      added = r_trust_store_add_pem_file (store, g__r_trust_system_bundles[i]);
    for (i = 0; i < R_N_ELEMENTS (g__r_trust_system_dirs) && added <= 0; i++)
      added = r_trust_store_add_dir (store, g__r_trust_system_dirs[i]);
  }

  if (added <= 0) {
    r_trust_store_unref (store);
    return NULL;
  }
  return store;
#else
  return NULL;
#endif
}

/* --- pinned backend: SubjectPublicKeyInfo SHA-256 pins ------------------- */

typedef struct {
  RTrustStore base;
  RPtrArray * pins;         /* ruint8[R_TRUST_SPKI_PIN_SIZE] blobs */
} RTrustPinned;

/* Hash a certificate's SubjectPublicKeyInfo into @out; FALSE if the key can't
 * be exported. */
static rboolean
r_trust_cert_spki_sha256 (const RCryptoCert * cert,
    ruint8 out[R_TRUST_SPKI_PIN_SIZE])
{
  RCryptoKey * pk;
  RAsn1BinEncoder * enc;
  RMsgDigest * md;
  ruint8 * der;
  rsize dersize;
  rboolean ok = FALSE;

  if ((pk = r_crypto_cert_get_public_key (cert)) == NULL)
    return FALSE;
  if ((enc = r_asn1_bin_encoder_new (R_ASN1_DER)) != NULL) {
    if (r_crypto_key_to_asn1 (pk, enc) == R_CRYPTO_OK &&
        (der = r_asn1_bin_encoder_get_data (enc, &dersize)) != NULL) {
      if ((md = r_msg_digest_new_sha256 ()) != NULL) {
        ok = r_msg_digest_update (md, der, dersize) &&
            r_msg_digest_get_data (md, out, R_TRUST_SPKI_PIN_SIZE, NULL);
        r_msg_digest_free (md);
      }
      r_free (der);
    }
    r_asn1_bin_encoder_unref (enc);
  }
  r_crypto_key_unref (pk);
  return ok;
}

static RTrustResult
r_trust_pinned_verify (RTrustStore * base, RCryptoCert * const * chain,
    ruint count, ruint64 now, RX509ExtKeyUsage required_eku)
{
  RTrustPinned * store = (RTrustPinned *) base;
  rsize np = r_ptr_array_size (store->pins);
  ruint8 spki[R_TRUST_SPKI_PIN_SIZE];
  rsize p;

  (void) count;
  (void) required_eku;          /* pinning authenticates the key directly */

  if (!r_trust_cert_time_valid (chain[0], now))
    return R_TRUST_EXPIRED;

  /* Only the leaf (chain[0]) is the certificate whose private key the peer
   * proves it holds; the rest of the chain is attacker-suppliable public data.
   * Matching a pin against a non-leaf certificate would let an attacker present
   * an unrelated leaf alongside the genuine pinned (public) certificate and be
   * trusted -- so pin strictly against the leaf. */
  if (r_trust_cert_spki_sha256 (chain[0], spki)) {
    for (p = 0; p < np; p++) {
      if (r_memcmp_ct (r_ptr_array_get (store->pins, p), spki,
              R_TRUST_SPKI_PIN_SIZE) == 0)
        return R_TRUST_OK;
    }
  }

  return R_TRUST_UNTRUSTED;
}

static void
r_trust_pinned_free (RTrustStore * base)
{
  RTrustPinned * store = (RTrustPinned *) base;
  r_ptr_array_unref (store->pins);
  r_free (store);
}

RTrustStore *
r_trust_store_new_pinned_spki (void)
{
  RTrustPinned * store;

  if ((store = r_mem_new0 (RTrustPinned)) == NULL)
    return NULL;
  r_ref_init (store, r_trust_pinned_free);
  store->base.verify = r_trust_pinned_verify;
  if ((store->pins = r_ptr_array_new ()) == NULL) {
    r_free (store);
    return NULL;
  }
  return &store->base;
}

rboolean
r_trust_store_add_spki_sha256 (RTrustStore * base,
    const ruint8 sha256[R_TRUST_SPKI_PIN_SIZE])
{
  RTrustPinned * store = (RTrustPinned *) base;
  ruint8 * pin;

  if (R_UNLIKELY (base == NULL || base->verify != r_trust_pinned_verify))
    return FALSE;
  if (R_UNLIKELY (sha256 == NULL))
    return FALSE;
  if ((pin = r_memdup (sha256, R_TRUST_SPKI_PIN_SIZE)) == NULL)
    return FALSE;

  if (r_ptr_array_add (store->pins, pin, r_free) == R_PTR_ARRAY_INVALID_IDX) {
    r_free (pin);
    return FALSE;
  }
  return TRUE;
}

rboolean
r_trust_store_pin_cert_spki (RTrustStore * base, const RCryptoCert * cert)
{
  ruint8 spki[R_TRUST_SPKI_PIN_SIZE];

  if (R_UNLIKELY (cert == NULL))
    return FALSE;
  if (!r_trust_cert_spki_sha256 (cert, spki))
    return FALSE;
  return r_trust_store_add_spki_sha256 (base, spki);
}
