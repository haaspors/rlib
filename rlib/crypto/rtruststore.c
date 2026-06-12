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

#if defined (R_OS_UNIX)
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
#endif

RTrustStore *
r_trust_store_new_system (void)
{
#if defined (R_OS_UNIX)
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
