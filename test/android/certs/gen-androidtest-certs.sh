#!/bin/sh
# Regenerate the cert material for the Android instrumented trust-store test
# (test/android). Self-contained -- independent of test/gen-rtlstestcerts.sh so
# the shared PKI is not perturbed. Requires openssl. Run from anywhere.
#
# Emits two artifacts:
#   jni/androidtest-certs.h                  PEM string constants for the bridge
#   app/src/main/res/raw/androidtest_root.pem  the trust anchor bundled in the APK
#
# The harness bundles androidtest_root as an app trust anchor (network security
# config), so leaves under it verify OK via the platform X509TrustManager;
# androidtest_root_alt is an independent root the device does NOT trust, giving a
# deterministic UNTRUSTED case.
set -eu

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
HDR="$HERE/../jni/androidtest-certs.h"
ANCHOR="$HERE/../app/src/main/res/raw/androidtest_root.pem"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# Fixed validity window (not generation-date-relative). The Android platform
# trust manager validates against the real wall clock and cannot be pinned, so
# the window must straddle "now"; 2015..2125 does.
NOT_BEFORE=20150101000000Z
NOT_AFTER=21250101000000Z

gen_key () { openssl genrsa -out "$1.key" 2048 2>/dev/null; }

# self_signed_ca <name> <subject-CN>
self_signed_ca () {
  gen_key "$1"
  openssl req -new -x509 -key "$1.key" -out "$1.crt" -sha256 \
    -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" -subj "/CN=$2" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

# issue <name> <ca> <extensions> <subject-CN>
issue () {
  gen_key "$1"
  openssl req -new -key "$1.key" -out "$1.csr" -subj "/CN=$4" 2>/dev/null
  printf '%s\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
    -out "$1.crt" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
    -sha256 -extfile "$1.ext" 2>/dev/null
}

self_signed_ca root     "rlib AndroidTest Root CA"
self_signed_ca root_alt "rlib AndroidTest Foreign Root CA"

issue leaf_server root     "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                  "localhost"
issue leaf_client root     "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                  "rlib AndroidTest Client"
issue leaf_alt    root_alt "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                  "localhost"

emit () {  # emit <c-name> <pem-file>
  printf 'static const rchar %s[] =\n' "$1"
  while IFS= read -r line; do printf '  "%s\\r\\n"\n' "$line"; done < "$2"
  printf ';\n\n'
}

{
  cat <<'HDR_TOP'
/* Cert material for the Android instrumented trust-store test (test/android).
 *
 * Generated with openssl: two independent self-signed roots and leaves under
 * each, fixed 2015-01-01..2125-01-01 validity. androidtest_root is bundled as an
 * app trust anchor (network_security_config.xml), so leaf_server/leaf_client
 * verify OK via the platform X509TrustManager; root_alt is NOT trusted, so
 * leaf_alt yields a deterministic UNTRUSTED. Regenerate via
 * test/android/certs/gen-androidtest-certs.sh.
 */
#ifndef __R_ANDROIDTEST_CERTS_H__
#define __R_ANDROIDTEST_CERTS_H__

HDR_TOP
  emit at_root_pem        root.crt
  emit at_leaf_server_pem leaf_server.crt
  emit at_leaf_client_pem leaf_client.crt
  emit at_root_alt_pem    root_alt.crt
  emit at_leaf_alt_pem    leaf_alt.crt
  echo "#endif /* __R_ANDROIDTEST_CERTS_H__ */"
} > "$HDR"

cp root.crt "$ANCHOR"

echo "wrote $HDR"
echo "wrote $ANCHOR"
