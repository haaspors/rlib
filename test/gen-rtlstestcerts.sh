#!/bin/sh
# Regenerate test/rtlstestcerts.h: a small RSA test PKI for the trust-store,
# hostname and certificate-pinning tests. Requires openssl. Run from anywhere;
# writes rtlstestcerts.h next to this script.
set -eu

OUT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/rtlstestcerts.h"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

# Fixed validity window (not generation-date-relative), so the certs are valid
# regardless of the build host's clock and the unit-test timestamps stay stable.
NOT_BEFORE=20150101000000Z
NOT_AFTER=21250101000000Z

gen_key () { openssl genrsa -out "$1.key" 2048 2>/dev/null; }

# issue <name> <ca> <extensions> <subject-CN>
issue () {
  gen_key "$1"
  openssl req -new -key "$1.key" -out "$1.csr" -subj "/CN=$4" 2>/dev/null
  printf '%s\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
    -out "$1.crt" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
    -sha256 -extfile "$1.ext" 2>/dev/null
}

gen_key root
openssl req -new -x509 -key root.key -out root.crt -sha256 \
  -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
  -subj "/CN=rlib Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

issue inter         root          "basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign"                                   "rlib Test Intermediate CA"
issue leaf          inter         "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "localhost"
issue leaf_root     root          "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "localhost"
issue leaf_noeku    root          "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "localhost"
issue leaf_wild     root          "basicConstraints=critical,CA:FALSE
extendedKeyUsage=serverAuth
subjectAltName=DNS:*.example.com"                                        "*.example.com"
issue leaf_clientauth root        "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "rlib Test Client"
issue inter_noksign root          "basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature"                                      "rlib Test Inter NoKeyCertSign"
issue leaf_noksign  inter_noksign "basicConstraints=critical,CA:FALSE
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "localhost"
issue midleaf_notca root          "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature"                                      "rlib Test NotCA Middle"
issue child_notca   midleaf_notca "basicConstraints=critical,CA:FALSE
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "localhost"
issue subinter      inter         "basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign"                                           "rlib Test SubIntermediate CA"
issue leaf_sub      subinter      "basicConstraints=critical,CA:FALSE
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "localhost"

# A parallel Ed448 chain (root/intermediate/leaf), for PureEdDSA chain
# verification. issue_ed448 mirrors issue but with an Ed448 key and no external
# digest (EdDSA signs the content directly).
issue_ed448 () {
  openssl genpkey -algorithm ed448 -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -out "$1.csr" -subj "/CN=$4" 2>/dev/null
  printf '%s\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
    -out "$1.crt" -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
    -extfile "$1.ext" 2>/dev/null
}

openssl genpkey -algorithm ed448 -out ed448_root.key 2>/dev/null
openssl req -new -x509 -key ed448_root.key -out ed448_root.crt \
  -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
  -subj "/CN=rlib Test Ed448 Root CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

issue_ed448 ed448_inter ed448_root "basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign"                                   "rlib Test Ed448 Intermediate CA"
issue_ed448 ed448_leaf  ed448_inter "basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1"                               "localhost"

emit () {  # emit <c-name> <pem-file>
  printf 'static const rchar %s[] =\n' "$1"
  while IFS= read -r line; do printf '  "%s\\r\\n"\n' "$line"; done < "$2"
  printf ';\n\n'
}

{
  cat <<'HDR'
/* Test PKI for trust-store / hostname / pinning tests.
 *
 * Generated with openssl: a 2048-bit RSA root CA (pathlen:1), an intermediate
 * CA (pathlen:0) and leaf certs, all with a fixed 2015-01-01..2125-01-01
 * validity window (independent of the build host's clock). Leaves carry SAN
 * DNS:localhost + IP:127.0.0.1 and extendedKeyUsage serverAuth unless their name
 * says otherwise; leaf_clientauth is the client (CN=rlib Test Client, clientAuth).
 * A parallel Ed448 root/intermediate/leaf chain exercises PureEdDSA chain
 * verification. Regenerate via test/gen-rtlstestcerts.sh.
 */
#ifndef __R_TEST_TLS_TEST_CERTS_H__
#define __R_TEST_TLS_TEST_CERTS_H__

HDR
  emit rtest_root_pem          root.crt
  emit rtest_inter_pem         inter.crt
  emit rtest_leaf_pem          leaf.crt
  emit rtest_leaf_root_pem     leaf_root.crt
  emit rtest_leaf_root_key_pem leaf_root.key
  emit rtest_leaf_noeku_pem    leaf_noeku.crt
  emit rtest_inter_noksign_pem inter_noksign.crt
  emit rtest_leaf_noksign_pem  leaf_noksign.crt
  emit rtest_midleaf_notca_pem midleaf_notca.crt
  emit rtest_child_notca_pem   child_notca.crt
  emit rtest_subinter_pem      subinter.crt
  emit rtest_leaf_sub_pem      leaf_sub.crt
  emit rtest_leaf_wild_pem     leaf_wild.crt
  emit rtest_leaf_clientauth_pem     leaf_clientauth.crt
  emit rtest_leaf_clientauth_key_pem leaf_clientauth.key
  emit rtest_ed448_root_pem          ed448_root.crt
  emit rtest_ed448_inter_pem         ed448_inter.crt
  emit rtest_ed448_leaf_pem          ed448_leaf.crt
  echo "#endif /* __R_TEST_TLS_TEST_CERTS_H__ */"
} > "$OUT"

echo "wrote $OUT"
