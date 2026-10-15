#!/usr/bin/env bash
# Writes Tests/iOSSecurityToolsTests/CertificateFixtures.swift: a small test PKI for the
# certificate pinning tests, and the SPKI SHA-256 pins of each certificate as computed by OpenSSL.
#
# The tests compare those pins with the ones SPKIPin computes, and evaluate the chains with
# SecTrust at a fixed date inside the validity period, so the fixtures do not expire.
#
# Usage: scripts/make-test-certificates.sh   (OpenSSL 3.4 or later, for -not_before/-not_after)
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
output="$repo_root/Tests/iOSSecurityToolsTests/CertificateFixtures.swift"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cd "$work"

openssl_bin="${OPENSSL:-openssl}"
"$openssl_bin" req -help 2>&1 | grep -q -- '-not_before' || {
  echo "$("$openssl_bin" version) lacks -not_before; set OPENSSL to OpenSSL 3.4 or later." >&2
  exit 1
}

leaf_start=20261001000000Z
leaf_end=20270930000000Z
root_end=20361001000000Z

# Root CA (EC P-256).
"$openssl_bin" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout root.key -out root.pem -subj "/CN=iOSSecurityTools Test Root" \
  -not_before "$leaf_start" -not_after "$root_end" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

issue_leaf() { # name key-spec host
  local name="$1" host="$3"
  # shellcheck disable=SC2086 # $2 holds several options on purpose.
  "$openssl_bin" req -new $2 -nodes -keyout "$name.key" -out "$name.csr" -subj "/CN=$host" 2>/dev/null
  printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s,DNS:api.%s\n' "$host" "$host" >"$name.ext"
  "$openssl_bin" x509 -req -in "$name.csr" -CA root.pem -CAkey root.key -out "$name.pem" \
    -not_before "$leaf_start" -not_after "$leaf_end" -extfile "$name.ext" -sha256 2>/dev/null
}
issue_leaf ec_leaf "-newkey ec -pkeyopt ec_paramgen_curve:P-256" pinned.test
issue_leaf rsa_leaf "-newkey rsa:2048" rsa.pinned.test

# Unrelated self-signed certificates: other key types for the SPKI tests, and backup pins.
"$openssl_bin" req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes -keyout p384.key -out p384.pem \
  -subj "/CN=p384.test" -not_before "$leaf_start" -not_after "$leaf_end" 2>/dev/null
"$openssl_bin" req -x509 -new -newkey rsa:4096 -nodes -keyout rsa4096.key -out rsa4096.pem \
  -subj "/CN=rsa4096.test" -not_before "$leaf_start" -not_after "$leaf_end" 2>/dev/null

der() { "$openssl_bin" x509 -in "$1.pem" -outform der | base64 | tr -d '\n'; }
pin() { "$openssl_bin" x509 -in "$1.pem" -pubkey -noout | "$openssl_bin" pkey -pubin -outform der | "$openssl_bin" dgst -sha256 -binary | base64; }

{
  echo "// Written by scripts/make-test-certificates.sh with $("$openssl_bin" version | cut -d' ' -f1-2). Do not edit."
  echo "//"
  echo "// A root CA (EC P-256) that issued two TLS leaf certificates — pinned.test (EC P-256) and"
  echo "// rsa.pinned.test (RSA 2048), each also valid for the api. subdomain — plus two unrelated"
  echo "// self-signed certificates (EC P-384, RSA 4096). Pins are base64(SHA-256(SubjectPublicKeyInfo))"
  echo "// computed by OpenSSL. Leaf certificates are valid from 2026-10-01 to 2027-09-30."
  echo "import Foundation"
  echo ""
  echo "enum CertificateFixtures {"
  for name in root ec_leaf rsa_leaf p384 rsa4096; do
    camel="$(echo "$name" | awk -F_ '{for (i = 2; i <= NF; i++) $i = toupper(substr($i, 1, 1)) substr($i, 2)} 1' OFS='')"
    echo "    static let ${camel}DER = \"$(der "$name")\""
    echo "    static let ${camel}Pin = \"$(pin "$name")\""
  done
  echo "    /// 2027-01-01T00:00:00Z, inside every certificate's validity period."
  echo "    static let verifyDate = Date(timeIntervalSince1970: 1_798_761_600)"
  echo "}"
} >"$output"

echo "Wrote $output"
