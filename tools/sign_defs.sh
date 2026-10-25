#!/bin/sh
# Sign a compiled definitions TSV with an Ed25519 key (OpenSSL 3).
# Usage: tools/sign_defs.sh PRIVATE_KEY.pem FILE.tsv   -> FILE.tsv.sig
set -eu
openssl pkeyutl -sign -rawin -inkey "$1" -in "$2" -out "$2.sig"
echo "signed $2 -> $2.sig"
