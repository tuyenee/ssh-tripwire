#!/bin/bash
# Decrypt a payload produced by ssh-ship.sh.
# Run this on your SEPARATE trusted device that holds the PRIVATE key — never on
# the monitored Mac (putting the private key there would defeat the whole point).
#
# Usage:
#   ./ssh-decrypt.sh <private-key.pem> 'v1:<enckey>:<iv>:<ciphertext>'
#   pbpaste | ./ssh-decrypt.sh <private-key.pem>            # read payload from stdin
set -u

PRIV="${1:?usage: ssh-decrypt.sh <private-key.pem> [payload]}"
PAYLOAD="${2:-$(cat)}"

IFS=':' read -r ver enckey_b64 ivhex ct_b64 <<EOF
$PAYLOAD
EOF

[ "$ver" = "v1" ] || { echo "unexpected format/version: '$ver'" >&2; exit 1; }

keyhex="$(printf '%s' "$enckey_b64" | openssl base64 -d -A \
          | openssl pkeyutl -decrypt -inkey "$PRIV" \
              -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 2>/dev/null)" \
  || { echo "RSA decrypt of AES key failed (wrong key?)" >&2; exit 1; }

printf '%s' "$ct_b64" \
  | openssl enc -d -aes-256-cbc -K "$keyhex" -iv "$ivhex" -a -A 2>/dev/null \
  || { echo "AES decrypt failed" >&2; exit 1; }
echo
