#!/bin/bash
# Ship one SSH event off-device, ENCRYPTED.
#
# Encryption model (hybrid / envelope — "RSA encryption" done correctly):
#   * A fresh random AES-256 key encrypts the message (handles any length).
#   * RSA (OAEP) encrypts that AES key.
#   * Only the PUBLIC key lives on this Mac. The PRIVATE key is kept OFF the
#     machine, so even root here cannot decrypt what was sent. The public key
#     can only encrypt, never decrypt.
#
# FAIL CLOSED: if encryption is configured but fails, nothing is sent (so we
# never leak plaintext to a public relay like ntfy.sh).
#
# Output payload format (single line, ':' separated; base64/hex contain no ':'):
#   v1:<base64 RSA-encrypted AES key>:<hex IV>:<base64 AES-CBC ciphertext>
set -u

MSG="$1"
CONF="/etc/ssh-tripwire.conf"
# shellcheck disable=SC1090
[ -f "$CONF" ] && . "$CONF"

: "${PUBKEY:=/etc/ssh-tripwire-public.pem}"   # public key used to encrypt

encrypt_msg() {
  # echoes the payload on success; returns non-zero on any failure
  local plaintext="$1" keyhex ivhex enckey_b64 ct_b64
  [ -r "$PUBKEY" ] || { echo "ssh-ship: public key not readable: $PUBKEY" >&2; return 1; }

  keyhex="$(openssl rand -hex 32)" || return 1   # AES-256 key
  ivhex="$(openssl rand -hex 16)"  || return 1   # CBC IV

  ct_b64="$(printf '%s' "$plaintext" \
            | openssl enc -aes-256-cbc -K "$keyhex" -iv "$ivhex" -a -A 2>/dev/null)" || return 1

  enckey_b64="$(printf '%s' "$keyhex" \
                | openssl pkeyutl -encrypt -pubin -inkey "$PUBKEY" \
                    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 2>/dev/null \
                | openssl base64 -A 2>/dev/null)" || return 1
  [ -n "$enckey_b64" ] || return 1

  printf 'v1:%s:%s:%s' "$enckey_b64" "$ivhex" "$ct_b64"
}

# Encrypt once; every destination gets ciphertext. Fail closed on error.
OUT="$(encrypt_msg "$MSG")" || {
  echo "ssh-ship: encryption failed — nothing sent" >&2
  exit 1
}

# --- Option A: ntfy ------------------------------------------------------------
: "${NTFY_URL:=}"
if [ -n "$NTFY_URL" ]; then
  curl -fsS --max-time 10 -H "Title: SSH Tripwire (encrypted)" -d "$OUT" "$NTFY_URL" >/dev/null 2>&1
fi

# --- Option B: remote syslog collector you control -----------------------------
: "${SYSLOG_HOST:=}"
if [ -n "$SYSLOG_HOST" ]; then
  logger -t ssh-tripwire -n "$SYSLOG_HOST" -P "${SYSLOG_PORT:-514}" "$OUT" 2>/dev/null
fi

# --- Option C: append-only S3 (strongest at-rest) ------------------------------
: "${S3_BUCKET:=}"
if [ -n "$S3_BUCKET" ] && command -v aws >/dev/null 2>&1; then
  key="ssh-events/$(date -u +%Y/%m/%d)/$(date -u +%s)-$RANDOM.enc"
  printf '%s\n' "$OUT" | aws s3 cp - "s3://$S3_BUCKET/$key" >/dev/null 2>&1
fi

exit 0
