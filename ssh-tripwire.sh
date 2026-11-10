#!/bin/bash
# SSH login tripwire.
# Watches the macOS unified log for sshd "Accepted"/"session opened" events,
# appends each to a hash-chained local log (tamper-EVIDENT), ships each event
# off-device immediately (tamper-RESISTANT for anything already delivered), and
# posts a desktop notification to the logged-in user.
#
# Runs as root via a LaunchDaemon so it can read info-level sshd logs and
# survive reboots. See README for the threat model and limits.
set -u

STATE_DIR="/var/db/ssh-tripwire"
LOG_FILE="$STATE_DIR/ssh-tripwire.log"
HASH_FILE="$STATE_DIR/last.hash"
SHIP="/usr/local/sbin/ssh-ship.sh"
NOTIFY="/usr/local/sbin/ssh-notify.sh"

mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"
[ -f "$HASH_FILE" ] || printf 'GENESIS' > "$HASH_FILE"

emit() {
  local ev="$1" ts prev rec hash
  ts="$(date -u +%FT%TZ)"
  prev="$(cat "$HASH_FILE" 2>/dev/null)"
  rec="$ts|$ev"
  # Chain: each record's hash covers the previous hash + this record.
  # Deleting or editing any line breaks every hash after it.
  hash="$(printf '%s%s' "$prev" "$rec" | shasum -a 256 | awk '{print $1}')"
  printf '%s|%s\n' "$rec" "$hash" >> "$LOG_FILE"
  printf '%s' "$hash" > "$HASH_FILE"
  "$SHIP"   "$ts|$ev|$hash" >/dev/null 2>&1 &
  "$NOTIFY" "SSH login detected: $ev" >/dev/null 2>&1 &
}

# --style syslog gives one human-readable line per event containing the message text.
# OpenSSH 9.8+ (ships in current macOS) logs the "Accepted" line from a child
# process named "sshd-session", not "sshd" — so match both. The message filter is
# in the predicate to keep the stream small; the case below is a second guard.
log stream --style syslog --info --predicate \
  '(process == "sshd" OR process == "sshd-session" OR process BEGINSWITH "sshd") AND (eventMessage CONTAINS "Accepted" OR eventMessage CONTAINS "session opened")' \
  2>/dev/null \
| while IFS= read -r line; do
    case "$line" in
      *"Accepted "*|*"session opened for user"*)
        emit "$line"
        ;;
    esac
  done
