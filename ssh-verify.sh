#!/bin/bash
# Verify the hash chain of the local tripwire log.
# Any break means a line was deleted or edited after it was written.
# Run the SAME check against your off-device copy and compare — if the local
# log is shorter than or diverges from the remote one, the local file was tampered.
set -u

LOG="${1:-/var/db/ssh-tripwire/ssh-tripwire.log}"
[ -f "$LOG" ] || { echo "No log at $LOG"; exit 2; }

prev="GENESIS"
n=0
while IFS= read -r line; do
  rec="${line%|*}"            # everything before the final '|' = ts|event
  hash="${line##*|}"          # final field = stored hash
  calc="$(printf '%s%s' "$prev" "$rec" | shasum -a 256 | awk '{print $1}')"
  n=$((n+1))
  if [ "$calc" != "$hash" ]; then
    echo "CHAIN BROKEN at record $n"
    echo "  line: $line"
    echo "  expected hash: $calc"
    exit 1
  fi
  prev="$hash"
done < "$LOG"

echo "OK: $n records verified, chain intact."
