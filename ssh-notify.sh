#!/bin/bash
# Post a desktop notification to whoever is logged in at the console.
# Needed because a LaunchDaemon runs outside any GUI session and cannot
# display notifications directly.
set -u

MSG="$1"
uid="$(stat -f %u /dev/console 2>/dev/null)"
[ -n "${uid:-}" ] || exit 0          # no one logged in at the console; skip
[ "$uid" = "0" ] && exit 0

launchctl asuser "$uid" /usr/bin/osascript \
  -e "display notification \"$MSG\" with title \"SSH Tripwire\" sound name \"Sosumi\"" \
  2>/dev/null

exit 0
