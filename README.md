# SSH Login Tripwire

A small kit for a macOS machine that monitors SSH logins, alerts you in real time,
keeps a **tamper-evident** local log, and replicates each event **off-device** so a
local admin (root) cannot erase the record after the fact.

It is built for the situation where someone else — e.g. a company IT admin — has
`sudo`/root on your Mac via **Remote Login (SSH)**. You cannot *prevent* a root user
from acting, but this makes their access **observable** and any cover-up **detectable**.

---

## What it does

On every SSH login (`sshd` "Accepted" / "session opened" event) it:

1. **Notifies** the logged-in desktop user (banner + sound).
2. **Appends** the event to a hash-chained local log — deleting or editing any line
   breaks every hash after it, so tampering is detectable.
3. **Encrypts** the event (hybrid RSA + AES) and **ships** it off-device immediately
   (ntfy / remote syslog / append-only S3), so anything already delivered is beyond
   the admin's reach *and* unreadable to the relay.

It does **not** block logins. It is detection and evidence, not prevention.

---

## Files

| File | Role |
|------|------|
| `ssh-tripwire.sh` | Main watcher. Streams the unified log for `sshd` events and reacts. Runs as root via LaunchDaemon. |
| `ssh-notify.sh` | Posts a desktop notification to the console user. |
| `ssh-ship.sh` | Encrypts each event, then sends it off-device. Reads destinations from `/etc/ssh-tripwire.conf`. |
| `ssh-decrypt.sh` | Decrypts a shipped payload. Run on your off-device machine that holds the **private** key. |
| `ssh-verify.sh` | Verifies the local log's hash chain; reports the first break. |
| `com.user.ssh-tripwire.plist` | LaunchDaemon: runs the watcher at boot and restarts it if killed. |
| `ssh-tripwire.conf` / `.conf.example` | Off-device destination settings. |

Runtime data lives in `/var/db/ssh-tripwire/`:
- `ssh-tripwire.log` — the hash-chained event log
- `last.hash` — current chain head
- `stdout.log` / `stderr.log` — daemon output

---

## Install

Requires admin/`sudo` on the Mac.

```bash
cd /path/to/ssh-tripwire

# 1. Generate the encryption keypair on a SEPARATE trusted device (NOT this Mac):
#      openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out ssh-tripwire-private.pem
#      openssl rsa -in ssh-tripwire-private.pem -pubout -out ssh-tripwire-public.pem
#    Copy ONLY the public key here, and keep the private key off this Mac:
sudo install -m 644 ssh-tripwire-public.pem /etc/ssh-tripwire-public.pem

# 2. Configure destinations (edit the file first — see "Configuration" below)
sudo install -m 600 ssh-tripwire.conf /etc/ssh-tripwire.conf

# 3. Create the required directories. Both must exist BEFORE the daemon starts:
#    - /usr/local/sbin may not exist by default on macOS (install fails without it).
#    - /var/db/ssh-tripwire holds the log + the daemon's StandardOut/StandardErrorPath,
#      which launchd opens *before* running the script — if it's missing the daemon
#      fails to spawn with "last exit code = 78: EX_CONFIG".
sudo mkdir -p /usr/local/sbin /var/db/ssh-tripwire

# 4. Install the scripts
sudo install -m 755 ssh-tripwire.sh ssh-ship.sh ssh-notify.sh ssh-verify.sh /usr/local/sbin/

# 5. Install and start the daemon
sudo install -m 644 com.user.ssh-tripwire.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.user.ssh-tripwire.plist

# 6. Confirm it's running (want: state = running, with a pid)
sudo launchctl print system/com.user.ssh-tripwire | grep -iE 'state|pid ='
```

> `ssh-decrypt.sh` is **not** installed on the Mac — keep it alongside the private key
> on your off-device machine.

> **Restarting later:** prefer `sudo launchctl bootout system/com.user.ssh-tripwire`
> followed by the `bootstrap` line above. Avoid `launchctl kickstart -k` — it waits for
> the `log stream` process to die and can appear to hang.

---

## Configuration

All settings live in `/etc/ssh-tripwire.conf`. Set one or more destinations; every
one that's filled in gets sent on each event.

> **Security rule:** root can read this file. Only ever put **write-only /
> append-only** credentials here — nothing that could delete or rewrite remote data.

### Encryption (applies to every destination)

Each event is encrypted before it leaves the machine, using hybrid encryption:

- A fresh random **AES-256** key encrypts the message (so any length works).
- **RSA (OAEP)** encrypts that AES key (`openssl pkeyutl`).
- Payload shipped is one line: `v1:<base64 RSA-encrypted AES key>:<hex IV>:<base64 ciphertext>`.

```bash
PUBKEY="/etc/ssh-tripwire-public.pem"
```

- **Only the public key** belongs on this Mac. It can encrypt but not decrypt, so even
  root here cannot read shipped events. The **private key stays off-device**, with
  `ssh-decrypt.sh`.
- `ssh-ship.sh` **fails closed**: if the public key is missing/unreadable, nothing is
  sent — plaintext never leaks to a public relay.
- Confidentiality only (AES-CBC), not authentication; integrity is covered by the
  local hash chain. Ask to switch to AES-GCM if you want authenticated encryption.

### Option A — ntfy (simplest; good for alerts)

```bash
NTFY_URL="https://ntfy.sh/your-long-random-topic-name"
```

- The topic name **is** the access — treat it like a password.
- Subscribe to the same topic in the ntfy phone app (or open the URL in a browser).
- Because events are encrypted, the notification shows an unreadable `v1:...` blob —
  you get the *alert* that a login happened, then run `ssh-decrypt.sh` to read details.
- ntfy.sh is a public relay, but it only ever sees ciphertext.
- Good for alerting, **weak** for integrity (anyone with the topic can post fakes).

### Option B — remote syslog (a collector you control)

```bash
SYSLOG_HOST="logs.example.com"
SYSLOG_PORT="514"
```

Plain syslog is unencrypted — use only over a trusted network or VPN.

### Option C — append-only S3 with Object Lock (strongest)

```bash
S3_BUCKET="my-ssh-audit-bucket"
```

- Create the bucket with **Object Lock (compliance mode)** enabled.
- Use an IAM key limited to **`s3:PutObject` only** (no Get/Delete).
- Install + configure `awscli` with that key.
- Result: even if the admin reads the key off disk, they can only *add* events —
  they cannot erase history. This is the real tamper-proof option.

After editing the config, redeploy and restart:

```bash
sudo install -m 600 ssh-tripwire.conf /etc/ssh-tripwire.conf
sudo launchctl kickstart -k system/com.user.ssh-tripwire
```

---

## Usage

### Test shipping end-to-end

```bash
# Direct ntfy test, bypassing encryption (shows HTTP 200 + JSON on success)
curl -sS -d "test event" https://ntfy.sh/your-topic

# Through the shipper — encrypts, then fires every configured destination
sudo /usr/local/sbin/ssh-ship.sh "$(date -u +%FT%TZ)|manual test|deadbeef"
```

The shipper's output arrives as an encrypted `v1:...` payload; decrypt it to confirm
(see below). A `200` with a JSON body on the direct `curl` means ntfy **accepted and
published** the message. If you still see no notification, the problem is the receiver:
check the exact topic name, that the app points at `ntfy.sh`, OS notification
permission, and (Android) that battery optimization is **off** for ntfy. The web URL
shows messages live regardless of app settings.

### Read / decrypt a shipped event

On your off-device machine that holds the **private** key (never on the Mac):

```bash
./ssh-decrypt.sh ssh-tripwire-private.pem 'v1:<enckey>:<iv>:<ciphertext>'
# or pipe a copied payload:
pbpaste | ./ssh-decrypt.sh ssh-tripwire-private.pem
```

### Trigger a real event

```bash
ssh localhost    # then exit
```

You should get a desktop notification, a new line in
`/var/db/ssh-tripwire/ssh-tripwire.log`, and a message at your off-device destination.

### See who is connected right now

```bash
who        # SSH sessions show the source IP in parentheses
w          # same, plus what each session is running
```

### Verify the local log hasn't been tampered with

```bash
sudo /usr/local/sbin/ssh-verify.sh
# OK: N records verified, chain intact.
# or: CHAIN BROKEN at record X   <- a line was deleted or edited
```

Also compare the local log against your off-device copy. If the local file is shorter
than or diverges from the remote one, the local file was tampered with.

---

## Uninstall

```bash
sudo launchctl bootout system/com.user.ssh-tripwire
sudo rm /Library/LaunchDaemons/com.user.ssh-tripwire.plist
sudo rm /usr/local/sbin/ssh-tripwire.sh /usr/local/sbin/ssh-ship.sh \
        /usr/local/sbin/ssh-notify.sh /usr/local/sbin/ssh-verify.sh
sudo rm /etc/ssh-tripwire.conf
sudo rm /etc/ssh-tripwire-public.pem
sudo rm -rf /var/db/ssh-tripwire
```

---

## Threat model — what this does and does NOT do

**Holds up:**
- **Already-shipped events are safe.** Once an event reaches your phone or an
  append-only store, a root user on the laptop cannot delete or alter it.
- **Local tampering is evident.** The hash chain exposes deletions/edits; comparing
  local vs. remote exposes gaps.
- **On-disk ship credentials stay safe *if* write-only.** That's why the config must
  only hold append-only / PutObject-only credentials.
- **Shipped events are unreadable off-device.** Only the public key is on the Mac, so
  neither the relay nor a root user here can decrypt what was sent; the private key
  lives elsewhere.

**Cannot do (root wins locally):**
- The admin can **stop the daemon, block the network, or remove the files**, so
  *future* events may stop being recorded. They can't rewrite the past — but they can
  end the stream. A **heartbeat / dead-man's-switch** (treat *missing* pings as the
  alarm) closes this gap; not included here by default.
- On a **public ntfy topic**, anyone who knows the topic can post **forged** events.
  Use the S3 Object Lock path when integrity matters.
- Nothing survives an admin who **reinstalls the OS or wipes the disk** (but that's
  loud and obvious).

**Bottom line:** on a machine where someone else has root, you can't *prevent* access —
you can only make it **observable** and get a durable record **off the box** before it
could be reached. This kit does that.

---

## Notes for a company-managed Mac

- IT's MDM may **detect or remove** unauthorized LaunchDaemons, and installing
  monitoring may conflict with acceptable-use policy. A transparent "I'd like to keep
  a local access log for my own records — any objection?" is often safer and more
  effective than a covert tripwire.
- If your real goal is privacy, the cleanest answer is to keep personal/sensitive data
  **off the managed device** entirely.
