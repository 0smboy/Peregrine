#!/usr/bin/env bash
# Grant a Cursor cloud agent a dedicated, revocable SSH identity on the
# Peregrine lab nodes, then hand that identity over through the Drive drop
# folder the agent already reads.
#
# Run this on the owner's Mac, which already has working `ssh swift1` /
# `ssh swift2`. It never touches prod :8080, /srv/node, the overseer, remint,
# or the live tip binary; the only write is one authorized_keys line per node.
#
#   bash tools/lab-agent-access-bootstrap.sh            # install + Drive drop
#   bash tools/lab-agent-access-bootstrap.sh --print-blobs
#   bash tools/lab-agent-access-bootstrap.sh --revoke
#
# macOS bash 3.2 compatible on purpose.

set -euo pipefail

DROP_FOLDER="Peregrine-agent-access-20260918"
DROP_FOLDER_ID="1HqCj1gZKPDe8nftoiVKLQnzXNRemXLeJ"
HANDSHAKE_TOKEN="79900f3640cee47c07ee201714f774b7"
KEY_COMMENT="peregrine-cloud-agent-20260918"
KEY_DIR="$HOME/.peregrine-cloud-agent"
KEY_FILE="$KEY_DIR/id_ed25519"
KNOWN_HOSTS="$KEY_DIR/known_hosts"
NODES="swift1 swift2"
RCLONE_REMOTE="gdrive"

MODE="bootstrap"
ROTATE="no"
PRINT_BLOBS="no"

while [ $# -gt 0 ]; do
  case "$1" in
    --revoke) MODE="revoke" ;;
    --print-blobs) PRINT_BLOBS="yes" ;;
    --rotate) ROTATE="yes" ;;
    --nodes) shift; NODES="$1" ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

say()  { printf '\n=== %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

b64()   { openssl base64 -A -in "$1"; }
sshq()  { ssh -o BatchMode=yes -o ConnectTimeout=10 "$@"; }

# grep -c prints 0 *and* exits non-zero on no match, so normalize to one number
count_agent_lines() {
  n=$(sshq "$1" "grep -c '$KEY_COMMENT' ~/.ssh/authorized_keys 2>/dev/null || true" | head -1 | tr -d ' \r')
  [ -n "$n" ] || n=0
  printf '%s' "$n"
}

# ---------------------------------------------------------------- preflight

say "preflight"
for bin in ssh ssh-keygen openssl awk sed grep; do
  command -v "$bin" >/dev/null 2>&1 || die "missing required tool: $bin"
done
for node in $NODES; do
  sshq "$node" true >/dev/null 2>&1 || die "cannot reach '$node' from this Mac (check ~/.ssh/config and your agent)"
  info "ssh $node OK"
done

pub_addr_of() {
  # public address the cloud agent will dial, from this Mac's ssh config
  ssh -G "$1" 2>/dev/null | awk '/^hostname /{print $2; exit}'
}

# ------------------------------------------------------------------ revoke

if [ "$MODE" = "revoke" ]; then
  say "revoking $KEY_COMMENT"
  for node in $NODES; do
    sshq "$node" "if [ -f ~/.ssh/authorized_keys ]; then \
        cp -a ~/.ssh/authorized_keys ~/.ssh/authorized_keys.bak-revoke && \
        grep -v '$KEY_COMMENT' ~/.ssh/authorized_keys.bak-revoke > ~/.ssh/authorized_keys && \
        chmod 600 ~/.ssh/authorized_keys; fi" >/dev/null
    info "$node: remaining agent key lines = $(count_agent_lines "$node")"
  done
  if sshq swift2 "command -v rclone" >/dev/null 2>&1; then
    sshq swift2 "rclone delete '$RCLONE_REMOTE:$DROP_FOLDER/' --include 'agent-*' 2>/dev/null || true" || true
    info "Drive drop: agent-* files deleted (folder kept)"
  fi
  rm -f "$KEY_FILE" "$KEY_FILE.pub" "$KNOWN_HOSTS"
  info "local key material removed from $KEY_DIR"
  say "revoke done — also trash Drive folder $DROP_FOLDER if you want it gone"
  exit 0
fi

# ------------------------------------------------------------------ keypair

say "dedicated keypair"
mkdir -p "$KEY_DIR"; chmod 700 "$KEY_DIR"
if [ -f "$KEY_FILE" ] && [ "$ROTATE" = "no" ]; then
  info "reusing $KEY_FILE"
else
  rm -f "$KEY_FILE" "$KEY_FILE.pub"
  ssh-keygen -t ed25519 -N '' -C "$KEY_COMMENT" -f "$KEY_FILE" >/dev/null
  info "generated $KEY_FILE"
fi
chmod 600 "$KEY_FILE"
PUBKEY=$(cat "$KEY_FILE.pub")
info "fingerprint: $(ssh-keygen -lf "$KEY_FILE.pub" | awk '{print $2}')"

# --------------------------------------------------- install + known_hosts

say "installing public key and collecting host keys"
: > "$KNOWN_HOSTS"
for node in $NODES; do
  addr=$(pub_addr_of "$node")
  [ -n "$addr" ] || die "cannot resolve the public address of '$node' from ssh -G"

  sshq "$node" "umask 077; mkdir -p ~/.ssh; touch ~/.ssh/authorized_keys; \
    grep -qxF '$PUBKEY' ~/.ssh/authorized_keys || printf '%s\n' '$PUBKEY' >> ~/.ssh/authorized_keys; \
    chmod 600 ~/.ssh/authorized_keys"
  info "$node ($addr): authorized_keys has $(count_agent_lines "$node") agent line(s)"

  # host keys straight from the node, not from a scan
  sshq "$node" 'cat /etc/ssh/ssh_host_ed25519_key.pub /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null' \
  | while read -r kt kd _rest; do
      [ -n "$kt" ] && [ -n "$kd" ] || continue
      printf '%s %s %s\n' "$addr" "$kt" "$kd" >> "$KNOWN_HOSTS"
    done
done
chmod 600 "$KNOWN_HOSTS"
info "known_hosts entries: $(wc -l < "$KNOWN_HOSTS" | tr -d ' ')"

# ----------------------------------------------- verify the agent's own path

say "verifying the exact path the cloud agent will use"
AGENT_SSH_OK="yes"
for node in $NODES; do
  addr=$(pub_addr_of "$node")
  out=$(ssh -i "$KEY_FILE" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 \
        -o UserKnownHostsFile="$KNOWN_HOSTS" -o StrictHostKeyChecking=yes \
        "root@$addr" 'printf "%s %s" "$(hostname -s)" "$(id -un)"' 2>&1) \
    || { info "$node: agent-path ssh FAILED -> $out"; AGENT_SSH_OK="no"; continue; }
  info "$node: agent-path ssh OK -> $out"
done
[ "$AGENT_SSH_OK" = "yes" ] || die "the agent path does not work yet; fix the above before handing over"

say "read-only lab snapshot (nothing is changed)"
sshq swift1 '
  for p in 18080 18082 8080; do
    code=$(curl -s -o /dev/null -m 5 -w "%{http_code}" "http://127.0.0.1:$p/info" 2>/dev/null) || code="unreachable"
    printf "    :%s /info=%s\n" "$p" "$code"
  done
  printf "    disk / free: %s\n" "$(df -h / | awk "NR==2{print \$4}")"
  bin=/root/work/g6-rust-bin/swift-proxy-server
  if [ -f "$bin" ]; then
    printf "    tip bin sha256: %s\n" "$(sha256sum "$bin" | cut -c1-16)"
  else
    printf "    tip bin: not found at %s\n" "$bin"
  fi
' 2>/dev/null || info "snapshot partially unavailable (not fatal)"

# ------------------------------------------------------------ handover blobs

say "handover"
KEY_B64=$(b64 "$KEY_FILE")
KH_B64=$(b64 "$KNOWN_HOSTS")
DRIVE_OK="no"

if sshq swift2 "command -v rclone" >/dev/null 2>&1; then
  token=$(sshq swift2 "rclone cat '$RCLONE_REMOTE:$DROP_FOLDER/HANDSHAKE.txt' 2>/dev/null | sed -n 's/^HANDSHAKE_TOKEN=//p'" || true)
  if [ "$token" = "$HANDSHAKE_TOKEN" ]; then
    info "Drive handshake matched — rclone '$RCLONE_REMOTE:' is the account the agent reads"
    tmp=$(sshq swift2 'd=$(mktemp -d); chmod 700 "$d"; echo "$d"')
    printf '%s' "$KEY_B64" | sshq swift2 "umask 077; cat > $tmp/agent-ssh-key.b64"
    printf '%s' "$KH_B64"  | sshq swift2 "umask 077; cat > $tmp/agent-known-hosts.b64"
    sshq swift2 "rclone copy $tmp/agent-ssh-key.b64 '$RCLONE_REMOTE:$DROP_FOLDER/' && \
                 rclone copy $tmp/agent-known-hosts.b64 '$RCLONE_REMOTE:$DROP_FOLDER/' && \
                 rm -rf $tmp"
    info "uploaded agent-ssh-key.b64 + agent-known-hosts.b64 to Drive/$DROP_FOLDER"
    DRIVE_OK="yes"
  else
    info "Drive handshake token mismatch or unreadable — rclone remote is a different account"
  fi
else
  info "rclone not found on swift2"
fi

if [ "$DRIVE_OK" = "yes" ] && [ "$PRINT_BLOBS" = "no" ]; then
  cat <<EOF

--------------------------------------------------------------------
DONE. Reply to the cloud agent with exactly:

    lab access ready, drive drop $HANDSHAKE_TOKEN

The agent picks the key up from
https://drive.google.com/drive/folders/$DROP_FOLDER_ID
Revoke any time:  bash tools/lab-agent-access-bootstrap.sh --revoke
--------------------------------------------------------------------
EOF
  exit 0
fi

cat <<EOF

--------------------------------------------------------------------
Drive drop unavailable (or --print-blobs given). Paste the two blobs
below to the cloud agent. They are a dedicated lab-only key you can
revoke with:  bash tools/lab-agent-access-bootstrap.sh --revoke

----- BEGIN PEREGRINE_LAB_SSH_KEY_B64 -----
$KEY_B64
----- END PEREGRINE_LAB_SSH_KEY_B64 -----

----- BEGIN PEREGRINE_LAB_KNOWN_HOSTS_B64 -----
$KH_B64
----- END PEREGRINE_LAB_KNOWN_HOSTS_B64 -----
--------------------------------------------------------------------
EOF
