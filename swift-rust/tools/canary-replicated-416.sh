#!/usr/bin/env bash
set -Eeuo pipefail
set +x
umask 077

usage() {
    printf 'usage: %s RUST_ENDPOINT CREDENTIAL_ENV TARGET_BACKEND_IP\n' "$0" >&2
    printf 'example: %s http://10.0.0.3:8080 /etc/swift/peregrine-lab.env 10.0.4.3\n' "$0" >&2
}

fail() {
    printf 'FAIL %s\n' "$*" >&2
    exit 1
}

if [[ $# != 3 ]]; then
    usage
    exit 64
fi

for dependency in awk bash cmp curl date mktemp python3 rm sha256sum tr wc; do
    command -v "$dependency" >/dev/null 2>&1 || fail "missing dependency: $dependency"
done

curl_bin=${CANARY_CURL_BIN:-$(command -v curl)}
get_nodes_bin=${CANARY_GET_NODES_BIN:-$(command -v swift-get-nodes || true)}
swift_conf=${CANARY_SWIFT_CONF:-/etc/swift/swift.conf}
object_ring=${CANARY_OBJECT_RING:-/etc/swift/object.ring.gz}
max_placement_attempts=${CANARY_MAX_PLACEMENT_ATTEMPTS:-512}
credential_env=$2

[[ -x $curl_bin ]] || fail "curl binary is not executable"
[[ -n $get_nodes_bin && -x $get_nodes_bin ]] || fail "swift-get-nodes is not installed or executable"
[[ -r $credential_env && -f $credential_env ]] || fail "credential env is not a readable regular file"
[[ -r $swift_conf && -f $swift_conf ]] || fail "swift.conf is not a readable regular file"
[[ -r $object_ring && -f $object_ring ]] || fail "object.ring.gz is not a readable regular file"
[[ $max_placement_attempts =~ ^[0-9]+$ ]] || fail "CANARY_MAX_PLACEMENT_ATTEMPTS must be an integer"
(( max_placement_attempts >= 1 && max_placement_attempts <= 100000 )) || \
    fail "CANARY_MAX_PLACEMENT_ATTEMPTS must be between 1 and 100000"

endpoint=$(python3 - "$1" <<'PY'
import sys
from urllib.parse import urlsplit

raw = sys.argv[1]
try:
    parsed = urlsplit(raw)
    port = parsed.port
except ValueError as exc:
    raise SystemExit("invalid RUST_ENDPOINT: {}".format(exc))
if (
    parsed.scheme not in {"http", "https"}
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
    or parsed.path not in {"", "/"}
):
    raise SystemExit("RUST_ENDPOINT must be an http(s) origin with no credentials, query, or path")
host = parsed.hostname
if ":" in host:
    host = "[{}]".format(host)
authority = host if port is None else "{}:{}".format(host, port)
print("{}://{}".format(parsed.scheme.lower(), authority))
PY
) || fail "invalid RUST_ENDPOINT"

target_backend_ip=$(python3 - "$3" <<'PY'
import ipaddress
import sys

try:
    print(ipaddress.ip_address(sys.argv[1]))
except ValueError as exc:
    raise SystemExit("invalid TARGET_BACKEND_IP: {}".format(exc))
PY
) || fail "invalid TARGET_BACKEND_IP"

policy0_name=$(python3 - "$swift_conf" <<'PY'
import configparser
import re
import sys

parser = configparser.RawConfigParser(interpolation=None, strict=False)
try:
    with open(sys.argv[1], "r", encoding="utf-8") as stream:
        parser.read_file(stream)
except (OSError, configparser.Error, UnicodeError) as exc:
    raise SystemExit("cannot parse swift.conf: {}".format(exc))

policies = {}
for section in parser.sections():
    match = re.fullmatch(r"storage-policy:([0-9]+)", section.strip(), re.IGNORECASE)
    if match:
        policies[int(match.group(1))] = section

if not policies:
    print("Policy-0")
    raise SystemExit(0)
if 0 not in policies:
    raise SystemExit("swift.conf defines policies but has no storage-policy:0")

truthy = {"1", "true", "yes", "on"}
defaults = [
    index
    for index, section in policies.items()
    if parser.get(section, "default", fallback="").strip().lower() in truthy
]
if len(defaults) > 1:
    raise SystemExit("swift.conf has more than one default storage policy")
if not defaults:
    if len(policies) != 1:
        raise SystemExit("swift.conf has multiple policies but no explicit default")
    default_index = next(iter(policies))
else:
    default_index = defaults[0]
if default_index != 0:
    raise SystemExit("the default storage policy is not policy 0")

section = policies[0]
policy_type = parser.get(section, "policy_type", fallback="replication").strip().lower()
if policy_type != "replication":
    raise SystemExit("storage-policy:0 is not replication")
if parser.get(section, "deprecated", fallback="").strip().lower() in truthy:
    raise SystemExit("storage-policy:0 is deprecated")
name = parser.get(section, "name", fallback="Policy-0").strip()
if not name or "\r" in name or "\n" in name:
    raise SystemExit("storage-policy:0 has an invalid name")
print(name)
PY
) || fail "policy 0 is not the active default replication policy"

tmp=$(mktemp -d "${TMPDIR:-/tmp}/peregrine-r416.XXXXXX")
auth_request_headers=$tmp/auth.request.headers
auth_response_headers=$tmp/auth.response.headers
token_request_headers=$tmp/token.request.headers
cleanup_authorized=0
cleanup_verified=0
token_ready=0
account_path=
container=
object=

curl_common=(
    --silent
    --show-error
    --noproxy '*'
    --connect-timeout 5
    --max-time 30
    --proto '=http,https'
)

proxy_request() {
    local method=$1
    local url=$2
    local response_headers=$3
    local response_body=$4
    shift 4
    local args=(
        "${curl_common[@]}"
        --dump-header "$response_headers"
        --output "$response_body"
        --write-out '%{http_code}'
        --header "@$token_request_headers"
    )
    if [[ $method == HEAD ]]; then
        args+=(--head)
    else
        args+=(--request "$method")
    fi
    "$curl_bin" "${args[@]}" "$@" "$url"
}

backend_request() {
    local method=$1
    local url=$2
    local response_headers=$3
    local response_body=$4
    shift 4
    local args=(
        "${curl_common[@]}"
        --dump-header "$response_headers"
        --output "$response_body"
        --write-out '%{http_code}'
        --header 'X-Backend-Storage-Policy-Index: 0'
    )
    if [[ $method == HEAD ]]; then
        args+=(--head)
    else
        args+=(--request "$method")
    fi
    "$curl_bin" "${args[@]}" "$@" "$url"
}

read_single_header() {
    local response_headers=$1
    local wanted=$2
    python3 - "$response_headers" "$wanted" <<'PY'
import sys

path, wanted = sys.argv[1], sys.argv[2].lower()
blocks = []
current = None
with open(path, "rb") as stream:
    for raw in stream.read().splitlines():
        line = raw.decode("iso-8859-1").rstrip("\r")
        if line.upper().startswith("HTTP/"):
            if current is not None:
                blocks.append(current)
            current = {}
            continue
        if current is None or not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        current.setdefault(name.strip().lower(), []).append(value.strip())
if current is not None:
    blocks.append(current)
if not blocks:
    raise SystemExit("response contained no HTTP header block")
values = blocks[-1].get(wanted, [])
if len(values) != 1 or not values[0]:
    raise SystemExit("expected exactly one non-empty {} header; got {}".format(wanted, len(values)))
print(values[0])
PY
}

expect_single_header() {
    local label=$1
    local response_headers=$2
    local wanted=$3
    local expected=$4
    python3 - "$label" "$response_headers" "$wanted" "$expected" <<'PY'
import sys

label, path, wanted, expected = sys.argv[1:]
wanted = wanted.lower()
blocks = []
current = None
with open(path, "rb") as stream:
    for raw in stream.read().splitlines():
        line = raw.decode("iso-8859-1").rstrip("\r")
        if line.upper().startswith("HTTP/"):
            if current is not None:
                blocks.append(current)
            current = {}
            continue
        if current is None or not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        current.setdefault(name.strip().lower(), []).append(value.strip())
if current is not None:
    blocks.append(current)
if not blocks:
    raise SystemExit("FAIL {} response contained no HTTP header block".format(label))
actual = blocks[-1].get(wanted, [])
if actual != [expected]:
    raise SystemExit(
        "FAIL {} header {} expected={!r} actual={!r}".format(label, wanted, expected, actual)
    )
PY
}

expect_code() {
    local label=$1
    local expected_regex=$2
    local actual=$3
    if [[ ! $actual =~ ^($expected_regex)$ ]]; then
        fail "$label status expected=$expected_regex actual=$actual"
    fi
    printf 'PASS %-28s status=%s\n' "$label" "$actual"
}

validate_416() {
    local label=$1
    local response_headers=$2
    local response_body=$3
    local response_code=$4
    local expected_body=$5
    local object_size=$6

    expect_code "$label" 416 "$response_code"
    expect_single_header "$label" "$response_headers" Content-Type application/octet-stream
    expect_single_header "$label" "$response_headers" Content-Range "bytes */$object_size"
    expect_single_header "$label" "$response_headers" Content-Length 97
    expect_single_header "$label" "$response_headers" Accept-Ranges bytes
    if ! cmp -s "$expected_body" "$response_body"; then
        printf 'FAIL %s body expected_bytes=%s actual_bytes=%s expected_sha256=%s actual_sha256=%s\n' \
            "$label" \
            "$(wc -c < "$expected_body" | tr -d ' ')" \
            "$(wc -c < "$response_body" | tr -d ' ')" \
            "$(sha256sum "$expected_body" | awk '{print $1}')" \
            "$(sha256sum "$response_body" | awk '{print $1}')" >&2
        exit 1
    fi
    printf 'PASS %-28s headers-and-body=exact\n' "$label"
}

cleanup_on_exit() {
    local rc=$?
    trap - EXIT
    set +e
    set +x
    if (( cleanup_authorized == 1 && cleanup_verified == 0 && token_ready == 1 )) \
        && [[ -n $account_path && -n $container && -n $object ]]; then
        proxy_request DELETE "$endpoint$account_path/$container/$object" \
            "$tmp/cleanup-object.headers" "$tmp/cleanup-object.body" >/dev/null 2>&1
        proxy_request DELETE "$endpoint$account_path/$container" \
            "$tmp/cleanup-container.headers" "$tmp/cleanup-container.body" >/dev/null 2>&1
        printf 'WARN exact canary namespace cleanup was attempted but not verified\n' >&2
    fi
    rm -rf -- "$tmp"
    exit "$rc"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Read the root-owned credential file as data, not shell code. The lab's
# rotation helper emits exactly these two literal KEY=VALUE lines. Keeping the
# values in a mode-0600 curl header file avoids putting either secret in curl's
# argv or in this script's stdout/stderr.
if ! python3 - "$credential_env" "$auth_request_headers" <<'PY'
import os
import re
import sys

source, destination = sys.argv[1:]
allowed_value = re.compile(r"[A-Za-z0-9._:+/@%=-]+")
values = {}
try:
    with open(source, "r", encoding="utf-8") as stream:
        for line_number, raw in enumerate(stream, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                raise ValueError("line {} is not KEY=VALUE".format(line_number))
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if key not in {"ST_USER", "ST_KEY"}:
                raise ValueError("line {} has unsupported key".format(line_number))
            if key in values:
                raise ValueError("line {} duplicates {}".format(line_number, key))
            if not allowed_value.fullmatch(value):
                raise ValueError("line {} has an empty or unsafe literal value".format(line_number))
            values[key] = value
    if set(values) != {"ST_USER", "ST_KEY"}:
        raise ValueError("credential file must define ST_USER and ST_KEY exactly once")
    with open(destination, "w", encoding="ascii", newline="\n") as stream:
        stream.write("X-Auth-User: {}\nX-Auth-Key: {}\n".format(values["ST_USER"], values["ST_KEY"]))
    os.chmod(destination, 0o600)
except (OSError, UnicodeError, ValueError) as exc:
    raise SystemExit("invalid credential env: {}".format(exc))
PY
then
    fail "could not load literal TempAuth credentials"
fi

if ! auth_code=$("$curl_bin" "${curl_common[@]}" \
    --dump-header "$auth_response_headers" --output /dev/null --write-out '%{http_code}' \
    --header "@$auth_request_headers" "$endpoint/auth/v1.0"); then
    fail "TempAuth request failed"
fi
expect_code tempauth 200 "$auth_code"
token=$(read_single_header "$auth_response_headers" X-Auth-Token) || \
    fail "TempAuth response has no unique token"
storage_url=$(read_single_header "$auth_response_headers" X-Storage-Url) || \
    fail "TempAuth response has no unique storage URL"
[[ $token != *$'\n'* && $token != *$'\r'* ]] || fail "TempAuth token contains a line break"
printf 'X-Auth-Token: %s\n' "$token" > "$token_request_headers"
token_ready=1
unset token

account_fields=$(python3 - "$storage_url" <<'PY'
import re
import sys
from urllib.parse import unquote, urlsplit

try:
    parsed = urlsplit(sys.argv[1])
    _ = parsed.port
except ValueError as exc:
    raise SystemExit("invalid X-Storage-Url: {}".format(exc))
if (
    parsed.scheme not in {"http", "https"}
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
):
    raise SystemExit("invalid X-Storage-Url origin")
match = re.fullmatch(r"/v1/([A-Za-z0-9._-]+?)/?", parsed.path)
if not match:
    raise SystemExit("X-Storage-Url path must be exactly /v1/<safe-account>")
account = unquote(match.group(1))
if account != match.group(1):
    raise SystemExit("percent-encoded account names are not supported by this canary")
print("/v1/{}\t{}".format(account, account))
PY
) || fail "invalid account path in X-Storage-Url"
unset storage_url
IFS=$'\t' read -r account_path account <<< "$account_fields"
[[ -n $account_path && -n $account ]] || fail "could not derive account from X-Storage-Url"
unset account_fields

nonce=$(printf '%s-%s-%04x%04x' "$(date -u +%Y%m%dT%H%M%S)" "$$" "$RANDOM" "$RANDOM")
container=codex-canary-r416-$nonce
object=
placement_fields=

for (( attempt=1; attempt<=max_placement_attempts; attempt++ )); do
    candidate=r416-$nonce-$attempt
    placement_json=$tmp/placement-$attempt.json
    if ! SWIFT_CONF="$swift_conf" "$get_nodes_bin" --json "$object_ring" \
        "$account" "$container" "$candidate" > "$placement_json"; then
        fail "swift-get-nodes failed on placement attempt $attempt"
    fi
    if placement_fields=$(python3 - "$placement_json" "$target_backend_ip" \
        "$account" "$container" "$candidate" <<'PY'
import ipaddress
import json
import re
import sys

path, target, account, container, obj = sys.argv[1:]
try:
    with open(path, "r", encoding="utf-8") as stream:
        report = json.load(stream)
except (OSError, UnicodeError, json.JSONDecodeError) as exc:
    raise SystemExit("invalid swift-get-nodes JSON: {}".format(exc))
if not isinstance(report, dict):
    raise SystemExit("swift-get-nodes JSON root is not an object")
if report.get("account") != account or report.get("container") != container or report.get("object") != obj:
    raise SystemExit("swift-get-nodes echoed a different object path")
partition = report.get("partition")
object_hash = report.get("hash")
nodes = report.get("nodes")
if not isinstance(partition, int) or partition < 0:
    raise SystemExit("swift-get-nodes returned an invalid partition")
if not isinstance(object_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", object_hash):
    raise SystemExit("swift-get-nodes returned an invalid object hash")
if not isinstance(nodes, list):
    raise SystemExit("swift-get-nodes returned no node list")
primaries = [node for node in nodes if isinstance(node, dict) and node.get("handoff") is False]
if not primaries:
    raise SystemExit("swift-get-nodes returned no primary nodes")
if any(not isinstance(node.get("index"), int) or node["index"] < 0 for node in primaries):
    raise SystemExit("swift-get-nodes returned an invalid primary index")
if len({node["index"] for node in primaries}) != len(primaries):
    raise SystemExit("swift-get-nodes returned duplicate primary indexes")
first = min(primaries, key=lambda node: node["index"])
if first["index"] != 0:
    raise SystemExit("swift-get-nodes primary indexes do not start at zero")
try:
    first_ip = str(ipaddress.ip_address(first.get("ip", "")))
except ValueError as exc:
    raise SystemExit("swift-get-nodes returned an invalid primary IP: {}".format(exc))
if first_ip != target:
    raise SystemExit(3)
port = first.get("port")
device = first.get("device")
if not isinstance(port, int) or not 1 <= port <= 65535:
    raise SystemExit("swift-get-nodes returned an invalid primary port")
if not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", device):
    raise SystemExit("swift-get-nodes returned an unsafe device name")
print("{}\t{}\t{}\t{}".format(partition, port, device, object_hash.lower()))
PY
    ); then
        object=$candidate
        break
    else
        placement_rc=$?
        if (( placement_rc != 3 )); then
            fail "could not validate swift-get-nodes output on placement attempt $attempt"
        fi
    fi
done

[[ -n $object && -n $placement_fields ]] || \
    fail "no object placed target backend first after $max_placement_attempts attempts"
IFS=$'\t' read -r partition backend_port device object_hash <<< "$placement_fields"
[[ -n $partition && -n $backend_port && -n $device && -n $object_hash ]] || \
    fail "selected placement is incomplete"

printf 'PASS %-28s target=%s port=%s device=%s partition=%s attempts=%s\n' \
    placement "$target_backend_ip" "$backend_port" "$device" "$partition" "$attempt"

preflight_headers=$tmp/preflight.headers
preflight_body=$tmp/preflight.body
if ! code=$(proxy_request HEAD "$endpoint$account_path/$container" \
    "$preflight_headers" "$preflight_body"); then
    fail "namespace preflight request failed"
fi
expect_code namespace-preflight 404 "$code"
# From this point onward the exact random namespace was proven absent first,
# so the EXIT trap is authorised to delete only this canary object/container.
cleanup_authorized=1

if ! code=$(proxy_request PUT "$endpoint$account_path/$container" \
    "$tmp/container-put.headers" "$tmp/container-put.body" --header 'Expect:'); then
    fail "replicated container PUT failed"
fi
expect_code replicated-container-put '201|202' "$code"

if ! code=$(proxy_request HEAD "$endpoint$account_path/$container" \
    "$tmp/container-head.headers" "$tmp/container-head.body"); then
    fail "replicated container HEAD failed"
fi
expect_code replicated-container-head 204 "$code"
expect_single_header replicated-container-head "$tmp/container-head.headers" \
    X-Storage-Policy "$policy0_name"
printf 'PASS %-28s policy=%s index=0 type=replication\n' replicated-policy "$policy0_name"

object_body=$tmp/object.put
printf '%s' '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > "$object_body"
object_size=$(wc -c < "$object_body" | tr -d ' ')
[[ $object_size == 64 ]] || fail "internal object fixture is not 64 bytes"

if ! code=$(proxy_request PUT "$endpoint$account_path/$container/$object" \
    "$tmp/object-put.headers" "$tmp/object-put.body" \
    --header 'Expect:' --header 'Content-Type: application/octet-stream' \
    --data-binary "@$object_body"); then
    fail "replicated object PUT failed"
fi
expect_code replicated-object-put 201 "$code"

if ! code=$(proxy_request HEAD "$endpoint$account_path/$container/$object" \
    "$tmp/object-head.headers" "$tmp/object-head.body"); then
    fail "replicated object HEAD failed"
fi
expect_code replicated-object-head 200 "$code"
expect_single_header replicated-object-head "$tmp/object-head.headers" \
    Content-Type application/octet-stream
expect_single_header replicated-object-head "$tmp/object-head.headers" Content-Length "$object_size"

expected_416_body=$tmp/expected-416.body
printf '%s' '<html><h1>Requested Range Not Satisfiable</h1><p>The Range requested is not available.</p></html>' \
    > "$expected_416_body"
[[ $(wc -c < "$expected_416_body" | tr -d ' ') == 97 ]] || \
    fail "internal 416 fixture is not 97 bytes"

backend_host=$target_backend_ip
if [[ $backend_host == *:* ]]; then
    backend_host=[$backend_host]
fi
backend_url=http://$backend_host:$backend_port/$device/$partition/$account/$container/$object
if ! backend_code=$(backend_request GET "$backend_url" \
    "$tmp/backend-416.headers" "$tmp/backend-416.body" \
    --header 'Range: bytes=999-1000'); then
    fail "target backend 416 request failed"
fi
validate_416 target-backend-416 "$tmp/backend-416.headers" "$tmp/backend-416.body" \
    "$backend_code" "$expected_416_body" "$object_size"

if ! proxy_code=$(proxy_request GET "$endpoint$account_path/$container/$object" \
    "$tmp/proxy-416.headers" "$tmp/proxy-416.body" \
    --header 'Range: bytes=999-1000'); then
    fail "Rust proxy 416 request failed"
fi
validate_416 rust-proxy-416 "$tmp/proxy-416.headers" "$tmp/proxy-416.body" \
    "$proxy_code" "$expected_416_body" "$object_size"

if ! code=$(proxy_request DELETE "$endpoint$account_path/$container/$object" \
    "$tmp/object-delete.headers" "$tmp/object-delete.body"); then
    fail "object cleanup DELETE failed"
fi
expect_code cleanup-object-delete 204 "$code"
if ! code=$(proxy_request HEAD "$endpoint$account_path/$container/$object" \
    "$tmp/object-final-head.headers" "$tmp/object-final-head.body"); then
    fail "object cleanup proof HEAD failed"
fi
expect_code cleanup-object-final-head 404 "$code"

if ! code=$(proxy_request DELETE "$endpoint$account_path/$container" \
    "$tmp/container-delete.headers" "$tmp/container-delete.body"); then
    fail "container cleanup DELETE failed"
fi
expect_code cleanup-container-delete 204 "$code"
if ! code=$(proxy_request HEAD "$endpoint$account_path/$container" \
    "$tmp/container-final-head.headers" "$tmp/container-final-head.body"); then
    fail "container cleanup proof HEAD failed"
fi
expect_code cleanup-container-final-head 404 "$code"
cleanup_verified=1
cleanup_authorized=0

printf 'OBJECT_SHA256=%s\n' "$(sha256sum "$object_body" | awk '{print $1}')"
printf 'EXPECTED_416_SHA256=%s\n' "$(sha256sum "$expected_416_body" | awk '{print $1}')"
printf 'PLACEMENT_HASH=%s\n' "$object_hash"
printf 'CLEANUP=PASS object_head=404 container_head=404\n'
printf 'CANARY_REPLICATED_416=PASS\n'
