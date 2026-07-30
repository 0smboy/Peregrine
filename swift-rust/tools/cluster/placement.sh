#!/bin/bash
# Check that every object sits where its ring says it should.
#
# The predecessor fired one ssh per object per device. A throttled ssh returned
# an empty string, the numeric test read empty as zero, and the object was
# scored MISSING — so it reported a different set of "missing" replicas on
# every run, and printed "RESULT: 0/0" when called with no arguments. Two rules
# follow from that:
#
#  1. ONE inventory per node (four ssh total), joined locally. Nothing scales
#     with the object count.
#  2. A failed inventory ABORTS. An unreachable node is an unknown, never an
#     empty device — scoring a probe failure as missing data is what made the
#     old output worthless.
#
# usage: placement.sh <ring.gz> <container> <manifest> <datadir>
#    eg: placement.sh object-1.ring.gz expand-ec /root/expand/expand-ec-manifest.txt objects-1
set -u
RING=${1:?usage: placement.sh <ring.gz> <container> <manifest> <datadir>}
CONT=${2:?container required}
MAN=${3:?manifest required}
DIR=${4:?datadir required}
[ -r "$MAN" ] || { echo "  ABORT: manifest $MAN unreadable"; exit 2; }

K="-i /etc/swift/replication_key -o BatchMode=yes -o ConnectTimeout=15"
INV=$(mktemp)
trap 'rm -f "$INV"' EXIT

# ---- one listing per node; any failure aborts rather than scoring empty ----
for n in 11 12 13 14; do
  cmd="find /srv/node/d1/$DIR /srv/node/d2/$DIR /srv/node/d3/$DIR -name '*.data' -printf '%h %f\n' 2>/dev/null"
  if [ "$n" = 11 ]; then out=$(eval "$cmd"); st=$?
  else out=$(ssh -n $K root@10.42.10.$n "$cmd"); st=$?; fi
  if [ $st -ne 0 ]; then
    echo "  ABORT: could not inventory swift.$n (ssh exit $st) — refusing to report placement"
    exit 2
  fi
  awk -v node="$n" '{print node, $0}' <<<"$out" >> "$INV"
done

# ---- join against ring placement, one swift-get-nodes per object ----
ok=0; bad=0; stray=0
while read -r -u 3 name _md5 _size; do
  [ -z "$name" ] && continue
  info=$(swift-get-nodes "/etc/swift/$RING" AUTH_test "$CONT" "$name" 2>/dev/null)
  hash=$(awk '/^Hash/{print $2}' <<<"$info")
  [ -z "$hash" ] && { echo "  ABORT: ring lookup failed for $name"; exit 2; }

  # swift-get-nodes lists primaries AND handoffs; the handoff lines carry a
  # "# [Handoff]" marker and must never be counted as a missing primary.
  prim=$(grep 'Server:Port Device' <<<"$info" | grep -v Handoff | awk '{split($3,a,":"); print substr(a[1],index(a[1],".")+0), $4}' | awk '{n=split($1,p,"."); print p[4], $2}')
  hand=$(grep 'Server:Port Device' <<<"$info" | grep    Handoff | awk '{split($3,a,":"); print $3, $4}' | awk '{n=split($1,p,"."); split(p[4],q,":"); print q[1], $2}')

  miss=""; on_hand=""; idxs=""
  while read -r node dev; do
    [ -z "$node" ] && continue
    files=$(awk -v n="$node" -v d="$dev" -v h="$hash" '$1==n && $2 ~ ("/"d"/") && $2 ~ ("/"h"$") {print $3}' "$INV")
    if [ -z "$files" ]; then miss="$miss ${node}/${dev}"
    else idxs="$idxs $(sed -n 's/.*#\([0-9]\+\)#.*/\1/p' <<<"$files" | tr '\n' ' ')"; fi
  done <<<"$prim"
  while read -r node dev; do
    [ -z "$node" ] && continue
    awk -v n="$node" -v d="$dev" -v h="$hash" '$1==n && $2 ~ ("/"d"/") && $2 ~ ("/"h"$")' "$INV" | grep -q . \
      && on_hand="$on_hand ${node}/${dev}"
  done <<<"$hand"

  if [ -n "$miss" ]; then bad=$((bad+1)); echo "  MISSING  $name ->$miss"; else ok=$((ok+1)); fi
  [ -n "$on_hand" ] && { stray=$((stray+1)); echo "  LEFTOVER $name on handoff ->$on_hand"; }
  # EC: distinct indexes matter, since two copies of #0 is one fragment.
  if [ -n "$idxs" ]; then
    d=$(tr ' ' '\n' <<<"$idxs" | grep -c . )
    u=$(tr ' ' '\n' <<<"$idxs" | grep . | sort -u | wc -l)
    [ "$d" != "$u" ] && echo "  DUPLICATE INDEX $name ($d files, $u distinct)"
  fi
done 3< "$MAN"
echo "  RESULT: $ok/$((ok+bad)) objects on every primary; $stray with leftovers on handoffs"
[ "$bad" -gt 0 ] && exit 1 || exit 0
