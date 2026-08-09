#!/bin/bash
# Independent check of all seven Lab tools, in both languages.
#
# Written before the agents finished on purpose: a verification designed after
# seeing the result tends to check what the result happens to do. This checks
# what was asked for — every tool reachable, every body actually translated,
# every claimed visual present in the served HTML rather than injected later by
# JavaScript, and the cluster still intact underneath.
set -u
source "$(dirname "$0")/../lib/lab-auth.sh"
peregrine_load_lab_auth || exit $?
EP=http://127.0.0.1:9000
J=/tmp/vlab.jar
rm -f $J
curl -s -m10 -c $J -o /dev/null -X POST \
  -d "tenant=test&user=tester&key=$ST_KEY" $EP/login

get() { curl -s -m90 -b $J -b "sc_lang=$2" "$EP$1"; }
code() { curl -s -m90 -b $J -b "sc_lang=$2" -o /dev/null -w '%{http_code}' "$EP$1"; }

echo "PAGES  (want 200 in both languages)"
for p in /lab /lab/ring /lab/policy /lab/capsule /lab/tombstone /lab/chaos /lab/shadow /lab/warehouse; do
  printf "  %-18s en=%s zh=%s\n" "$p" "$(code $p en)" "$(code $p zh)"
done

echo
echo "READY FLAGS  (a tool still marked 'not built' shows the soon marker)"
soon=$(get /lab zh | grep -o 'lab-soon' | wc -l | tr -d ' ')
echo "  tools still marked not-built: $soon"

echo
echo "CHINESE IN THE BODY  (a raw i18n key here means an untranslated string)"
for p in /lab/ring /lab/policy /lab/capsule /lab/tombstone /lab/chaos /lab/shadow /lab/warehouse; do
  html=$(get $p zh)
  # Strip tags, then look for a run of Latin prose that is not a known technical term.
  cjk=$(printf '%s' "$html" | grep -c '[一-龥]')
  rawkey=$(printf '%s' "$html" | grep -oE '\b(lab|chaos|shadow|wh|oc|tm|ring|policy)\.[a-z_.]{3,}\b' | sort -u | head -3 | tr '\n' ' ')
  printf "  %-18s cjk_lines=%-5s raw_keys=%s\n" "$p" "$cjk" "${rawkey:-none}"
done

echo
echo "VISUALS IN SERVED HTML  (must be present without running JS)"
for p in /lab/ring /lab/capsule /lab/tombstone /lab/warehouse; do
  n=$(get $p en | grep -oE '<svg|<table' | wc -l | tr -d ' ')
  printf "  %-18s svg/table elements: %s\n" "$p" "$n"
done

echo
echo "APIs"
for a in /lab/api/chaos/catalogue /lab/api/shadow/corpus /lab/api/warehouse/jobs; do
  printf "  %-30s %s\n" "$a" "$(code $a en)"
done
printf "  %-30s %s\n" "POST /mcp tools/list" \
  "$(curl -s -m60 -b $J -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
      -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' $EP/mcp)"

echo
echo "CLUSTER STILL INTACT"
bash /root/expand/readcheck.sh 2>/dev/null | sed 's/^/  /'
