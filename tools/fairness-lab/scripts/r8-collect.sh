#!/usr/bin/env bash
# Pull R8 artifacts from swift4 into tools/test-results/fairness-lab-R8-20260803/
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
EVID="$ROOT/tools/test-results/fairness-lab-R8-20260803"
REMOTE=/tmp/fairness-R8
mkdir -p "$EVID/runs" "$EVID/soak" "$EVID/logs"
scp -q swift4:"$REMOTE/logs/runner.log" "$EVID/logs/" || true
scp -q swift4:"$REMOTE/logs/nohup.out" "$EVID/logs/" || true
scp -q -r swift4:"$REMOTE/runs/." "$EVID/runs/" || true
scp -q swift4:"$REMOTE/soak/SUMMARY.json" "$EVID/soak/" || true
scp -q swift4:"$REMOTE/soak/summary.tsv" "$EVID/soak/" || true

python3 - <<'PY' "$EVID"
import json, pathlib, sys, datetime
evid = pathlib.Path(sys.argv[1])
direct = evid / "runs/DIRECT-4PROXY_16MB_read_4/SUMMARY.json"
ha = evid / "runs/HA-PATH_16MB_read_4/SUMMARY.json"
soak = evid / "soak/SUMMARY.json"
d = json.loads(direct.read_text()) if direct.exists() else None
h = json.loads(ha.read_text()) if ha.exists() else None
s = json.loads(soak.read_text()) if soak.exists() else None

def cell_line(x, name):
    if not x:
        return f"| {name} | MISSING | — |"
    return f"| {name} | **{x.get('validity')}** | median ops/s={x.get('ops_median')} n={x.get('n')} fail_rate={x.get('fail_rate_median')} |"

gate = "GREEN" if (
    d and d.get("validity") == "ACCEPT" and d.get("reps_met")
    and h and h.get("validity") == "ACCEPT" and h.get("reps_met")
    and s and s.get("validity") == "ACCEPT"
) else "PARTIAL"

md = f"""# R8 Stop — 16MB retune + 6h soak

| | |
|--|--|
| **Status** | **{gate}** |
| **When** | {datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%MZ')} |
| **Params** | object_count=40 runtime=180 (retune from R4 object_count=2000@30s) |

## Stop 验收

| 条 | 结果 |
|----|------|
| DIRECT 16MB_read ≥8 ACCEPT | {d.get('validity') if d else 'MISSING'} (n={d.get('n') if d else 0}) |
| HA 16MB_read ≥8 ACCEPT | {h.get('validity') if h else 'MISSING'} (n={h.get('n') if h else 0}) |
| Soak 6h fails=0 | {s.get('validity') if s else 'MISSING'} (fail_total={s.get('fail_total') if s else '—'}) |

## Cells

{cell_line(d, 'DIRECT-4PROXY 16MB_read_4')}
{cell_line(h, 'HA-PATH 16MB_read_4')}
| Soak DIRECT 4KB_write_128 6h | **{(s or {}).get('validity','MISSING')}** | ok={(s or {}).get('ok_total')} fail={(s or {}).get('fail_total')} chunks={(s or {}).get('chunks')} |

## Still backlog (not this gate)

- L3b sharding · Paste pipeline · memcache · servers_per_port · Python formal cluster · dedicated hub HW
"""
(evid / "R8-GATE.md").write_text(md)
score = {
    "round": "R8",
    "gate": gate,
    "direct_16mb": d,
    "ha_16mb": h,
    "soak_6h": s,
}
# strip heavy runs arrays for top-level
for key in ("direct_16mb", "ha_16mb"):
    if score[key] and "runs" in score[key]:
        score[key] = {k: v for k, v in score[key].items() if k != "runs"}
(evid / "SCORECARD.json").write_text(json.dumps(score, indent=2) + "\n")
print("gate", gate)
print(md)
PY

# HTML report
python3 - <<'PY' "$EVID"
import json, pathlib, sys
evid = pathlib.Path(sys.argv[1])
sc = json.loads((evid/"SCORECARD.json").read_text()) if (evid/"SCORECARD.json").exists() else {}
d, h, s = sc.get("direct_16mb") or {}, sc.get("ha_16mb") or {}, sc.get("soak_6h") or {}
def cls(v):
    return "ok" if v == "ACCEPT" else ("warn" if v else "warn")
html = f"""<!doctype html><html lang="zh-CN"><meta charset="utf-8"><title>Fairness Lab R8</title>
<style>
:root{{--bg:#14120f;--ink:#f2ebe1;--muted:#a89a88;--ok:#7dba6e;--warn:#d4a24c;--line:#2c2822}}
body{{margin:0;font:15px/1.45 ui-sans-serif,system-ui;background:var(--bg);color:var(--ink)}}
main{{max-width:920px;margin:0 auto;padding:28px 22px 72px}}
h1{{font-size:28px;margin:0 0 6px}}.sub{{color:var(--muted)}}
.ok{{color:var(--ok);font-weight:650}}.warn{{color:var(--warn);font-weight:650}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
td,th{{padding:8px 6px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}}
th{{color:var(--muted)}}
</style>
<main>
<h1>Fairness Lab · R8</h1>
<p class="sub">16MB_read retune + 6h soak · gate=<strong class="{cls(sc.get('gate'))}">{sc.get('gate')}</strong></p>
<table>
<tr><th>Cell</th><th>validity</th><th>median ops/s</th><th>n</th></tr>
<tr><td>DIRECT 16MB_read_4</td><td class="{cls(d.get('validity'))}">{d.get('validity')}</td><td>{d.get('ops_median')}</td><td>{d.get('n')}</td></tr>
<tr><td>HA 16MB_read_4</td><td class="{cls(h.get('validity'))}">{h.get('validity')}</td><td>{h.get('ops_median')}</td><td>{h.get('n')}</td></tr>
<tr><td>Soak 6h 4KB_write_128</td><td class="{cls(s.get('validity'))}">{s.get('validity')}</td><td>ok={s.get('ok_total')} fail={s.get('fail_total')}</td><td>chunks={s.get('chunks')}</td></tr>
</table>
<p class="sub">Params: object_count=40 runtime=180 · Evidence <code>fairness-lab-R8-20260803/</code></p>
</main></html>"""
(evid/"REPORT.html").write_text(html)
print("wrote REPORT.html")
PY
