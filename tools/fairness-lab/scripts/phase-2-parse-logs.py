#!/usr/bin/env python3
"""Re-parse autocos logs (ANSI-safe) into matrix.tsv."""
import re
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
STAGE = re.compile(
    r"stage finished.*?stage\s*=\s*(\w+).*?ok\s*=\s*(\d+).*?fail\s*=\s*(\d+).*?success\s*=\s*\"?([0-9.]+%?)\"?",
    re.I,
)


def parse_log(path: Path):
    text = ANSI.sub("", path.read_text(errors="replace"))
    normal = None
    last = None
    for m in STAGE.finditer(text):
        last = m
        if m.group(1).lower() == "normal":
            normal = m
    m = normal or last
    if not m:
        return None
    return {
        "stage": m.group(1),
        "ok": int(m.group(2)),
        "fail": int(m.group(3)),
        "success": m.group(4),
    }


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/phase2-20260804")
    out = root / "perf" / "matrix.tsv"
    rows = ["entry\ttask\truntime\tobject_count\trc\tok\tfail\tops_per_s\tsuccess"]
    # runtime/oc from filename alone unknown — keep from old tsv if present
    meta = {}
    old = root / "perf" / "matrix.tsv"
    if old.exists():
        for line in old.read_text().splitlines()[1:]:
            p = line.split("\t")
            if len(p) >= 4:
                meta[(p[0], p[1])] = (p[2], p[3], p[4] if len(p) > 4 else "0")
    for entry in ("vip", "direct"):
        d = root / "perf" / entry
        if not d.is_dir():
            continue
        for log in sorted(d.glob("*.log")):
            task = log.stem
            p = parse_log(log)
            rt, oc, rc = meta.get((entry, task), ("?", "?", "0"))
            if not p:
                rows.append(f"{entry}\t{task}\t{rt}\t{oc}\t{rc}\t0\t1\tn/a\tPARSE_FAIL")
                continue
            ops = "n/a"
            try:
                if int(rt) > 0 and p["ok"] > 0:
                    ops = f"{p['ok']/int(rt):.2f}"
            except Exception:
                pass
            rows.append(
                f"{entry}\t{task}\t{rt}\t{oc}\t{rc}\t{p['ok']}\t{p['fail']}\t{ops}\t{p['success']}"
            )
    out.write_text("\n".join(rows) + "\n")
    print(out)
    print("\n".join(rows))


if __name__ == "__main__":
    main()
