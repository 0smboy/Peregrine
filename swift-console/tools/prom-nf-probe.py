#!/usr/bin/env python3
"""Probe whether the console's {nf} PromQL filter matches live series."""
import json
import time
import urllib.parse
import urllib.request

END = int(time.time())
START = END - 3600
NF = ',instance=~"^(swift1|10\\.42\\.10\\.11|10\\.42\\.20\\.11|10\\.42\\.30\\.11)(:[0-9]+)?$"'
QUERIES = [
    ("cpu_nf", f'1 - avg by (instance) (rate(node_cpu_seconds_total{{job="node"{NF}}}[1m]))'),
    ("cpu_all", '1 - avg by (instance) (rate(node_cpu_seconds_total{job="node"}[1m]))'),
    ("mem_nf", f'1 - (node_memory_MemAvailable_bytes{{job="node"{NF}}} / node_memory_MemTotal_bytes{{job="node"{NF}}})'),
    ("net_nf", f'sum(rate(node_network_receive_bytes_total{{job="node",plane="storage"{NF}}}[1m]))'),
    ("net_all", 'sum(rate(node_network_receive_bytes_total{job="node",plane="storage"}[1m]))'),
    ("up_nf", f'up{{job="node"{NF}}}'),
]


def qrange(query: str):
    url = "http://127.0.0.1:9090/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": query, "start": START, "end": END, "step": 60}
    )
    with urllib.request.urlopen(url, timeout=10) as r:
        return json.load(r)


for name, query in QUERIES:
    d = qrange(query)
    results = d.get("data", {}).get("result", [])
    print(
        f"{name}: status={d.get('status')} n={len(results)} "
        f"err={d.get('error')} metrics={[x.get('metric') for x in results[:4]]}"
    )
