#!/usr/bin/env bash
# Publish docs-site to Vercel production (docs.myswift.rs).
# Requires: logged-in `vercel` CLI (`vercel whoami`).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v vercel >/dev/null 2>&1; then
  echo "error: vercel CLI not found" >&2
  exit 1
fi

who="$(vercel whoami 2>/dev/null || true)"
if [[ -z "$who" || "$who" == *"Error"* ]]; then
  echo "error: not logged in to Vercel (run: vercel login)" >&2
  exit 1
fi

echo "Deploying docs-site as ${who} → production…"
vercel --prod --yes
echo "Live: https://docs.myswift.rs"
