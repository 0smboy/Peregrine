#!/usr/bin/env bash
# Idempotent bootstrap for the Peregrine dev environment.
#
# Peregrine is a set of independent Rust workspaces (swift-rust, swift-deploy-rs,
# cosbench-rs, autocos, swift-console) plus an Astro docs site (docs-site). This
# script installs the system libraries and toolchains they need and warms the
# dependency caches so builds are fast and offline-friendly.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUST_CHANNEL="1.97.0"

echo "==> System packages (build tools + liberasurecode for the EC policy)"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  build-essential pkg-config libssl-dev \
  liberasurecode-dev libjerasure-dev \
  sqlite3 libsqlite3-dev libxml2-dev

echo "==> Rust toolchain ${RUST_CHANNEL} (pinned by the workspaces' rust-toolchain.toml)"
rustup toolchain install "${RUST_CHANNEL}" --profile minimal -c clippy -c rustfmt
rustup default "${RUST_CHANNEL}"
rustc --version

echo "==> Warm Cargo dependency caches for each workspace"
for ws in swift-rust swift-deploy-rs cosbench-rs autocos swift-console; do
  if [ -f "${REPO_ROOT}/${ws}/Cargo.toml" ]; then
    echo "    - ${ws}"
    ( cd "${REPO_ROOT}/${ws}" && cargo fetch --locked )
  fi
done

echo "==> Docs site (Astro / Nimbus) dependencies"
if [ -f "${REPO_ROOT}/docs-site/package-lock.json" ]; then
  ( cd "${REPO_ROOT}/docs-site" && npm ci )
fi

echo "==> Peregrine environment ready."
