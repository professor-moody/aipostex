#!/usr/bin/env bash
# Build a Linux amd64 aipostex binary for copying to the lab attack box.
# Usage: from repo root: ./scripts/lab-build-linux.sh [output-path]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/aipostex-linux-amd64}"
(cd "$ROOT" && GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$OUT" ./cmd/aipostex)
echo "Built: $OUT"
echo "Copy: scp \"$OUT\" \${LAB_HOST:-labadmin@<attack-ip>}:~/aipostex"
echo "Then: ssh \"\${LAB_HOST}\" chmod +x ~/aipostex"
