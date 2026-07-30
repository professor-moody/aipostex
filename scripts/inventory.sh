#!/usr/bin/env bash
# Canonical capability inventory for aipostex. Run this to reconcile the public
# numbers (README badges, docs/, conference copy) with the code, so they cannot
# silently drift. The template count is additionally asserted by the Go test
# pkg/vulncheck/template_test.go; the lab's 170 planted findings are asserted by
# aipostex-lab tests/test_scoring.py.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

templates=$(find "${ROOT}/pkg/vulncheck/templates" -name '*.yaml' | wc -l | tr -d ' ')
exploit_engines=$(find "${ROOT}/pkg/exploit" -mindepth 1 -maxdepth 1 -type d ! -name common | wc -l | tr -d ' ')
cli_modules=$(grep -rlE 'PersistentFlags\(\).*"target"' "${ROOT}"/cmd/aipostex/*.go | grep -cvE '_test|cli_flags')
families=$(grep -oE 'Name:[[:space:]]*"[a-z0-9-]+"' "${ROOT}/pkg/fingerprint/fingerprint.go" | wc -l | tr -d ' ')

echo "aipostex capability inventory"
echo "  vulncheck templates    : ${templates}   (currently 131; counted live from pkg/vulncheck/templates)"
echo "  exploit engines (pkg)  : ${exploit_engines}"
echo "  exploit modules (CLI)  : ${cli_modules}   (engines + litellm, which reuses the openaicompat engine)"
echo "  fingerprint families   : ${families}"
echo
echo "Public copy should state: templates=${templates}, exploit modules=${cli_modules}, ${families}+ service families."
echo "Companion lab: 170 planted findings (aipostex-lab/lab-scripts/scoring/manifest.json)."
