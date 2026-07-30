#!/usr/bin/env bash
# Run the aipostex-lab scorer against local JSON outputs (after copying from the attack box).
# Usage:
#   ./scripts/lab-score-results.sh /path/to/aipostex-lab /path/to/json-dir --strict --verbose
# All arguments after the lab repo path are forwarded to score.py (see lab-scripts/scoring/score.py).
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo "usage: $0 <aipostex-lab-repo-path> <json-file-or-dir> [score.py args...]" >&2
  exit 2
fi
LAB="${1:?}"
shift
SCORE_PY="$LAB/lab-scripts/scoring/score.py"
if [[ ! -f "$SCORE_PY" ]]; then
  echo "[!] missing $SCORE_PY — pass path to aipostex-lab checkout" >&2
  exit 1
fi
exec python3 "$SCORE_PY" "$@"
