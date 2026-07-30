#!/usr/bin/env bash
# Run verify-aipostex.sh layers on the attack box (SSH key auth required).
# Usage:
#   export LAB_HOST=labadmin@<attack-box-host>
#   ./scripts/lab-remote-verify.sh [operator|contract|active|all]
set -euo pipefail
LAYER="${1:-operator}"
HOST="${LAB_HOST:?set LAB_HOST e.g. labadmin@<attack-box-host>}"
ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$HOST" bash -s -- "$LAYER" <<'REMOTE'
set -euo pipefail
LAYER="${1:-operator}"
for d in "$HOME/lab/lab-scripts/attack-box" "$HOME/lab/attack-box" "$HOME/lab-scripts/attack-box"; do
  if [[ -f "$d/verify-aipostex.sh" ]]; then
    cd "$d"
    exec bash verify-aipostex.sh --layer "$LAYER"
  fi
done
echo "[!] verify-aipostex.sh not found under ~/lab or ~/lab-scripts" >&2
exit 1
REMOTE
