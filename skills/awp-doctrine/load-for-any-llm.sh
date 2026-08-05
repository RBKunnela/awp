#!/usr/bin/env bash
# Host-agnostic: print skill context for injection into any LLM prompt.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
TOPIC="${1:-}"
echo "=== AWP DOCTRINE SKILL (any LLM) ==="
echo "Path: $ROOT"
echo
sed -n '1,120p' "$ROOT/SKILL.md"
if [ -n "$TOPIC" ]; then
  echo
  echo "=== TOPIC HIT: $TOPIC ==="
  # simple grep across skill
  rg -n -i -C 2 "$TOPIC" "$ROOT" --glob '*.md' || true
fi
echo
echo "=== END SKILL CONTEXT ==="
echo "Inject the above into your model (Grok/GPT/local/Claude/…). No Claude required."
