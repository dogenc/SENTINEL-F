#!/usr/bin/env bash
# Veröffentlicht den aktuellen Stand von main als EINEN Commit ins öffentliche Repo (ohne Entwicklungshistorie).
#   scripts/publish_public.sh "SENTINEL-F 1.0.1"
# Voraussetzung: Remote "public" → https://github.com/dogenc/SENTINEL-F.git
set -euo pipefail
cd "$(dirname "$0")/.."
msg="${1:-SENTINEL-F $(sed -n 's/^APP_VERSION *= *"\(.*\)".*/\1/p' config/settings.py)}"
git diff --quiet && git diff --cached --quiet || { echo "Erst alles committen."; exit 1; }
tree=$(git rev-parse "main^{tree}")
parent=$(git ls-remote public refs/heads/main | cut -f1 || true)
if [ -n "$parent" ]; then
  git fetch -q public main
  commit=$(git commit-tree "$tree" -p "$parent" -m "$msg")   # öffentliche Historie: nur Releases
else
  commit=$(git commit-tree "$tree" -m "$msg")                # erster Commit, keine Vorgeschichte
fi
git push public "$commit:refs/heads/main"
echo "Veröffentlicht: $commit"
