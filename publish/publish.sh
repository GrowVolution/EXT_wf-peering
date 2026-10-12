#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

if [ -n "$(git status --porcelain)" ]; then
    echo "ERROR: working tree is dirty (uncommitted or untracked changes). Commit or stash before releasing." >&2
    exit 1
fi

LOCAL="$(git rev-parse HEAD)"

trap 'rm -rf tmp' EXIT

rm -rf tmp
git clone https://github.com/GrowVolution/WebFluid tmp
cd tmp

CLONED="$(git rev-parse HEAD)"
if [ "$LOCAL" != "$CLONED" ]; then
    echo "ERROR: the published branch is at ${CLONED:0:8}, your working tree at ${LOCAL:0:8}." >&2
    echo "Push and merge your release commit before publishing." >&2
    exit 1
fi

pip install -r requirements.txt
python -m build
twine upload dist/*

cd stubs
python -m build
twine upload dist/*

cd ../..
echo "Published."
