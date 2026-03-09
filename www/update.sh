#!/bin/sh
# sync board wallet and export notes to memos.json
set -e

IDENTITY="${ZCLI_IDENTITY:-$HOME/.ssh/id_claude}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

zcli sync --script -i "$IDENTITY"
zcli notes --script -i "$IDENTITY" > "$SCRIPT_DIR/memos.json"
