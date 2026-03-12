#!/bin/sh
# sync board wallet and export notes to memos.json
set -e

IDENTITY="${ZCLI_IDENTITY:-$HOME/.ssh/id_claude}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BLOCKLIST="$SCRIPT_DIR/blocked.txt"

zcli sync --json -i "$IDENTITY" 2>/dev/null || true
zcli notes --json -i "$IDENTITY" > "$SCRIPT_DIR/memos.raw.json"

# filter: remove blocked txids, strip amounts/nullifiers/cmx for privacy
if [ -f "$BLOCKLIST" ]; then
  python3 -c "
import json, sys
blocked = set(open('$BLOCKLIST').read().split())
notes = json.load(open('$SCRIPT_DIR/memos.raw.json'))
filtered = [{'height':n['height'],'memo':n.get('memo',''),'txid':n['txid'][:8]}
            for n in notes if n['txid'][:8] not in blocked]
json.dump(filtered, sys.stdout)
" > "$SCRIPT_DIR/memos.json"
else
  python3 -c "
import json, sys
notes = json.load(open('$SCRIPT_DIR/memos.raw.json'))
clean = [{'height':n['height'],'memo':n.get('memo',''),'txid':n['txid'][:8]}
         for n in notes]
json.dump(clean, sys.stdout)
" > "$SCRIPT_DIR/memos.json"
fi
