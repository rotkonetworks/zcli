#!/bin/sh
# pre-create payment request addresses for a static webshop
# run this once to seed the request pool, then start watch
#
# usage: ./seed-requests.sh [count]
#
# creates N addresses with amount=0 (any amount) for reuse.
# for fixed-price products, create with specific amounts:
#   zcli merchant create 0.001 --memo "sticker pack" --json
#   zcli merchant create 0.01  --memo "t-shirt" --json

set -eu

COUNT="${1:-10}"
echo "creating $COUNT payment request addresses..." >&2

for i in $(seq 1 "$COUNT"); do
  zcli merchant create 0 --json
done

echo "done. start watch to begin monitoring:" >&2
echo "  zcli merchant watch --dir /srv/shop/data" >&2
