#!/bin/sh
# minimal API server wrapping zcli merchant commands
# serves: POST /create?amount=X&label=Y → zcli merchant create
#         GET  /requests.json           → static file from --dir
#
# usage: ZCLI_DIR=/srv/shop api.sh
#
# in production: replace this with caddy's reverse_proxy or a proper backend.
# this exists so the example works without extra dependencies.

set -eu

PORT="${API_PORT:-8080}"
DIR="${ZCLI_DIR:-/srv/shop}"
FIFO=$(mktemp -u)
mkfifo "$FIFO"
trap 'rm -f "$FIFO"' EXIT

echo "api: listening on :$PORT, serving from $DIR" >&2

while true; do
  # read one HTTP request
  {
    read -r METHOD PATH _REST
    # consume headers
    while read -r LINE; do
      LINE=$(printf '%s' "$LINE" | tr -d '\r\n')
      [ -z "$LINE" ] && break
    done

    PATH=$(printf '%s' "$PATH" | tr -d '\r\n')
    RESPONSE=""
    STATUS="200 OK"
    CONTENT_TYPE="application/json"

    case "$PATH" in
      /create*)
        # parse query: ?amount=X&label=Y
        QUERY="${PATH#*\?}"
        AMOUNT=$(printf '%s' "$QUERY" | tr '&' '\n' | grep '^amount=' | cut -d= -f2)
        LABEL=$(printf '%s' "$QUERY" | tr '&' '\n' | grep '^label=' | cut -d= -f2)
        AMOUNT="${AMOUNT:-0}"

        if [ -n "$LABEL" ]; then
          RESPONSE=$(zcli merchant create "$AMOUNT" --memo "$LABEL" --json 2>/dev/null)
        else
          RESPONSE=$(zcli merchant create "$AMOUNT" --json 2>/dev/null)
        fi

        if [ -z "$RESPONSE" ]; then
          STATUS="500 Internal Server Error"
          RESPONSE='{"error":"create failed"}'
        fi
        ;;

      /requests.json)
        if [ -f "$DIR/requests.json" ]; then
          RESPONSE=$(cat "$DIR/requests.json")
        else
          RESPONSE='[]'
        fi
        ;;

      *)
        # serve static files
        FILE="$DIR${PATH}"
        if [ -f "$FILE" ]; then
          RESPONSE=$(cat "$FILE")
          case "$FILE" in
            *.html) CONTENT_TYPE="text/html" ;;
            *.js)   CONTENT_TYPE="application/javascript" ;;
            *.css)  CONTENT_TYPE="text/css" ;;
            *.json) CONTENT_TYPE="application/json" ;;
            *)      CONTENT_TYPE="application/octet-stream" ;;
          esac
        else
          STATUS="404 Not Found"
          RESPONSE='{"error":"not found"}'
        fi
        ;;
    esac

    LEN=$(printf '%s' "$RESPONSE" | wc -c)
    printf 'HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n%s' \
      "$STATUS" "$CONTENT_TYPE" "$LEN" "$RESPONSE"
  } < "$FIFO" | nc -l -p "$PORT" -q 1 > "$FIFO" 2>/dev/null || true
done
