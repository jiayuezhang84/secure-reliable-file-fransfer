#!/bin/bash
set -e

cd "$(dirname "$0")/.."

FILENAME="${1:-README.md}"
CONFIG="${2:-config_retransmission.json}"
TIMEOUT="${3:-20}"

CLIENT="hostA-10.0.1.10"
SERVER="hostB-10.0.1.20"
WORKDIR="/root/srft"
OUTFILE="received_$(basename "$FILENAME")"

SERVER_LOG="/tmp/srft_server.log"
CLIENT_LOG="/tmp/srft_client.log"

docker cp . "$CLIENT":"$WORKDIR"
docker cp . "$SERVER":"$WORKDIR"

docker exec "$CLIENT" sh -lc "rm -f '$WORKDIR/$OUTFILE'"

docker exec "$SERVER" sh -lc \
  "cd '$WORKDIR' && python3 -u main.py --mode server --config '$CONFIG'" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

sleep 1

docker exec "$CLIENT" sh -lc \
  "cd '$WORKDIR' && python3 -u main.py --mode client --config '$CONFIG' --file '$FILENAME'" \
  >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

START=$(date +%s)
while kill -0 "$CLIENT_PID" 2>/dev/null; do
  NOW=$(date +%s)
  ELAPSED=$((NOW - START))
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "Client timed out after ${TIMEOUT}s"
    kill "$CLIENT_PID" 2>/dev/null || true
    break
  fi
  sleep 1
done

wait "$CLIENT_PID" || true

echo "=== Server Log ==="
cat "$SERVER_LOG"
echo
echo "=== Client Log ==="
cat "$CLIENT_LOG"

grep -q "retransmitted" "$SERVER_LOG"
docker exec "$CLIENT" sh -lc "cd '$WORKDIR' && cmp '$FILENAME' '$OUTFILE'"

echo "Test passed"
