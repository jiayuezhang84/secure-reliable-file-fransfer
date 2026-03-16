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

cleanup() {
  if [ -n "${CLIENT_PID:-}" ] && kill -0 "$CLIENT_PID" 2>/dev/null; then
    kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
  fi

  if [ -n "${SERVER_PID:-}" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  docker exec "$CLIENT" sh -lc "pkill -f 'main.py --mode client' || true" >/dev/null 2>&1 || true
  docker exec "$SERVER" sh -lc "pkill -f 'main.py --mode server' || true" >/dev/null 2>&1 || true
}

trap cleanup EXIT

docker exec "$CLIENT" sh -lc "pkill -f 'main.py --mode client' || true" >/dev/null 2>&1 || true
docker exec "$SERVER" sh -lc "pkill -f 'main.py --mode server' || true" >/dev/null 2>&1 || true

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

server_status=0
if kill -0 "$SERVER_PID" 2>/dev/null; then
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" || server_status=$?
else
  wait "$SERVER_PID" || server_status=$?
fi

echo "=== Server Log ==="
cat "$SERVER_LOG"
echo
echo "=== Client Log ==="
cat "$CLIENT_LOG"

if [ "$server_status" -ne 0 ] && [ "$server_status" -ne 143 ]; then
  echo "Server exited with status $server_status"
  exit 1
fi

grep -q "retransmitted" "$SERVER_LOG"
docker exec "$CLIENT" sh -lc "cd '$WORKDIR' && cmp '$FILENAME' '$OUTFILE'"

echo "Test passed"
