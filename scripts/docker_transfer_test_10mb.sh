#!/bin/bash
set -euo pipefail

cd "$(dirname "$0")/.."

CLIENT_SERVICE="hostA"
SERVER_SERVICE="hostB"
WORKDIR="/root/srft"
SOURCE_NAME="test_10mb_file"
DOWNLOAD_URL="https://drive.usercontent.google.com/download?id=1dSVOBCC6KcLRemG64TTNXMKG1oe9gIjR&export=download&confirm=t"
CONFIG_NAME="${1:-config_10mb.json}"
TIMEOUT_SECONDS="${2:-120}"

TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/srft_fast_10mb.XXXXXX")"
SOURCE_PATH="$TEMP_DIR/$SOURCE_NAME"
OUTPUT_NAME="received_${SOURCE_NAME}"
SERVER_LOG="$TEMP_DIR/server.log"
CLIENT_LOG="$TEMP_DIR/client.log"
SUMMARY_LOG="$PWD/transfer_test_10mb.log"

resolve_container() {
  docker compose ps -q "$1" | head -n 1
}

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
  rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

echo "Ensuring Docker containers are up"
docker compose up -d >/dev/null

CLIENT="$(resolve_container "$CLIENT_SERVICE")"
SERVER="$(resolve_container "$SERVER_SERVICE")"

if [ -z "$CLIENT" ] || [ -z "$SERVER" ]; then
  echo "Failed to resolve Docker Compose services" >&2
  exit 1
fi

echo "Downloading 10 MB test file"
curl -fsSL -o "$SOURCE_PATH" "$DOWNLOAD_URL"

docker exec "$CLIENT" sh -lc "pkill -f 'main.py --mode client' || true" >/dev/null 2>&1 || true
docker exec "$SERVER" sh -lc "pkill -f 'main.py --mode server' || true" >/dev/null 2>&1 || true

echo "Copying repo and test assets into containers"
docker cp . "$CLIENT":"$WORKDIR"
docker cp . "$SERVER":"$WORKDIR"
docker cp "$SOURCE_PATH" "$CLIENT":"$WORKDIR/$SOURCE_NAME"
docker cp "$SOURCE_PATH" "$SERVER":"$WORKDIR/$SOURCE_NAME"

docker exec "$CLIENT" sh -lc "rm -f '$WORKDIR/$OUTPUT_NAME'"

echo "Starting server"
docker exec "$SERVER" sh -lc \
  "cd '$WORKDIR' && python3 -u main.py --mode server --config '$CONFIG_NAME'" \
  >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

sleep 1

echo "Starting client"
START_TIME="$(date +%s)"
docker exec "$CLIENT" sh -lc \
  "cd '$WORKDIR' && python3 -u main.py --mode client --config '$CONFIG_NAME' --file '$SOURCE_NAME'" \
  >"$CLIENT_LOG" 2>&1 &
CLIENT_PID=$!

while kill -0 "$CLIENT_PID" 2>/dev/null; do
  NOW="$(date +%s)"
  ELAPSED=$((NOW - START_TIME))
  if [ "$ELAPSED" -ge "$TIMEOUT_SECONDS" ]; then
    echo "Client timed out after ${TIMEOUT_SECONDS}s"
    kill "$CLIENT_PID" 2>/dev/null || true
    break
  fi

  if [ $((ELAPSED % 10)) -eq 0 ]; then
    echo "Waiting... ${ELAPSED}s/${TIMEOUT_SECONDS}s"
  fi
  sleep 1
done

CLIENT_STATUS=0
wait "$CLIENT_PID" || CLIENT_STATUS=$?
END_TIME="$(date +%s)"
TOTAL_SECONDS=$((END_TIME - START_TIME))

SERVER_STATUS=0
if kill -0 "$SERVER_PID" 2>/dev/null; then
  kill "$SERVER_PID" 2>/dev/null || true
  wait "$SERVER_PID" || SERVER_STATUS=$?
else
  wait "$SERVER_PID" || SERVER_STATUS=$?
fi

{
  echo "=== Server Log ==="
  cat "$SERVER_LOG"
  echo
  echo "=== Client Log ==="
  cat "$CLIENT_LOG"
  echo
  echo "=== Summary ==="
  echo "Config: $CONFIG_NAME"
  echo "Elapsed seconds: $TOTAL_SECONDS"
} > "$SUMMARY_LOG"

if [ "$CLIENT_STATUS" -ne 0 ]; then
  echo "Client failed"
  echo "Client exited with status $CLIENT_STATUS"
  echo "Logs saved to $SUMMARY_LOG"
  exit 1
fi

if [ "$SERVER_STATUS" -ne 0 ] && [ "$SERVER_STATUS" -ne 143 ]; then
  echo "Server failed"
  echo "Server exited with status $SERVER_STATUS"
  echo "Logs saved to $SUMMARY_LOG"
  exit 1
fi

echo "Verifying received file"
docker exec "$CLIENT" sh -lc "cd '$WORKDIR' && cmp '$SOURCE_NAME' '$OUTPUT_NAME'"

echo "10 MB transfer test passed in ${TOTAL_SECONDS}s"
echo "Logs saved to $SUMMARY_LOG"
