#!/bin/bash

cd "$(dirname "$0")/.."

CONFIG_PATH="config.json"
FILENAME="$1"

if [ -z "$FILENAME" ]; then
    echo "Usage: ./run_client.sh <filename>"
    exit 1
fi

echo "Starting SRFT client..."
echo "Requesting file: $FILENAME"

sudo PYTHONPATH=. python3 main.py --mode client --config "$CONFIG_PATH" --file "$FILENAME"