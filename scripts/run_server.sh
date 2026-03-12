#!/bin/bash

cd "$(dirname "$0")/.."

CONFIG_PATH="config.json"

echo "Starting SRFT server..."

sudo PYTHONPATH=. python3 main.py --mode server --config "$CONFIG_PATH"