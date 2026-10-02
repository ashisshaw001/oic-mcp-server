#!/bin/sh
# Start the server locally. Reads .env (see .env.example) and OIC_CONFIG_FILE.
set -e
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
	python3 -m venv .venv
fi
. .venv/bin/activate
pip -q install -r requirements.txt

exec python -m oic_mcp
