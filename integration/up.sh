#!/bin/sh
# Start (or restart into a known-good state) the SMB1 test server.
# Idempotent: safe to run when the container is already up.
set -eu
cd "$(dirname "$0")"
docker compose up --build --detach --wait
