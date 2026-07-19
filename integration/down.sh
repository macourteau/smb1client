#!/bin/sh
# Stop and remove the SMB1 test server. Idempotent: safe when already down.
set -eu
cd "$(dirname "$0")"
docker compose down
