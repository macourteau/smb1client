#!/bin/bash
# Test runner for smb1client. Defaults to the full test suite (./...) when no
# arguments are given; any arguments are passed through to `go test`.
#
# Usage:
#   ./test.sh                    # Run all tests
#   ./test.sh -v ./...          # Verbose all tests
#   ./test.sh -cover ./...      # With coverage
#   ./test.sh -race ./...       # With race detector
#   ./test.sh ./internal/client # Specific package

set -e

if [ $# -eq 0 ]; then
	set -- ./...
fi

go test "$@"
