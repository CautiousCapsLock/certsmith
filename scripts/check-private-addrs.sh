#!/bin/sh
# Fails if a private-range IPv4 address (10/8, 172.16/12, 192.168/16) appears in a
# tracked source file. Keeps one site's network details out of the product.
# Test fixtures, go.sum and Markdown (docs and examples) are exempt.
#
# Optional: set CHECK_EXTRA_PATTERN (an extended regex, e.g. a personal domain) to
# forbid more. In CI it comes from the repository variable of the same name, so the
# value itself never has to be committed.
set -eu
cd "$(dirname "$0")/.."

re='(^|[^0-9.])(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})([^0-9]|$)'
if [ -n "${CHECK_EXTRA_PATTERN:-}" ]; then
  re="$re|${CHECK_EXTRA_PATTERN}"
fi

hits=$(git grep -nEI -e "$re" -- . ':!*_test.go' ':!go.sum' ':!*.md' ':!scripts/check-private-addrs.sh' || true)
if [ -n "$hits" ]; then
  echo "private addresses or forbidden patterns found:" >&2
  echo "$hits" >&2
  exit 1
fi
echo "ok: no private-range addresses in tracked source"
