#!/bin/sh
# Fails if a command-line option, daemon flag or environment variable used by the code is
# not mentioned in README.md or docs/REFERENCE.md. The lists are read from the code, so a
# new switch cannot be added without documenting it.
set -eu
cd "$(dirname "$0")/.."
DOCS="README.md docs/REFERENCE.md"

# check LABEL PREFIX TOKENS...: report each token that no document contains
check() {
  label="$1"; prefix="$2"; tokens="$3"
  printf '%s\n' "$tokens" | while IFS= read -r t; do
    [ -n "$t" ] || continue
    # shellcheck disable=SC2086
    grep -qF -- "$prefix$t" $DOCS || echo "undocumented $label: $prefix$t"
  done
}

installer=$(sed -n '/^while \[ \$# -gt 0 \]/,/^done/p' deploy/install.sh | grep -oE -- '--[a-z][a-z-]*' | sort -u)
daemon=$(grep -oE 'flag\.(String|Bool|Int|Duration)\("[a-z-]+"' cmd/certsmith/main.go | sed 's/.*("//; s/"$//' | sort -u)
resetadmin=$(grep -oE 'fs\.(String|Bool)\("[a-z-]+"' cmd/certsmith/main.go | sed 's/.*("//; s/"$//' | sort -u)
environment=$(grep -rhoE 'CERTSMITH_[A-Z_]+|CHECK_[A-Z_]+' --include='*.go' --include='*.sh' --include='*.service' \
  --exclude='*_test.go' --exclude='check-docs.sh' . | sort -u)

out=$(
  check "installer option" "" "$installer"
  check "daemon flag" '`-' "$daemon"
  check "reset-admin flag" '`-' "$resetadmin"
  check "environment variable" "" "$environment"
)
if [ -n "$out" ]; then
  printf '%s\n' "$out" >&2
  exit 1
fi
printf 'ok: %s installer options, %s daemon flags, %s reset-admin flags, %s environment variables are documented\n' \
  "$(printf '%s\n' "$installer" | wc -l | tr -d ' ')" "$(printf '%s\n' "$daemon" | wc -l | tr -d ' ')" \
  "$(printf '%s\n' "$resetadmin" | wc -l | tr -d ' ')" "$(printf '%s\n' "$environment" | wc -l | tr -d ' ')"
