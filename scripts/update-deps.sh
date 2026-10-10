#!/bin/sh
# Dependency maintenance, as described in docs/DEPENDENCIES.md.
#
#   sh scripts/update-deps.sh check    list what is newer, and any new lego major version
#   sh scripts/update-deps.sh apply    bump, tidy, regenerate the notices, build, vet, test, govulncheck
#
# "apply" moves the direct modules to their latest release and every other module to its latest patch
# release. It stops at the first failure and leaves the working tree as it is, so the cause can be
# examined; review the result with `git diff --stat go.mod go.sum internal/web/static/THIRD_PARTY_NOTICES.txt`.
set -eu
cd "$(dirname "$0")/.."

# the version the CI job pins
GOVULNCHECK="golang.org/x/vuln/cmd/govulncheck@v1.8.0"

direct() { go list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all | grep -v '^$' | grep -v '^github.com/CautiousCapsLock/'; }

check() {
  echo "== direct modules with a newer release =="
  found=0
  go list -m -u -f '{{if and (not .Indirect) .Update}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all | grep -v '^$' | grep -v '^github.com/CautiousCapsLock/' | { while read -r line; do echo "  $line"; found=1; done; [ "$found" = 1 ] || echo "  none"; }
  echo "== newer major versions of direct modules =="
  for m in $(direct); do
    base=$(printf '%s' "$m" | sed -E 's#/v[0-9]+$##')
    cur=$(printf '%s' "$m" | sed -nE 's#.*/v([0-9]+)$#\1#p'); cur=${cur:-1}
    next=$((cur + 1))
    # "go list -m -versions" prints just the path for a module that has no versions, so a version must follow it
    latest=$(go list -m -versions "$base/v$next" 2>/dev/null | awk 'NF > 1 { print $NF }')
    if [ -n "$latest" ]; then
      echo "  $base/v$next exists (using v$cur): $latest is the latest"
    fi
  done
  echo "== Go toolchain =="
  echo "  go.mod: $(grep -E '^go ' go.mod)    installed: $(go version | awk '{print $3}')"
  echo "== indirect modules with a newer release =="
  echo "  $(go list -m -u -f '{{if and .Indirect .Update}}x{{end}}' all | grep -c x) (not bulk-upgraded: see docs/DEPENDENCIES.md)"
}

apply() {
  echo "== direct modules to the latest release =="
  for m in $(direct); do go get "$m@latest"; done
  echo "== everything else to the latest patch release =="
  go get -u=patch ./...
  go mod tidy
  echo "== notices =="
  go run ./scripts/notices
  go run ./scripts/notices -check
  echo "== build =="
  go build ./...
  for arch in amd64 arm64; do CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -o /dev/null ./cmd/certsmith; done
  echo "== vet =="
  go vet ./...
  echo "== tests =="
  go test -race -count=1 ./...
  echo "== govulncheck =="
  go run "$GOVULNCHECK" ./...
  echo
  echo "ok: review with  git diff --stat go.mod go.sum internal/web/static/THIRD_PARTY_NOTICES.txt"
}

case "${1:-}" in
  check) check ;;
  apply) apply ;;
  *) echo "usage: sh scripts/update-deps.sh check|apply" >&2; exit 2 ;;
esac
