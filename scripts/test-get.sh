#!/bin/sh
# Tests get.sh without a network: curl is a stub that serves files from a fixture
# directory, and the packaged installer is a stub that records how it was called.
#
#   sh scripts/test-get.sh        runs under sh, and under dash when present
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
passes=0; fails=0
pass() { passes=$((passes + 1)); printf '  ok    %s\n' "$1"; }
skip() { printf '  skip  %s\n' "$1"; }
fail() { fails=$((fails + 1));  printf '  FAIL  %s\n' "$1"; [ -z "${2:-}" ] || printf '        %s\n' "$2"; }
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# ---- stubs ---------------------------------------------------------------------------
mkdir -p "$work/stubs"
stub() { printf '#!/bin/sh\n%s\n' "$2" > "$work/stubs/$1"; chmod +x "$work/stubs/$1"; }
# curl: "-I ... -w %{url_effective} URL" answers with the latest-release redirect target;
# "-o FILE URL" copies the fixture named by the last path segment (404 -> exit 22).
stub curl 'out=""; head=0; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) shift 2 ;;
    -*I*) head=1; shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "curl $url" >> "$STUB_LOG"
if [ "$head" = 1 ]; then
  [ -n "${STUB_NO_RELEASE:-}" ] && { echo "${url%/latest}"; exit 0; }
  echo "${url%/latest}/tag/${STUB_LATEST:-v9.9.9}"; exit 0
fi
f="$STUB_FIXTURES/${url##*/}"
[ -f "$f" ] || exit 22
cp "$f" "$out"'
# wget: the same fixtures. "-S ... URL" prints the redirect the way wget -S does; "-O FILE URL" copies.
stub wget 'out=""; spider=0; url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -O) out="$2"; shift 2 ;;
    -S) spider=1; shift ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "wget $url" >> "$STUB_LOG"
if [ "$spider" = 1 ]; then
  [ -n "${STUB_NO_RELEASE:-}" ] && exit 8
  printf "  HTTP/1.1 302 Found\r\n  Location: %s/tag/%s\r\n" "${url%/latest}" "${STUB_LATEST:-v9.9.9}" >&2; exit 8
fi
f="$STUB_FIXTURES/${url##*/}"
[ -f "$f" ] || exit 8
cp "$f" "$out"'
stub uname 'case "${1:-}" in -s) echo "${STUB_OS:-Linux}" ;; -m) echo "${STUB_ARCH:-x86_64}" ;; *) echo Linux ;; esac'
stub id 'if [ "${1:-}" = "-u" ]; then echo "${STUB_UID:-0}"; else exec /usr/bin/id "$@"; fi'
stub sudo 'echo "sudo $*" >> "$STUB_LOG"; exec "$@"'

# a release fixture: certsmith-9.9.9-linux-<arch>.tar.gz with a recording installer inside
mkrelease() { # dir arch [evil]
  d="$1"; a="$2"; pkg="certsmith-9.9.9-linux-$a"
  rm -rf "$d"; mkdir -p "$d/build/$pkg"
  printf '#!/bin/sh\necho "INSTALLER cwd=$(basename "$(pwd)") args=$*" >> "$STUB_LOG"\n' > "$d/build/$pkg/install.sh"
  echo bin > "$d/build/$pkg/certsmith-linux-$a"; echo unit > "$d/build/$pkg/certsmith.service"
  if [ "${3:-}" = evil ]; then echo x > "$d/build/evil.txt"; (cd "$d/build" && tar czf "$d/$pkg.tar.gz" "$pkg" evil.txt)
  elif [ "${3:-}" = apple ]; then
    # What bsdtar on macOS stores for files that have extended attributes: AppleDouble companions, one of
    # them beside the package directory instead of inside it. Written with Python's tarfile so the fixture
    # is the same on every platform.
    python3 - "$d" "$pkg" <<'FIXTURE'
import io, sys, tarfile
d, pkg = sys.argv[1], sys.argv[2]
with tarfile.open("%s/%s.tar.gz" % (d, pkg), "w:gz") as t:
    def add(name, data=b"x"):
        ti = tarfile.TarInfo(name); ti.size = len(data); t.addfile(ti, io.BytesIO(data))
    add("._" + pkg)
    top = tarfile.TarInfo(pkg); top.type = tarfile.DIRTYPE; top.mode = 0o755; t.addfile(top)
    add(pkg + "/install.sh", open("%s/build/%s/install.sh" % (d, pkg), "rb").read())
    add(pkg + "/._install.sh")
FIXTURE
  else (cd "$d/build" && tar czf "$d/$pkg.tar.gz" "$pkg"); fi
  printf '%s  ./%s.tar.gz\n' "$(sum "$d/$pkg.tar.gz")" "$pkg" > "$d/SHA256SUMS"
}

run() { # runs get.sh in a clean environment, sets OUT and RC
  OUT=$(CERTSMITH_BASE_URL=https://example.test CERTSMITH_REPO=owner/repo STUB_LOG="$LOG" STUB_FIXTURES="$FIX" \
        TMPDIR="$work/tmp" PATH="$work/stubs:$PATH" "$SH" "$here/get.sh" "$@" 2>&1)
  RC=$?
}
newcase() { LOG="$work/$1.log"; : > "$LOG"; FIX="$work/$1.fix"; mkrelease "$FIX" amd64; rm -rf "$work/tmp"; mkdir -p "$work/tmp"
  unset STUB_LATEST STUB_NO_RELEASE STUB_OS STUB_ARCH STUB_UID CERTSMITH_VERSION; }
logged() { grep -q -- "$1" "$LOG"; }
leftover() { [ -z "$(ls -A "$work/tmp" 2>/dev/null)" ]; }

suite() {
  SH="$1"; printf '== under %s ==\n' "$SH"

  newcase ok
  run --allow-from 192.0.2.0/24 --no-auto-updates
  [ "$RC" -eq 0 ] && pass "installs the latest release" || fail "installs the latest release" "$OUT"
  logged "INSTALLER cwd=certsmith-9.9.9-linux-amd64 args=--allow-from 192.0.2.0/24 --no-auto-updates" && pass "runs the packaged installer with the options passed through" || fail "options passed through" "$(cat "$LOG")"
  logged "releases/download/v9.9.9/certsmith-9.9.9-linux-amd64.tar.gz" && pass "downloads the archive for this version and architecture" || fail "downloads the archive"
  leftover && pass "removes its temporary directory" || fail "removes its temporary directory"

  newcase noargs
  run
  logged "INSTALLER cwd=certsmith-9.9.9-linux-amd64 args=$" && pass "runs with no options" || fail "runs with no options" "$(cat "$LOG")"

  newcase pin
  export CERTSMITH_VERSION=9.9.9
  mkrelease "$FIX" amd64; STUB_LATEST=v1.0.0 run
  ! logged "releases/latest" && pass "a pinned version skips the latest-release lookup" || fail "pinned version skips lookup"
  [ "$RC" -eq 0 ] && pass "a version without a leading v is accepted" || fail "version without v" "$OUT"
  unset CERTSMITH_VERSION

  newcase arm
  mkrelease "$FIX" arm64; STUB_ARCH=aarch64 run
  [ "$RC" -eq 0 ] && logged "linux-arm64.tar.gz" && pass "arm64 selects the arm64 archive" || fail "arm64" "$OUT"

  newcase badarch
  STUB_ARCH=riscv64 run
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "an unsupported architecture is refused" || fail "unsupported architecture"
  newcase notlinux
  STUB_OS=Darwin run
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "a non-Linux system is refused" || fail "non-Linux"

  newcase tamper
  echo "tampered" >> "$FIX/certsmith-9.9.9-linux-amd64.tar.gz"; run
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "a checksum mismatch stops before anything runs" || fail "checksum mismatch" "$OUT"
  case "$OUT" in *"checksum mismatch"*) pass "and says why" ;; *) fail "says why" "$OUT" ;; esac
  leftover && pass "and cleans up" || fail "cleans up after a failure"

  newcase nosum
  : > "$FIX/SHA256SUMS"; run
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "a missing checksum entry stops the install" || fail "missing checksum entry"

  newcase norelease
  STUB_NO_RELEASE=1 run
  [ "$RC" -ne 0 ] && ! logged "releases/download" && pass "no published release is reported, nothing downloaded" || fail "no release" "$OUT"
  case "$OUT" in *"no published release"*) pass "with a clear message" ;; *) fail "clear message" "$OUT" ;; esac

  newcase notfound
  rm -f "$FIX/certsmith-9.9.9-linux-amd64.tar.gz"; run
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "a missing archive stops the install" || fail "missing archive"

  newcase evil
  mkrelease "$FIX" amd64 evil; run
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "an archive with paths outside its directory is refused" || fail "evil archive" "$OUT"
  [ ! -e "$work/tmp/evil.txt" ] && pass "and was not unpacked" || fail "was not unpacked"

  newcase apple
  if tar --version 2>/dev/null | grep -qi bsdtar; then
    # bsdtar folds ._ files away when listing, so this host's tar cannot see them; get.sh runs on Linux
    skip "an archive made on macOS is refused (needs GNU tar; bsdtar hides ._ entries, CI runs this)"
  else
    mkrelease "$FIX" amd64 apple; run
    [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "an archive made on macOS (._ files) is refused" || fail "macOS archive refused" "$OUT"
    case "$OUT" in *"._certsmith-9.9.9-linux-amd64"*"COPYFILE_DISABLE"*) pass "and the message names the file and the fix" ;; *) fail "message names the file and the fix" "$OUT" ;; esac
    leftover && pass "and nothing is left behind" || fail "nothing left behind"
  fi

  newcase sudo
  STUB_UID=1000 run --no-firewall
  logged "sudo sh ./install.sh --no-firewall" && pass "a non-root user runs the installer with sudo" || fail "sudo used" "$(cat "$LOG")"
  newcase nosudo
  mv "$work/stubs/sudo" "$work/stubs/sudo.off"; STUB_UID=1000 run
  mv "$work/stubs/sudo.off" "$work/stubs/sudo"
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "non-root without sudo is refused" || fail "non-root without sudo" "$OUT"

  # a system with only wget (or neither): the same installer, or a message that says what to install
  tools="$work/tools"; rm -rf "$tools"; mkdir -p "$tools"
  for t in sh awk grep head mktemp rm tar sha256sum shasum openssl cat tr sed dirname basename mkdir cp sort pwd; do
    p=$(command -v "$t" 2>/dev/null) && [ -x "$p" ] && ln -s "$p" "$tools/$t"
  done
  nocurl() { # run with a PATH that has the stubs (uname, id, sudo, and wget unless $1 is none) but no curl
    mkdir -p "$work/stubs2"; rm -f "$work/stubs2"/*
    for s in uname id sudo; do cp "$work/stubs/$s" "$work/stubs2/$s"; done
    [ "${1:-}" = none ] || cp "$work/stubs/wget" "$work/stubs2/wget"
    OUT=$(CERTSMITH_BASE_URL=https://example.test CERTSMITH_REPO=owner/repo STUB_LOG="$LOG" STUB_FIXTURES="$FIX" \
          TMPDIR="$work/tmp" PATH="$work/stubs2:$tools" "$(command -v "$SH")" "$here/get.sh" 2>&1)
    RC=$?
  }
  newcase wget
  nocurl
  if logged "wget https://example.test/owner/repo/releases/latest" && logged "INSTALLER cwd=certsmith-9.9.9-linux-amd64"; then
    pass "with only wget, the latest release is found, downloaded and installed"
  else fail "wget only" "$OUT $(cat "$LOG")"; fi
  ! logged "curl " && pass "and curl was not needed" || fail "no curl" "$(cat "$LOG")"
  newcase nofetch
  nocurl none
  case "$OUT" in *"curl or wget is required"*"apt-get install -y curl"*) pass "with neither, the message says what to install" ;; *) fail "neither tool" "$OUT" ;; esac
  [ "$RC" -ne 0 ] && ! logged INSTALLER && pass "and nothing was installed" || fail "nothing installed" "$OUT"
  newcase wgetprivate
  STUB_NO_RELEASE=1 nocurl
  case "$OUT" in *"private"*) pass "with wget, a repository with no visible release is explained" ;; *) fail "wget private repo" "$OUT" ;; esac

  newcase hostile
  CERTSMITH_VERSION='v1.0.0;rm -rf /' run
  [ "$RC" -ne 0 ] && ! logged curl && pass "a hostile version string is refused before any download" || fail "hostile version" "$OUT"
  unset CERTSMITH_VERSION
}

suite sh
if command -v dash >/dev/null 2>&1; then suite dash; fi
printf '\n%d passed, %d failed\n' "$passes" "$fails"
[ "$fails" -eq 0 ]
