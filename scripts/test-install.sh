#!/bin/sh
# Tests deploy/install.sh without root and without touching the machine: every file is
# written under a temporary CERTSMITH_ROOT and every system command it calls is a stub
# that logs its arguments. Covers what the installer decides (new install or upgrade,
# listen address, firewall rules, rollback), not what systemd or ufw do with it.
#
#   sh scripts/test-install.sh            runs under sh, and under dash when present
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
passes=0; fails=0

pass() { passes=$((passes + 1)); printf '  ok    %s\n' "$1"; }
fail() { fails=$((fails + 1));  printf '  FAIL  %s\n' "$1"; [ -z "${2:-}" ] || printf '        %s\n' "$2"; }
check() { # description, command...
  _d="$1"; shift
  if "$@" >/dev/null 2>&1; then pass "$_d"; else fail "$_d"; fi
}

# ---- stubs --------------------------------------------------------------------------
mkdir -p "$work/stubs"
stub() { printf '#!/bin/sh\n%s\n' "$2" > "$work/stubs/$1"; chmod +x "$work/stubs/$1"; }
LOGIT='echo "$(basename "$0") $*" >> "$STUB_LOG"'

stub systemctl  "$LOGIT"
stub useradd    "$LOGIT"
stub userdel    "$LOGIT"
stub apt-get    "$LOGIT"
stub journalctl "$LOGIT"
stub sysctl     "$LOGIT"
stub sleep      "exit 0"
stub ip         "exit 0"
stub uname      'echo x86_64'
stub openssl    'echo "sha256 Fingerprint=AA:BB:CC:DD"'
stub hostname   'echo "${STUB_ADDRS:-192.0.2.10}"'
stub sshd       'echo "port 22"'
stub dpkg       '[ -n "${STUB_HAS_UU:-}" ]'
stub id         'if [ "${1:-}" = certsmith ]; then [ -z "${STUB_NOUSER:-}" ]; exit; fi; exec /usr/bin/id "$@"'
stub ss         'case "$*" in
  *p*) echo "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))" ;;
  *)   [ -z "${STUB_LISTEN:-}" ] || echo "LISTEN 0 4096 0.0.0.0:$STUB_LISTEN 0.0.0.0:*" ;;
esac'
stub ufw        "$LOGIT"'
if [ -n "${STUB_UFW_FAIL:-}" ] && echo "$*" | grep -q -- "$STUB_UFW_FAIL"; then echo "ERROR: simulated failure"; exit 1; fi
case "$*" in
  status*) echo "Status: ${STUB_UFW:-inactive}" ;;
  *allow*) if [ -n "${STUB_UFW_HAS:-}" ] && echo "$*" | grep -q "$STUB_UFW_HAS"; then echo "Skipping adding existing rule"; else echo "Rule added"; fi ;;
esac'

# ---- one test case --------------------------------------------------------------------
newcase() { # name
  rm -rf "${work:?}/$1"          # each case (and each shell) starts from nothing
  R="$work/$1/root"; REL="$work/$1/rel"; LOG="$work/$1/log"
  mkdir -p "$R" "$REL"; : > "$LOG"
  cp "$here/deploy/install.sh" "$here/deploy/certsmith.service" "$REL/"
  printf '#!/bin/sh\necho 9.9.9\n' > "$REL/certsmith-linux-amd64"; chmod +x "$REL/certsmith-linux-amd64"
  echo "third-party notices" > "$REL/THIRD_PARTY_NOTICES.txt"
  unset STUB_UFW STUB_UFW_HAS STUB_UFW_FAIL STUB_LISTEN STUB_ADDRS STUB_HAS_UU STUB_NOUSER
}
run() { # installer arguments
  OUT=$(cd "$REL" && CERTSMITH_ROOT="$R" CERTSMITH_WAIT=2 STUB_LOG="$LOG" \
        PATH="$work/stubs:$PATH" "$SH" ./install.sh "$@" 2>&1)
  RC=$?
}
logged()   { grep -q -- "$1" "$LOG"; }
lineno()   { grep -n -- "$1" "$LOG" | head -1 | cut -d: -f1; }
envfile()  { sed -n "s/^$1=//p" "$R/etc/certsmith/certsmith.env" | tail -1; }
legacy_install() { # seed a first-release install: inline flags, no env file
  mkdir -p "$R/etc/systemd/system" "$R/usr/local/bin" "$R/var/lib/certsmith"
  printf '[Service]\nExecStart=/usr/local/bin/certsmith -data /var/lib/certsmith %s\n' "$1" > "$R/etc/systemd/system/certsmith.service"
  printf '#!/bin/sh\necho OLD\n' > "$R/usr/local/bin/certsmith"; chmod +x "$R/usr/local/bin/certsmith"
  echo '{}' > "$R/var/lib/certsmith/db.json"
}

suite() {
  SH="$1"
  printf '== under %s ==\n' "$SH"

  newcase fresh
  mkdir -p "$R/var/lib/certsmith/ui-tls"; : > "$R/var/lib/certsmith/ui-tls/fullchain.pem"
  STUB_LISTEN=443 run
  [ "$RC" -eq 0 ] && pass "new install succeeds" || fail "new install succeeds" "$OUT"
  [ "$(envfile CERTSMITH_LISTEN)" = "0.0.0.0:443" ] && pass "new install listens on 443" || fail "new install listens on 443"
  check "unit installed with EnvironmentFile" grep -q '^EnvironmentFile=' "$R/etc/systemd/system/certsmith.service"
  check "unit grants only CAP_NET_BIND_SERVICE" grep -q '^AmbientCapabilities=CAP_NET_BIND_SERVICE$' "$R/etc/systemd/system/certsmith.service"
  logged "ufw allow 443/tcp" && pass "firewall: 443 opened from any source" || fail "firewall: 443 opened from any source"
  a=$(lineno "ufw allow 22/tcp"); b=$(lineno "ufw --force enable")
  { [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; } && pass "firewall: SSH kept open before enabling" || fail "firewall: SSH kept open before enabling" "ssh@$a enable@$b"
  logged "ufw default deny incoming" && pass "firewall: default deny incoming" || fail "firewall: default deny incoming"
  logged "apt-get install.*unattended-upgrades" && pass "security updates enabled" || fail "security updates enabled"
  case "$OUT" in *"https://192.0.2.10/"*) pass "prints URL without :443" ;; *) fail "prints URL without :443" "$OUT" ;; esac
  case "$OUT" in *"AA:BB:CC:DD"*) pass "prints certificate fingerprint" ;; *) fail "prints certificate fingerprint" ;; esac

  check "third-party notices are installed with the program" test -f "$R/usr/share/doc/certsmith/THIRD_PARTY_NOTICES.txt"

  newcase rerun
  STUB_LISTEN=443 run; : > "$LOG"; STUB_LISTEN=443 run
  [ "$RC" -eq 0 ] && pass "running again succeeds" || fail "running again succeeds" "$OUT"
  case "$OUT" in *upgraded*) pass "second run is an upgrade" ;; *) fail "second run is an upgrade" "$OUT" ;; esac
  ! logged "^ufw" && pass "second run leaves the firewall alone" || fail "second run leaves the firewall alone"

  newcase legacy
  legacy_install "-listen 0.0.0.0:8443 -no-tls"
  STUB_LISTEN=8443 run
  [ "$RC" -eq 0 ] && pass "upgrade of a first-release install succeeds" || fail "upgrade of a first-release install succeeds" "$OUT"
  [ "$(envfile CERTSMITH_LISTEN)" = "0.0.0.0:8443" ] && pass "upgrade keeps port 8443" || fail "upgrade keeps port 8443" "$(envfile CERTSMITH_LISTEN)"
  [ "$(envfile CERTSMITH_ARGS)" = "-no-tls" ] && pass "upgrade keeps -no-tls" || fail "upgrade keeps -no-tls" "$(envfile CERTSMITH_ARGS)"
  ! logged "^ufw" && ! logged "^apt-get" && pass "upgrade does not touch firewall or packages" || fail "upgrade does not touch firewall or packages"
  case "$OUT" in *"http://192.0.2.10:8443/"*) pass "prints http URL with port for -no-tls" ;; *) fail "prints http URL with port for -no-tls" "$OUT" ;; esac
  check "unit moved to the environment-file form" grep -q 'CERTSMITH_LISTEN' "$R/etc/systemd/system/certsmith.service"

  newcase envkeep
  legacy_install "-listen 0.0.0.0:8443"
  mkdir -p "$R/etc/certsmith"
  printf '# mine\nCERTSMITH_LISTEN=0.0.0.0:9443\nCERTSMITH_ARGS=-tls-dir /srv/tls\n' > "$R/etc/certsmith/certsmith.env"
  cp "$R/etc/certsmith/certsmith.env" "$work/envkeep/before"
  STUB_LISTEN=9443 run
  check "existing env file is not rewritten" cmp -s "$R/etc/certsmith/certsmith.env" "$work/envkeep/before"

  newcase listen
  STUB_LISTEN=8443 run --listen 0.0.0.0:8443 --allow-from 203.0.113.0/24,198.51.100.7
  logged "ufw allow from 203.0.113.0/24 to any port 8443 proto tcp" && pass "allow-from: first network" || fail "allow-from: first network" "$(cat "$LOG")"
  logged "ufw allow from 198.51.100.7 to any port 8443 proto tcp" && pass "allow-from: second network" || fail "allow-from: second network"
  ! logged "ufw allow 8443/tcp" && pass "allow-from: no open-to-any rule" || fail "allow-from: no open-to-any rule"
  case "$OUT" in *"public address"*) fail "no public-address warning when networks are limited" ;; *) pass "no public-address warning when networks are limited" ;; esac

  # re-running with --allow-from must really narrow access, not just add rules next to the open ones
  newcase narrow
  STUB_LISTEN=443 run
  : > "$LOG"
  STUB_LISTEN=443 run --allow-from 203.0.113.0/24
  logged "ufw allow from 203.0.113.0/24 to any port 443 proto tcp" && pass "narrowing: the restricted rule is added" || fail "narrowing: restricted rule added" "$(cat "$LOG")"
  logged "ufw --force delete allow 443/tcp" && logged "ufw --force delete allow 80/tcp" && pass "narrowing: the earlier open-to-any rules are removed" || fail "narrowing: open rules removed" "$(cat "$LOG")"
  ! grep -qxF "allow 443/tcp" "$R/etc/certsmith/firewall.rules" && grep -qxF "allow from 203.0.113.0/24 to any port 443 proto tcp" "$R/etc/certsmith/firewall.rules" \
    && pass "narrowing: the record matches what is on the host" || fail "narrowing: record" "$(cat "$R/etc/certsmith/firewall.rules")"
  a=$(lineno "ufw allow from 203.0.113.0/24 to any port 443"); b=$(lineno "ufw --force delete allow 443/tcp")
  { [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]; } && pass "narrowing: the new rule goes in before the old one comes out" || fail "narrowing: order" "add@$a delete@$b"

  newcase narrowfail
  STUB_LISTEN=443 run
  : > "$LOG"
  STUB_UFW_FAIL="allow from" STUB_LISTEN=443 run --allow-from 203.0.113.0/24
  ! logged "ufw --force delete" && pass "narrowing: nothing is removed when a new rule could not be added" || fail "narrowing: kept the open rule on failure" "$(cat "$LOG")"

  newcase fwactive
  STUB_UFW=active STUB_LISTEN=443 run
  logged "ufw allow 443/tcp" && pass "active firewall: rule added" || fail "active firewall: rule added"
  ! logged "default deny" && ! logged "force enable" && pass "active firewall: policy left alone" || fail "active firewall: policy left alone"

  newcase nofw
  STUB_LISTEN=443 run --no-firewall
  ! logged "^ufw" && pass "--no-firewall leaves ufw alone" || fail "--no-firewall leaves ufw alone"

  newcase forcefw
  legacy_install "-listen 0.0.0.0:8443"
  STUB_LISTEN=8443 run --firewall
  logged "ufw allow 8443/tcp" && pass "--firewall applies rules on an upgrade" || fail "--firewall applies rules on an upgrade"

  newcase noupd
  STUB_LISTEN=443 run --no-auto-updates
  ! logged "^apt-get" && pass "--no-auto-updates" || fail "--no-auto-updates"

  newcase haveuu
  STUB_HAS_UU=1 STUB_LISTEN=443 run
  ! logged "apt-get install.*unattended" && pass "existing unattended-upgrades left as configured" || fail "existing unattended-upgrades left as configured"

  # ---- port 80 redirecting to the HTTPS page ----
  newcase redir
  STUB_LISTEN=443 run
  [ "$(envfile CERTSMITH_ARGS)" = "-http-redirect 0.0.0.0:80" ] && pass "new install on 443 enables the port-80 redirect" || fail "new install on 443 enables the port-80 redirect" "[$(envfile CERTSMITH_ARGS)]"
  logged "ufw allow 80/tcp" && pass "firewall: 80 opened with 443" || fail "firewall: 80 opened with 443"
  case "$OUT" in *"Port 80 redirects"*) pass "tells the user about the redirect" ;; *) fail "tells the user about the redirect" "$OUT" ;; esac

  newcase redirnets
  STUB_LISTEN=443 run --allow-from 203.0.113.0/24
  logged "ufw allow from 203.0.113.0/24 to any port 443 proto tcp" && logged "ufw allow from 203.0.113.0/24 to any port 80 proto tcp" \
    && pass "allow-from covers 443 and 80" || fail "allow-from covers 443 and 80" "$(cat "$LOG")"

  newcase redirport
  STUB_LISTEN=8443 run --listen 0.0.0.0:8443
  [ -z "$(envfile CERTSMITH_ARGS)" ] && ! logged "allow 80/tcp" && pass "a non-443 listen port gets no redirect by default" || fail "a non-443 listen port gets no redirect by default" "[$(envfile CERTSMITH_ARGS)]"

  newcase redirno
  STUB_LISTEN=443 run --no-http-redirect
  [ -z "$(envfile CERTSMITH_ARGS)" ] && ! logged "allow 80/tcp" && pass "--no-http-redirect on a new install" || fail "--no-http-redirect on a new install" "[$(envfile CERTSMITH_ARGS)]"

  newcase redirup
  legacy_install "-listen 0.0.0.0:443"
  STUB_LISTEN=443 run
  [ -z "$(envfile CERTSMITH_ARGS)" ] && pass "an upgrade does not add the redirect by itself" || fail "an upgrade does not add the redirect by itself" "[$(envfile CERTSMITH_ARGS)]"

  newcase redirupyes
  legacy_install "-listen 0.0.0.0:443"
  STUB_LISTEN=443 run --http-redirect --firewall
  [ "$(envfile CERTSMITH_ARGS)" = "-http-redirect 0.0.0.0:80" ] && pass "--http-redirect on an upgrade" || fail "--http-redirect on an upgrade" "[$(envfile CERTSMITH_ARGS)]"
  logged "ufw allow 80/tcp" && pass "--http-redirect --firewall opens 80" || fail "--http-redirect --firewall opens 80"

  newcase redirstrip
  legacy_install "-listen 0.0.0.0:443"
  mkdir -p "$R/etc/certsmith"
  printf 'CERTSMITH_LISTEN=0.0.0.0:443\nCERTSMITH_ARGS=-tls-dir /srv/tls -http-redirect 0.0.0.0:80 -foo\n' > "$R/etc/certsmith/certsmith.env"
  STUB_LISTEN=443 run --no-http-redirect
  [ "$(envfile CERTSMITH_ARGS)" = "-tls-dir /srv/tls -foo" ] && pass "--no-http-redirect removes only the redirect flag" || fail "--no-http-redirect removes only the redirect flag" "[$(envfile CERTSMITH_ARGS)]"

  newcase redirplain
  legacy_install "-listen 0.0.0.0:443 -no-tls"
  STUB_LISTEN=443 run --http-redirect
  [ "$(envfile CERTSMITH_ARGS)" = "-no-tls" ] && pass "no redirect is added to a plain-HTTP install" || fail "no redirect is added to a plain-HTTP install" "[$(envfile CERTSMITH_ARGS)]"
  case "$OUT" in *"nothing to redirect"*) pass "explains why" ;; *) fail "explains why" "$OUT" ;; esac

  newcase harden
  STUB_LISTEN=443 run --harden
  check "--harden writes the sysctl file" test -f "$R/etc/sysctl.d/90-certsmith-hardening.conf"

  newcase public
  STUB_ADDRS="203.0.113.9" STUB_LISTEN=443 run
  case "$OUT" in *"public address"*) pass "warns about a public address" ;; *) fail "warns about a public address" "$OUT" ;; esac

  newcase public6
  STUB_ADDRS="2a0e:1d47:cc85:c400:be24:11ff:fed1:f2d8 fe80::1" STUB_LISTEN=443 run
  case "$OUT" in *"public address"*) pass "warns about a global IPv6 address" ;; *) fail "warns about a global IPv6 address" "$OUT" ;; esac

  newcase private6
  STUB_ADDRS="fd12:3456:789a::1 fe80::1 ::1" STUB_LISTEN=443 run
  case "$OUT" in *"public address"*) fail "no warning for private and link-local IPv6" "$OUT" ;; *) pass "no warning for private and link-local IPv6" ;; esac

  # the result lists only addresses the firewall rules admit
  newcase reach4
  STUB_ADDRS="192.0.2.10 2a0e:1d47:cc85:c400::1" STUB_LISTEN=443 run --allow-from 203.0.113.0/24
  case "$OUT" in *"https://192.0.2.10/"*) pass "allowed IPv4 network: the IPv4 address is listed" ;; *) fail "IPv4 listed" "$OUT" ;; esac
  case "$OUT" in *"[2a0e"*) fail "allowed IPv4 network: the IPv6 address is not listed" "$OUT" ;; *) pass "allowed IPv4 network: the IPv6 address is not listed" ;; esac

  newcase reach6
  STUB_ADDRS="192.0.2.10 2a0e:1d47:cc85:c400::1" STUB_LISTEN=443 run --allow-from 2a0e:1d47::/32
  case "$OUT" in *"https://[2a0e:1d47:cc85:c400::1]/"*) pass "allowed IPv6 network: the IPv6 address is listed" ;; *) fail "IPv6 listed" "$OUT" ;; esac
  case "$OUT" in *"192.0.2.10"*) fail "allowed IPv6 network: the IPv4 address is not listed" "$OUT" ;; *) pass "allowed IPv6 network: the IPv4 address is not listed" ;; esac

  newcase reachboth
  STUB_ADDRS="192.0.2.10 2a0e:1d47:cc85:c400::1" STUB_LISTEN=443 run --allow-from 203.0.113.0/24,2a0e:1d47::/32
  case "$OUT" in *"192.0.2.10"*"[2a0e"*) pass "both families allowed: both are listed" ;; *) fail "both listed" "$OUT" ;; esac

  newcase reachany
  STUB_ADDRS="192.0.2.10 2a0e:1d47:cc85:c400::1" STUB_LISTEN=443 run
  case "$OUT" in *"192.0.2.10"*"[2a0e"*) pass "no network list: every address is listed" ;; *) fail "all listed" "$OUT" ;; esac

  newcase reachnofw
  STUB_ADDRS="192.0.2.10 2a0e:1d47:cc85:c400::1" STUB_LISTEN=443 run --allow-from 203.0.113.0/24 --no-firewall
  case "$OUT" in *"192.0.2.10"*"[2a0e"*) pass "firewall untouched: every address is listed" ;; *) fail "firewall untouched: all listed" "$OUT" ;; esac

  newcase badallow
  run --allow-from "1.2.3.4;reboot"
  [ "$RC" -ne 0 ] && ! logged "systemctl" && pass "rejects a hostile --allow-from before doing anything" || fail "rejects a hostile --allow-from before doing anything"
  newcase badlisten
  run --listen "nonsense"
  [ "$RC" -ne 0 ] && pass "rejects a bad --listen" || fail "rejects a bad --listen"
  newcase badopt
  run --frobnicate
  [ "$RC" -ne 0 ] && pass "rejects an unknown option" || fail "rejects an unknown option"

  newcase rollback
  legacy_install "-listen 0.0.0.0:8443"
  run   # nothing listens: the new version "fails to start"
  [ "$RC" -ne 0 ] && pass "failed start is reported" || fail "failed start is reported"
  [ "$("$R/usr/local/bin/certsmith")" = OLD ] && pass "failed start restores the previous program" || fail "failed start restores the previous program"
  check "failed start restores the previous unit" grep -q -- '-listen 0.0.0.0:8443' "$R/etc/systemd/system/certsmith.service"
  [ ! -f "$R/etc/certsmith/certsmith.env" ] && pass "failed start removes the env file it created" || fail "failed start removes the env file it created"

  newcase uninstall
  legacy_install "-listen 0.0.0.0:8443"
  mkdir -p "$R/etc/certsmith"; echo "allow 443/tcp" > "$R/etc/certsmith/firewall.rules"
  run --uninstall
  [ "$RC" -eq 0 ] && pass "uninstall succeeds" || fail "uninstall succeeds" "$OUT"
  [ ! -f "$R/usr/local/bin/certsmith" ] && [ ! -f "$R/etc/systemd/system/certsmith.service" ] && pass "uninstall removes program and unit" || fail "uninstall removes program and unit"
  [ -f "$R/var/lib/certsmith/db.json" ] && pass "uninstall keeps the data" || fail "uninstall keeps the data"
  logged "ufw --force delete allow 443/tcp" && pass "uninstall removes only rules it added" || fail "uninstall removes only rules it added"
  ! logged "userdel" && pass "uninstall keeps the service account" || fail "uninstall keeps the service account"

  newcase purge
  legacy_install "-listen 0.0.0.0:8443"
  run --uninstall --purge --yes
  [ ! -e "$R/var/lib/certsmith" ] && pass "--purge --yes deletes the data" || fail "--purge --yes deletes the data"
  logged "userdel certsmith" && pass "--purge removes the service account" || fail "--purge removes the service account"

  newcase purgeask
  legacy_install "-listen 0.0.0.0:8443"
  OUT=$(cd "$REL" && echo no | CERTSMITH_ROOT="$R" STUB_LOG="$LOG" PATH="$work/stubs:$PATH" "$SH" ./install.sh --uninstall --purge 2>&1); RC=$?
  [ "$RC" -ne 0 ] && [ -f "$R/var/lib/certsmith/db.json" ] && pass "--purge without confirmation keeps the data" || fail "--purge without confirmation keeps the data"
}

suite sh
if command -v dash >/dev/null 2>&1; then suite dash; fi

printf '\n%d passed, %d failed\n' "$passes" "$fails"
[ "$fails" -eq 0 ]
