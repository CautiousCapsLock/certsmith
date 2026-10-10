#!/bin/sh
# CertSmith installer and upgrader for systemd hosts (Debian and Ubuntu are what it is
# tested on). Run as root from the directory of an unpacked release:
#
#     sh install.sh [options]        (sh install.sh --help for the list)
#
# A NEW install listens on 443 (with port 80 redirecting to it), gets a host firewall and
# automatic security updates.
# An UPGRADE replaces the program and the unit file and changes nothing else: the listen
# address, the firewall and the operating system stay as they are unless you ask.
# It never touches networking (address, gateway, DNS).
set -eu

# CERTSMITH_ROOT is a test hook: a prefix for every file this script writes.
ROOT="${CERTSMITH_ROOT:-}"
DATA_DIR=/var/lib/certsmith
BIN_PATH="$ROOT/usr/local/bin/certsmith"
UNIT_PATH="$ROOT/etc/systemd/system/certsmith.service"
CONF_DIR="$ROOT/etc/certsmith"
ENV_PATH="$CONF_DIR/certsmith.env"
FW_RECORD="$CONF_DIR/firewall.rules"
DEFAULT_LISTEN="0.0.0.0:443"
REDIRECT_ADDR="0.0.0.0:80"
WAIT_SECS="${CERTSMITH_WAIT:-20}"

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  cat <<'EOF'
Usage: sh install.sh [options]

  --listen ADDR:PORT     address for the web page. New installs default to
                         0.0.0.0:443. Upgrades keep the current one.
                         Settings are kept in /etc/certsmith/certsmith.env.
  --allow-from LIST      comma-separated networks allowed to reach the web page, for
                         example 192.0.2.0/24,198.51.100.7 (default: any). Applies the
                         firewall rules even on an upgrade.
  --http-redirect        make port 80 redirect to the HTTPS page (the default on a new
                         install that listens on 443). Applies on an upgrade too.
  --no-http-redirect     do not listen on port 80.
  --firewall             apply firewall rules on an upgrade too.
  --no-firewall          never touch the firewall.
  --no-auto-updates      do not enable unattended security updates (new installs).
  --harden               also install the kernel network hardening file
                         (/etc/sysctl.d/90-certsmith-hardening.conf). Off by default
                         because reverse-path filtering can affect multi-homed hosts.
  --binary PATH          program to install (default: certsmith-linux-<arch> here).
  --uninstall            stop and remove the service. Data in /var/lib/certsmith is kept.
  --purge                with --uninstall: also delete the data and the service account.
  --yes                  do not ask for confirmation (with --purge).
  -h, --help             this text.
EOF
}

# ---- options ---------------------------------------------------------------
LISTEN=""; ALLOW=""; DO_FW=auto; DO_UPD=yes; HARDEN=0; HTTP_REDIR=auto
BIN=""; UNINSTALL=0; PURGE=0; YES=0

need_value() { [ $# -ge 2 ] || die "$1 needs a value"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --listen)           need_value "$@"; LISTEN="$2"; shift 2 ;;
    --listen=*)         LISTEN="${1#*=}"; shift ;;
    --allow-from)       need_value "$@"; ALLOW="$2"; shift 2 ;;
    --allow-from=*)     ALLOW="${1#*=}"; shift ;;
    --binary)           need_value "$@"; BIN="$2"; shift 2 ;;
    --binary=*)         BIN="${1#*=}"; shift ;;
    --firewall)         DO_FW=yes; shift ;;
    --no-firewall)      DO_FW=no; shift ;;
    --http-redirect)    HTTP_REDIR=yes; shift ;;
    --no-http-redirect) HTTP_REDIR=no; shift ;;
    --no-auto-updates)  DO_UPD=no; shift ;;
    --harden)           HARDEN=1; shift ;;
    --uninstall)        UNINSTALL=1; shift ;;
    --purge)            PURGE=1; shift ;;
    --yes|-y)           YES=1; shift ;;
    -h|--help)          usage; exit 0 ;;
    -*)                 usage >&2; die "unknown option: $1" ;;
    *)                  # a bare path is the binary, as in earlier releases
                        [ -z "$BIN" ] || die "unexpected argument: $1"
                        BIN="$1"; shift ;;
  esac
done

# ---- validation (everything below is passed to other programs as arguments) ----
valid_listen() {
  case "$1" in *:*) ;; *) return 1 ;; esac
  _p="${1##*:}"; _h="${1%:*}"
  case "$_p" in ''|*[!0-9]*) return 1 ;; esac
  [ "$_p" -ge 1 ] && [ "$_p" -le 65535 ] || return 1
  case "$_h" in *[!]0-9A-Za-z.:[-]*) return 1 ;; esac
  return 0
}
valid_net() {  # "any", an address, or an address/prefix
  [ "$1" = any ] && return 0
  case "$1" in ''|*[!0-9A-Fa-f:./]*) return 1 ;; esac
  case "$1" in */*/*) return 1 ;; esac
  return 0
}

[ -z "$LISTEN" ] || valid_listen "$LISTEN" || die "--listen must look like 0.0.0.0:443 or [::]:443"
if [ -n "$ALLOW" ]; then
  for _n in $(printf '%s' "$ALLOW" | tr ',' ' '); do
    valid_net "$_n" || die "--allow-from: not an address or network: $_n"
  done
  [ "$DO_FW" != auto ] || DO_FW=yes
fi

# ---- preflight ---------------------------------------------------------------
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || die "run as root (for example: sudo sh install.sh)"
[ -n "$ROOT" ] || [ -d /run/systemd/system ] || die "this installer needs a systemd host"

OWN="-o root -g root"; [ -z "$ROOT" ] || OWN=""

# ---- uninstall -----------------------------------------------------------------
if [ "$UNINSTALL" -eq 1 ]; then
  say "Stopping and removing CertSmith..."
  systemctl disable --now certsmith.service >/dev/null 2>&1 || true
  rm -f "$UNIT_PATH" "$UNIT_PATH.prev" "$BIN_PATH" "$BIN_PATH.prev" "$BIN_PATH.new"
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [ -f "$FW_RECORD" ] && have ufw; then
    while IFS= read -r _spec; do
      [ -n "$_spec" ] || continue
      # shellcheck disable=SC2086  # the spec is words we recorded ourselves
      ufw --force delete $_spec >/dev/null 2>&1 || true
      say "removed firewall rule: $_spec"
    done < "$FW_RECORD"
  fi
  rm -f "$ENV_PATH" "$FW_RECORD"; rmdir "$CONF_DIR" 2>/dev/null || true
  rm -f "$ROOT/usr/share/doc/certsmith/THIRD_PARTY_NOTICES.txt"; rmdir "$ROOT/usr/share/doc/certsmith" 2>/dev/null || true
  if [ "$PURGE" -eq 1 ]; then
    if [ "$YES" -ne 1 ]; then
      printf 'This permanently deletes %s (database, keys, certificates). Type DELETE to continue: ' "$DATA_DIR"
      read -r _ans || _ans=""
      [ "$_ans" = DELETE ] || die "not confirmed; data kept"
    fi
    rm -rf "$ROOT$DATA_DIR"
    userdel certsmith >/dev/null 2>&1 || true
    say "Data and service account removed."
  else
    say "Data kept in $DATA_DIR (add --purge to delete it)."
  fi
  say "Not changed: unattended-upgrades, sysctl hardening, any firewall rule not added by this installer."
  exit 0
fi

# ---- inputs ---------------------------------------------------------------------
if [ -z "$BIN" ]; then
  case "$(uname -m)" in
    x86_64|amd64)  BIN="./certsmith-linux-amd64" ;;
    aarch64|arm64) BIN="./certsmith-linux-arm64" ;;
    *) die "unsupported architecture $(uname -m); pass --binary PATH" ;;
  esac
fi
UNIT_SRC="./certsmith.service"
[ -f "$BIN" ]      || die "program not found: $BIN (run from the unpacked release, or use --binary)"
[ -f "$UNIT_SRC" ] || die "unit file not found: $UNIT_SRC (run from the unpacked release)"

# ---- fresh install or upgrade? -----------------------------------------------------
FRESH=1
if [ -f "$UNIT_PATH" ] || [ -f "$BIN_PATH" ] || [ -f "$ROOT$DATA_DIR/db.json" ]; then FRESH=0; fi

# Work out the listen address and extra flags for an existing install, so an upgrade
# never moves the web page. The first release used a unit file with the flags inline.
env_get() { [ -f "$ENV_PATH" ] && sed -n "s/^$1=//p" "$ENV_PATH" | tail -1; return 0; }

legacy_unit() {  # sets LEG_LISTEN and LEG_ARGS from an inline ExecStart
  LEG_LISTEN=""; LEG_ARGS=""
  [ -f "$UNIT_PATH" ] || return 0
  _line=$(sed -n 's/^ExecStart=//p' "$UNIT_PATH" | head -1)
  case "$_line" in *'${CERTSMITH_LISTEN}'*) return 0 ;; esac   # already the new form
  # shellcheck disable=SC2086
  set -- $_line
  [ $# -gt 0 ] && shift       # the program path
  while [ $# -gt 0 ]; do
    case "$1" in
      -data|--data)     shift; [ $# -gt 0 ] && shift ;;
      -data=*|--data=*) shift ;;
      -listen|--listen) shift; [ $# -gt 0 ] && { LEG_LISTEN="$1"; shift; } ;;
      -listen=*|--listen=*) LEG_LISTEN="${1#*=}"; shift ;;
      *) LEG_ARGS="${LEG_ARGS:+$LEG_ARGS }$1"; shift ;;
    esac
  done
}

CUR_LISTEN=$(env_get CERTSMITH_LISTEN)
CUR_ARGS=$(env_get CERTSMITH_ARGS)
if [ -z "$CUR_LISTEN" ]; then
  legacy_unit
  CUR_LISTEN="$LEG_LISTEN"; [ -n "$CUR_ARGS" ] || CUR_ARGS="$LEG_ARGS"
fi

if   [ -n "$LISTEN" ];      then :
elif [ -n "$CUR_LISTEN" ];  then LISTEN="$CUR_LISTEN"
else                             LISTEN="$DEFAULT_LISTEN"
fi
PORT="${LISTEN##*:}"

# Port 80 redirecting to the HTTPS page. New installs on 443 get it; an upgrade only
# changes it when asked.
ORIG_ARGS="$CUR_ARGS"
has_flag() {  # has_flag "$ARGS" -name   (-name, --name, -name=value)
  case " $1 " in *" $2 "*|*" -$2 "*|*" $2="*|*" -$2="*) return 0 ;; esac
  return 1
}
strip_flag() {  # strip_flag "$ARGS" -name   removes the flag and its value
  set -- "$1" "$2"; _in="$1"; _name="$2"; _out=""
  # shellcheck disable=SC2086
  set -- $_in
  while [ $# -gt 0 ]; do
    case "$1" in
      "$_name"|"-$_name") shift; [ $# -gt 0 ] && shift ;;
      "$_name="*|"-$_name="*) shift ;;
      *) _out="${_out:+$_out }$1"; shift ;;
    esac
  done
  printf '%s' "$_out"
}
PLAIN=0; has_flag "$CUR_ARGS" -no-tls && PLAIN=1
has_flag "$CUR_ARGS" -no-tls=true && PLAIN=1
WANT_REDIRECT=0
case "$HTTP_REDIR" in
  yes)  WANT_REDIRECT=1 ;;
  no)   WANT_REDIRECT=0 ;;
  auto) if has_flag "$CUR_ARGS" -http-redirect; then WANT_REDIRECT=1
        elif [ "$FRESH" -eq 1 ] && [ "$PORT" = 443 ] && [ "$PLAIN" -eq 0 ]; then WANT_REDIRECT=1
        fi ;;
esac
if [ "$WANT_REDIRECT" -eq 1 ] && [ "$PLAIN" -eq 1 ]; then
  warn "the page is served as plain HTTP (-no-tls), so there is nothing to redirect to; not enabling the redirect"
  WANT_REDIRECT=0
fi
if [ "$WANT_REDIRECT" -eq 1 ]; then
  has_flag "$CUR_ARGS" -http-redirect || CUR_ARGS="${CUR_ARGS:+$CUR_ARGS }-http-redirect $REDIRECT_ADDR"
else
  CUR_ARGS=$(strip_flag "$CUR_ARGS" -http-redirect)
fi
# the port the redirect listens on, for the firewall
REDIRECT_PORT=""
if [ "$WANT_REDIRECT" -eq 1 ]; then
  # shellcheck disable=SC2086
  set -- $CUR_ARGS
  while [ $# -gt 0 ]; do
    case "$1" in
      -http-redirect|--http-redirect) REDIRECT_PORT="${2##*:}"; break ;;
      -http-redirect=*|--http-redirect=*) _v="${1#*=}"; REDIRECT_PORT="${_v##*:}"; break ;;
    esac
    shift
  done
  case "$REDIRECT_PORT" in ''|*[!0-9]*) REDIRECT_PORT=80 ;; esac
fi

# ---- install ---------------------------------------------------------------------------
if ! id certsmith >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir "$DATA_DIR" \
          --shell /usr/sbin/nologin --comment "CertSmith service" certsmith
fi

mkdir -p "$ROOT/usr/local/bin" "$ROOT/etc/systemd/system" "$CONF_DIR"

# keep the previous program and unit so a failed start can be undone
[ ! -f "$BIN_PATH" ]  || cp -p "$BIN_PATH"  "$BIN_PATH.prev"
[ ! -f "$UNIT_PATH" ] || cp -p "$UNIT_PATH" "$UNIT_PATH.prev"
HAD_ENV=0; [ ! -f "$ENV_PATH" ] || { HAD_ENV=1; cp -p "$ENV_PATH" "$ENV_PATH.prev"; }

# shellcheck disable=SC2086
install -m 0755 $OWN "$BIN" "$BIN_PATH.new"
mv -f "$BIN_PATH.new" "$BIN_PATH"
# shellcheck disable=SC2086
install -m 0644 $OWN "$UNIT_SRC" "$UNIT_PATH"
# the licences of the bundled components travel with the program
if [ -f ./THIRD_PARTY_NOTICES.txt ]; then
  mkdir -p "$ROOT/usr/share/doc/certsmith"
  # shellcheck disable=SC2086
  install -m 0644 $OWN ./THIRD_PARTY_NOTICES.txt "$ROOT/usr/share/doc/certsmith/THIRD_PARTY_NOTICES.txt"
fi

if [ "$HAD_ENV" -eq 0 ] || [ "$LISTEN" != "$CUR_LISTEN" ] || [ "$CUR_ARGS" != "$ORIG_ARGS" ]; then
  umask 022
  {
    echo "# Written by install.sh. Read by certsmith.service; edit and run"
    echo "#   systemctl restart certsmith"
    echo "# Upgrades keep this file."
    echo "CERTSMITH_LISTEN=$LISTEN"
    echo "# Extra flags, for example -no-tls when a reverse proxy terminates TLS on this host."
    echo "CERTSMITH_ARGS=$CUR_ARGS"
  } > "$ENV_PATH.new"
  mv -f "$ENV_PATH.new" "$ENV_PATH"
fi

systemctl daemon-reload
systemctl enable certsmith.service >/dev/null 2>&1 || true
systemctl restart certsmith.service

wait_listening() {
  _n=0
  while [ "$_n" -lt "$WAIT_SECS" ]; do
    if have ss; then
      ss -ltn 2>/dev/null | grep -q "[:.]$1[[:space:]]" && return 0
    else
      systemctl is-active --quiet certsmith.service && return 0
    fi
    _n=$((_n + 1)); sleep 1
  done
  return 1
}

if ! wait_listening "$PORT"; then
  warn "CertSmith did not start listening on port $PORT."
  have journalctl && journalctl -u certsmith.service -n 15 --no-pager >&2 || true
  if [ -f "$BIN_PATH.prev" ]; then
    warn "restoring the previous version"
    mv -f "$BIN_PATH.prev" "$BIN_PATH"
    [ ! -f "$UNIT_PATH.prev" ] || mv -f "$UNIT_PATH.prev" "$UNIT_PATH"
    if [ "$HAD_ENV" -eq 1 ]; then mv -f "$ENV_PATH.prev" "$ENV_PATH"; else rm -f "$ENV_PATH"; fi
    systemctl daemon-reload
    systemctl restart certsmith.service || true
  fi
  die "install failed"
fi
rm -f "$BIN_PATH.prev" "$UNIT_PATH.prev" "$ENV_PATH.prev"

# ---- host configuration: new installs only, or when asked ------------------------------
ssh_ports() {
  {
    if [ -n "${SSH_CONNECTION:-}" ]; then
      # shellcheck disable=SC2086
      set -- $SSH_CONNECTION; [ $# -ge 4 ] && echo "$4"
    fi
    have sshd && sshd -T 2>/dev/null | sed -n 's/^port //p'
    have ss   && ss -H -ltnp 2>/dev/null | awk '/sshd/ { n = split($4, a, ":"); print a[n] }'
    true
  } | grep -E '^[0-9]+$' | sort -u
}

FW_NOTE=""
setup_firewall() {
  if ! have ufw && have apt-get; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null 2>&1 || true
  fi
  if ! have ufw; then
    FW_NOTE="ufw is not available, so no firewall rules were added."
    return 0
  fi
  _active=0
  ufw status 2>/dev/null | head -1 | grep -qi 'status: active' && _active=1
  : > "$FW_RECORD.new"
  [ ! -f "$FW_RECORD" ] || cat "$FW_RECORD" >> "$FW_RECORD.new"

  if [ "$_active" -eq 0 ]; then
    # about to switch the firewall on: keep the session this script is running in
    for _p in $(ssh_ports); do
      ufw allow "$_p/tcp" >/dev/null 2>&1 || true
      say "firewall: kept SSH open on $_p/tcp"
    done
    ufw default deny incoming  >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
  fi

  _failed=0; _narrowing=0
  for _port in $PORT $REDIRECT_PORT; do
    for _n in $(printf '%s' "${ALLOW:-any}" | tr ',' ' '); do
      if [ "$_n" = any ]; then _spec="allow $_port/tcp"
      else                     _spec="allow from $_n to any port $_port proto tcp"; _narrowing=1
      fi
      # shellcheck disable=SC2086  # words validated above
      _out=$(ufw $_spec 2>&1) || { warn "ufw: $_out"; _failed=1; continue; }
      case "$_out" in
        *"Skipping adding existing rule"*) say "firewall: already present: $_spec" ;;
        *) echo "$_spec" >> "$FW_RECORD.new"; say "firewall: $_spec" ;;
      esac
    done
  done

  # Narrowing to specific networks must also take away the open-to-any rule this installer added on an
  # earlier run, or the new rules change nothing. Done only after every new rule is in place, so a
  # failure cannot leave the port closed, and only for rules recorded as ours.
  if [ "$_narrowing" -eq 1 ] && [ "$_failed" -eq 0 ]; then
    for _port in $PORT $REDIRECT_PORT; do
      _old="allow $_port/tcp"
      if grep -qxF "$_old" "$FW_RECORD.new" 2>/dev/null; then
        if ufw --force delete $_old >/dev/null 2>&1; then
          grep -vxF "$_old" "$FW_RECORD.new" > "$FW_RECORD.tmp" || true
          mv -f "$FW_RECORD.tmp" "$FW_RECORD.new"
          say "firewall: removed the open-to-any rule: $_old"
        else
          warn "could not remove the open-to-any rule '$_old'; remove it with: ufw delete $_old"
        fi
      elif ufw status 2>/dev/null | grep -E "^$_port/tcp +ALLOW +Anywhere" >/dev/null; then
        warn "an existing firewall rule still allows $_port/tcp from any source (it was not added by this installer); remove it with: ufw delete allow $_port/tcp"
      fi
    done
  fi

  if [ "$_active" -eq 0 ]; then
    ufw --force enable >/dev/null 2>&1 || warn "could not enable ufw"
  fi
  mv -f "$FW_RECORD.new" "$FW_RECORD"
}

setup_auto_updates() {
  have apt-get || return 0
  if have dpkg && dpkg -s unattended-upgrades >/dev/null 2>&1; then
    say "automatic updates: unattended-upgrades is already installed, left as configured"
    return 0
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq unattended-upgrades >/dev/null 2>&1 \
    || { warn "could not install unattended-upgrades"; return 0; }
  _f="$ROOT/etc/apt/apt.conf.d/20auto-upgrades"
  if [ ! -f "$_f" ]; then
    mkdir -p "$(dirname "$_f")"
    printf 'APT::Periodic::Update-Package-Lists "1";\nAPT::Periodic::Unattended-Upgrade "1";\n' > "$_f"
  fi
  say "automatic updates: security updates enabled (no automatic reboot)"
}

harden_kernel() {
  _f="$ROOT/etc/sysctl.d/90-certsmith-hardening.conf"
  mkdir -p "$(dirname "$_f")"
  cat > "$_f" <<'EOF'
# Installed by CertSmith install.sh --harden. Remove the file to undo.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF
  if have sysctl; then
    sysctl -p "$_f" >/dev/null 2>&1 || warn "some kernel settings could not be applied (normal inside a container)"
  fi
  say "hardening: wrote $_f"
}

if [ "$DO_FW" = yes ] || { [ "$DO_FW" = auto ] && [ "$FRESH" -eq 1 ]; }; then
  setup_firewall
elif [ "$DO_FW" = no ]; then
  FW_NOTE="firewall: left alone (--no-firewall)"
elif [ "$FRESH" -eq 0 ]; then
  FW_NOTE="firewall: left alone on upgrade (use --firewall or --allow-from to apply rules)"
fi
if [ "$FRESH" -eq 1 ] && [ "$DO_UPD" = yes ]; then setup_auto_updates; fi
if [ "$HARDEN" -eq 1 ]; then harden_kernel; fi

# ---- result ---------------------------------------------------------------------------------
VERSION=$("$BIN_PATH" -version 2>/dev/null | head -1 || true)
SCHEME=https
case " $CUR_ARGS " in *" -no-tls "*|*" -no-tls=true "*|*" --no-tls "*) SCHEME=http ;; esac
SUFFIX=":$PORT"; [ "$PORT" != 443 ] || [ "$SCHEME" != https ] || SUFFIX=""

ADDRS=$(hostname -I 2>/dev/null || true)
[ -n "$ADDRS" ] || ADDRS=$(ip -4 -o addr show scope global 2>/dev/null | awk '{ sub(/\/.*/, "", $4); print $4 }' | tr '\n' ' ')

say ""
if [ "$FRESH" -eq 1 ]; then say "CertSmith ${VERSION:+($VERSION) }is installed."; else say "CertSmith ${VERSION:+($VERSION) }is upgraded."; fi
for _a in $ADDRS; do
  case "$_a" in *:*) _u="[$_a]" ;; *) _u="$_a" ;; esac
  say "  Open  $SCHEME://$_u$SUFFIX/"
done
[ -z "$REDIRECT_PORT" ] || say "  Port $REDIRECT_PORT redirects to the HTTPS page."
[ -n "$ADDRS" ] || say "  Open  $SCHEME://<this host>$SUFFIX/"

CERT="$ROOT$DATA_DIR/ui-tls/fullchain.pem"
if [ "$SCHEME" = https ] && have openssl; then
  _n=0; while [ ! -f "$CERT" ] && [ "$_n" -lt 10 ]; do sleep 1; _n=$((_n + 1)); done
  if [ -f "$CERT" ]; then
    _fp=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 2>/dev/null | sed 's/^.*=//')
    [ -z "$_fp" ] || say "  Certificate fingerprint (SHA-256): $_fp"
  fi
fi
if [ "$FRESH" -eq 1 ]; then
  [ "$SCHEME" != https ] || say "  Expect a browser warning at first: the page starts with a self-signed certificate."
  say "  The first visit asks you to create the administrator account."
fi
[ -z "$FW_NOTE" ] || say "  $FW_NOTE"

# a public address means the login page is reachable from the Internet unless filtered
_public=""
for _a in $ADDRS; do
  case "$_a" in
    # IPv6: global unicast is 2000::/3 (first digit 2 or 3). fe80:: (link-local), fc00::/7
    # (private) and ::1 (loopback) are not reachable from the Internet.
    *:*) case "$_a" in 2*|3*) _public="$_public $_a" ;; esac ;;
    10.*|192.168.*|169.254.*|127.*) ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) ;;
    *) _public="$_public $_a" ;;
  esac
done
if [ -n "$_public" ] && [ -z "$ALLOW" ]; then
  say ""
  warn "this host has a public address ($_public ): the web page is reachable from the Internet. Use --allow-from to limit it."
fi
exit 0
