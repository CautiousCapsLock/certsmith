# Command-line reference

Every option, flag and environment variable used by the scripts and the daemon. The
[README](../README.md) describes the common ones in context. `scripts/check-docs.sh` fails the
build if a switch exists in the code and is not mentioned in this file or the README.

- [get.sh: online installer](#getsh-online-installer)
- [install.sh: installer and upgrader](#installsh-installer-and-upgrader)
- [certsmith: the daemon](#certsmith-the-daemon)
- [certsmith reset-admin](#certsmith-reset-admin)
- [Environment variables](#environment-variables)
- [Files and paths](#files-and-paths)
- [Repository scripts](#repository-scripts)

## get.sh: online installer

Downloads a release, verifies its checksum and runs the installer packaged with it.

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh)" _ [installer options]
```

The first argument after the script (`_` above) is the shell's `$0` and is ignored. Every
argument after it is passed unchanged to `install.sh`, so any option in the next section can be
given. As a pipe: `curl -fsSL URL | sudo bash -s -- [installer options]`.

| Setting | Default | Purpose |
|---|---|---|
| `CERTSMITH_VERSION` | latest release | Release to install, for example `v0.12.0`. A leading `v` is optional. Pre-releases are installed only when named here. |
| `CERTSMITH_REPO` | `CautiousCapsLock/certsmith` | `owner/name` of the repository that publishes the releases. |
| `CERTSMITH_BASE_URL` | `https://github.com` | Base address of the download host. For testing only. |

Behaviour:

1. Requires Linux, `curl` and `tar`, and an amd64 or arm64 CPU.
2. Resolves the release, downloads `certsmith-<version>-linux-<arch>.tar.gz` and `SHA256SUMS`.
3. Stops, before unpacking, if the archive's SHA-256 is missing from or differs from `SHA256SUMS`.
4. Stops if the archive contains any path outside its own directory.
5. Runs `install.sh` from the unpacked directory: directly when run as root, otherwise through `sudo`.
6. Removes its temporary directory on every exit path.

The checksum is published with the release. It detects a damaged or incomplete download; it does
not authenticate the publisher.

## install.sh: installer and upgrader

Run from the unpacked release directory, which must contain `certsmith.service` and the program
file `certsmith-linux-<arch>`. Needs root and systemd. Safe to run again: a second run is an
upgrade. Options accept either `--option value` or `--option=value`.

| Option | Default | Effect |
|---|---|---|
| `--listen ADDR:PORT` | New install: `0.0.0.0:443`. Upgrade: the current address. | Address of the web interface. Written to `/etc/certsmith/certsmith.env`. |
| `--allow-from LIST` | `any` | Comma-separated addresses or networks (or the word `any`) allowed to reach the web interface and the redirect port. Applies firewall rules even on an upgrade. When narrowing from `any`, the open-to-any rules this installer added earlier for the same ports are removed after the new rules are in place. Each value is validated: only hexadecimal digits, `:`, `.` and `/` are accepted. |
| `--firewall` | | Apply firewall rules on an upgrade (a new install always does, unless `--no-firewall`). |
| `--no-firewall` | | Never touch the firewall. |
| `--http-redirect` | New install on 443: on. Upgrade: unchanged. | Listen on `0.0.0.0:80` and redirect to HTTPS. Not applied when the interface is plain HTTP (`-no-tls`). |
| `--no-http-redirect` | | Do not listen on port 80. Removes an existing redirect. |
| `--no-auto-updates` | | Do not install or enable `unattended-upgrades` (new install only). An existing configuration is never changed. |
| `--harden` | off | Install `/etc/sysctl.d/90-certsmith-hardening.conf` and apply it. Opt-in because reverse-path filtering can break asymmetric routing. |
| `--binary PATH` | `./certsmith-linux-<arch>` | Program file to install. A bare path argument is treated the same way. |
| `--uninstall` | | Stop and remove the service, program, unit file, settings file and the firewall rules this installer added. Data is kept. |
| `--purge` | | With `--uninstall`: delete `/var/lib/certsmith` and the `certsmith` account. Asks for the word `DELETE` unless `--yes` is given. |
| `--yes`, `-y` | | Do not ask for confirmation (used with `--purge`). |
| `--help`, `-h` | | Print the option list and exit. |

Behaviour that is not an option:

- **New or upgrade.** An install is an upgrade when the unit file, the program or `db.json` already exists. Only a new install touches the firewall, `unattended-upgrades` and the redirect, unless an option above asks.
- **Never changes networking** (address, gateway, DNS).
- **Keeps the current SSH session.** When it turns the firewall on, the SSH ports in use are allowed first, from any source, as they were before the firewall existed. `--allow-from` does not narrow SSH, so a typo cannot lock you out. Narrow it yourself once you have confirmed access: `ufw delete allow 22/tcp` then `ufw allow from NETWORK to any port 22 proto tcp`.
- **Keeps the listen address.** A first-release unit file with inline `-listen`/`-no-tls` flags is migrated into the settings file.
- **Rolls back.** If the service is not listening within the wait time, the previous program, unit file and settings file are restored.
- **Lists only reachable addresses.** The result names the addresses the firewall rules admit. With `--allow-from`, an address family that none of the listed networks belongs to (for example IPv6 when only IPv4 networks are given) is left out, and is not warned about.
- **Warns** when the host has a public IPv4 address or a global IPv6 address (`2000::/3`) and `--allow-from` was not given. The firewall rule for a port applies to both IPv4 and IPv6 on a host where `ufw` has IPv6 enabled, which is the Ubuntu default.

| Variable | Default | Purpose |
|---|---|---|
| `CERTSMITH_WAIT` | `20` | Seconds to wait for the service to start listening before rolling back. |
| `CERTSMITH_ROOT` | empty | Prefix for every path the installer writes. For testing only; `scripts/test-install.sh` uses it. |

## certsmith: the daemon

```sh
certsmith [flags]
```

| Flag | Default | Purpose |
|---|---|---|
| `-data DIR` | `./data` | Data directory: database, keys, certificates. Created with mode 0700. |
| `-listen ADDR` | `127.0.0.1:8443` | Address of the web interface. The packaged unit sets this from `CERTSMITH_LISTEN`. |
| `-tls-dir DIR` | `<data>/ui-tls` | Directory holding `fullchain.pem` and `key.pem` for the web interface. A self-signed pair is created if none exists. |
| `-http-redirect ADDR` | none | Also listen for plain HTTP on this address and answer GET and HEAD with a temporary redirect to the HTTPS page. Other methods get 405. Ignored with `-no-tls`. A bind failure is logged and does not stop the daemon. |
| `-no-tls` | off | Serve the web interface over plain HTTP. Only for use behind a reverse proxy on the same host that terminates TLS. |
| `-version` | | Print the version and exit. |
| `-h`, `-help` | | Print the flag list and exit. |

## certsmith reset-admin

Offline account recovery. Stop the service first and run as the service user.

```sh
certsmith reset-admin -data DIR [-user NAME]
certsmith reset-admin -data DIR -wipe
```

| Flag | Default | Purpose |
|---|---|---|
| `-data DIR` | `./data` | Data directory of the installation. |
| `-user NAME` | the only user | User to reset. Required when more than one user exists. |
| `-wipe` | off | Remove all users instead, so the first-run setup wizard appears again. |

Without `-wipe`, a new random password is set for the user and printed once. The password hash in the database is replaced; nothing else is changed.

## Environment variables

### Daemon

| Variable | Default | Purpose |
|---|---|---|
| `CERTSMITH_LISTEN` | `0.0.0.0:443` | Read by the systemd unit from `/etc/certsmith/certsmith.env`; becomes `-listen`. |
| `CERTSMITH_ARGS` | empty | Read by the systemd unit from the same file; extra daemon flags such as `-http-redirect 0.0.0.0:80` or `-no-tls`. |
| `CERTSMITH_ADMIN_PASSWORD` | unset | Creates the first administrator at start-up, for automated installs, instead of the setup wizard. At least 12 characters. Ignored once any user exists, and when empty. |
| `CERTSMITH_ADMIN_USER` | `admin` | User name for the account created from `CERTSMITH_ADMIN_PASSWORD`. |
| `CERTSMITH_ALLOW_COMMANDS` | unset | Set to `1` to permit the local-files target to run its post-deployment command. |
| `CERTSMITH_REPO` | `CautiousCapsLock/certsmith` | `owner/name` of the repository the daemon asks for newer releases. The same variable selects the repository for `get.sh`. |
| `CERTSMITH_UPDATE_API` | `https://api.github.com` | Base address of the release API. For testing only. |
| `CERTSMITH_MASTER_KEY` | unset | The key that encrypts stored credentials: 64 hexadecimal characters (32 bytes). When set it is used instead of `<data>/master.key`, and no file is created. It must then be supplied on every start; losing it makes stored credentials unrecoverable. |

### Update check

The daemon asks the release API for the latest published release once a day (an hour after a failure) and
when **Settings → Software → Check now** is used. It reads one JSON document, sends only the request itself
and a `User-Agent` of `certsmith/<version>`, and never downloads or installs anything. Pre-releases and drafts
are ignored. The automatic check is on by default and is switched off with **Check for updates automatically**
in Settings; a manual check works either way. Nothing is installed from the web interface: an available
update shows the install command to run on the server.

### Provided to a post-deployment command

The local-files target runs its command with the daemon's environment plus:

| Variable | Value |
|---|---|
| `CERTSMITH_CERT_DIR` | The directory the certificate files were written to. |
| `CERTSMITH_SERIAL` | Serial number of the deployed certificate. |

### Scripts

| Variable | Used by | Purpose |
|---|---|---|
| `CERTSMITH_VERSION`, `CERTSMITH_REPO`, `CERTSMITH_BASE_URL` | `get.sh` | See [get.sh](#getsh-online-installer). `CERTSMITH_REPO` is also read by the daemon. |
| `CERTSMITH_WAIT`, `CERTSMITH_ROOT` | `install.sh` | See [install.sh](#installsh-installer-and-upgrader). |
| `CHECK_EXTRA_PATTERN` | `scripts/check-private-addrs.sh` | Extended regular expression forbidden in tracked source, in addition to private-range addresses. In CI it is read from the repository variable of the same name, so the value need not be committed. |

## Files and paths

| Path | Contents |
|---|---|
| `/usr/local/bin/certsmith` | The program. |
| `/etc/systemd/system/certsmith.service` | The systemd unit. |
| `/usr/share/doc/certsmith/THIRD_PARTY_NOTICES.txt` | The licences of the software bundled in the program. Also served by the web interface at `/THIRD_PARTY_NOTICES.txt`. |
| `/etc/certsmith/certsmith.env` | `CERTSMITH_LISTEN` and `CERTSMITH_ARGS`. Created once; never overwritten by an upgrade. |
| `/etc/certsmith/firewall.rules` | The firewall rules the installer added, so `--uninstall` removes only those. |
| `/var/lib/certsmith/` | State: `db.json`, `master.key`, `session.key`, `acme/`, `certs/`, `targets/`, `ui-tls/`. |
| `/var/lib/certsmith/ui-tls/` | The web interface's certificate (`fullchain.pem`, `key.pem`). The self-signed one CertSmith creates is valid for five years, covers the host name and addresses present when it was made, is renewed 30 days before it expires, and can be regenerated in Settings. A certificate that CertSmith did not create is never replaced by either. |
| `/etc/sysctl.d/90-certsmith-hardening.conf` | Written only with `--harden`. |
| `/etc/apt/apt.conf.d/20auto-upgrades` | Written only when `unattended-upgrades` was not already configured. |

## Repository scripts

| Script | Purpose |
|---|---|
| `scripts/test-install.sh` | Tests `deploy/install.sh` with stubbed system commands, under `sh` and `dash`. |
| `scripts/test-get.sh` | Tests `get.sh` with a stubbed network, under `sh` and `dash`. |
| `scripts/check-private-addrs.sh` | Fails if a private-range IPv4 address appears in tracked source (tests and Markdown excepted). |
| `scripts/check-docs.sh` | Fails if an option, flag or environment variable in the code is not documented. |
| `scripts/update-deps.sh check` / `apply` | Lists newer dependency versions and newer major versions of direct modules; or bumps the direct modules to the latest release and everything else to the latest patch, regenerates the notices, and runs the build, vet, tests and `govulncheck`. See [DEPENDENCIES.md](DEPENDENCIES.md). |
| `go run ./scripts/notices` | Regenerates `internal/web/static/THIRD_PARTY_NOTICES.txt` from the licence files of the modules compiled into the binary. With `-check` it fails if the file is out of date. It also fails when a dependency's licence is not on the allowlist (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0). |
