# CertSmith

CertSmith automates the lifecycle of TLS certificates. It obtains certificates from an ACME certificate authority using DNS-01 validation, renews them before they expire, deploys them to network devices and services through their APIs, and verifies that each device is serving the new certificate. It runs as a single daemon with an embedded web interface.

> **AI-assisted software.** CertSmith was designed and written with the assistance of an artificial intelligence system. See [AI-assisted development](#ai-assisted-development) before deploying it.

## Contents

- [Quick install](#quick-install)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [First use](#first-use)
- [Configuration](#configuration)
- [Data and backup](#data-and-backup)
- [Security](#security)
- [Building from source](#building-from-source)
- [AI-assisted development](#ai-assisted-development)
- [Licence](#licence)

## Quick install

On a Debian or Ubuntu host with systemd, as root or with `sudo`:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh)"
```

The script downloads the latest release for the host architecture, verifies its SHA-256 checksum, and runs the installer packaged with it. The installer prints the address of the web interface and the fingerprint of its certificate.

Installer options follow the script, after a placeholder argument:

```sh
bash -c "$(curl -fsSL https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh)" _ --allow-from 192.0.2.0/24
```

To read the script before running it:

```sh
curl -fsSLO https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh
less get.sh
sudo sh get.sh
```

| Variable | Purpose |
|---|---|
| `CERTSMITH_VERSION` | Install a specific release, for example `v0.12.0`, instead of the latest. |
| `CERTSMITH_REPO` | Install from another repository, as `owner/name`. |

The checksum is published with the release, so it detects a damaged or incomplete download but does not authenticate the publisher. Review the scripts before running them as root. See [Installation](#installation) for the manual procedure and every option, and [docs/REFERENCE.md](docs/REFERENCE.md) for the complete reference.

## Features

| Area | Capability |
|---|---|
| Issuing | ACME with DNS-01 validation only. Let's Encrypt, and certificate authorities that use External Account Binding (ZeroSSL, Sectigo, Google Trust Services, or a custom directory). Single-name and wildcard certificates. |
| Importing | A certificate issued elsewhere (a company CA, a purchased certificate) can be imported from a PKCS#12 file or PEM files, then deployed, monitored and alerted on like any other. It is replaced by uploading a new one; CertSmith never issues or renews it. |
| Renewal | Automatic renewal at a configurable threshold, with expiry and failure alerts by email and webhook. The events sent to each channel are selectable. |
| Deployment | FortiGate (REST API), FortiManager and FortiAnalyzer (JSON-RPC), Proxmox VE, generic webhook, local files, monitor-only, and CertSmith's own web interface. |
| Verification | Scheduled and on-demand checks of the certificate each target is serving: correct certificate, remaining validity and complete chain. |
| Visibility | Every API call sent to a device is recorded with the device's response and shown beside the target, together with a description of each call a target type can make. |
| Auditing | A log of certificate operations and a separate audit log of administrative actions. Both can be filtered. |
| Versions | The running version is shown on every page. Once a day the daemon checks whether a newer release has been published and, if so, shows the install command to run. The check can be switched off. |

### Status

CertSmith is pre-1.0. The FortiGate (FortiOS 7.6 and 8.0) and the FortiManager and FortiAnalyzer (7.4) targets have been run against real devices. External Account Binding has been verified against a live certificate authority, ZeroSSL; the other External Account Binding authorities (Sectigo, Google Trust Services and custom directories) are tested against a mock authority only. The other targets are covered by automated tests.

## Requirements

- A Linux host with systemd (Debian and Ubuntu are tested), on amd64 or arm64, and root access to install.
- Outbound access to the certificate authority, the DNS provider's API, DNS resolvers, and the API address of each target.
- API credentials for the DNS provider that hosts the zone, with permission to create and remove TXT records. Certificate authorities that validate domains in advance within the customer account do not need DNS credentials.
- Go (the version named in `go.mod`) is required only to build from source.

## Installation

The [quick install](#quick-install) command performs the steps below automatically. To install manually, download the release archive for the host architecture and `SHA256SUMS` from the Releases page, then verify, unpack and install:

```sh
sha256sum -c SHA256SUMS --ignore-missing
tar xzf certsmith-<version>-linux-amd64.tar.gz
cd certsmith-<version>-linux-amd64
sudo sh install.sh
```

### New installation

- The web interface listens on `0.0.0.0:443` with a self-signed certificate. CertSmith renews that certificate by itself 30 days before it expires, and Settings can regenerate it at any time. Port 80 redirects to HTTPS.
- Ports 80 and 443 are opened in the host firewall (`ufw`). The SSH port in use is kept open to any source, as it was before the firewall was enabled; narrow it with `ufw` when you have confirmed access.
- Automatic security updates are enabled (`unattended-upgrades`, without automatic reboot).
- A dedicated `certsmith` service account runs the daemon under a hardened systemd unit. The only capability granted is binding to ports below 1024.
- Networking (address, gateway, DNS) is never changed.

### Upgrade

Run the installer from a newer release, or run the quick install command again. An upgrade replaces the program and the unit file only. The listen address, firewall and operating system are left unchanged unless an option below is given. If the new version does not start, the previous version is restored automatically.

### Installer options

| Option | Effect |
|---|---|
| `--listen ADDR:PORT` | Address of the web interface. Default `0.0.0.0:443` for a new installation; an upgrade keeps the current address. |
| `--allow-from LIST` | Comma-separated networks allowed to reach the web interface, for example `192.0.2.0/24,198.51.100.7`. Default: any. Applies firewall rules on an upgrade as well. |
| `--firewall`, `--no-firewall` | Apply firewall rules on an upgrade, or never modify the firewall. |
| `--http-redirect`, `--no-http-redirect` | Enable or disable the port 80 redirect. On by default for a new installation that listens on 443. |
| `--no-auto-updates` | Do not enable unattended security updates. |
| `--harden` | Also install a kernel network hardening file, `/etc/sysctl.d/90-certsmith-hardening.conf`. Reverse-path filtering can affect hosts with asymmetric routing, so this is opt-in. |
| `--binary PATH` | Install a specific program file instead of the one in the release archive. A bare path argument has the same effect. |
| `--uninstall` | Stop and remove the service. Data in `/var/lib/certsmith` is kept. |
| `--purge` | With `--uninstall`: also delete the data and the service account. Asks for confirmation unless `--yes` is given. |
| `--yes`, `-y` | Do not ask for confirmation. |
| `--help`, `-h` | Print the option list and exit. |

Options accept `--option value` or `--option=value`. If the host has a public IPv4 or global IPv6 address, the installer warns that the web interface may be reachable from the Internet. Use `--allow-from` to restrict it.

## First use

1. Open the address printed by the installer. The browser reports the self-signed certificate as untrusted; the printed fingerprint can be compared with the one the browser shows.
2. Create the first administrator account. There is no default password.
3. Enter the contact email address for the certificate authority account.
4. Add a certificate provider, add a certificate, then add the targets that should receive it.

The **Readme** button in the web interface opens the full user guide with screenshots.

## Configuration

The daemon is started by systemd with the settings in `/etc/certsmith/certsmith.env`, which the installer creates once and never overwrites:

| Variable | Purpose |
|---|---|
| `CERTSMITH_LISTEN` | Address of the web interface, for example `0.0.0.0:443`. |
| `CERTSMITH_ARGS` | Additional daemon flags, for example `-http-redirect 0.0.0.0:80` or `-no-tls`. |

After editing the file, run `systemctl restart certsmith`.

### Daemon flags

| Flag | Purpose |
|---|---|
| `-data DIR` | Data directory for the database, keys and certificates. |
| `-listen ADDR` | Address of the web interface. |
| `-tls-dir DIR` | Directory holding `fullchain.pem` and `key.pem` for the web interface. Defaults to `<data>/ui-tls`, where a self-signed pair is created if none exists. |
| `-http-redirect ADDR` | Also listen for plain HTTP on this address and redirect every request to the HTTPS page. |
| `-no-tls` | Serve the web interface over plain HTTP. Only for use behind a reverse proxy on the same host that terminates TLS. |
| `-version` | Print the version and exit. |
| `-h`, `-help` | Print the flag list and exit. |

### Environment variables

| Variable | Purpose |
|---|---|
| `CERTSMITH_ADMIN_PASSWORD` | Create the first administrator at start-up for automated installations, instead of using the setup wizard (at least 12 characters). |
| `CERTSMITH_ADMIN_USER` | User name for that account. Defaults to `admin`. |
| `CERTSMITH_ALLOW_COMMANDS=1` | Permit the local-files target to run its post-deployment command. Disabled by default. |
| `CERTSMITH_REPO` | `owner/name` of the repository checked for newer releases (and used by `get.sh`). |
| `CERTSMITH_MASTER_KEY` | The 64-hexadecimal-character key that encrypts stored credentials. When set it replaces `master.key`, and must then be supplied on every start. |

The complete list, including the variables passed to a post-deployment command and the installer's testing settings, is in [docs/REFERENCE.md](docs/REFERENCE.md).

### Password recovery

Stop the service, then run the command as the service user:

```sh
certsmith reset-admin -data /var/lib/certsmith
```

It sets a new random password for the user and prints it. `-user NAME` selects the user when there is more than one. With `-wipe`, all users are removed and the setup wizard runs again.

## Data and backup

All state is in `/var/lib/certsmith`. Back up the whole directory and store the backup securely, because it contains private keys. `master.key` decrypts every stored credential; without it the stored credentials cannot be recovered.

## Security

- Stored credentials are encrypted with AES-256-GCM. The key is generated on first start and is unique to each installation.
- There are no default credentials. Failed sign-ins are rate-limited per address and per user.
- Certificates, private keys, tokens and request bodies are never written to the API call log. An imported certificate's private key is stored encrypted like every other credential, is never returned to the browser, and the PKCS#12 password is not kept.
- Device API accounts used by CertSmith should be restricted to the CertSmith server's address (for example Trusted Hosts on a FortiGate). Update that restriction before changing the server's address.
- Report a suspected vulnerability through GitHub's private vulnerability reporting, not in a public issue. See [SECURITY.md](SECURITY.md).
- The only outbound request that is not to a certificate authority, a DNS provider or a managed device is the daily check for a newer release. It reads one document from `api.github.com`, sends nothing about the installation, and can be switched off in Settings.
- The licences of the bundled third-party software are in [THIRD_PARTY_NOTICES.txt](internal/web/static/THIRD_PARTY_NOTICES.txt), which every release archive and the web interface also carry.

## Building from source

```sh
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=0.0.0-dev" -o dist/certsmith-linux-amd64 ./cmd/certsmith
```

To run without installing: `go run ./cmd/certsmith -data ./data -listen 127.0.0.1:8443`.

### Repository layout

| Path | Contents |
|---|---|
| `get.sh` | The online installer used by the quick install command. |
| `cmd/certsmith` | The daemon and the `reset-admin` command. |
| `internal/acme`, `internal/dns` | ACME client, certificate authority presets and DNS-01 providers. |
| `internal/targets`, `internal/plugin` | Deployment targets and the interface they implement. |
| `internal/engine` | Scheduling, renewal, deployment and alerting. |
| `internal/web` | HTTP API and the embedded web interface (`internal/web/static`). |
| `internal/certimport` | Reading and validating an imported certificate (PKCS#12 or PEM). |
| `internal/store`, `internal/secret`, `internal/model` | Persistence, encryption of stored secrets and data types. |
| `deploy/` | systemd unit and the installer packaged with each release. |
| `docs/` | [Command-line reference](docs/REFERENCE.md), the [dependency policy](docs/DEPENDENCIES.md), and plans for the [installer and appliance](docs/APPLIANCE.md), [target plugins](docs/PLUGINS.md) and [DNS-PERSIST-01](docs/DNS-PERSIST.md). |
| `scripts/` | Repository checks, the installer tests, `scripts/update-deps.sh` (dependency updates) and `scripts/notices`, which generates the third-party licence notices. |

## AI-assisted development

CertSmith was designed and written with the assistance of an artificial intelligence system, Claude (developed by Anthropic), working under the direction of the maintainer. This applies to the source code, the automated tests, the installer scripts and this documentation. Commits containing AI-authored changes carry a `Co-Authored-By` trailer.

The maintainer directs the work and tests it against real equipment, as described under [Status](#status). The code is also covered by automated tests that run on every change. Even so, this software holds private keys and administrative credentials for network devices. Review the code, and test in a non-production environment, before relying on it.

## Licence

A licence has not yet been chosen. Until a licence file is added, all rights are reserved.
