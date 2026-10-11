# CertSmith

CertSmith automates the lifecycle of TLS certificates. It obtains certificates from an ACME certificate authority using DNS-01 validation, renews them before they expire, deploys them to network devices and services through their APIs, and verifies that each target serves the new certificate. It runs as a single daemon with an embedded web interface.

> **AI-assisted software.** CertSmith was designed and written with the assistance of an artificial intelligence system. See [AI-assisted development](#ai-assisted-development).

## Contents

- [Quick start](#quick-start)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Data and backup](#data-and-backup)
- [Security](#security)
- [Building from source](#building-from-source)
- [Status](#status)
- [AI-assisted development](#ai-assisted-development)
- [Licence](#licence)

## Quick start

### Install

Run as root, or with `sudo`, on a Debian or Ubuntu host with systemd:

```sh
bash -c "$(wget -nv -O- https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh)"
```

The script downloads the latest release for the host architecture, verifies its SHA-256 checksum and runs the packaged installer. The installer prints the address of the web interface and the SHA-256 fingerprint of its certificate.

### First run

1. Open the printed address. The browser reports the self-signed certificate as untrusted; compare the fingerprint with the one printed by the installer.
2. Create the first administrator account. There is no default password.
3. Under **Settings**, enter the account email address used for the certificate authority.
4. Under **Certificate providers**, add a provider: a certificate authority and the DNS credentials that prove domain ownership, or import an existing certificate.
5. On **Certificates**, add a certificate: a name and the domain names.
6. On **Targets**, add a target to receive the certificate and select **Deploy**. The first deployment to each target is always started manually; renewals are then deployed automatically.

The **Set up in this order** checklist on the Certificates, Targets and Certificate providers pages tracks these steps. **Readme** in the web interface opens the full user guide.

### Upgrade

Run the install command again, or use the command shown under **Settings → Software**. Settings and data are kept, and the previous version is restored if the new one does not start. **Release notes** in the same card lists what a version changes.

## Features

| Area | Capability |
|---|---|
| Issuing | ACME with DNS-01 validation. Let's Encrypt, and certificate authorities that use External Account Binding (ZeroSSL, Sectigo, Google Trust Services, or a custom directory). Single-name and wildcard certificates. |
| Importing | A certificate issued elsewhere (company CA, purchased certificate) is imported from a PKCS#12 file or PEM files, then deployed, monitored and alerted on like any other. It is replaced by uploading a new one and is never renewed by CertSmith. |
| Renewal | Automatic renewal at a configurable threshold, with expiry and failure alerts by email and webhook. The events sent to each channel are selectable. |
| Deployment | FortiGate (REST API, including ZTNA server certificates on FortiOS 7.6 and later), FortiManager and FortiAnalyzer (JSON-RPC), Proxmox VE, generic webhook, local files, monitor-only, and CertSmith's own web interface. |
| Manual import | FortiClient EMS has no API for installing a server certificate. It is monitored (console port 443 and FortiClient port 8013), and the certificate is imported in its console. |
| Verification | Scheduled and on-demand checks of the certificate each target serves: expected certificate, remaining validity, complete chain. |
| Visibility | Every API call sent to a device is recorded with the device's response and shown beside the target, with a description of each call a target type can make. |
| Download | A certificate and private key can be downloaded as a password-protected PKCS#12 file or as PEM files, for a device with no API. It requires the signed-in user's password and is recorded in the audit log. |
| Auditing | A log of certificate operations and a separate audit log of administrative actions, both filterable. |
| Versions | The running version is shown on every page. A daily check reports a newer release, with its install command and release notes. The check can be switched off. |

## Requirements

- Linux with systemd, amd64 or arm64. Debian and Ubuntu are tested. Root access to install.
- `wget` or `curl`, and `tar`, for the online installer.
- Outbound access to the certificate authority, the DNS provider's API, DNS resolvers and each target's API address.
- API credentials for the DNS provider that hosts the zone, with permission to create and remove TXT records. Certificate authorities that validate domains within the customer account need no DNS credentials.
- Go (the version in `go.mod`) to build from source only.

## Installation

The quick start command performs the steps below. To install manually, download the release archive for the host architecture and `SHA256SUMS` from the Releases page, then:

```sh
sha256sum -c SHA256SUMS --ignore-missing
tar xzf certsmith-<version>-linux-amd64.tar.gz
cd certsmith-<version>-linux-amd64
sudo sh install.sh
```

Release archives carry a signed build provenance attestation; see [Verifying a release](SECURITY.md#verifying-a-release).

Online installer environment:

| Variable | Purpose |
|---|---|
| `CERTSMITH_VERSION` | Install a specific release, for example `v0.14.1`, instead of the latest. |
| `CERTSMITH_REPO` | Install from another repository, as `owner/name`. |

Installer options follow the script after a placeholder argument:

```sh
bash -c "$(wget -nv -O- https://raw.githubusercontent.com/CautiousCapsLock/certsmith/main/get.sh)" _ --allow-from 192.0.2.0/24
```

### New installation

- The web interface listens on `0.0.0.0:443` with a self-signed certificate that CertSmith renews 30 days before expiry. Port 80 redirects to HTTPS.
- Ports 80 and 443 are opened in the host firewall (`ufw`). The SSH port in use stays open to any source.
- Unattended security updates are enabled, without automatic reboot.
- The daemon runs as the unprivileged `certsmith` account under a sandboxed systemd unit. The only capability is binding ports below 1024.
- Networking (address, gateway, DNS) is never changed.

### Upgrade

An upgrade replaces the program and the unit file only. The listen address, firewall and operating system are unchanged unless an option below is given. A version that fails to start is replaced by the previous one.

### Installer options

| Option | Effect |
|---|---|
| `--listen ADDR:PORT` | Address of the web interface. Default `0.0.0.0:443` for a new installation; an upgrade keeps the current address. |
| `--allow-from LIST` | Comma-separated networks allowed to reach the web interface, for example `192.0.2.0/24,198.51.100.7`. Default: any. Also applies firewall rules on an upgrade. |
| `--firewall`, `--no-firewall` | Apply firewall rules on an upgrade, or never modify the firewall. |
| `--http-redirect`, `--no-http-redirect` | Enable or disable the port 80 redirect. On by default for a new installation that listens on 443. |
| `--no-auto-updates` | Do not enable unattended security updates. |
| `--harden` | Install a kernel network hardening file, `/etc/sysctl.d/90-certsmith-hardening.conf`. Opt-in: reverse-path filtering can affect hosts with asymmetric routing. |
| `--binary PATH` | Install a specific program file instead of the one in the archive. A bare path argument has the same effect. |
| `--uninstall` | Stop and remove the service. Data in `/var/lib/certsmith` is kept. |
| `--purge` | With `--uninstall`: also delete the data and the service account. Asks for confirmation unless `--yes` is given. |
| `--yes`, `-y` | Do not ask for confirmation. |
| `--help`, `-h` | Print the option list and exit. |

Options accept `--option value` or `--option=value`. The installer warns when the host has a public IPv4 or global IPv6 address, because the web interface may then be reachable from the Internet.

## Configuration

The daemon reads `/etc/certsmith/certsmith.env`, which the installer creates once and never overwrites. After editing it, run `systemctl restart certsmith`.

| Variable | Purpose |
|---|---|
| `CERTSMITH_LISTEN` | Address of the web interface, for example `0.0.0.0:443`. |
| `CERTSMITH_ARGS` | Additional daemon flags, for example `-http-redirect 0.0.0.0:80` or `-no-tls`. |

### Daemon flags

| Flag | Purpose |
|---|---|
| `-data DIR` | Data directory for the database, keys and certificates. |
| `-listen ADDR` | Address of the web interface. |
| `-tls-dir DIR` | Directory holding `fullchain.pem` and `key.pem` for the web interface. Default `<data>/ui-tls`, where a self-signed pair is created if none exists. |
| `-http-redirect ADDR` | Also listen for plain HTTP on this address and redirect every request to the HTTPS page. |
| `-no-tls` | Serve the web interface over plain HTTP. For use behind a reverse proxy on the same host that terminates TLS. |
| `-version` | Print the version and exit. |
| `-h`, `-help` | Print the flag list and exit. |

### Environment variables

| Variable | Purpose |
|---|---|
| `CERTSMITH_ADMIN_PASSWORD` | Create the first administrator at start-up instead of using the setup wizard (at least 12 characters). |
| `CERTSMITH_ADMIN_USER` | User name for that account. Default `admin`. |
| `CERTSMITH_ALLOW_COMMANDS=1` | Permit the local-files target to run its post-deployment command. Disabled by default. |
| `CERTSMITH_REPO` | `owner/name` of the repository checked for newer releases and used by `get.sh`. |
| `CERTSMITH_MASTER_KEY` | The 64-hexadecimal-character key that encrypts stored credentials. When set it replaces `master.key` and must be supplied on every start. |

The complete list is in [docs/REFERENCE.md](docs/REFERENCE.md).

### Password recovery

Stop the service, then run as the service user:

```sh
certsmith reset-admin -data /var/lib/certsmith
```

This sets a new random password for the user and prints it. `-user NAME` selects the user when there is more than one. `-wipe` removes all users, so the setup wizard runs again.

## Data and backup

All state is in `/var/lib/certsmith`. Back up the whole directory and store the backup securely: it contains private keys. `master.key` decrypts every stored credential and cannot be recovered if lost.

## Security

- Stored credentials are encrypted with AES-256-GCM. The key is generated on first start, is unique to each installation, and is kept beside the data (or in `CERTSMITH_MASTER_KEY`). It protects a copy of the database, not a compromised host.
- There are no default credentials. Passwords are stored as bcrypt hashes. Failed sign-ins are rate-limited per address and per user.
- Sessions use a signed, HttpOnly, SameSite=Strict cookie, expire after 12 hours, and end at sign-out and on a password change. State-changing requests require a custom header. Downloading a private key and changing users or passwords require the signed-in user's own password again.
- The web interface sends a restrictive Content-Security-Policy and renders all data as text. The daemon runs unprivileged under a sandboxed systemd unit.
- Certificates, private keys, tokens and request bodies are never written to the API call log. An imported private key is stored encrypted and never returned to the browser; the PKCS#12 password is not kept.
- Device API accounts should be restricted to the CertSmith server's address (for example Trusted Hosts on a FortiGate). Update that restriction before changing the server's address.
- The only outbound request other than to a certificate authority, DNS provider or managed device is the daily release check: one request to `api.github.com`, carrying nothing that identifies the installation. It can be switched off in Settings.
- Until the first administrator exists, anyone who can reach the web interface can create it. Complete the setup wizard first and restrict the address with `--allow-from`. All users are administrators; there are no roles.
- Report a suspected vulnerability through GitHub private vulnerability reporting. See [SECURITY.md](SECURITY.md).
- Licences of bundled third-party software: [THIRD_PARTY_NOTICES.txt](internal/web/static/THIRD_PARTY_NOTICES.txt).

## Building from source

```sh
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=0.0.0-dev" -o dist/certsmith-linux-amd64 ./cmd/certsmith
```

To run without installing:

```sh
go run ./cmd/certsmith -data ./data -listen 127.0.0.1:8443
```

### Repository layout

| Path | Contents |
|---|---|
| `get.sh` | The online installer. |
| `cmd/certsmith` | The daemon and the `reset-admin` command. |
| `internal/acme`, `internal/dns` | ACME client, certificate authority presets and DNS-01 providers. |
| `internal/targets`, `internal/plugin` | Deployment targets and the interface they implement. |
| `internal/engine` | Scheduling, renewal, deployment and alerting. |
| `internal/web` | HTTP API and the embedded web interface (`internal/web/static`), including the release notes (`static/releases`). |
| `internal/certimport` | Reading and validating an imported certificate. |
| `internal/store`, `internal/secret`, `internal/model` | Persistence, encryption of stored secrets and data types. |
| `internal/update` | The release check. |
| `deploy/` | systemd unit and the installer packaged with each release. |
| `docs/` | [Reference](docs/REFERENCE.md), [dependency policy](docs/DEPENDENCIES.md), and plans for the [installer and appliance](docs/APPLIANCE.md), [target plugins](docs/PLUGINS.md) and [DNS-PERSIST-01](docs/DNS-PERSIST.md). |
| `scripts/` | Repository checks, installer tests, dependency updates and the third-party notices generator. |

## Status

CertSmith is pre-1.0.

- **Run against real devices:** FortiGate (FortiOS 7.6 and 8.0), FortiManager and FortiAnalyzer (7.4), Proxmox VE, Let's Encrypt issuance with a Cloudflare DNS zone, and import of a certificate from a private CA.
- **Verified against a live CA:** External Account Binding with ZeroSSL.
- **Covered by automated tests only:** ZTNA server certificates on FortiOS 7.6 (verified on 8.0 only), External Account Binding with Sectigo, Google Trust Services and custom directories (tested against a mock authority), and the remaining targets.

## AI-assisted development

CertSmith was designed and written with the assistance of an artificial intelligence system, Claude (Anthropic), under the direction of the maintainer. This covers the source code, tests, installer scripts and documentation. Commits containing AI-authored changes carry a `Co-Authored-By` trailer.

The maintainer directs the work and tests it against real equipment (see [Status](#status)); automated tests run on every change. The software holds private keys and administrative credentials for network devices: review the code and test in a non-production environment before relying on it.

## Licence

CertSmith is licensed under the [Apache License, Version 2.0](LICENSE). Bundled software is under its own licences, listed in [THIRD_PARTY_NOTICES.txt](internal/web/static/THIRD_PARTY_NOTICES.txt). The software is provided without warranty of any kind.
