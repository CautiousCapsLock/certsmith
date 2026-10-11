# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately**, not in a public issue or discussion.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability**. The report is visible only to the maintainer.

Please include:

- the CertSmith version (`certsmith -version`, or the version shown in the web interface),
- what you found and the impact you believe it has,
- steps or a configuration that reproduce it, and
- whether it requires a signed-in user, network access to the web interface, or access to the host.

CertSmith is maintained by one person. Reports are handled on a best-effort basis; you will receive an
acknowledgement and, where a fix is needed, a new release and a published advisory.

## Supported versions

Only the latest release receives fixes. Upgrade with the quick install command in the README, or by running
the installer from the newer release; an upgrade keeps your settings and data.

## Scope

In scope: the daemon and its web interface, the installer scripts (`get.sh`, `deploy/install.sh`), the
systemd unit, and the release workflow.

Out of scope: weaknesses in a third-party service CertSmith connects to (a certificate authority, a DNS
provider or a managed device), and configurations that the documentation advises against, such as exposing
the web interface to the Internet without a restriction.

## Verifying a release

Every release archive is published with `SHA256SUMS`, and with a signed build provenance attestation that ties
the archive to this repository and to the workflow run that built it. With the GitHub CLI:

```sh
gh attestation verify certsmith-<version>-linux-amd64.tar.gz --repo CautiousCapsLock/certsmith
```

The quick install script checks the SHA-256 checksum only. It runs the installer from the archive as root, so
read `get.sh` and `deploy/install.sh` first, or download the archive and verify it as above.

## What CertSmith protects

CertSmith holds private keys and administrative credentials for network devices. Stored credentials are
encrypted at rest, secrets and certificates are never written to the API call log, and the service runs as an
unprivileged user under a restricted systemd unit. See the **Security** section of the README for details.

## Known limits

These are properties of the design, not defects waiting for a fix; they are listed so you can decide whether
they matter for your deployment.

- **First visitor.** Until the first user exists, anyone who can reach the web interface can create it. Finish the
  setup wizard straight away, and restrict the address with `--allow-from` or a firewall.
- **One role.** Every user is an administrator, and can manage users, credentials and targets.
- **The key beside the lock.** Stored credentials are encrypted with a key kept in the data directory (or in
  `CERTSMITH_MASTER_KEY`). That protects a copy of `db.json`; it does not protect a host an attacker already controls.
  Treat the whole data directory, and its backups, as secret.
- **Sign-in throttle.** Failed sign-ins are counted in memory per address and per account, 8 in 10 minutes, and
  a restart clears them. Behind a reverse proxy, list the proxy under Settings, Trusted proxies; otherwise every
  client shares one address and the throttle is shared too. Anyone can lock an account for ten minutes by failing.
- **Outbound connections.** CertSmith connects to the addresses an administrator configures (devices, certificate
  authorities, DNS providers, the alert webhook) and, once a day, to `api.github.com` to look for a newer release.
- **Commands.** The local-files target can run a command after writing the files, only when the service is
  started with `CERTSMITH_ALLOW_COMMANDS=1`. The command runs as the service account, inside the service's sandbox.
