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

## What CertSmith protects

CertSmith holds private keys and administrative credentials for network devices. Stored credentials are
encrypted at rest, secrets and certificates are never written to the API call log, and the service runs as an
unprivileged user under a restricted systemd unit. See the **Security** section of the README for details.
