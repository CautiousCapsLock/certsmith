# CertSmith as a downloadable appliance (OVA): what it takes

Status: **plan for review, nothing in here is built yet.** Written against CertSmith 0.9.1.
Facts about today's system come from the repository and from the author's lab LXC, checked on 2026-10-09.
Anything I could not check is marked **Unverified**. Effort figures are rough.

---

## 0. Revision 2026-10-10: installer first, OVA later

Decided after review: **ship an install script first.** The OVA is built *from* that script later, so nothing below is wasted, but it is no longer the first deliverable. Everything in sections 1 to 10 still describes the end state. What changes is the order and two defaults.

**Order of work (replaces the phase table in section 8 until the OVA is back on the table):**

| Step | What | Exit criteria |
|---|---|---|
| 0 | Repository: git, `.gitignore`, CI (`gofmt`, `go vet`, `go test -race`), tag-triggered release that publishes static binaries and `SHA256SUMS` | A tag produces a downloadable release and CI is green on every push |
| 1 | **Installer**: `install.sh` v2 (below), run from an unpacked release | A fresh Ubuntu VM goes from nothing to a working HTTPS login page with one command |
| 2 | Listen on 443 (`CAP_NET_BIND_SERVICE`), `schema_version` + migrations in `db.json` | Fresh install answers on 443; an upgrade across a schema change keeps data |
| 3 | Backup and restore (section 4.10) | A backup restores into a new machine, credentials included |
| 4 | Update from the UI (section 4.9), with signatures, which brings in the root helper | Update and a deliberately failing update (auto-rollback) both pass |
| 5+ | Only if the OVA goes ahead: console network setup (`certsmith-setup`, 4.5), Settings → Network, image build (5.4). Plugins ([PLUGINS.md](PLUGINS.md)) whenever the release and signing work is in | As in sections 5 and 8 |

**The installer (step 1):**
- Run as root, from the directory of a release: `sh install.sh`. Needs systemd and a Debian/Ubuntu-style userland. Idempotent: running it again upgrades in place and never regenerates keys or touches `/var/lib/certsmith`.
- Does today's `install.sh` job (service account, binary, hardened unit) and adds: the 443 capability, firewall rules (4.7), unattended upgrades, the sysctl hardening from Appendix A, and a printed result: URL and certificate fingerprint.
- **It does not touch networking.** A VM or container already has its address from the hypervisor, the host or DHCP, and the installer leaves it exactly as it is. Setting an IP, mask and gateway from a console menu (4.5) belongs to the OVA, where there is no other way into the machine, and is deferred with it.
- **It never cuts off the session it is running in.** If sshd is listening, the SSH port is kept open whatever else the firewall does.
- Flags: `--listen`, `--allow-from CIDR[,CIDR]`, `--firewall`, `--no-firewall`, `--no-auto-updates`, `--harden`, `--binary`, `--uninstall` (keeps data unless `--purge`). See the README for what each does.
- **Upgrades are conservative.** The listen address and extra flags live in `/etc/certsmith/certsmith.env`, created once and never overwritten; a first-release install (flags inline in the unit) is migrated into it, so a host behind a reverse proxy on 8443 stays on 8443. Firewall, auto-updates and kernel hardening are only touched on a new install, or when asked. A start failure restores the previous program, unit and env file.
- **Kernel hardening is opt-in (`--harden`)** rather than default: reverse-path filtering can break asymmetric routing on multi-homed hosts, and a certificate service should not change that silently.
- Tested by `scripts/test-install.sh` (stubbed system commands, run under `sh` and `dash`); it checks decisions, not what systemd or ufw do with them, so a real-host run is still part of each release.
- Release downloads: `get.sh` in the repository root is the one-line form. It resolves the latest release, downloads the archive for the host architecture, verifies it against `SHA256SUMS`, unpacks it and runs the packaged installer with the options passed through. It needs the repository (or a separate release location) to be public. Detached signatures replace the plain checksum before the in-app updater exists.

**Firewall default relaxed (replaces the "local subnet only" rule in 4.7):** `443/tcp` (and `80/tcp`, redirect only) are open from **any source**, not just the appliance's own subnet, so a routed network, a VPN or a WAN-side address can reach the page without extra steps. `--allow-from` tightens it to a list of networks at install time and Settings (step 4, with the helper) edits it later. Reasons that make this acceptable as a default: the page has no default password and the first-run wizard forces a user to be created, login is rate-limited per address and per user, sessions and CSRF are already enforced, and the certificate is not usable without the master key. The cost is real, though: if the machine is port-forwarded from the Internet, the login page is Internet-facing. The installer prints that sentence when it sees a default route over a public address.

**Trusted Hosts** (4.8) stays in the plan but is deferred: it is a documentation and form-hint change on the device side and does not block anything above.

---

## 1. The goal in one paragraph

Someone downloads a single file from GitHub, imports it into VMware, Proxmox, Hyper-V or VirtualBox, and powers it on.
The console shows a short setup screen that asks for an IP address, subnet and gateway (or DHCP).
Then it shows a web address and the certificate's fingerprint.
They open `https://<that address>/` (a self-signed certificate on port 443, as expected for a new appliance), create the first user, and are in.
From then on the web interface can change the appliance's network settings, update CertSmith itself, update Ubuntu underneath it, back it up, and restore it.
No SSH, no shell and no Linux knowledge is needed for any of that.

## 2. Where we are today

### What already works in our favour
- One static Go binary with the web UI embedded. No runtime dependencies.
- A hardened systemd unit: dedicated user, no capabilities, `ProtectSystem=strict`, syscall filter, state under `/var/lib/certsmith`.
- A first-run wizard (user, then ACME email), no default password, multi-user login, sealed secrets (AES-256-GCM, key in `master.key`).
- A self-signed certificate for the web page is created automatically on first start (`/var/lib/certsmith/ui-tls`).
- Graceful shutdown that removes DNS challenge records before the service stops.
- A `selfui` target that already lets the user replace that self-signed certificate with a real one issued by CertSmith itself.

### What is built by hand on the lab LXC and not in the repository
All of this was done over SSH and exists only on that machine. For an appliance it must become scripts that run while the image is built (Appendix A has the exact contents):
- `ufw` rules, `fail2ban` (sshd jail), `unattended-upgrades` with our origins list, sshd hardening drop-ins, a sysctl hardening file, an SSH login banner.
- The systemd unit and `deploy/install.sh` are in the repo, but nothing builds a whole machine.

### Where the lab's private addresses live
- **In the repository: nowhere.** Every file in the repository, tests included, was searched and has no private-range address, no lab hostname and no personal domain (CI keeps it that way, see 4.8). The code never assumed the author's network.
- **On the host only**, in the firewall: `22/tcp` allowed from the lab LAN, and `8443/tcp` allowed from the lab's reverse proxy. Those two lines are the whole of it, and they are not shipped.
- The appliance will not carry any default allow list from our lab. See 4.7.

### Gaps against an appliance
| Need | Today |
|---|---|
| Listen on 443 | Listens on 8443 (the unit has no capabilities, so it cannot bind below 1024). |
| Set IP, gateway, subnet | Nothing. The LXC's address comes from Proxmox. No netplan on the box. |
| Change anything on the OS from the UI | Impossible by design: the service is unprivileged and sandboxed. |
| Update CertSmith | Manual: build, `scp`, `install.sh`. |
| Update Ubuntu | `unattended-upgrades` only, no visibility in the UI, no reboot handling. |
| Unique secrets per install | `master.key` and `session.key` are created on first start, which is right, but the image build must never boot the service once and then snapshot. |
| Database schema versioning | `db.json` has no version field. Updates need one. |
| Backup / restore | None in the UI. Losing `master.key` loses every stored credential. |

## 3. Decisions to make before building

| # | Decision | My recommendation |
|---|---|---|
| 1 | Base OS | Ubuntu Server **current LTS** (26.04 is what the lab runs), minimal install. Pin the LTS per CertSmith release line. |
| 2 | Disk image formats | Ship **OVA** (VMware, VirtualBox, Proxmox import) plus **qcow2** (KVM/Proxmox) and **VHDX** (Hyper-V). One build, three conversions. |
| 3 | Architecture | amd64 first. arm64 later only if asked. |
| 4 | Resources | 2 vCPU, 2 GB RAM, 16 GB thin disk (the lab box uses 1.1 GB of its disk, and the idle service takes about 7 MB of RAM). |
| 5 | Update source | **GitHub Releases** with signed assets and a small `latest.json` (see 4.9). |
| 6 | Update signing | **minisign** or **cosign** key kept offline, public key compiled into the binary. Not just a checksum from the same place as the file. |
| 7 | How privileged actions work | A small root **helper** with a fixed menu of actions (see 4.3), not `sudo` for the web service. |
| 8 | Port 80 | Listen on 80 only to redirect to 443. Off if you would rather not. |
| 9 | SSH | **Off by default**, enabled by a switch on the console or in Settings, key-only. |
| 10 | Telemetry | **None.** The update check is the only outbound call that is not to a CA, DNS provider or device you configured. Make it switchable. |
| 11 | License and support terms | Needed before publishing. Third-party notices for lego and the other modules must ship in the image. |
| 12 | Release channels | `stable` only at first. `beta` later. |

## 4. Design

### 4.1 The image
- Ubuntu Server minimal, **no cloud-init at runtime** (it is the usual cause of "my VM changed IP and hostname after import"). A first-boot unit of our own does what is needed.
- Packages: `ufw`, `fail2ban`, `unattended-upgrades`, `open-vm-tools` (VMware), `hyperv-daemons` (Hyper-V), `qemu-guest-agent` (KVM/Proxmox), `chrony`, `netplan.io`, `whiptail` for the console menu. Nothing else: no compiler, no Python packages we do not use.
- Disk: GPT, EFI boot, a single root filesystem on LVM so it can grow. `growpart` + `resize2fs` at first boot so a bigger virtual disk just works.
- Hostname `certsmith`, changeable. Time zone UTC, changeable. `chrony` on by default: ACME and TLS both depend on correct time, so the console and UI must show time-sync status.
- No root password. No default user password. Console login is described in 4.11.
- Secure Boot: Ubuntu's signed shim and kernel work on Hyper-V Generation 2 with the "Microsoft UEFI Certificate Authority" template and on VMware. **Unverified** on each product: the build pipeline must boot-test it.

### 4.2 Layout on disk
```
/usr/local/bin/certsmith              the daemon (replaced by the updater)
/usr/local/lib/certsmith/helper       the root helper
/usr/local/lib/certsmith/console      the console menu
/etc/certsmith/appliance.json         network/firewall settings the helper owns (root-owned)
/var/lib/certsmith/                   state: db.json, keys, certificates (certsmith user, 0700)
/var/lib/certsmith/ui-tls/            the web page's certificate (self-signed by default)
/var/backups/certsmith/               backups taken before updates and on request
```

### 4.3 Privilege model: the helper
The web service must stay unprivileged and sandboxed. Changing an IP address, running `apt`, or restarting the machine needs root. The safe shape is a separate root process that does exactly a short list of things and nothing else.

- `certsmith-helper.service`, root, listens on a **Unix socket** (`/run/certsmith/helper.sock`, mode 0660, group `certsmith`). It is not on the network.
- It accepts only these actions, each with strictly validated arguments (no shell strings, no free-form paths):
  1. `network.get`, `network.apply` (with automatic rollback, 4.5)
  2. `firewall.get`, `firewall.apply` (allowed admin networks, SSH on/off)
  3. `ssh.set` (on/off)
  4. `hostname.set`, `timezone.set`, `ntp.set`
  5. `os.check` (apt update + list pending), `os.upgrade`, `os.reboot`, `os.status`
  6. `app.stage` (verify and place a new binary), `app.activate`, `app.rollback`
  7. `tls.regenerate` (new self-signed certificate for the current address)
  8. `backup.create`, `backup.restore`
  9. `support.bundle`
- Every call is logged to the journal and to an audit list shown in the UI. Every action that can lock the user out has a rollback timer.
- The web service calls it only after the logged-in user's request has passed the existing session and CSRF checks. Destructive actions ask for the user's password again, the same way "delete user" does today.
- Why not `sudo` or polkit: they can be made to work, but each is another place where an argument can be misread. A fixed protocol with typed arguments is smaller to audit.

### 4.4 First boot
A `certsmith-firstboot.service` runs once, **before** the web service ever starts:
1. Regenerate SSH host keys and `/etc/machine-id` (the build deleted them).
2. Create `master.key` and `session.key` (the daemon already does this on first start; the point is that the *image* contains none).
3. Create the self-signed certificate for the chosen address (4.6).
4. Read network settings from OVF properties if present (4.5), otherwise leave the console to ask.
5. Enable the web service and write a marker so none of this runs again.

Build rule that must be enforced in CI: **the image is never booted with the service enabled before it is exported**, and a test fails the build if the exported disk contains a `master.key`, `session.key`, `db.json`, an SSH host key, or a shell history.

### 4.5 Network: the console script, OVF properties, and Settings

**Console (the always-works path).**
`certsmith-console` runs on tty1 in place of a login prompt (a `getty` override). On first boot, and any time there is no usable address, it shows:

```
CertSmith setup
  1  Addressing        ( ) DHCP   (x) Static
  2  IP address        192.168.1.50
  3  Subnet mask       255.255.255.0        (or /24)
  4  Gateway           192.168.1.1
  5  DNS servers       192.168.1.1, 1.1.1.1
  6  Hostname          certsmith
  [Apply]   [Cancel]
```
- Accepts a mask or a prefix length, validates that the gateway is inside the subnet, refuses `0.0.0.0`, multicast and the broadcast address, and tests reachability of the gateway before it commits.
- Writes `/etc/netplan/50-certsmith.yaml` and applies it with the same "confirm or revert" idea as `netplan try`: if the user does not press a key within 60 seconds, the old configuration returns. This matters because a typo here would otherwise strand a VM that has no other way in.
- After applying, it regenerates the self-signed certificate so it names the new address, and prints:
  ```
  Open  https://192.168.1.50/
  Certificate fingerprint (SHA-256): AB:CD:...
  ```
  The fingerprint is there so a careful user can compare it with the browser's warning instead of clicking through.
- Later the same screen is a menu (4.11).

**OVF properties (optional, nice for VMware).**
The OVA declares vApp properties: `hostname`, `ip`, `netmask`, `gateway`, `dns`, `dhcp`. vSphere and Proxmox's OVF import can prompt for them at deploy time, and first boot reads them from the OVF environment (`ovf-env.xml` on VMware). Anything not supplied falls back to the console. This is an extra path, not a replacement.

**Settings tab, "Network" card.**
Shows the current address, mask, gateway, DNS, hostname and link state, and lets an admin change them. It calls `network.apply` through the helper, with the same confirm-or-revert behaviour: the browser is told "reconnect to https://NEW-ADDRESS/ within 60 seconds to keep this change", and the page polls the new address. If it cannot be reached, the old settings return by themselves.

### 4.6 TLS on 443 by default
- The daemon listens on `:443`, and optionally on `:80` with the `-http-redirect` flag, which answers GET and HEAD with a temporary (307, not cached) redirect to the same path on HTTPS and refuses anything else. The installer turns it on for a new install that listens on 443. The unit gains `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, and nothing else.
- The default certificate is **self-signed**, created at first boot, valid for 2 years, ECDSA P-256, with a SAN for the current IP address, the hostname, and `localhost`. It is regenerated when the address or hostname changes.
- The browser warning is expected, and the console fingerprint is the answer to it.
- The existing "Use a real certificate for this page" feature stays as the way out: CertSmith can issue and renew a real certificate for its own address through any provider the user has set up. Settings keeps showing whether the page is using the self-signed or a real certificate.
- The existing `-no-tls` flag stays for people who put the appliance behind their own reverse proxy, but it is not exposed in the UI by default.

### 4.7 Firewall and access
- `ufw`, default deny inbound, allow outbound, managed only through the helper.
- Inbound allowed by default: `443/tcp` (and `80/tcp` if redirect is on) **from any source** (revised 2026-10-10, see section 0; the original proposal was the local subnet only). "Which networks may use this page?" is an editable list of CIDRs that starts as "anywhere" and can be narrowed at install time (`--allow-from`), in the setup wizard, or later in Settings.
- **SSH is off.** It is enabled from the console or Settings, key-only, and restricted to the same allowed networks. When it is on, the sshd and fail2ban settings in Appendix A apply.
- The lab's LAN and reverse-proxy rules are *not* carried over. They exist only in the lab LXC's `ufw` and would be recreated there as ordinary entries in the allowed-networks list.
- Egress: the appliance needs outbound HTTPS to the CAs and DNS providers and the update source, DNS (53, or DoH if you add it), NTP, and TCP to the managed devices' API ports. A short "what this appliance connects to" table belongs in the docs so firewall teams can approve it.

### 4.8 Removing lab-specific references, and Trusted Hosts
- **Code and docs:** nothing to remove today (see section 2). Add a CI check that fails the build if a private-range address (`10.`, `172.16-31.`, `192.168.`) or a known personal domain appears in tracked files outside `_test.go` fixtures and `docs/` examples. That keeps it that way.
- **Host:** the image build creates no allow rules except from the setup wizard.
- **Trusted Hosts on the devices.** The FortiGate, FortiManager and FortiAnalyzer API users should be restricted to this appliance's address. Today the form help says "restrict it to this server's address" without telling the user what that address is. For the appliance:
  - Every target form shows **"This appliance connects from: 192.168.1.50"** with a copy button, taken from the helper (`network.get`), including a warning if the appliance has more than one address, with the one used to reach the target highlighted.
  - The "Test connection" result mentions the source address the device saw, when the device reports it.
  - The per-vendor setup notes (docs and in-app help) say "add that address under Trusted Hosts for the API administrator", and **say what to do when the appliance's IP changes**: update Trusted Hosts first, or the next deployment fails with an authorisation error.
  - Changing the IP in Settings shows a checklist of the targets that use the API and reminds the user to update their Trusted Hosts.

### 4.9 Updating from the UI

There are two things to update, with different risks, so they are two separate cards under **Settings → Updates**.

**A. CertSmith itself**
- Source: GitHub Releases of the project's repository. Each release carries:
  - `certsmith-linux-amd64` and `-arm64` (static binaries),
  - `SHA256SUMS` and a **detached signature** over it (minisign/cosign),
  - `latest.json`: `{version, released, min_updater_version, schema_version, notes_url, assets: [{name, url, sha256}]}`.
- The daemon checks `latest.json` once a day (and on "Check now") over HTTPS. The **signature public key is compiled in**; a download that does not verify is discarded and reported. A channel switch and a "pause update checks" switch exist.
- The UI shows: installed version, latest version, release notes, "Update now". Updates are never applied without a click unless the admin switches on "install updates automatically" with a maintenance window.
- Applying (helper `app.stage` → `app.activate`):
  1. Take a backup (4.10), refusing to continue if it fails.
  2. Download, verify, write to `/usr/local/lib/certsmith/versions/<ver>/certsmith`.
  3. Wait for running issuances and deployments to finish (the engine already has `Drain`), or tell the user what is still running.
  4. Atomically switch a symlink, restart the unit, and wait for the daemon to answer a health check.
  5. **If the health check fails within 60 s, switch the symlink back and restart.** The user sees "Update failed and was rolled back" with the log.
- The last two versions are kept for a manual "Roll back" button.
- **Database changes:** `db.json` gets a `schema_version`. Each release carries its migrations, which run on start after the pre-update backup. A migration is forward-only, so the backup is the way back. A binary refuses to start on a schema newer than it understands, and says so.
- **Air-gapped sites:** "Upload an update file" (the signed release bundle) as an alternative to online checking.

**B. Ubuntu**
- `unattended-upgrades` stays on for security updates, as it is today. The new part is **visibility and control**:
  - "Pending updates: 12 (3 security). Last run: 02:41 today. **Reboot required: yes** (kernel)."
  - "Check now", "Install now" (helper `os.check` / `os.upgrade`), and a switch for **automatic reboot** with a chosen window (default off: on a certificate appliance an unplanned reboot during a deployment is worse than a one-day delay; the UI should nag when a reboot has been pending for more than N days).
  - The helper drains running work (same `Drain`) before a reboot, and the UI shows progress and reconnects.
  - A kernel or library update that needs a reboot is shown as such, never silently ignored.
- Release policy: each CertSmith release is tested on the current Ubuntu LTS point release. When Ubuntu releases a new LTS, a **new appliance image** is published, and an in-place `do-release-upgrade` is **not** offered from the UI (too risky unattended; the supported move is "export backup, deploy new OVA, import backup").
- A one-line "Update everything" button runs A then B with a single backup and a single reboot at the end.

### 4.10 Backup and restore
Needed *before* the updater, because the updater depends on it.
- **Create backup** (UI and console): a single file, encrypted with a passphrase the user supplies, containing `db.json`, `master.key`, `session.key` (optional), the ACME account keys, issued certificates and keys, the self-signed certificate, and `appliance.json`.
- **Restore** from the UI (at the setup wizard too, so a new OVA can be brought up from a backup) and from the console.
- Automatic pre-update backups are kept (last 5), unencrypted but root-only on the appliance disk, and **excluded** from the downloadable file unless the user picks it.
- The backup is the only supported way to move to a new appliance image. The docs say clearly: losing `master.key` loses every stored credential.

### 4.11 Console menu (after first setup)
Reached on the VM's console. Requires the console password (set in the wizard; there is no default).
```
1  Show address and certificate fingerprint
2  Change network settings
3  Reset the web administrator password   (the existing reset-admin command, with confirmation)
4  Enable / disable SSH
5  Restart CertSmith  /  Restart the appliance
6  Check for updates / Install updates
7  Back up / Restore
8  Show service status and recent log
9  Factory reset (wipes all data)
```
If no console password has been set, it is requested on first use. Three failed attempts add a delay. No shell is offered, with a clearly marked **recovery** entry that needs the console password for people who want one.

### 4.12 Settings tab: what is added
A new **Appliance** group above the existing cards, shown only when running on the appliance (the daemon detects the helper socket; on a plain install none of this appears):
- **Network**: addressing, IP, mask, gateway, DNS, hostname (4.5).
- **Access**: which networks may reach this page, SSH on/off, the web page's certificate (self-signed or real) and its fingerprint.
- **Updates**: CertSmith and Ubuntu (4.9), channel, automatic options, maintenance window, history.
- **Backup**: create, restore, schedule (4.10).
- **Time**: time zone, NTP servers, sync status.
- **About**: versions (CertSmith, Ubuntu, kernel), uptime, disk use, a **support bundle** download (logs with secrets and addresses redacted, never including keys).

## 5. Build and release pipeline (GitHub)

### 5.1 Repository
```
/cmd/certsmith             daemon (exists)
/cmd/certsmith-helper      root helper (new)
/cmd/certsmith-console     console menu (new)
/internal/...              (exists) + /internal/appliance, /internal/update (new)
/appliance/                files that go onto the machine: systemd units, sudo-free configs, first-boot, console, hardening
/appliance/hardening/      Appendix A as scripts and drop-ins
/image/                    Packer template, autoinstall, OVF template, conversion scripts
/docs/                     this plan, install guide, per-hypervisor notes, security notes
/.github/workflows/        ci.yml, release.yml, image.yml
```
Private or public: the update check needs the releases to be reachable without a token, so either the repository is public, or releases are published to a separate public location (a second repository, or GitHub Pages for `latest.json` plus release assets). **Decision needed.**

### 5.2 Versioning
- Semantic versions, `vMAJOR.MINOR.PATCH`, tags on `main`. The version already comes from `-X main.version`.
- A release line is `0.x` until the appliance is declared stable.
- A short CHANGELOG, human-written, linked from `latest.json`.

### 5.3 Workflows
1. **`ci.yml`** on every push and pull request: `gofmt`, `go vet`, `go test -race ./...`, the "no private addresses" check, `govulncheck`, a build for amd64 and arm64.
2. **`release.yml`** on a tag: build static binaries with `-trimpath`, produce `SHA256SUMS`, **sign** it, generate an SBOM (SPDX or CycloneDX), generate `latest.json`, create the GitHub Release.
3. **`image.yml`** on a tag (after `release.yml`): build the appliance image (5.4), run the image tests (5.5), attach the OVA, qcow2, VHDX, and their checksums to the same release.

### 5.4 Building the image
Packer with the QEMU builder is the usual route, and it works in a GitHub-hosted runner (nested virtualisation is available on the larger runners; otherwise use a self-hosted runner). **Unverified** which runner size is enough; try first.

Steps the template performs:
1. Install Ubuntu Server minimal from the official ISO using autoinstall, or start from the official cloud image and customise it offline (`virt-customize`), which is faster and fully scriptable.
2. Run the hardening scripts from `/appliance/hardening/` (Appendix A).
3. Install the binaries from the release being built, the helper, the console, the units, the first-boot service.
4. Remove everything that is per-machine: SSH host keys, `/etc/machine-id`, DHCP leases, logs, shell history, apt lists, any `master.key`, `session.key`, `db.json`.
5. Zero free space and shut down.
6. Convert: raw → `vmdk` (streamOptimized) for the OVA, → `qcow2`, → `vhdx`.
7. Write the **OVF** descriptor (hardware: 2 vCPU, 2 GB, one NIC `vmxnet3`/`virtio`/`e1000e` per target product, UEFI firmware, the vApp properties from 4.5), then the **manifest** (`.mf`, SHA-256) and `tar` them into the `.ova` in the order the OVF standard requires (descriptor first).

### 5.5 Testing the image in CI (before anything is published)
- Boot the image in QEMU with a blank disk and check: no leftover secrets (4.4), first-boot service completes, the web UI answers on 443 with a self-signed certificate, the setup wizard loads, `latest.json` signature verification works with a test key.
- Network test: start with OVF properties, start with none (console path via a scripted TTY), change the address through the helper and confirm the rollback timer restores the old one when not confirmed.
- Update test: install the previous release's image, run the update to the new binary, confirm data migrated; run an update with a deliberately broken binary and confirm the automatic rollback.
- A manual checklist per hypervisor before a release is declared stable (VMware ESXi/Workstation, Proxmox, Hyper-V Gen 2, VirtualBox): import, boot, console setup, wizard, one deployment to a lab FortiGate.

## 6. Security considerations
- **Update trust is the biggest new risk.** An updater that fetches and runs code is the most attractive target on the appliance. Controls: signature check against a compiled-in key, key kept offline and not in CI secrets for the long term (sign in a manual or hardware-key step, or use cosign keyless with a pinned identity), refusal to downgrade past a minimum version, TLS to GitHub, and the helper only ever executes files it placed itself in its own directory.
- **No secrets in the image** and a test to prove it (4.4).
- **No default credentials**: the web UI wizard, and the console password, are both created by the user.
- **The helper is small and has no network listener.** It is the only root code beyond systemd, so it gets the most review and fuzzing of its argument parsing.
- **Updates must not strand users.** Rollback timers on network changes, health-checked rollback on software updates, backups before schema changes.
- **Hardening baseline carries over** from the lab (Appendix A), plus: the web service stays sandboxed exactly as today, `CAP_NET_BIND_SERVICE` being the only capability added.
- **Supply chain:** pin GitHub Actions by commit hash, `govulncheck` in CI, SBOM per release, `go.sum` verified, reproducible build flags.
- **Vulnerability response:** a `SECURITY.md` with a contact and a fix-and-release commitment, because users cannot patch an appliance themselves between releases.
- **Privacy:** no telemetry. The update check sends nothing except the request itself; the docs state that.

## 7. Supportability
- **Support bundle** from the UI and console, with addresses and secrets redacted, and a note of what was redacted.
- **Health page:** time sync, DNS reachability of the configured resolvers, outbound reachability of each configured CA, disk space, pending OS updates, last backup age, last update result. This is where problems like the "DNS interception" we found in your lab become visible to a user without a packet capture.
- **Version report** on every page footer and in `latest.json` handling, so a support request always has the version.
- Logs go to the journal with a size limit, and the verbose per-certificate and per-target logs already exist.

## 8. Phases

| Phase | What | Exit criteria | Rough effort |
|---|---|---|---|
| 0 | GitHub repository, CI, release workflow, signing, `latest.json`, SECURITY.md | A tagged release produces signed binaries and a manifest | 2–3 days |
| 1 | Appliance foundations: 443 + capability, first-boot unit, per-install secrets, `schema_version` + migrations, hardening as scripts, allowed-networks firewall | A fresh VM from a script boots to a working HTTPS wizard with no lab addresses | 1 week |
| 2 | Backup and restore (create, restore, wizard import) | Backup from one VM restores into a new one, including credentials | 3–4 days |
| 3 | Helper + network: console setup, OVF properties, Settings → Network, rollback timer | IP changed three ways, revert works when unconfirmed | 1–1.5 weeks |
| 4 | Updates: CertSmith updater (verify, stage, health-checked rollback), Ubuntu status and control, "Update everything" | Update and deliberate-failure rollback both pass in CI | 1.5–2 weeks |
| 5 | Image build and OVA/qcow2/VHDX packaging, image tests in CI | Release workflow attaches the images; the image test suite is green | 1 week |
| 6 | Hypervisor matrix, install guide, support bundle, health page, docs | Manual checklist passed on four hypervisors | 1–1.5 weeks |
| 7 | Pilot with a few outside users, fix what they find, then declare stable | Two pilot users deploy and update without help | 2+ weeks |
| 8 | Target plugins as installable, signed files, managed in Settings → Plugins (separate plan: [PLUGINS.md](PLUGINS.md)) | A third-party target installs, runs sandboxed, and is removed from the UI | 3–4 weeks, after phases 0, 1 and 3 |

Phases 1 and 2 are useful on their own: they make the current LXC install safer to update even if the OVA never ships.

## 9. Risks and how to reduce them
| Risk | Reduction |
|---|---|
| A bad network change strands a VM with no way in | Confirm-or-revert on every change; console always available; OVF properties as a second path |
| A bad update bricks it | Backup first, health check, automatic rollback, two versions kept, "upload update file" for repairs |
| Updater is compromised | Signature with an offline key, compiled-in public key, downgrade protection |
| Packer/nested virtualisation is awkward in GitHub runners | Prove it in phase 0 with a "hello world" image; fall back to a self-hosted runner |
| Hypervisor differences (NIC drivers, UEFI/Secure Boot, tools) | Test matrix in phase 6; choose `virtio`/`vmxnet3` per product in the OVF; keep a BIOS fallback image if UEFI proves troublesome |
| Users lose `master.key` | Backup prompts in the wizard, a visible "last backup" age, a warning on the dashboard when there has never been one |
| Users expect to patch Ubuntu themselves over SSH | SSH exists but is off by default; the docs state which changes are supported and that unsupported ones may not survive an update |
| Ubuntu LTS and CertSmith release cadences drift | One image per CertSmith release, Ubuntu patched in place until the next LTS image |
| One developer, many moving parts | Phases are independently shippable; 1 and 2 are valuable even if later phases slip |

## 10. What changes in the code (checklist)
- `cmd/certsmith`: default listen `:443`; optional `:80` redirect; detect the helper socket and expose `/api/appliance/*` only when present; report version, build and schema version.
- `internal/store`: `schema_version`, a migration framework, pre-migration backup, refusal to start on a newer schema.
- `internal/web`: endpoints for network, access, updates, backup, time, support bundle; the "this appliance connects from" value in the target forms; wizard step for allowed networks and console password; all behind the existing session and CSRF checks, with password re-entry for destructive actions.
- `internal/appliance` (new): client for the helper socket, typed requests and responses, no shell strings.
- `cmd/certsmith-helper` (new): the action list in 4.3, argument validation, audit log, rollback timers.
- `cmd/certsmith-console` (new): the whiptail-style menu in 4.5 and 4.11, no dependency on the web service being up.
- `internal/update` (new): `latest.json` fetch, signature verification, staging, health-checked activation, rollback.
- `deploy/certsmith.service`: `CAP_NET_BIND_SERVICE`, `StateDirectory`, new `ExecStart`; new units for the helper, first boot, and update health check.
- `docs`/in-app help: the Trusted Hosts wording in 4.8.
- CI: the private-address check, the secrets-in-image check, and the image tests in 5.5.

---

## Appendix A: the hardening that exists today and must be scripted

Taken from the lab LXC on 2026-10-09. These become files under `/appliance/hardening/` and are installed by the image build.

**sshd** (`/etc/ssh/sshd_config.d/10-hardening.conf` and `20-hardening-extra.conf`):
```
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no
Banner /etc/issue.net
LogLevel VERBOSE
```
(Lab only: `PermitRootLogin prohibit-password` was kept for the session key. The appliance should use `PermitRootLogin no` and a dedicated admin account, created only when SSH is enabled.)

**sysctl** (`/etc/sysctl.d/90-certsmith-hardening.conf`):
```
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
```

**Automatic updates** (`/etc/apt/apt.conf.d/20auto-upgrades` + `52certsmith-upgrades`):
```
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Allowed-Origins { "${distro_id}:${distro_codename}"; "${distro_id}:${distro_codename}-security";
  "${distro_id}:${distro_codename}-updates"; "${distro_id}ESMApps:${distro_codename}-apps-security";
  "${distro_id}ESM:${distro_codename}-infra-security"; };
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";   // the appliance makes this a UI setting, see 4.9
```
(The lab comment "LXC shares the host kernel" does not apply to a VM: kernel updates *do* need a reboot there, which is why 4.9 shows it.)

**fail2ban** (`/etc/fail2ban/jail.d/defaults-debian.conf`): `banaction = nftables`, `[sshd]` jail enabled with the systemd backend. Only meaningful while SSH is on.

**Firewall** (lab): `ufw` default deny in, allow out; `22/tcp` from the lab LAN; `8443/tcp` from the reverse proxy. **None of these rules go in the image** (4.7).

**Service** (`deploy/certsmith.service`): dedicated `certsmith` user, `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, kernel/clock/hostname protections, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service` minus `@privileged @resources`, empty capability sets, 60 s stop timeout. The appliance adds only `CAP_NET_BIND_SERVICE`.

## Appendix B: OVF properties the OVA would declare
| Key | Meaning | Default |
|---|---|---|
| `certsmith.hostname` | Hostname | `certsmith` |
| `certsmith.dhcp` | `true` to use DHCP | `false` |
| `certsmith.ip` | IPv4 address | empty (console asks) |
| `certsmith.netmask` | Mask or prefix length | empty |
| `certsmith.gateway` | Default gateway | empty |
| `certsmith.dns` | Comma-separated DNS servers | empty |
| `certsmith.ntp` | Comma-separated NTP servers | empty (distribution default) |

Anything left empty falls back to the console. Passwords are deliberately **not** OVF properties (they would sit in plain text in the VM's configuration).

## Appendix C: notes per hypervisor
- **VMware (ESXi, vCenter, Workstation, Fusion):** the OVA imports directly; `open-vm-tools` is in the image; vApp properties appear in the deploy wizard. Use `vmxnet3`.
- **Proxmox VE:** `qm importovf` or the UI's import handle the OVA; the qcow2 is simpler. Use `virtio` and enable the QEMU guest agent. As far as I know Proxmox does not prompt for OVF properties (**unverified**), so plan on the console path there.
- **Hyper-V:** use the VHDX on a Generation 2 VM, Secure Boot template "Microsoft UEFI Certificate Authority", and the synthetic network adapter. No OVF import in Hyper-V Manager, so again the console path.
- **VirtualBox:** import the OVA; Intel PRO/1000 or virtio-net. OVF properties are ignored, the console path applies.
- **Cloud (AWS, Azure, GCP):** out of scope. The addressing model, console, and OVA all assume a hypervisor.

## Appendix D: questions that change the plan
1. Public repository, or public releases from a private source?
2. Is `qcow2` + `VHDX` worth shipping from day one, or OVA only to start?
3. Is "allowed networks defaults to the local subnet" acceptable, or should it default to "anywhere on a private range"?
4. Should the Ubuntu update also be allowed to reboot automatically in a window, or always require a click?
5. Do you want a paid-support or licence-key hook in the appliance, or none?
6. Do you want arm64 (Apple silicon hosts, Raspberry Pi) in the first release?
7. Installable target plugins ([PLUGINS.md](PLUGINS.md)) change who can run code next to the private keys. Is that acceptable for your customers, and curated or open?
