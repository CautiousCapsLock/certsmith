# Target plugins as separate files, added and removed in the GUI

Status: **design for review, nothing here is built.** Written against CertSmith 0.9.2.
Companion to [APPLIANCE.md](APPLIANCE.md): plugin signing and distribution reuse the release and update machinery described there.

## 1. Short answer

**Yes, it is possible, and it fits the way CertSmith is already structured.** The recommended shape is:

1. **Executable plugins**: a separate program per plugin that talks to CertSmith over a small JSON-RPC protocol on stdin/stdout. Anything that can be compiled to an executable can be a plugin (Go first, with an SDK).
2. **Recipe plugins**: a data file (YAML/JSON) describing a plain REST API as a series of HTTP calls with templates. No code, so easy to write, review and trust.
3. **Host-mediated networking**: plugins do not open their own connections. They ask CertSmith to make HTTP requests for them. That keeps the API-call log, trust-on-first-use certificate pinning and an egress allow-list working for plugins exactly as they do for built-in targets.
4. **Signed packages** installed, updated, disabled and removed from **Settings → Plugins**, with a catalog published on GitHub.

What I would **not** do is use Go's own `plugin` package (loading `.so` files). Details in section 3.

## 2. How it works today (the part we build on)

- Every deployment target is a Go value implementing `plugin.Target` (`Descriptor`, `Deploy`, `Test`, and the optional `Endpointer` and `Prober`).
- A target's **entire form is generated from its `Descriptor`**: fields, types, secrets, show-if rules, advanced section, the list of API calls it documents. The UI has no per-vendor code.
- Plugins are compiled into the binary and register in `init()`. The engine, the web server and the UI only ever see the `plugin.Target` interface.
- Every HTTP request a built-in target makes goes through one client that records the call (method, path, status, device answer, timing), pins certificates the user confirmed, and redacts secrets.

So the work is mostly **an adapter that makes an out-of-process plugin look like a `plugin.Target`**, plus the install/remove lifecycle. The engine and the form UI do not change.

## 3. Options considered

| Option | Verdict | Why |
|---|---|---|
| Go `plugin` package (`.so`) | **No** | Needs cgo and the exact same Go version, flags and dependency versions as the host. Our binary is a static, cgo-free build. Linux-only, cannot be unloaded, and a bad plugin crashes the whole daemon with the keys in memory. |
| **Separate executable, JSON-RPC over stdio** | **Yes, for code** | Language-independent, crash-isolated, can be sandboxed by the OS, and maps one-to-one to the existing interface. The model Terraform, Packer and Vault use. |
| **Declarative recipes** | **Yes, for simple REST devices** | Covers the long tail (a NAS, a load balancer, a web console with a certificate-upload endpoint) without anyone writing code. |
| WebAssembly (pure-Go runtime) | **Later** | Attractive: sandboxed by construction, one portable file, no per-OS builds, the runtime is pure Go so the daemon stays static. Costs more to build and a smaller authoring community today. Revisit after the first two exist. |
| Embedded scripting language | No | Another language to secure and document, with the same trust problem as executables and none of the isolation. |

## 4. The two plugin kinds

### 4.1 Executable plugins
The host starts the plugin as a child process for each operation, sends JSON-RPC requests on stdin, reads responses on stdout, and kills it on timeout.

Methods the plugin implements:

| Method | Purpose |
|---|---|
| `describe` | Returns the descriptor: the same JSON `plugin.Descriptor` serialises to today (kind, vendor, label, help, fields, documented API calls). |
| `test` | `{config}` → `{message}` or an error. Must not change the device. |
| `deploy` | `{config, bundle: {name, domains, serial, not_after, full_chain_pem, chain_pem, key_pem}}` → `{message}` or an error. Roll back its own partial changes on failure. |
| `endpoint` *(optional)* | `{config}` → `"host:port"` the host should show a trust prompt for. |
| `probes` *(optional)* | `{config}` → list of `host:port` to check for the served certificate. |

Calls the plugin may make **back to the host** while running:

| Host method | Purpose |
|---|---|
| `http.request` | `{method, url, headers, body, timeout}` → `{status, headers, body}`. Made by CertSmith with its own client: recorded in the call log, certificate trust/pinning applied, URL restricted to the hosts the plugin declared. |
| `log` | A line for the per-target log. |
| `progress` | A short stage text, shown like the stage text of an issuance. |
| `annotate` | The device's own account of the previous call, shown beside it in the call log (what the FortiManager plugin does for JSON-RPC errors today). |

Things a plugin never receives: other targets' configuration, other certificates, the master key, the session key, or anything outside the single call.

### 4.2 Recipe plugins
A recipe is data. Sketch (not final syntax):

```yaml
id: acme-nas
name: ACME NAS (certificate upload API)
vendor: Acme
api_version: 1
fields:
  - {key: host, label: Host, type: text, required: true, row: conn}
  - {key: port, label: Port, type: number, default: "443", row: conn}
  - {key: token, label: API token, type: password, secret: true, required: true}
test:
  - request: {method: GET, url: "https://{{host}}:{{port}}/api/v1/system", headers: {Authorization: "Bearer {{token}}"}}
    expect: {status: 200, json: {"$.version": "exists"}}
deploy:
  - request:
      method: POST
      url: "https://{{host}}:{{port}}/api/v1/certificate"
      headers: {Authorization: "Bearer {{token}}"}
      json: {certificate: "{{cert.full_chain}}", key: "{{cert.key}}"}
    expect: {status: 200}
  - request: {method: POST, url: "https://{{host}}:{{port}}/api/v1/service/restart", headers: {Authorization: "Bearer {{token}}"}}
    retry: {attempts: 5, delay: 3s}   # the web service restarts and drops the connection
```
- Template variables: the config fields, `cert.full_chain`, `cert.chain`, `cert.leaf`, `cert.key`, `cert.name`, `cert.serial`, plus filters (`base64`, `pkcs12(password)`, `urlencode`).
- Step results can be captured and reused (`capture: {id: "$.id"}`), with `on_failure` steps for rollback.
- Deliberately **not** a programming language: no loops, no arbitrary expressions. Anything that needs real logic (FortiOS capability planning, FortiManager's get/add/update choice) is an executable plugin.

## 5. Why host-mediated HTTP is the important decision
If plugins opened their own sockets we would lose, for plugins only, everything we built in the last few days:
- the **API-call log and verbose panel** (the plugin would have to report its own calls, honestly),
- **trust on first use**: the "this device's certificate is not trusted, do you want to trust it?" dialog, the pin, and the Go negative-serial-number handling,
- **egress control**: a plugin that can only ask for requests to `fg.example.com:443` cannot send your private key to anywhere else,
- **secret redaction** in logs.

With host-mediated HTTP all four work unchanged, and a plugin can run with **no network at all** (`PrivateNetwork=yes` in a systemd sandbox, or an empty network namespace). It can only talk to the host over its stdin and stdout.

Protocols that are not HTTP (SSH, SNMP, a vendor TCP protocol) are the exception. They need either a host-provided `tcp.dial` with the same allow-list and logging, or an explicit permission for direct sockets restricted to named hosts. I would **leave these out of version 1**, ship HTTP-only, and see what people ask for.

## 6. Package format and trust

### 6.1 Package
A plugin is a `.csplugin` file (a zip) or a release asset on GitHub:
```
plugin.json          manifest
bin/linux-amd64/…    the executable(s), per platform (executable plugins)
recipe.yaml          the recipe (recipe plugins)
LICENSE
SIGNATURE            signature over the manifest and the files' hashes
```
`plugin.json`:
```json
{
  "id": "acme-nas",
  "name": "ACME NAS",
  "version": "1.2.0",
  "api_version": 1,
  "kind": "executable",
  "publisher": "Example Ltd",
  "min_certsmith": "0.10.0",
  "permissions": {
    "http_hosts": ["{config.host}:{config.port}"],
    "needs_private_key": true,
    "direct_network": false
  },
  "files": {"bin/linux-amd64/acme-nas": "sha256:…"}
}
```
- `http_hosts` may use `{config.field}` placeholders so the allow-list follows what the user configured; a plugin cannot reach a host the user did not type into its form.
- `needs_private_key: false` is for monitoring-style plugins. The host then does not send the key at all.

### 6.2 Trust model (be honest about it)
**An installed plugin that deploys a certificate receives that certificate's private key.** It is as trusted as the box itself, within what the sandbox allows. The controls are layered:

1. **Signature**: packages are signed. CertSmith ships with the project's own public key. The user may add publisher keys. **Unsigned packages are refused**, unless an admin turns on "Allow unsigned plugins" in Settings, which is off by default and shows a permanent warning banner when on.
2. **Permissions are shown and confirmed at install**: publisher, signature state, the hosts it may contact, whether it receives the private key. Changing permissions in an update requires a new confirmation.
3. **Sandbox at run time** (4.1/7): no network of its own, no access to the state directory, a private temp directory, CPU, memory and time limits, killed when the call ends.
4. **Least data**: only the one target's configuration and the one certificate bundle, only for the one call.
5. **Visibility**: everything a plugin did over HTTP is in the call log, like a built-in.

## 7. Running plugins safely

| Environment | How |
|---|---|
| Appliance (OVA) or any systemd host | The helper (APPLIANCE.md 4.3) starts each plugin call as a **transient systemd unit** (`systemd-run`): dynamic unprivileged user, `PrivateNetwork=yes`, `PrivateTmp`, `ProtectSystem=strict`, empty capabilities, `MemoryMax`, `RuntimeMaxSec`, syscall filter. |
| Plain install without systemd access | The plugin runs as the service's own user with a cleared environment, a private working directory and a timeout, and the UI states plainly that **OS-level isolation is not available**; unsigned plugins are not permitted in this mode. |

The sandbox makes "a plugin cannot reach anywhere except through the host" enforceable by the kernel instead of being a convention.

## 8. The GUI: Settings → Plugins

- **Installed** table: name, version, publisher, type (built-in, executable, recipe), signature state, targets using it, enabled/disabled.
- **Install**:
  - *From the catalog*: a list from `catalog.json` published on GitHub (the project's own plus any extra catalog URLs an admin adds), with search by vendor.
  - *From a file*: upload a `.csplugin` (the air-gapped route).
  - Both show the permissions screen before anything is written.
- **Update**: shown when the catalog has a newer version; the same permission re-confirmation applies.
- **Disable / enable**: a disabled plugin keeps its targets, which show "plugin disabled" and are skipped by the scheduler. Nothing is deleted.
- **Remove**: refused while targets use it, with the list of those targets and two choices: delete them, or disable the plugin instead.
- **Built-in plugins** (FortiGate, FortiManager, FortiAnalyzer, Proxmox VE, webhook, files, monitor-only, this server) are listed as "built in". They cannot be removed. A setting can hide vendors you do not use from the Add target drop-down.
- **A plugin's "API calls" documentation** appears in the existing API calls dialog, because the descriptor carries it.

## 9. Compatibility and lifecycle
- `api_version` is an integer. The host supports the current and the previous version. A plugin on an unsupported version is disabled with a message, never loaded.
- New descriptor field kinds are additive; the UI ignores field types it does not know and says so, rather than breaking the form.
- A plugin crash or a malformed answer fails that one operation, with the plugin's stderr (redacted) in the target's log. The daemon is unaffected.
- A hanging plugin is killed at the operation timeout (the same 45 s test and 5 min deploy limits as today).

## 10. GitHub layout and authoring experience
- **`certsmith-pluginsdk`** (Go module): `Serve(plugin)` handles the JSON-RPC loop, a typed `Host` interface with `HTTP()`, `Log()`, `Progress()`, `Annotate()`, and a **test harness** that runs a plugin against a fake device and checks the descriptor and the documented API calls against what was actually sent. That is the same check the built-in FortiGate and FortiManager tests do.
- **`certsmith-plugin-template`**: a template repository with a workflow that builds, signs and attaches a `.csplugin` to a release, and adds it to a catalog entry.
- **A conformance test** the SDK runs: describe is valid, test does not change anything, deploy is idempotent when run twice, failure leaves the device as it was.
- **A short authoring guide**: "a recipe in ten minutes", "a Go plugin in an hour".
- The project's own catalog repo holds `catalog.json` listing official and accepted community plugins with the publisher's key id, version, hashes and URLs.

## 11. What changes in CertSmith
- `internal/plugin`: the registry gains a second source (installed plugins) next to the compiled-in one. The `Target` interface does not change.
- `internal/pluginhost` (new): process management, JSON-RPC, the host callbacks, sandbox launcher, descriptor cache, an adapter that implements `plugin.Target` and `Endpointer`/`Prober`.
- `internal/recipe` (new): parser, templating, step runner, using the same HTTP client as the built-ins.
- `internal/web`: install/remove/enable/disable/update endpoints, the catalog fetch, the schema endpoint merging installed descriptors.
- Settings UI: the Plugins section above.
- The DNS-provider side is the same shape: today 23 curated lego providers plus a generic one are compiled in. The same mechanism could make DNS providers installable. Not proposed for version 1.

## 12. Phases and rough effort
| Phase | Work | Rough effort |
|---|---|---|
| 1 | Protocol, host, adapter, SDK, and **one existing target (the webhook) re-implemented as an external plugin** as the conformance fixture | 1.5–2 weeks |
| 2 | Package format, signing and verification, install/remove/enable/disable, Settings → Plugins, catalog, permissions screen | about 1 week |
| 3 | Recipe plugins: parser, templating, runner, a handful of example recipes | about 1 week |
| 4 | Sandboxing through the helper (transient units, no network, limits); degraded mode for hosts without systemd | 3–4 days |
| 5 | Authoring docs, template repository, plugin conformance suite | 3–4 days |
| 6 | Evaluate WebAssembly as a third kind | investigation only |

Depends on the release signing and the privileged helper from the appliance plan, so it comes **after** APPLIANCE.md phases 0, 1 and 3. Phase 1 here can start earlier, since it needs neither.

## 13. Risks
| Risk | Reduction |
|---|---|
| A malicious or careless plugin steals private keys | Signatures, shown permissions, no-network sandbox, host-mediated HTTP with a host allow-list, key sent only when the manifest says it needs it |
| Plugin API churn breaks users' plugins | Versioned protocol, N and N−1 support, a conformance suite, a deprecation policy |
| Support burden: "your product broke" when a third-party plugin did | Every plugin shows its publisher; the support bundle lists installed plugins; the project supports built-ins only |
| Recipes grow into a bad programming language | Hold the line: no control flow; anything complex is an executable plugin |
| Authors want non-HTTP protocols (SSH, SNMP) | Version 1 is HTTP-only; add `tcp.dial` with allow-list and logging when there is demand |
| Cross-platform builds for executable plugins | The SDK's template builds linux-amd64 and linux-arm64 by default; the manifest lists per-platform files |

## 14. Questions that change this
1. Is **running third-party executables on the appliance** acceptable at all for the kind of customer you have in mind? If not, ship recipes (and later WebAssembly) only. They are data, not code.
2. **Curated or open?** A catalog with only plugins you review, or anyone's with a warning?
3. Should plugins be allowed to **replace** a built-in (a newer FortiGate plugin than the one shipped), or only add new targets?
4. Do you want **DNS providers** installable the same way?
