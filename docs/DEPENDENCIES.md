# Dependencies: policy and procedure

How CertSmith keeps its dependencies current, and what has to be true before a bump is accepted.
Written 10 October 2026, against CertSmith 0.12.x and Go 1.27.

## What there is to maintain

| | Count | Notes |
|---|---|---|
| Direct modules | 4 | `go-acme/lego/v5` (ACME client and DNS provider clients), `miekg/dns`, `golang.org/x/crypto`, `software.sslmate.com/src/go-pkcs12` |
| Indirect modules | about 700 | Almost all are cloud and DNS vendor SDKs that lego's providers need. Only about 200 are compiled into the binary. |
| Go toolchain | 1 | The `go` line in `go.mod`; the release workflow builds with the same version. |
| GitHub Actions | 2 | `actions/checkout`, `actions/setup-go`, pinned by commit SHA. |
| Bundled software | 193 components | Listed with their licences in `internal/web/static/THIRD_PARTY_NOTICES.txt`. |

## Principles

1. **Direct modules track the latest stable release.** They are the code CertSmith calls itself, and each is small
   enough to review. Bumping them is routine.
2. **Indirect modules are not bulk-upgraded.** Go selects the minimum version that satisfies every requirement, and
   lego's authors test lego against the versions it requires. Moving about 450 vendor SDKs to their newest minor
   versions would produce a large, unreviewable change and exercise combinations nobody tested. They move in three ways:
   with a new lego release, as patch releases (`go get -u=patch`), and individually when an advisory requires it.
3. **A security advisory is never waiting on a schedule.** A failing `govulncheck` job is fixed the same day, by the
   smallest bump that clears it.
4. **A bump is only accepted green.** Formatting, vet, the race-enabled tests, the installer tests, the documentation
   check, the private-address check, `govulncheck`, and the notices check must all pass.
5. **A major version is a project, not a bump.** It gets a branch, an assessment of what changed, and live testing
   against real CAs before it merges (see [lego v5](#lego-v5)).
6. **Every bump leaves the notices current.** `go run ./scripts/notices` regenerates the licence file and fails the
   build when a dependency's licence is not on the allowlist (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
   MPL-2.0). A new copyleft or unrecognised licence stops the change until a person decides.

## Cadence

| When | What | How |
|---|---|---|
| Every Monday | Pull requests for newer direct modules and newer Action versions | Dependabot (`.github/dependabot.yml`), grouped so one weekly pull request carries all direct modules |
| Every Monday | `govulncheck` against the default branch, even with no commits | `.github/workflows/vulncheck.yml`; a red run is an advisory published since the last release |
| On every pull request and push | The full gate | `.github/workflows/ci.yml` |
| Monthly, by hand | Patch-level refresh of indirect modules, and a look at `go list -m -u` | `sh scripts/update-deps.sh apply`, reviewed as one change |
| Within a month of a Go minor release | Move the `go` line in `go.mod` | After the `.1` patch release, never on the first release |
| Immediately | A Go patch release that fixes a vulnerability in the standard library | Bump the `go` line and tag a patch release |
| Before every release | Read the weekly results, run `sh scripts/update-deps.sh check`, confirm `govulncheck` is clean | Part of the release checklist |

## Procedure for a routine bump

```sh
sh scripts/update-deps.sh check     # what is newer, and any new major version
sh scripts/update-deps.sh apply     # bump, tidy, regenerate notices, build, vet, test, govulncheck
git diff --stat go.mod go.sum internal/web/static/THIRD_PARTY_NOTICES.txt
```

`apply` stops at the first failure and leaves the working tree changed so the cause can be examined. When it passes,
commit the three files together. A Dependabot pull request fails the notices check because Dependabot cannot run the
generator; check the branch out, run `go run ./scripts/notices`, and push the regenerated file to it.

## What to look at in a bump

- **lego minor releases.** Read the changelog for the providers CertSmith exposes (the curated list in
  `internal/dns`). A provider whose environment variable names or behaviour changed needs its form and tests updated.
- **`miekg/dns`.** Used for the zone and nameserver lookups behind propagation checks and DNS interception detection.
  Run the DNS tests and, for anything beyond a patch, one live DNS-01 test.
- **`golang.org/x/crypto`.** Reached through ACME signing, bcrypt and the PKCS#12 reader. The import tests exercise it.
- **`go-pkcs12`.** Run the import tests with a PKCS#12 file produced by the current OpenSSL as well as the generated ones.
- **The Go toolchain.** Run the whole suite with `-race`, build `linux/amd64` and `linux/arm64`, and check the
  `x509negativeserial` setting still takes effect: FortiManager and FortiAnalyzer ship certificates that need it.

## lego v5

CertSmith moved from lego v4.35.2 to **v5.5.2** (v5.0.0 was published on 11 May 2026). The change is isolated to
`internal/acme` (the issuer and the log writer) and the DNS provider interface, which now takes a context.

**Why.** v5 adds the `dns-persist-01` challenge (see [DNS-PERSIST.md](DNS-PERSIST.md)), context support throughout,
structured logging, account key rollover, and new DNS providers. v4 receives no further provider additions.

**Experimental interface in use.** CertSmith's dns-persist-01 support calls `SolverManager.SetDNSPersist01`, which lego
marks experimental and may change in any release. It, and the settings lego reads for it
(`DNSPERSIST_MANUAL_*`), are confined to `internal/acme/persist.go`; the live tests in
`internal/acme/pebble_test.go` are what to run after a lego update.

**What changed, and what CertSmith does about it.**

| Change in v5 | Handling |
|---|---|
| Account object is `acme.ExtendedAccount`, not `registration.Resource` | `registration.json` is still written in the old `{"body", "uri"}` shape, so existing accounts are found and a rollback still works (tested) |
| Private keys are returned as PKCS#8 | Converted back to PKCS#1 (RSA) and SEC 1 (ECDSA), the forms the device plug-ins and every stored key use (tested) |
| Certificates have no common name unless asked | `EnableCommonName` is set, as v4 behaved (tested) |
| Logging is `log/slog` | A small handler keeps the plain `date [LEVEL] message` lines of the issuance log (tested) |
| `Register`, `Obtain`, challenge providers and propagation checks take a context | Adopted throughout |
| Resolver list is set on a default DNS client, not as a challenge option | Set per issuance, under the issuance lock |
| `rfc2136` provider renamed `dnsupdate` | No action: the old code name and `RFC2136_*` variables are still accepted (checked in lego's source) |
| Providers removed: `azure`, `brandit`, `cloudxns`, `dnspod`, `googledomains`, `iij`, `iwantmyname` | None is offered in CertSmith's forms; a provider entered under "Other" with one of these codes will stop working |

**Verified.** The mock-CA tests (EAB signing, the full order flow, accounts reused across a restart), the DNS tests,
the race-enabled suite, and the 22 curated providers' environment variable names against v5's source.

**Not verified by tests; check on a live system after deployment.** Issuance from Let's Encrypt staging with a real
DNS provider; ZeroSSL with EAB; a wildcard; renewal of a certificate that was issued by v4; and a deployment to each
device type of a certificate issued by v5.

## Go toolchain

`go.mod` names an exact patch release (`go 1.27.2`). CI and the release workflow read it, so they cannot drift from
local builds. A Go release that changes behaviour CertSmith depends on is called out in `cmd/certsmith/main.go`
(`//go:debug x509negativeserial=1`); revisit that directive on each Go minor release.

## Records

Each bump commit names what moved and why, and says which advisories it clears. `git log -- go.mod` is the history of
dependency decisions.
