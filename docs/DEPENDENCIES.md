# Dependencies: policy and procedure

How CertSmith keeps its dependencies current, and what has to be true before a bump is accepted.
Written 10 October 2026, against CertSmith 0.12.x and Go 1.27.

## What there is to maintain

| | Count | Notes |
|---|---|---|
| Direct modules | 4 | `go-acme/lego/v4` (ACME client and 20+ DNS provider clients), `miekg/dns`, `golang.org/x/crypto`, `software.sslmate.com/src/go-pkcs12` |
| Indirect modules | about 680 | Almost all are cloud and DNS vendor SDKs that lego's providers need. Only about 200 are compiled into the binary. |
| Go toolchain | 1 | The `go` line in `go.mod`; the release workflow builds with the same version. |
| GitHub Actions | 2 | `actions/checkout`, `actions/setup-go`, pinned by commit SHA. |
| Bundled software | 205 components | Listed with their licences in `internal/web/static/THIRD_PARTY_NOTICES.txt`. |

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

lego published v5.0.0 on 11 May 2026 (current release 5.5.2). CertSmith is on v4.35.2, the last v4 release.

**Why move.** v5 adds the `dns-persist-01` challenge (see [DNS-PERSIST.md](DNS-PERSIST.md)), context support
throughout, structured logging, ACME error codes, account key rollover, and new DNS providers. v4 is expected to
receive no further provider additions.

**What changes for CertSmith.** A trial build in a throwaway copy produced 19 compile errors, all in
`internal/acme/issuer.go`, in about 14 distinct places:

| Change in v5 | Affects |
|---|---|
| `registration.Resource` is gone | account handling, 4 places |
| `Register`, `RegisterWithExternalAccountBinding`, `Obtain` take a context | issuance and registration |
| `legolog.Logger` is replaced by `log/slog` | the issuance log writer |
| `lego.LEDirectoryProduction` and `LEDirectoryStaging` are gone | directory selection |
| `dns01.FindZoneByFqdn`, `ParseNameservers`, `AddRecursiveNameservers` moved | the propagation wrapper |
| `dns01.WrapPreCheck` signature | the DNS interception handling |
| `CertificateConfig.KeyType` moved | key type selection |
| `legoUser` must satisfy a changed `registration.User` | the ACME account |

The DNS provider packages (`internal/dns`) and the engine compiled unchanged, but behaviour must be verified: the
provider factory and its environment variable names are part of "new approach of the DNS calls".

**Plan.**

1. Branch. Replace the import path, then fix `internal/acme/issuer.go` and its tests until the build is clean.
2. Run the existing mock-CA tests (they verify EAB signing and the full order flow) and the DNS tests.
3. For every provider in the curated list, compare the field names CertSmith sends with what v5 reads.
4. Live tests: Let's Encrypt staging with a real DNS provider, ZeroSSL with EAB, and a wildcard.
5. Update the notices, this document, and the README; merge to the default branch only when all of the above pass.

Estimate: one to two days including live tests. The migration has value on its own, and it is the prerequisite for
DNS-PERSIST-01.

## Go toolchain

`go.mod` names an exact patch release (`go 1.27.2`). CI and the release workflow read it, so they cannot drift from
local builds. A Go release that changes behaviour CertSmith depends on is called out in `cmd/certsmith/main.go`
(`//go:debug x509negativeserial=1`); revisit that directive on each Go minor release.

## Records

Each bump commit names what moved and why, and says which advisories it clears. `git log -- go.mod` is the history of
dependency decisions.
