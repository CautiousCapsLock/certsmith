# DNS-PERSIST-01

Status: **built, experimental.** Implemented against Pebble (Let's Encrypt's test CA, v2.10.1) and tested end to
end there on 14 October 2026. No production CA has been tried yet. The draft is still moving and lego marks its
interface experimental, so the feature is off unless a provider is switched to it.

Sources are listed at the end. Things that could not be confirmed are marked **Unverified**.

## 1. What it is

`dns-persist-01` is an ACME challenge type. `dns-01` makes CertSmith publish a fresh, temporary TXT record for
every issuance and every renewal, which means the appliance must hold DNS credentials that can write to the zone,
permanently. `dns-persist-01` replaces that with **one standing TXT record**, created once:

```
_validation-persist.example.com.  3600  IN  TXT  "pebble.letsencrypt.org; accounturi=https://ca.example/acct/1; policy=wildcard; persistUntil=1798675200"
```

| Part | Meaning |
|---|---|
| Name | `_validation-persist.<domain>` |
| First value | The CA's *issuer domain name*. The CA lists the names it accepts in the challenge (`issuer-domain-names`). |
| `accounturi` | The ACME account that is authorised (required). Also in the challenge. |
| `policy=wildcard` | The record also authorises wildcard certificates (optional; needed for them) |
| `persistUntil` | A Unix time after which the CA no longer accepts it (optional) |

**What it changes for CertSmith users.**

- **DNS credentials leave the appliance.** After the record exists, issuance and renewal need no DNS write access.
- **It works where DNS-01 cannot.** A zone whose API cannot be reached from the appliance, or that somebody else
  administers, needs the record created once by hand.
- **A trade-off.** The record is a standing authorisation: whoever holds the ACME account key can obtain
  certificates for those names until the record is removed or expires. The account key becomes as sensitive as
  the DNS token was.

## 2. Where things stand

### The standard

| | |
|---|---|
| Document | `draft-ietf-acme-dns-persist`, an IETF Internet-Draft (not an RFC). Revision -01 is dated March 2026; a -02 was listed in September 2026. |
| Adoption | Adopted by the IETF ACME working group in October 2025. The CA/Browser Forum ballot SC-088v3 passed in October 2025, so the Baseline Requirements allow persistent DNS validation (section 3.2.2.4.22). |
| Stability | **Still moving.** Syntax and optional parameters have changed between revisions. Records may have to be republished after a CA moves to a newer revision. |

### Certificate authorities

| CA | Status | Notes |
|---|---|---|
| **Pebble** (test CA) | **Works** | v2.10.0 added the challenge; **v2.10.1 (April 2026) is the first with `accounturi` in it, which lego needs.** Tested here. |
| **Google Trust Services** | **Announced 28 September 2026** | Draft revision 01, issuer domain name `pki.goog`, wildcard policy, optional `persistUntil`. Whether production, staging or both: **Unverified.** Not tried. |
| **Let's Encrypt** | **Not in production, not scheduled** | A staff statement of 25 June 2026 says it will not be deployed until draft issue #64 is resolved. |
| Sectigo, ZeroSSL, DigiCert, SSL.com and others | **No announcement found** | Check each CA's ACME documentation before relying on it. |

CertSmith therefore offers the method on every provider and says so in the dialog: it is for a CA that offers it,
and with DNS credentials present the provider falls back to DNS-01 when the CA does not.

### The client library

lego v5.5.2 implements the challenge (`challenge/dnspersist01`). Its only solver is a *manual* one: it logs the
record and waits. There is no way to give it a DNS provider (the solver map is private, and lego's DNS providers
write only the `_acme-challenge` name with a digest value), so **CertSmith cannot publish the record for you.**
It shows it, and verifies it.

## 3. What was built

### The model

Validation is a property of the **certificate provider**, because the authorisation belongs to the ACME account:

| Field | Values |
|---|---|
| `validation` | `dns-01` (default) or `dns-persist-01` |
| `persist_until` | none, or an instant (the dialog takes a date and means the end of that day, UTC) |

A provider with `dns-persist-01` may have no DNS credentials, at any CA, including Let's Encrypt. With credentials
they are the fallback. A wildcard policy is not a setting: the record needs it exactly when the certificate has a
wildcard name, so it is derived from the names.

### The flow

1. **Choose** the method in the provider dialog. **Check CA account** creates the account (the record names it).
2. **Check record** on the certificate. CertSmith creates an order at the CA only to read the challenges, then
   deactivates its authorisations, and shows for each name the record name, the value (from lego's own helper),
   and what DNS holds now: *in place*, *not published*, *does not match* (with the reason), or a problem (the CA
   offered no `dns-persist-01`, with the types it did offer).
3. **Publish** the record at your DNS provider, by hand, once. Check again.
4. **Issue and renew.** CertSmith writes nothing to DNS. If the record is not visible to the resolvers it stops
   *before* asking the CA, because a failed validation counts against the account's rate limits, and the error names
   the record. If the provider has DNS credentials it falls back to DNS-01 instead and says so in the log and in the
   events.
5. **Watch.** Once a day each certificate on such a provider is checked. Two alerts, routable like the others:
   *a dns-persist-01 record is missing or no longer matches* (urgent when the certificate has 14 days or less),
   and *an authorisation is close to its end date* (30 days; urgent at 7, and once it has passed). A check that
   could not reach the CA is not an alert: only a record that was looked at and is not there is.

### Behaviour worth knowing (found in the Pebble run)

- **`persistUntil` must match exactly.** lego accepts a record only when its `persistUntil` is identical to the one
  it is configured with, including its absence. The provider's date is therefore the single source of truth, and
  changing it changes the record. The dialog says so, and the check says *which* part differs.
- **A wildcard record covers the bare name too.** `*.example.com` and `example.com` share one record that carries
  `policy=wildcard`; the check shows it once.
- **The account URL is part of the record.** At Pebble it contains the host the client used (`localhost:14000`), so
  the directory URL must stay the same. Replacing the account (a different email or EAB key) changes it.
- **A record for another account is refused** by the CA with `accounturi mismatch`, and reported here as *does not
  match* with the values seen.
- **Several issuer names.** lego uses the one that already has a matching record, otherwise the first in
  alphabetical order; the check does the same.
- **Where the zone's nameservers cannot be asked.** In *DNS check: wait* mode (or on a network that intercepts DNS)
  the resolvers are asked once after the wait, and that settles it. Without it, lego also requires the zone's own
  nameservers to serve the record.

### Security properties

- The ACME account key is sealed like every other secret and is included in backups. It is now an authorisation
  for the persisted names; the help says so.
- Removing the record, or letting `persistUntil` pass, ends the authorisation.
- A CAA record with `accounturi` limits issuance to the same account and is complementary.

## 4. Not done

| Item | Why |
|---|---|
| Publishing the record through a DNS provider | lego's providers cannot write a `_validation-persist` name; it needs per-provider support upstream or in CertSmith's plug-ins. |
| A live run against Google Trust Services | Needs an account with EAB credentials. The only CA exercised is Pebble. |
| Let's Encrypt production | Not available (section 2). |
| Per-CA "supports dns-persist-01" flag in the presets | Set it only after a CA has been observed to offer the challenge. |
| TTL advice, CAA helper | Documentation only, if wanted. |

## 5. Testing it

The unit tests use an in-process mock CA and a DNS server (`internal/acme/persist_test.go`) and run everywhere.
`internal/acme/pebble_test.go` runs the same flows against a real Pebble and is skipped unless
`CERTSMITH_PEBBLE` is set.

```sh
# Pebble and its DNS server (Go 1.24 or later; add GOOS/GOARCH to build for another machine)
go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
go install github.com/letsencrypt/pebble/v2/cmd/pebble-challtestsrv@v2.10.1
```

Pebble needs External Account Binding so that it behaves like the CAs this is meant for. Use its
`test/config/pebble-config-external-account-bindings.json` (the MAC key of `kid-1` is in the test), the
`test/certs` directory next to it, and start the two programs:

```sh
pebble-challtestsrv -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 -http01 "" -https01 "" -tlsalpn01 "" -doh ""
PEBBLE_VA_NOSLEEP=1 pebble -config pebble-config.json -dnsserver 127.0.0.1:8053
```

The tests, with Pebble's own CA certificate trusted by lego only:

```sh
CERTSMITH_PEBBLE=1 LEGO_CA_CERTIFICATES=test/certs/pebble.minica.pem \
  go test ./internal/acme -run Pebble -v
```

To try it in the page, run CertSmith with the same `LEGO_CA_CERTIFICATES` (and `LEGO_CA_SYSTEM_CERT_POOL=true`, so
real CAs stay trusted), set under Settings the resolver `127.0.0.1:8053` and *DNS check: wait*, and add a provider
for the directory `https://localhost:14000/dir` with the key `kid-1` and its MAC key. The record the page shows is
published into Pebble's DNS with:

```sh
wget -qO- --header='Content-Type: application/json' \
  --post-data='{"host":"_validation-persist.app.persist.test.","value":"<the value shown>"}' \
  http://127.0.0.1:8055/set-txt
```

Pebble is a test CA whose private key is public. Bind it to 127.0.0.1, and never trust its CA certificate
system-wide.

## Sources

- Let's Encrypt, [DNS-PERSIST-01: A New Model for DNS-based Challenge Validation](https://letsencrypt.org/2026/02/18/dns-persist-01), 18 February 2026
- Let's Encrypt community, [Dns-persist-01 deployment status and timeline](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468)
- Google Trust Services, [September 2026: supports ACME DNS-PERSIST-01](https://developers.google.com/public-key-infrastructure/updates/september2026-dns-persist-01)
- IETF, [draft-ietf-acme-dns-persist-01](https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-01.html)
- Pebble, [v2.10.0](https://github.com/letsencrypt/pebble/releases/tag/v2.10.0) (challenge, PR 536) and [v2.10.1](https://github.com/letsencrypt/pebble/releases/tag/v2.10.1) (`accounturi`, PR 544)
- lego v5.5.2 source: `challenge/dnspersist01`, `challenge/resolver/solver_manager.go`, `internal/dnspersist`
