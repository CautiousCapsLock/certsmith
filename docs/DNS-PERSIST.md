# Plan: DNS-PERSIST-01 support

Status: **plan for review, nothing here is built.** Researched on 10 October 2026 against CertSmith 0.12.x.
Sources are listed at the end. Things that could not be confirmed are marked **Unverified**.

## 1. What it is

`dns-persist-01` is a new ACME challenge type. Today's `dns-01` makes CertSmith publish a fresh, temporary TXT
record for every issuance and every renewal, which means the appliance must hold DNS credentials that can write to
the zone, permanently. `dns-persist-01` replaces that with **one standing TXT record**, created once:

```
_validation-persist.example.com.  3600  IN  TXT  "pki.goog; accounturi=https://pki.goog/acct/12345678; policy=wildcard; persistUntil=1798675200"
```

| Part | Meaning |
|---|---|
| Name | `_validation-persist.<domain>` |
| First value | The CA's *issuer domain name* (the CA publishes it; for Google Trust Services it is `pki.goog`) |
| `accounturi` | The ACME account that is authorised (required) |
| `policy=wildcard` | The record also authorises subdomains and wildcard certificates (optional) |
| `persistUntil` | A Unix time after which the CA no longer accepts it (optional) |

Several CAs can have a record at the same name; each reads only the one carrying its own issuer domain name.

**What it would change for CertSmith users.**

- **DNS credentials leave the appliance.** After the record exists, issuance and renewal need no DNS write access.
  Today CertSmith's DNS tokens are among the most sensitive things it stores.
- **It works where DNS-01 cannot.** A zone whose API cannot be reached from the appliance, or that somebody else
  administers, needs the record created once by hand.
- **A trade-off.** The record is a standing authorisation: whoever holds the ACME account key can obtain certificates
  for those names until the record is removed or expires. The account key becomes as sensitive as the DNS token was.

## 2. Where things stand

### The standard

| | |
|---|---|
| Document | `draft-ietf-acme-dns-persist`, an IETF Internet-Draft (not an RFC). Revision -01 is dated March 2026; a -02 was listed in September 2026. |
| Adoption | Adopted by the IETF ACME working group in October 2025. The CA/Browser Forum ballot SC-088v3 passed in October 2025, so the Baseline Requirements allow persistent DNS validation (section 3.2.2.4.22). |
| Stability | **Still moving.** Syntax and optional parameters have changed between revisions, and there are open issues. Early adopters are told they may need to update records. |

### Certificate authorities

| CA | Status | Notes |
|---|---|---|
| **Google Trust Services** | **Announced 28 September 2026** | Draft revision 01, issuer domain name `pki.goog`, wildcard policy, optional `persistUntil`. The announcement does not say whether it is production, staging, or both. **Unverified.** |
| **Let's Encrypt** | **Not in production, not scheduled** | Supported in Pebble (its test CA); staging was partial (an `accounturi` was missing from challenges as of June 2026). A staff statement of 25 June 2026 says it will not be deployed until draft issue #64 is resolved. |
| Sectigo, ZeroSSL, DigiCert, SSL.com and others | **No announcement found** | Nothing from these CAs turned up. Each should be checked against its own ACME documentation before any claim is made. |

### The client library

lego **v5** implements it (`challenge/dnspersist01`, added in v5.0.0 on 11 May 2026 and moved to draft revision 01
later). A provider supplies one method, `Persist(ctx, fqdn, value)`, plus a timeout. lego checks the record on the
authoritative and recursive nameservers, and offers `WithIssuerDomainName`, `WithPersistUntil` and propagation
options. The provider interface is documented by lego as **experimental and may change without notice.**

CertSmith now uses lego v5, so the library prerequisite is met (see [DEPENDENCIES.md](DEPENDENCIES.md#lego-v5)).

## 3. Recommendation

**Do not build user-facing support yet, but prepare for it.** The only CA that has shipped it is Google, the draft can
still change under us, and the library interface is experimental. Building the full feature now would risk a
rewrite. What is worth doing now costs little and is useful regardless:

1. ~~**Migrate to lego v5.**~~ Done; the live checks listed in DEPENDENCIES.md remain.
2. **Run a spike against Google Trust Services** with a throwaway domain, to confirm the real behaviour (about 1 day).
   CertSmith already supports Google Trust Services through External Account Binding.
3. **Decide on the feature when two things are true:** a second CA supports it in production (Let's Encrypt being
   the one that matters), and the draft has had a revision with no syntax change.

## 4. Design

### 4.1 The model

Validation is a property of the **certificate provider** (the CA account), because the authorisation is tied to the
ACME account:

| Field | Values |
|---|---|
| `validation` | `dns-01` (default) or `dns-persist-01` |
| `persist_until` | none, or a number of months (default proposal: 12) |
| `wildcard_policy` | derived: on when any name on a certificate using this provider is a wildcard, or the domain's zone is shared |

A CA preset gains a `supports_persist` flag. It is set only after the behaviour has been observed against that CA.
For a custom directory the option is offered with a warning, because support appears per authorisation at order time
and cannot be read from the directory.

### 4.2 The flow

1. **Choose.** In the provider dialog: *Domain validation* with the two methods, each explained in a sentence, and
   the second offered only where the CA supports it.
2. **Show the record.** Once the account exists (the existing "Check CA account" button registers it), CertSmith
   shows, per domain, the exact record: name, TTL, and the value built from the account URI and the CA's issuer
   domain name. A copy button for each. If the provider also has DNS credentials, a **Publish record** button creates
   it through the existing DNS provider, and nothing is removed afterwards.
3. **Verify.** A **Check record** button queries the authoritative nameservers and reports what it found.
4. **Issue and renew** with no DNS writes. If the CA does not offer `dns-persist-01` for an authorisation and the
   provider has DNS credentials, fall back to `dns-01` and say so in the log; without credentials, fail with a
   message that names the missing record.
5. **Watch it.** The record is checked daily. Two new alerts: the record is missing or no longer matches the account,
   and `persistUntil` is within 30 days. Without them, a lapsed record would surface as a failed renewal.

### 4.3 Security properties to keep

- The ACME account key stays sealed like every other secret and is included in backups; document that it is now an
  authorisation for the persisted domains.
- Rotating the account key changes `accounturi`, so every record must be re-published. The dialog must say so before
  it lets anyone do it.
- A CAA record with `accounturi` limits issuance to the same account and is complementary; mention it in the help.
- Removing the record, or letting `persistUntil` pass, is the revocation mechanism for the authorisation.

### 4.4 What is not in scope

HTTP-01 and TLS-ALPN-01, and the manual DNS provider flow, are not part of this plan.

## 5. Phases

| Phase | Work | Exit criteria | Effort |
|---|---|---|---|
| 0 | Watch: Let's Encrypt production status, the draft, lego releases | A decision gate is met (section 3) | none |
| 1 | lego v4 to v5 ([DEPENDENCIES.md](DEPENDENCIES.md#lego-v5)) | **Done.** Tests pass; live DNS-01 issuance (Let's Encrypt staging, ZeroSSL) still to confirm | done |
| 2 | Spike: issue from Google Trust Services with `dns-persist-01` | A certificate issued with no DNS write at issuance; findings written down | 1 day |
| 3 | Model, engine and provider dialog; record display, publish and verify | Issue and renew with no DNS credentials; mock-CA tests; one live test | 2 to 3 days |
| 4 | Monitoring, the two alerts, documentation, notices | Alerts tested; README and Readme updated | 1 to 2 days |
| 5 | Let's Encrypt, when it ships to production | Live test against production | 0.5 day |

## 6. Risks

| Risk | Reduction |
|---|---|
| The draft changes and records stop validating | Track the revision lego implements; build the record from lego's own helpers, not by hand; keep the feature off by default; tell users which draft revision is supported |
| lego's provider interface is experimental | Isolate it behind one small adapter in `internal/acme`; pin lego to a tested version |
| Users treat a standing authorisation lightly | Say plainly, in the dialog, what the record allows and how to end it; default `persistUntil` to a bound |
| Only one CA supports it | Offer it only where verified; DNS-01 stays the default and the fallback |
| Testing needs a CA that supports it | Pebble supports it locally; Google Trust Services needs an EAB account |

## 7. Questions for you

1. **Is "prepare, don't build yet" the right call?** The alternative is to build against Google Trust Services now and
   accept some rework if the draft changes.
2. **Default `persistUntil`.** None (simplest, longest exposure), or 12 months with an expiry alert (my suggestion).
3. **Do you have a Google Trust Services account** (it needs EAB credentials) for the phase 2 spike?

## Sources

- Let's Encrypt, [DNS-PERSIST-01: A New Model for DNS-based Challenge Validation](https://letsencrypt.org/2026/02/18/dns-persist-01), 18 February 2026
- Let's Encrypt community, [Dns-persist-01 deployment status and timeline](https://community.letsencrypt.org/t/dns-persist-01-deployment-status-and-timeline/246468)
- Google Trust Services, [September 2026: supports ACME DNS-PERSIST-01](https://developers.google.com/public-key-infrastructure/updates/september2026-dns-persist-01)
- IETF, [draft-ietf-acme-dns-persist-01](https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-01.html)
- lego v5.5.2 source and changelog: `challenge/dnspersist01`, `challenge/provider.go`
