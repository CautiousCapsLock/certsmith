package engine

import "strings"

// hintFor turns errors people commonly hit into plain-language next steps. The
// raw error is always kept; the hint is added underneath it.
func hintFor(err string) string {
	l := strings.ToLower(err)
	switch {
	case strings.Contains(l, "did not return the expected txt record"):
		return "CertSmith created the challenge record (the DNS provider accepted it), but the zone's authoritative nameservers never served it. Check that: " +
			"(1) the API token belongs to the same account and zone that actually serves this domain (compare the nameservers in your provider dashboard with `dig NS yourdomain`); " +
			"(2) no CNAME delegates _acme-challenge to another zone; " +
			"(3) old _acme-challenge TXT records left by another ACME tool do not hide the problem: they are harmless, but if they are the only records returned, ours was not published where the world can see it; " +
			"(4) with a slow provider, raise \"Max DNS propagation wait\" on the certificate."
	case strings.Contains(l, "dns-persist-01"), strings.Contains(l, "dnspersist01"), strings.Contains(l, "_validation-persist"):
		return "This provider validates names with a standing dns-persist-01 record. Open the certificate and use \"Check record\": it shows the record to publish at _validation-persist.<your domain>, " +
			"and what is published now. The record names the CA and this ACME account, so it must be published again if the account, the CA or the provider's end date changes."
	case strings.Contains(l, "set an acme account email"):
		return "Open Settings and enter an email address under Certificate authority."
	case strings.Contains(l, "ratelimited"), strings.Contains(l, "rate limit"):
		return "Let's Encrypt is rate limiting this account or domain. Use the staging directory while testing, and wait before retrying production."
	case strings.Contains(l, "could not find zone"), strings.Contains(l, "unable to find zone"), strings.Contains(l, "zone not found"):
		return "The DNS provider could not find the zone for this domain. Check the token can read the zone, and that the domain is hosted in that account."
	case strings.Contains(l, "403"), strings.Contains(l, "unauthorized"), strings.Contains(l, "authentication error"), strings.Contains(l, "invalid api"):
		return "The DNS provider rejected the credentials. Check the token's permissions (it must edit DNS records and read the zone) and that it has not expired."
	case strings.Contains(l, "no such host"), strings.Contains(l, "i/o timeout"), strings.Contains(l, "connection refused"):
		return "CertSmith could not reach a required service. Check this server's outbound access and DNS."
	}
	return ""
}

func withHint(err error) string {
	msg := err.Error()
	if h := hintFor(msg); h != "" {
		msg += "\n\nHint: " + h
	}
	return msg
}
