package acme

import (
	"errors"
	"strings"
	"testing"
)

func TestObservationsSayWhatEachNameserverIsServing(t *testing.T) {
	const ours = "w6Lh3Z02a245"
	cases := []struct {
		vals []string
		err  error
		want string
	}{
		{[]string{"YfC9kZAO5BOh"}, nil, "but not the record for this run yet"},
		{[]string{"YfC9kZAO5BOh", ours}, nil, "record for this run IS among them"},
		{nil, nil, "serves no TXT record"},
		{nil, errors.New("i/o timeout"), "could not be queried: i/o timeout"},
	}
	for _, c := range cases {
		got := describeObservation("duke.ns.cloudflare.com", c.vals, c.err, ours)
		if !strings.Contains(got, c.want) || !strings.Contains(got, "duke.ns.cloudflare.com") {
			t.Errorf("describeObservation(%v, %v) = %q, want mention of %q", c.vals, c.err, got, c.want)
		}
	}
}
