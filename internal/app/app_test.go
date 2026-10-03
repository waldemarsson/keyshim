package app

import (
	"regexp"
	"testing"
)

func TestClientTokenFormat(t *testing.T) {
	format := regexp.MustCompile(`^fm_[A-Za-z0-9]{16}$`)
	seen := map[string]bool{}
	for range 1000 {
		token := newClientToken()
		if !format.MatchString(token) {
			t.Fatalf("token %q does not match %s", token, format)
		}
		if seen[token] {
			t.Fatalf("duplicate token %q", token)
		}
		seen[token] = true
	}
}
