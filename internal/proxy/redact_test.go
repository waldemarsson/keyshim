package proxy

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestRedactor(t *testing.T) {
	values := []string{"Bearer secret-token", "secret-token", "abc"}
	tests := []struct {
		in, want string
	}{
		{"no secrets here", "no secrets here"},
		{"x secret-token y", "x [REDACTED] y"},
		{"Authorization: Bearer secret-token", "Authorization: [REDACTED]"},
		{"secret-tokensecret-token", "[REDACTED][REDACTED]"},
		{"ends with secret-tok", "ends with secret-tok"},
		{"abcabc ab", "[REDACTED][REDACTED] ab"},
		{"", ""},
	}
	for _, tt := range tests {
		for name, src := range map[string]io.Reader{
			"whole":   strings.NewReader(tt.in),
			"onebyte": iotest.OneByteReader(strings.NewReader(tt.in)),
			"half":    iotest.HalfReader(strings.NewReader(tt.in)),
		} {
			got, err := io.ReadAll(newRedactor(io.NopCloser(src), values))
			if err != nil {
				t.Fatalf("%s %q: %v", name, tt.in, err)
			}
			if string(got) != tt.want {
				t.Errorf("%s %q = %q, want %q", name, tt.in, got, tt.want)
			}
		}
	}
}

func TestRedactorDropsHeldBytesOnError(t *testing.T) {
	src := io.MultiReader(strings.NewReader("data secret-to"), iotest.ErrReader(errors.New("boom")))
	got, err := io.ReadAll(newRedactor(io.NopCloser(src), []string{"secret-token"}))
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(string(got), "secret-to") {
		t.Errorf("partial secret leaked: %q", got)
	}
}
