package rules

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/waldemarsson/fullmakt/internal/config"
)

func knownSecrets(names ...string) func(string) bool {
	return func(n string) bool { return slices.Contains(names, n) }
}

func getter(values map[string]string) Getter {
	return func(_ context.Context, name string) (string, error) {
		v, ok := values[name]
		if !ok {
			return "", errors.New("missing")
		}
		return v, nil
	}
}

func mustCompile(t *testing.T, rs ...config.Rule) *Engine {
	t.Helper()
	e, err := Compile(rs, knownSecrets("gh", "other"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func bearer(secret string) []config.Inject {
	return []config.Inject{{Header: "Authorization", Value: `Bearer {{ secret "` + secret + `" }}`}}
}

func TestMatch(t *testing.T) {
	e := mustCompile(t,
		config.Rule{Name: "repo", Host: "api.github.com", Methods: []string{"get"}, Paths: []string{"/repos/me/*"}, Inject: bearer("gh")},
		config.Rule{Name: "wild", Host: "*.example.com:8443", Inject: bearer("other")},
	)
	tests := []struct {
		host, port, method, path string
		want                     string
	}{
		{"api.github.com", "443", "GET", "/repos/me/x/issues", "repo"},
		{"API.GitHub.com.", "443", "GET", "/repos/me/x", "repo"},
		{"api.github.com", "443", "POST", "/repos/me/x", ""},
		{"api.github.com", "443", "GET", "/repos/other/x", ""},
		{"api.github.com", "443", "GET", "/repos/me", ""},
		{"api.github.com", "8443", "GET", "/repos/me/x", ""},
		{"a.example.com", "8443", "PUT", "/", "wild"},
		{"a.b.example.com", "8443", "PUT", "/", "wild"},
		{"example.com", "8443", "PUT", "/", ""},
		{"a.example.com", "443", "PUT", "/", ""},
		{"evilexample.com", "8443", "PUT", "/", ""},
	}
	for _, tt := range tests {
		u, _ := url.Parse(tt.path)
		got := ""
		if r := e.Match(tt.host, tt.port, tt.method, u); r != nil {
			got = r.Name
		}
		if got != tt.want {
			t.Errorf("Match(%s:%s %s %s) = %q, want %q", tt.host, tt.port, tt.method, tt.path, got, tt.want)
		}
	}
}

func TestMatchRejectsAmbiguousPaths(t *testing.T) {
	e := mustCompile(t, config.Rule{Host: "api.github.com", Paths: []string{"/repos/me/*"}, Inject: bearer("gh")})
	for _, p := range []string{
		"/repos/me/../other/x",
		"/repos/me/%2e%2e/other/x",
		"/repos/me/x%2f..%2f..%2fother",
		"/repos/me/..;/other/x",
		"/repos/me//x",
		"/repos/me/%252e%252e/x",
		`/repos/me/..\other`,
	} {
		u, err := url.Parse(p)
		if err != nil {
			t.Fatalf("parse %q: %v", p, err)
		}
		if r := e.Match("api.github.com", "443", "GET", u); r != nil {
			t.Errorf("path %q matched rule %s", p, r.Name)
		}
	}
}

func TestDisabledRules(t *testing.T) {
	e := mustCompile(t,
		config.Rule{Name: "paused", Disabled: true, Host: "api.github.com", Inject: bearer("gh")},
		config.Rule{Name: "active", Host: "*.github.com", Inject: bearer("other")},
		config.Rule{Name: "paused-only", Disabled: true, Host: "gitlab.com", Inject: bearer("gh")},
	)
	u, _ := url.Parse("/")
	if r := e.Match("api.github.com", "443", "GET", u); r == nil || r.Name != "active" {
		t.Errorf("Match = %v, want the active rule after the paused one", r)
	}
	if e.Intercepts("gitlab.com", "443") {
		t.Error("paused-only host should be tunneled")
	}
	if _, err := Compile([]config.Rule{{Disabled: true, Host: "a.com", Inject: bearer("unknown")}}, knownSecrets("gh")); err == nil {
		t.Error("disabled rule with unknown secret: want validation error")
	}
}

func TestIntercepts(t *testing.T) {
	e := mustCompile(t, config.Rule{Host: "*.example.com", Inject: bearer("gh")})
	if !e.Intercepts("x.example.com", "443") {
		t.Error("want intercept for x.example.com:443")
	}
	if e.Intercepts("x.example.com", "80") || e.Intercepts("example.com", "443") {
		t.Error("unexpected intercept")
	}
}

func TestRender(t *testing.T) {
	e := mustCompile(t, config.Rule{Name: "git", Host: "github.com", Inject: []config.Inject{
		{Header: "authorization", Value: `{{ basic "x-access-token" (secret "gh") }}`},
		{Header: "X-Static", Value: "plain"},
	}})
	u, _ := url.Parse("/")
	inj, err := e.Match("github.com", "443", "GET", u).Render(context.Background(), getter(map[string]string{"gh": "tok"}))
	if err != nil {
		t.Fatal(err)
	}
	wantAuth := "Basic eC1hY2Nlc3MtdG9rZW46dG9r" // base64("x-access-token:tok")
	if inj.Headers[0] != (Header{"Authorization", wantAuth}) || inj.Headers[1] != (Header{"X-Static", "plain"}) {
		t.Errorf("headers = %+v", inj.Headers)
	}
	if !slices.Equal(inj.Secrets, []string{"gh"}) {
		t.Errorf("secrets = %v", inj.Secrets)
	}
	for _, want := range []string{"tok", wantAuth, "eC1hY2Nlc3MtdG9rZW46dG9r"} {
		if !slices.Contains(inj.Redact, want) {
			t.Errorf("redact list %v missing %q", inj.Redact, want)
		}
	}
	if slices.Contains(inj.Redact, "plain") {
		t.Error("static header value should not be redacted")
	}
	for i := 1; i < len(inj.Redact); i++ {
		if len(inj.Redact[i]) > len(inj.Redact[i-1]) {
			t.Errorf("redact list not sorted longest first: %v", inj.Redact)
		}
	}
}

func TestRenderRejectsControlCharacters(t *testing.T) {
	e := mustCompile(t, config.Rule{Host: "github.com", Inject: bearer("gh")})
	u, _ := url.Parse("/")
	_, err := e.Match("github.com", "443", "GET", u).Render(context.Background(),
		getter(map[string]string{"gh": "tok\r\nX-Evil: 1"}))
	if err == nil || strings.Contains(err.Error(), "tok") {
		t.Fatalf("err = %v; want control-character error without the value", err)
	}
}

func TestCompileErrors(t *testing.T) {
	tests := []config.Rule{
		{Host: "github.com", Inject: bearer("unknown")},
		{Host: "github.com", Inject: []config.Inject{{Header: "A", Value: "{{ secret "}}},
		{Host: "*.com", Inject: bearer("gh")},
		{Host: "github.com:99999", Inject: bearer("gh")},
		{Host: "git*hub.com", Inject: bearer("gh")},
	}
	for _, r := range tests {
		if _, err := Compile([]config.Rule{r}, knownSecrets("gh")); err == nil {
			t.Errorf("Compile(%+v) succeeded, want error", r)
		}
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"/a/*", "/a/b/c", true},
		{"/a/*", "/a/", true},
		{"/a/*", "/a", false},
		{"/a*", "/abc", true},
		{"/a/*/c", "/a/b/x/c", true},
		{"/a/*/c", "/a/b/x/d", false},
		{"/exact", "/exact", true},
		{"/exact", "/exact/", false},
	}
	for _, tt := range tests {
		if got := glob(tt.pattern, tt.s); got != tt.want {
			t.Errorf("glob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}
