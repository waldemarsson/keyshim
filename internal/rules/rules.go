// Package rules decides which requests receive secrets and renders the
// headers that carry them.
package rules

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"golang.org/x/net/publicsuffix"

	"github.com/waldemarsson/keyshim/internal/config"
)

// Getter resolves a secret name to its value.
type Getter func(ctx context.Context, name string) (string, error)

// Engine holds rules in configuration order; the first match wins.
type Engine struct {
	rules []*Rule
}

// Rule is a compiled config.Rule.
type Rule struct {
	Name     string
	host     string // exact host, or a suffix starting with "." for wildcards
	wildcard bool
	port     string
	clients  map[string]bool // nil means any client
	methods  map[string]bool // nil means any method
	paths    []string        // empty means any path
	headers  []headerTemplate
}

type headerTemplate struct {
	name string
	tmpl *template.Template
}

// Injection is the result of rendering a rule for one request.
type Injection struct {
	Rule    string
	Headers []Header
	// Secrets lists the secret names used, for audit logging.
	Secrets []string
	// Redact lists values to remove from responses, longest first.
	Redact []string
}

// Header is one rendered request header.
type Header struct {
	Name  string
	Value string
}

// Template functions available in inject values. "secret" is replaced per
// render so it can resolve values; the stub only fixes its signature.
var stubFuncs = template.FuncMap{
	"secret": func(string) (string, error) { return "", nil },
	"basic":  basicAuth,
}

func basicAuth(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

// Compile validates rules and checks that every referenced secret is known.
// Disabled rules are validated too, so resuming one cannot fail, but they are
// left out of the engine.
func Compile(cfg []config.Rule, known func(string) bool) (*Engine, error) {
	e := &Engine{}
	var errs []error
	for i, cr := range cfg {
		r, err := compileRule(i, cr, known)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !cr.Disabled {
			e.rules = append(e.rules, r)
		}
	}
	return e, errors.Join(errs...)
}

func compileRule(i int, cr config.Rule, known func(string) bool) (*Rule, error) {
	r := &Rule{Name: cr.Name, paths: cr.Paths}
	if r.Name == "" {
		r.Name = fmt.Sprintf("rule-%d", i+1)
	}
	var err error
	if r.host, r.port, r.wildcard, err = parseHostPattern(cr.Host); err != nil {
		return nil, fmt.Errorf("rule %s: %w", r.Name, err)
	}
	if len(cr.Clients) > 0 {
		r.clients = map[string]bool{}
		for _, c := range cr.Clients {
			r.clients[c] = true
		}
	}
	if len(cr.Methods) > 0 {
		r.methods = map[string]bool{}
		for _, m := range cr.Methods {
			r.methods[strings.ToUpper(m)] = true
		}
	}
	for _, inj := range cr.Inject {
		t, err := template.New(inj.Header).Funcs(stubFuncs).Parse(inj.Value)
		if err != nil {
			return nil, fmt.Errorf("rule %s: header %s: %w", r.Name, inj.Header, err)
		}
		// Dry run: catches unknown secrets and template errors at startup.
		_, _, err = render(context.Background(), t, func(_ context.Context, name string) (string, error) {
			if !known(name) {
				return "", fmt.Errorf("unknown secret %q", name)
			}
			return "placeholder", nil
		})
		if err != nil {
			return nil, fmt.Errorf("rule %s: header %s: %w", r.Name, inj.Header, err)
		}
		r.headers = append(r.headers, headerTemplate{name: http.CanonicalHeaderKey(inj.Header), tmpl: t})
	}
	return r, nil
}

// parseHostPattern accepts "host", "host:port", "*.domain" and "*.domain:port".
// The port defaults to 443.
func parseHostPattern(s string) (host, port string, wildcard bool, err error) {
	host, port = strings.ToLower(strings.TrimSpace(s)), "443"
	if h, p, splitErr := net.SplitHostPort(host); splitErr == nil {
		host, port = h, p
	}
	if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
		return "", "", false, fmt.Errorf("host %q: invalid port", s)
	}
	host = strings.TrimSuffix(host, ".")
	if rest, ok := strings.CutPrefix(host, "*."); ok {
		wildcard = true
		host = "." + rest
		// A wildcard on a shared suffix (s3.amazonaws.com, github.io,
		// azurewebsites.net, ...) covers hosts that anyone can register.
		if suffix, _ := publicsuffix.PublicSuffix(rest); suffix == rest {
			return "", "", false, fmt.Errorf("host %q: %s is a public suffix where anyone can create subdomains; name exact hosts instead", s, rest)
		}
	}
	if host == "" || host == "." || strings.ContainsAny(host, "*/@ \\") {
		return "", "", false, fmt.Errorf("host %q: invalid host", s)
	}
	return host, port, wildcard, nil
}

// NormalizeHost lowercases a host name and drops a trailing dot.
func NormalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// Intercepts reports whether client's CONNECT requests to host:port need
// TLS interception, meaning at least one rule may apply to that client.
func (e *Engine) Intercepts(host, port, client string) bool {
	host = NormalizeHost(host)
	for _, r := range e.rules {
		if r.matchClient(client) && r.matchHost(host, port) {
			return true
		}
	}
	return false
}

// Match returns the first rule that applies to client's request, or nil.
func (e *Engine) Match(host, port, method string, u *url.URL, client string) *Rule {
	host = NormalizeHost(host)
	for _, r := range e.rules {
		if !r.matchClient(client) || !r.matchHost(host, port) {
			continue
		}
		if r.methods != nil && !r.methods[method] {
			continue
		}
		if len(r.paths) > 0 && !matchPaths(r.paths, u) {
			continue
		}
		return r
	}
	return nil
}

func (r *Rule) matchClient(client string) bool {
	return r.clients == nil || r.clients[client]
}

func (r *Rule) matchHost(host, port string) bool {
	if port != r.port {
		return false
	}
	if r.wildcard {
		return len(host) > len(r.host) && strings.HasSuffix(host, r.host) && sameOwner(host, r.host[1:])
	}
	return host == r.host
}

// sameOwner reports whether base lies within host's registrable domain. It
// stops *.amazonaws.com from matching evil.s3.amazonaws.com, which belongs
// to whoever created the bucket, not to amazonaws.com.
func sameOwner(host, base string) bool {
	registrable, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return false
	}
	return base == registrable || strings.HasSuffix(base, "."+registrable)
}

// matchPaths refuses paths that servers may normalize differently from us,
// so a path rule cannot be bypassed with dot segments or encoded separators.
func matchPaths(patterns []string, u *url.URL) bool {
	if !isCanonicalPath(u.EscapedPath()) || !isCanonicalPath(u.Path) {
		return false
	}
	for _, p := range patterns {
		if glob(p, u.Path) {
			return true
		}
	}
	return false
}

func isCanonicalPath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "//") || strings.Contains(p, `\`) {
		return false
	}
	lower := strings.ToLower(p)
	for _, encoded := range []string{"%2f", "%5c", "%2e", "%00", "%25"} {
		if strings.Contains(lower, encoded) {
			return false
		}
	}
	for _, seg := range strings.Split(p, "/") {
		// Some servers treat ";params" as part of a segment ("..;" == "..").
		seg, _, _ = strings.Cut(seg, ";")
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// glob reports whether s matches pattern, where '*' matches any sequence of
// characters, including '/'.
func glob(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case p < len(pattern) && pattern[p] == s[i]:
			p++
			i++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// Render resolves the rule's secrets and returns the headers to set.
func (r *Rule) Render(ctx context.Context, get Getter) (*Injection, error) {
	inj := &Injection{Rule: r.Name}
	names := map[string]bool{}
	redact := map[string]bool{}
	for _, h := range r.headers {
		value, used, err := render(ctx, h.tmpl, get)
		if err != nil {
			return nil, fmt.Errorf("rule %s: header %s: %w", r.Name, h.name, err)
		}
		if !validHeaderValue(value) {
			return nil, fmt.Errorf("rule %s: header %s: rendered value contains control characters", r.Name, h.name)
		}
		inj.Headers = append(inj.Headers, Header{Name: h.name, Value: value})
		if len(used) == 0 {
			continue
		}
		for name, v := range used {
			names[name] = true
			redact[v] = true
		}
		// Also redact the full header value and its credential part, which
		// differ from the raw secret for encodings such as Basic auth.
		redact[value] = true
		if _, cred, ok := strings.Cut(value, " "); ok {
			redact[cred] = true
		}
	}
	delete(redact, "")
	inj.Secrets = slices.Sorted(maps.Keys(names))
	inj.Redact = slices.SortedFunc(maps.Keys(redact), func(a, b string) int {
		return cmp.Or(cmp.Compare(len(b), len(a)), cmp.Compare(a, b))
	})
	return inj, nil
}

func render(ctx context.Context, t *template.Template, get Getter) (string, map[string]string, error) {
	used := map[string]string{}
	c, err := t.Clone()
	if err != nil {
		return "", nil, err
	}
	c.Funcs(template.FuncMap{"secret": func(name string) (string, error) {
		v, err := get(ctx, name)
		if err != nil {
			return "", err
		}
		used[name] = v
		return v, nil
	}})
	var b strings.Builder
	if err := c.Execute(&b, nil); err != nil {
		return "", nil, err
	}
	return b.String(), used, nil
}

func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}
