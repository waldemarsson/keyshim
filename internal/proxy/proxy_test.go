package proxy

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/waldemarsson/keyshim/internal/audit"
	"github.com/waldemarsson/keyshim/internal/ca"
	"github.com/waldemarsson/keyshim/internal/config"
	"github.com/waldemarsson/keyshim/internal/keystore/keystoretest"
	"github.com/waldemarsson/keyshim/internal/rules"
)

const (
	testSecret      = "s3cret-token-value"
	testClient      = "sandbox"
	testClientToken = "fmk_test-client-token"
)

var testClients = map[string][32]byte{testClient: sha256.Sum256([]byte(testClientToken))}

// upstream records the Authorization header it receives and echoes it in a
// response header and the body, gzip-encoded when the client accepts gzip.
type upstream struct {
	*httptest.Server
	mu     sync.Mutex
	auth   []string
	ranges []string
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{}
	u.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		u.mu.Lock()
		u.auth = append(u.auth, auth)
		u.ranges = append(u.ranges, r.Header.Get("Range"))
		u.mu.Unlock()

		w.Header().Set("X-Echo-Auth", auth)
		var body io.Writer = w
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			defer gz.Close()
			body = gz
		}
		io.WriteString(body, "auth="+auth+" host="+r.Host)
	}))
	t.Cleanup(u.Close)
	return u
}

func (u *upstream) lastAuth() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.auth) == 0 {
		return "<none>"
	}
	return u.auth[len(u.auth)-1]
}

type fixture struct {
	target   *upstream // matched by the rule
	other    *upstream // no rule: tunneled
	client   *http.Client
	events   *audit.Log
	proxyURL *url.URL // without credentials
	proxy    *Proxy
	roots    *x509.CertPool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	target, other := newUpstream(t), newUpstream(t)
	targetURL, _ := url.Parse(target.URL)

	engine, err := rules.Compile([]config.Rule{{
		Name:    "test",
		Host:    targetURL.Host,           // 127.0.0.1:<port>
		Methods: []string{"GET", "TRACE"}, // TRACE so the refusal can be tested
		Paths:   []string{"/api/*"},
		Inject:  []config.Inject{{Header: "Authorization", Value: `Bearer {{ secret "token" }}`}},
	}}, func(n string) bool { return n == "token" })
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.LoadOrCreate(t.TempDir()+"/ca", keystoretest.NewKey(t))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{target: target, other: other, events: audit.NewLog(100)}

	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(target.Certificate())
	p := New(Options{
		Rules:   engine,
		Clients: testClients,
		Secrets: func(_ context.Context, name string) (string, error) {
			if name != "token" {
				return "", errors.New("unknown")
			}
			return testSecret, nil
		},
		CA:                   authority,
		Logger:               slog.New(slog.DiscardHandler),
		Audit:                f.events.Add,
		AllowLoopbackTargets: true, // the test upstreams listen on 127.0.0.1
		UpstreamRootCAs:      upstreamRoots,
	})
	f.proxy = p
	proxySrv := httptest.NewServer(p)
	t.Cleanup(proxySrv.Close)
	f.proxyURL, _ = url.Parse(proxySrv.URL)
	proxyURL := *f.proxyURL
	proxyURL.User = url.UserPassword(testClient, testClientToken)

	// The client trusts the keyshim CA (intercepted host) and the other
	// upstream's own certificate (tunneled host).
	clientRoots := x509.NewCertPool()
	clientRoots.AppendCertsFromPEM(authority.CertPEM())
	clientRoots.AddCert(other.Certificate())
	tr := &http.Transport{
		Proxy:           http.ProxyURL(&proxyURL),
		TLSClientConfig: &tls.Config{RootCAs: clientRoots},
	}
	f.roots = clientRoots
	t.Cleanup(tr.CloseIdleConnections)
	f.client = &http.Client{Transport: tr}
	return f
}

func (f *fixture) get(t *testing.T, rawURL string, mutate func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer dummy")
	if mutate != nil {
		mutate(req)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestInjectsAndRedacts(t *testing.T) {
	f := newFixture(t)
	resp, body := f.get(t, f.target.URL+"/api/items", nil)

	if got := f.target.lastAuth(); got != "Bearer "+testSecret {
		t.Errorf("upstream Authorization = %q, want injected secret", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if strings.Contains(body, testSecret) || strings.Contains(resp.Header.Get("X-Echo-Auth"), testSecret) {
		t.Errorf("secret leaked to client: header %q body %q", resp.Header.Get("X-Echo-Auth"), body)
	}
	if !strings.Contains(body, "auth=[REDACTED]") {
		t.Errorf("body = %q, want redacted echo", body)
	}
}

func TestNoInjectionOutsideRule(t *testing.T) {
	f := newFixture(t)
	f.get(t, f.target.URL+"/other", nil)
	if got := f.target.lastAuth(); got != "Bearer dummy" {
		t.Errorf("path outside rule: upstream Authorization = %q, want client's dummy", got)
	}
	f.get(t, f.target.URL+"/api/../other", nil)
	if got := f.target.lastAuth(); strings.Contains(got, testSecret) {
		t.Error("dot-segment path received the secret")
	}
}

func TestRejectsHostMismatch(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.get(t, f.target.URL+"/api/items", func(r *http.Request) { r.Host = "evil.example" })
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("status = %d, want 421", resp.StatusCode)
	}
	if got := f.target.lastAuth(); got != "<none>" {
		t.Errorf("upstream received a request: %q", got)
	}
}

func TestRejectsUpgradeWithSecret(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.get(t, f.target.URL+"/api/ws", func(r *http.Request) {
		r.Header.Set("Connection", "Upgrade")
		r.Header.Set("Upgrade", "websocket")
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", resp.StatusCode)
	}
}

func TestTunnelsHostsWithoutRules(t *testing.T) {
	f := newFixture(t)
	// The other upstream presents its own certificate, which only works if
	// the proxy tunnels instead of intercepting.
	resp, body := f.get(t, f.other.URL+"/api/items", nil)
	if resp.StatusCode != http.StatusOK || resp.TLS == nil {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !resp.TLS.PeerCertificates[0].Equal(f.other.Certificate()) {
		t.Error("tunneled connection did not reach the upstream certificate")
	}
	if !strings.Contains(body, "auth=Bearer dummy") {
		t.Errorf("body = %q", body)
	}
}

func TestPlainHTTPIsForwardedWithoutSecrets(t *testing.T) {
	f := newFixture(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "auth="+r.Header.Get("Authorization"))
	}))
	defer plain.Close()
	_, body := f.get(t, plain.URL+"/api/items", nil)
	if body != "auth=Bearer dummy" {
		t.Errorf("body = %q", body)
	}
}

func TestSameAuthority(t *testing.T) {
	tests := []struct {
		header, host, port string
		want               bool
	}{
		{"api.github.com", "api.github.com", "443", true},
		{"API.github.com.:443", "api.github.com", "443", true},
		{"api.github.com:8443", "api.github.com", "443", false},
		{"127.0.0.1:8443", "127.0.0.1", "8443", true},
		{"[::1]", "::1", "443", true},
		{"other.com", "api.github.com", "443", false},
	}
	for _, tt := range tests {
		if got := sameAuthority(tt.header, tt.host, tt.port); got != tt.want {
			t.Errorf("sameAuthority(%q, %q, %q) = %v", tt.header, tt.host, tt.port, got)
		}
	}
}

func TestAuditEventsHaveNoSecretValues(t *testing.T) {
	f := newFixture(t)
	f.get(t, f.target.URL+"/api/items", nil)
	var found bool
	for _, e := range f.events.Recent() {
		if strings.Contains(fmt.Sprintf("%+v", e), testSecret) {
			t.Fatalf("event contains secret: %+v", e)
		}
		if e.Kind == "request" && e.Rule == "test" && slices.Equal(e.Secrets, []string{"token"}) && e.Status == http.StatusOK {
			found = true
		}
	}
	if !found {
		t.Errorf("no request event for the injected request: %+v", f.events.Recent())
	}
}

func TestBlocksLoopbackTargetsByDefault(t *testing.T) {
	authority, err := ca.LoadOrCreate(t.TempDir()+"/ca", keystoretest.NewKey(t))
	if err != nil {
		t.Fatal(err)
	}
	engine, _ := rules.Compile(nil, func(string) bool { return false })
	p := New(Options{Rules: engine, Clients: testClients, CA: authority, Logger: slog.New(slog.DiscardHandler)})
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()
	proxyURL, _ := url.Parse(proxySrv.URL)
	proxyURL.User = url.UserPassword(testClient, testClientToken)

	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("loopback service was reached through the proxy")
	}))
	defer local.Close()
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	// Plain HTTP request to a loopback service.
	resp, err := client.Get(local.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("plain: status = %d, want 403", resp.StatusCode)
	}

	// CONNECT to a loopback service.
	conn, err := net.Dial("tcp", proxyURL.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte(testClient + ":" + testClientToken))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", local.Listener.Addr(), local.Listener.Addr(), auth)
	resp, err = http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("CONNECT: status = %d, want 403", resp.StatusCode)
	}

	for _, ip := range []string{"127.0.0.1", "::1", "0.0.0.0", "169.254.169.254", "fe80::1"} {
		if !forbiddenIP(net.ParseIP(ip)) {
			t.Errorf("%s should be forbidden", ip)
		}
	}
	for _, ip := range []string{"140.82.112.6", "10.0.0.1", "2606:50c0:8000::153"} {
		if forbiddenIP(net.ParseIP(ip)) {
			t.Errorf("%s should be allowed", ip)
		}
	}
}

func TestRequiresClientCredentials(t *testing.T) {
	f := newFixture(t)
	for name, user := range map[string]*url.Userinfo{
		"none":         nil,
		"wrong token":  url.UserPassword(testClient, "fmk_wrong"),
		"unknown name": url.UserPassword("other", testClientToken),
		"empty token":  url.UserPassword(testClient, ""),
	} {
		proxyURL := *f.proxyURL
		proxyURL.User = user
		client := &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyURL(&proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: f.roots},
		}}
		// HTTPS: the CONNECT is refused, so the request never reaches upstream.
		if _, err := client.Get(f.target.URL + "/api/items"); err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
			t.Errorf("%s, CONNECT: err = %v, want 407", name, err)
		}
		// Plain HTTP is refused too.
		resp, err := client.Get("http://example.invalid/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Proxy-Authenticate") == "" {
			t.Errorf("%s, plain: status = %d", name, resp.StatusCode)
		}
	}
	if got := f.target.lastAuth(); got != "<none>" {
		t.Errorf("upstream was reached without credentials: %q", got)
	}
	var rejected int
	for _, e := range f.events.Recent() {
		if e.Status == http.StatusProxyAuthRequired {
			rejected++
		}
	}
	if rejected != 8 {
		t.Errorf("rejected events = %d, want 8", rejected)
	}
}

func TestInjectedRequestsDropRangeAndRefuseTrace(t *testing.T) {
	f := newFixture(t)
	f.get(t, f.target.URL+"/api/items", func(r *http.Request) { r.Header.Set("Range", "bytes=5-9") })
	f.target.mu.Lock()
	gotRange := f.target.ranges[len(f.target.ranges)-1]
	f.target.mu.Unlock()
	if gotRange != "" {
		t.Errorf("Range reached upstream on an injected request: %q", gotRange)
	}
	resp, _ := f.get(t, f.target.URL+"/api/items", func(r *http.Request) { r.Method = http.MethodTrace })
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("TRACE: status = %d, want 403", resp.StatusCode)
	}
	for _, e := range f.events.Recent() {
		if e.Kind == "request" && e.Client != testClient {
			t.Errorf("event without client name: %+v", e)
		}
	}
}

func TestBlocksInterceptedHostResolvingToLoopback(t *testing.T) {
	authority, err := ca.LoadOrCreate(t.TempDir()+"/ca", keystoretest.NewKey(t))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := rules.Compile([]config.Rule{{
		Host:   "localhost:8443",
		Inject: []config.Inject{{Header: "Authorization", Value: `Bearer {{ secret "token" }}`}},
	}}, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{Rules: engine, Clients: testClients, CA: authority, Logger: slog.New(slog.DiscardHandler)})
	proxySrv := httptest.NewServer(p)
	defer proxySrv.Close()

	conn, err := net.Dial("tcp", strings.TrimPrefix(proxySrv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte(testClient + ":" + testClientToken))
	fmt.Fprintf(conn, "CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("CONNECT to a rule host resolving to loopback: status = %d, want 403", resp.StatusCode)
	}
}

func TestRuleScopedToAnotherClient(t *testing.T) {
	f := newFixture(t)
	targetURL, _ := url.Parse(f.target.URL)
	engine, err := rules.Compile([]config.Rule{{
		Host:    targetURL.Host,
		Clients: []string{"someone-else"},
		Inject:  []config.Inject{{Header: "Authorization", Value: `Bearer {{ secret "token" }}`}},
	}}, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	f.proxy.Update(engine, func(context.Context, string) (string, error) { return testSecret, nil }, testClients)

	resp, _ := f.get(t, f.target.URL+"/api/items", nil)
	if got := f.target.lastAuth(); got != "Bearer dummy" {
		t.Errorf("upstream Authorization = %q, want the client's own value", got)
	}
	// Tunneled, so the client sees the upstream's own certificate.
	if resp.TLS == nil || !resp.TLS.PeerCertificates[0].Equal(f.target.Certificate()) {
		t.Error("request was intercepted although no rule applies to this client")
	}
}
