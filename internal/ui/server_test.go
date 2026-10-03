package ui

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/waldemarsson/fullmakt/internal/app"
	"github.com/waldemarsson/fullmakt/internal/audit"
	"github.com/waldemarsson/fullmakt/internal/ca"
	"github.com/waldemarsson/fullmakt/internal/config"
)

const storedValue = "very-secret-local-value"

type harness struct {
	srv     *Server
	ts      *httptest.Server
	cfgPath string
	changes int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{cfgPath: filepath.Join(dir, "config.yaml")}
	secretsPath := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(secretsPath, []byte("token: "+storedValue+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := "providers:\n  local: {type: local, file: " + secretsPath + "}\n" +
		"secrets:\n  token: {provider: local, name: token}\n" +
		"rules:\n  - {host: api.example.com, inject: [{header: Authorization, value: 'Bearer {{ secret \"token\" }}'}]}\n"
	if err := os.WriteFile(h.cfgPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	rt, err := app.Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.LoadOrCreate(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	application := app.New(h.cfgPath, cfg, rt, func(*app.Runtime) { h.changes++ })

	// Listen first so the server knows its own address for the Host check.
	h.ts = httptest.NewUnstartedServer(nil)
	h.srv, err = New(Options{
		App:         application,
		Audit:       audit.NewLog(10),
		CA:          authority,
		Listen:      h.ts.Listener.Addr().String(),
		ProxyListen: "127.0.0.1:8899",
		Version:     "test",
		Logger:      slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ts.Config.Handler = h.srv
	h.ts.Start()
	t.Cleanup(h.ts.Close)
	return h
}

// login returns a client holding a session cookie.
func (h *harness) login(t *testing.T) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	resp, err := client.Get(h.srv.LoginURL())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		t.Fatalf("login: status %d, landed on %s", resp.StatusCode, resp.Request.URL)
	}
	return client
}

func (h *harness) do(t *testing.T, client *http.Client, method, path, body string, mutate func(*http.Request)) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, h.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", h.ts.URL)
	req.Header.Set(requestHeader, "1")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, string(data)
}

func TestLoginRequired(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, http.DefaultClient, "GET", "/api/config", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no session: status = %d, want 401", resp.StatusCode)
	}
	resp, _ = h.do(t, http.DefaultClient, "GET", "/login?token=wrong", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("bad token: status = %d, want 403", resp.StatusCode)
	}
	resp, body := h.do(t, http.DefaultClient, "GET", "/", "", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Fullmakt") {
		t.Errorf("static page: status = %d", resp.StatusCode)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") {
		t.Errorf("CSP = %q", csp)
	}
}

func TestSessionCookieAttributes(t *testing.T) {
	h := newHarness(t)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(h.srv.LoginURL())
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie = %+v", cookies)
	}
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "token") {
		t.Errorf("redirect keeps token: %s", loc)
	}
}

func TestRejectsForeignHostAndCrossOrigin(t *testing.T) {
	h := newHarness(t)
	client := h.login(t)

	resp, _ := h.do(t, client, "GET", "/api/config", "", func(r *http.Request) { r.Host = "attacker.example:80" })
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Errorf("rebinding Host: status = %d, want 421", resp.StatusCode)
	}
	resp, _ = h.do(t, client, "POST", "/api/reload", "", func(r *http.Request) { r.Header.Set("Origin", "http://attacker.example") })
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("foreign Origin: status = %d, want 403", resp.StatusCode)
	}
	resp, _ = h.do(t, client, "POST", "/api/reload", "", func(r *http.Request) { r.Header.Del(requestHeader) })
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("missing request header: status = %d, want 403", resp.StatusCode)
	}
	resp, _ = h.do(t, client, "GET", "/api/config", "", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") })
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-site fetch: status = %d, want 403", resp.StatusCode)
	}
}

func TestSecretValuesAreWriteOnly(t *testing.T) {
	h := newHarness(t)
	client := h.login(t)

	resp, _ := h.do(t, client, "POST", "/api/secrets/token/check", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check: status = %d", resp.StatusCode)
	}
	resp, _ = h.do(t, client, "PUT", "/api/providers/local/keys/other", `{"value":"`+storedValue+`-2"}`, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set key: status = %d", resp.StatusCode)
	}
	for _, path := range []string{"/api/config", "/api/secrets", "/api/providers/local/keys", "/api/events", "/api/status"} {
		_, body := h.do(t, client, "GET", path, "", nil)
		if strings.Contains(body, storedValue) {
			t.Errorf("%s exposes a secret value: %s", path, body)
		}
	}
	_, body := h.do(t, client, "GET", "/api/providers/local/keys", "", nil)
	var keys []string
	if err := json.Unmarshal([]byte(body), &keys); err != nil || strings.Join(keys, ",") != "other,token" {
		t.Errorf("keys = %s", body)
	}
}

func TestPutConfig(t *testing.T) {
	h := newHarness(t)
	client := h.login(t)

	// Referencing an unknown secret is rejected and nothing is saved.
	before, _ := os.ReadFile(h.cfgPath)
	invalid := `{"providers":{"local":{"type":"local","file":"/tmp/x"}},"secrets":{},` +
		`"rules":[{"host":"a.com","inject":[{"header":"A","value":"{{ secret \"missing\" }}"}]}]}`
	resp, body := h.do(t, client, "PUT", "/api/config", invalid, nil)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "unknown secret") {
		t.Errorf("invalid config: status = %d body = %s", resp.StatusCode, body)
	}
	if after, _ := os.ReadFile(h.cfgPath); string(after) != string(before) || h.changes != 0 {
		t.Error("invalid config changed the file or runtime")
	}

	valid := `{"providers":{"local":{"type":"local","file":"/tmp/x"}},"secrets":{"s":{"provider":"local","name":"s","ttl":"5m"}},` +
		`"rules":[{"host":"b.com","inject":[{"header":"X-Key","value":"{{ secret \"s\" }}"}]}]}`
	resp, body = h.do(t, client, "PUT", "/api/config", valid, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid config: status = %d body = %s", resp.StatusCode, body)
	}
	if h.changes != 1 {
		t.Errorf("runtime updates = %d, want 1", h.changes)
	}
	saved, err := config.Load(h.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Rules[0].Host != "b.com" || saved.Secrets["s"].TTL.String() != "5m0s" {
		t.Errorf("saved config = %+v", saved)
	}
	if info, _ := os.Stat(h.cfgPath); info.Mode().Perm() != 0o600 {
		t.Errorf("config permissions = %#o", info.Mode().Perm())
	}
}

func TestLoginURLUsesListenAddress(t *testing.T) {
	h := newHarness(t)
	u, err := url.Parse(h.srv.LoginURL())
	if err != nil || u.Host != h.ts.Listener.Addr().String() || len(u.Query().Get("token")) != 64 {
		t.Errorf("login URL = %s", h.srv.LoginURL())
	}
}
