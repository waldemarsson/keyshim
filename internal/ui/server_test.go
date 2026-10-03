package ui

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/waldemarsson/fullmakt/internal/app"
	"github.com/waldemarsson/fullmakt/internal/audit"
	"github.com/waldemarsson/fullmakt/internal/ca"
	"github.com/waldemarsson/fullmakt/internal/config"
	"github.com/waldemarsson/fullmakt/internal/keystore/keystoretest"
	"github.com/waldemarsson/fullmakt/internal/secrets"
)

const storedValue = "very-secret-local-value"

type harness struct {
	announced []string
	srv       *Server
	ts        *httptest.Server
	cfgPath   string
	changes   int
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{cfgPath: filepath.Join(dir, "config.yaml")}
	key := keystoretest.NewKey(t)
	secretsPath := filepath.Join(dir, "secrets.enc")
	if err := secrets.NewLocal(secretsPath, key).Add("token", storedValue); err != nil {
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
	rt, err := app.Build(cfg, key)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.LoadOrCreate(filepath.Join(dir, "ca"), key)
	if err != nil {
		t.Fatal(err)
	}
	application := app.New(h.cfgPath, key, cfg, rt, func(*app.Runtime) { h.changes++ })

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
		OnLoginURL:  func(u string) { h.announced = append(h.announced, u) },
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ts.Config.Handler = h.srv
	h.ts.Start()
	t.Cleanup(h.ts.Close)
	return h
}

// loginToken extracts the login token from the URL fragment.
func (h *harness) loginToken(t *testing.T) string {
	t.Helper()
	token, ok := strings.CutPrefix(h.srv.LoginURL(), "http://"+h.ts.Listener.Addr().String()+"/#login=")
	if !ok || len(token) != 64 {
		t.Fatalf("login URL = %s", h.srv.LoginURL())
	}
	return token
}

// exchange posts a login token and returns the response and session token.
func (h *harness) exchange(t *testing.T, token string) (*http.Response, string) {
	t.Helper()
	resp, body := h.do(t, http.DefaultClient, "POST", "/api/session", `{"token":"`+token+`"}`, nil)
	var out struct {
		Session string `json:"session"`
	}
	_ = json.Unmarshal([]byte(body), &out)
	return resp, out.Session
}

// login returns a client that sends a fresh session as a bearer token.
func (h *harness) login(t *testing.T) *http.Client {
	t.Helper()
	resp, session := h.exchange(t, h.loginToken(t))
	if resp.StatusCode != http.StatusOK || len(session) != 64 {
		t.Fatalf("login: status %d", resp.StatusCode)
	}
	return &http.Client{Transport: bearer(session)}
}

type bearer string

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+string(b))
	return http.DefaultTransport.RoundTrip(r)
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
	if resp, _ := h.exchange(t, strings.Repeat("0", 64)); resp.StatusCode != http.StatusForbidden {
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
	resp, _ = h.do(t, client, "POST", "/api/providers/local/keys", `{"name":"other","value":"`+storedValue+`-2"}`, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add key: status = %d", resp.StatusCode)
	}
	// Existing values cannot be replaced, and there is no route to edit one.
	resp, _ = h.do(t, client, "POST", "/api/providers/local/keys", `{"name":"token","value":"replacement"}`, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("overwrite: status = %d, want 409", resp.StatusCode)
	}
	resp, _ = h.do(t, client, "PUT", "/api/providers/local/keys/token", `{"value":"replacement"}`, nil)
	if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusNotFound {
		t.Errorf("PUT on a value: status = %d, want 404 or 405", resp.StatusCode)
	}
	for _, path := range []string{"/api/config", "/api/secrets", "/api/providers/local/keys", "/api/events", "/api/status"} {
		_, body := h.do(t, client, "GET", path, "", nil)
		if strings.Contains(body, storedValue) {
			t.Errorf("%s exposes a secret value: %s", path, body)
		}
	}
	_, body := h.do(t, client, "GET", "/api/providers/local/keys", "", nil)
	var entries []secrets.Entry
	if err := json.Unmarshal([]byte(body), &entries); err != nil || len(entries) != 2 ||
		entries[0].Name != "other" || entries[1].Name != "token" || entries[1].AddedAt.IsZero() {
		t.Errorf("entries = %s", body)
	}

	resp, _ = h.do(t, client, "DELETE", "/api/providers/local/keys/other", "", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: status = %d", resp.StatusCode)
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

func TestLoginTokenIsSingleUse(t *testing.T) {
	h := newHarness(t)
	first := h.loginToken(t)
	if resp, session := h.exchange(t, first); resp.StatusCode != http.StatusOK || session == "" {
		t.Fatalf("first login: status %d", resp.StatusCode)
	}
	if resp, _ := h.exchange(t, first); resp.StatusCode != http.StatusForbidden {
		t.Errorf("reused token: status = %d, want 403", resp.StatusCode)
	}
	if next := h.loginToken(t); next == first {
		t.Error("login token was not replaced")
	}
	if len(h.announced) != 2 || h.announced[1] != h.srv.LoginURL() {
		t.Errorf("announced URLs = %d, want the new URL announced after login", len(h.announced))
	}
}

func TestNoCookiesAndSessionsExpire(t *testing.T) {
	h := newHarness(t)
	resp, session := h.exchange(t, h.loginToken(t))
	if len(resp.Cookies()) != 0 {
		t.Errorf("login set cookies: %v", resp.Cookies())
	}
	client := &http.Client{Transport: bearer(session)}
	if resp, _ := h.do(t, client, "GET", "/api/status", "", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	h.srv.mu.Lock()
	h.srv.sessions[session] = time.Now().Add(-time.Minute)
	h.srv.mu.Unlock()
	if resp, _ := h.do(t, client, "GET", "/api/status", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expired session: status = %d, want 401", resp.StatusCode)
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	client := h.login(t)
	if resp, _ := h.do(t, client, "DELETE", "/api/session", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: status = %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, client, "GET", "/api/status", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("after logout: status = %d, want 401", resp.StatusCode)
	}
}

func TestClients(t *testing.T) {
	h := newHarness(t)
	client := h.login(t)
	resp, body := h.do(t, client, "POST", "/api/clients", `{"name":"agentbox"}`, nil)
	var created struct{ Name, Token string }
	if err := json.Unmarshal([]byte(body), &created); err != nil || resp.StatusCode != http.StatusOK || !regexp.MustCompile(`^fm_[A-Za-z0-9]{16}$`).MatchString(created.Token) {
		t.Fatalf("add client: status %d body %s", resp.StatusCode, body)
	}
	if resp, _ := h.do(t, client, "POST", "/api/clients", `{"name":"agentbox"}`, nil); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("duplicate client: status = %d", resp.StatusCode)
	}
	for _, path := range []string{"/api/clients", "/api/config", "/api/status"} {
		_, body := h.do(t, client, "GET", path, "", nil)
		if strings.Contains(body, created.Token) || strings.Contains(body, "sha256:") {
			t.Errorf("%s exposes the token or its hash: %s", path, body)
		}
	}
	saved, err := config.Load(h.cfgPath)
	if err != nil || len(saved.Clients) != 1 || saved.Clients[0].TokenHash != config.HashToken(created.Token) {
		t.Errorf("saved clients = %+v, err = %v", saved.Clients, err)
	}
	if resp, _ := h.do(t, client, "DELETE", "/api/clients/agentbox", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete client: status = %d", resp.StatusCode)
	}
}
