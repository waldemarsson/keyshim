// Package ui serves the local management web UI.
//
// The UI listens on loopback, but a VM may still reach the host's loopback,
// so every API request needs a session. A single-use login token, printed at
// startup and replaced after each use, is exchanged for a session token that
// the page keeps in origin-scoped storage and sends as a bearer header.
// Cookies are not used: browsers send them to every port on a host, including
// ports a VM forwards to the host. Secret values can be written but are
// never returned.
package ui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/waldemarsson/fullmakt/internal/app"
	"github.com/waldemarsson/fullmakt/internal/audit"
	"github.com/waldemarsson/fullmakt/internal/ca"
	"github.com/waldemarsson/fullmakt/internal/config"
	"github.com/waldemarsson/fullmakt/internal/secrets"
)

//go:embed static
var staticFiles embed.FS

const (
	sessionLifetime = 12 * time.Hour
	requestHeader   = "X-Fullmakt-Request"
	maxBodyBytes    = 1 << 20
	checkTimeout    = 30 * time.Second
	streamKeepWarm  = 25 * time.Second
)

const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Options configures the UI server.
type Options struct {
	App         *app.App
	Audit       *audit.Log
	CA          *ca.Authority
	Listen      string
	ProxyListen string
	Version     string
	Logger      *slog.Logger
	// OnLoginURL receives the login URL at startup and after each login,
	// when the previous token stops working.
	OnLoginURL func(string)
}

// Server is the UI's http.Handler.
type Server struct {
	opts         Options
	token        string
	allowedHosts map[string]bool
	handler      http.Handler

	mu       sync.Mutex
	sessions map[string]time.Time // session token -> expiry
}

// New returns a UI server with a fresh login token.
func New(o Options) (*Server, error) {
	_, port, err := net.SplitHostPort(o.Listen)
	if err != nil {
		return nil, err
	}
	s := &Server{
		opts:     o,
		token:    randomHex(32),
		sessions: map[string]time.Time{},
		// Only names that point at this listener, which blocks DNS rebinding.
		allowedHosts: map[string]bool{
			o.Listen:            true,
			"localhost:" + port: true,
			"127.0.0.1:" + port: true,
			"[::1]:" + port:     true,
		},
	}

	static, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return nil, err
	}
	api := http.NewServeMux()
	api.HandleFunc("DELETE /api/session", s.logout)
	api.HandleFunc("GET /api/status", s.status)
	api.HandleFunc("GET /api/clients", s.listClients)
	api.HandleFunc("POST /api/clients", s.addClient)
	api.HandleFunc("DELETE /api/clients/{name}", s.deleteClient)
	api.HandleFunc("GET /api/ca.pem", s.caCert)
	api.HandleFunc("GET /api/config", s.getConfig)
	api.HandleFunc("PUT /api/config", s.putConfig)
	api.HandleFunc("POST /api/reload", s.reload)
	api.HandleFunc("GET /api/secrets", s.listSecrets)
	api.HandleFunc("POST /api/secrets/{name}/check", s.checkSecret)
	api.HandleFunc("GET /api/providers/{name}/keys", s.listKeys)
	api.HandleFunc("POST /api/providers/{name}/keys", s.addKey)
	api.HandleFunc("DELETE /api/providers/{name}/keys/{key}", s.deleteKey)
	api.HandleFunc("GET /api/events", s.events)
	api.HandleFunc("GET /api/events/stream", s.eventStream)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/session", s.login)
	mux.Handle("/api/", s.requireSession(api))
	mux.Handle("/", http.FileServerFS(static))
	s.handler = s.guard(mux)
	s.announce()
	return s, nil
}

// LoginURL returns the current single-use login URL. The token is in the
// fragment, so it is never sent to the server in a request line or logged.
func (s *Server) LoginURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loginURL()
}

func (s *Server) loginURL() string {
	return "http://" + s.opts.Listen + "/#login=" + s.token
}

func (s *Server) announce() {
	if s.opts.OnLoginURL != nil {
		s.opts.OnLoginURL(s.LoginURL())
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// guard applies the checks every request must pass.
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		if !s.allowedHosts[r.Host] {
			http.Error(w, "fullmakt: unexpected Host header", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// Cross-site requests cannot set a custom header without a CORS
			// preflight, which this server never approves.
			if r.Header.Get("Origin") != "http://"+r.Host || r.Header.Get(requestHeader) != "1" {
				http.Error(w, "fullmakt: cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "fullmakt: cross-site request refused", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// login exchanges the single-use login token for a session token. The login
// token is replaced on success, and the new login URL is announced.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	now := time.Now()
	s.mu.Lock()
	if subtle.ConstantTimeCompare([]byte(body.Token), []byte(s.token)) != 1 {
		s.mu.Unlock()
		writeError(w, http.StatusForbidden, errors.New("invalid or already used login token; use the newest URL printed by fullmakt"))
		return
	}
	s.token = randomHex(32)
	for id, expiry := range s.sessions {
		if now.After(expiry) {
			delete(s.sessions, id)
		}
	}
	id, expiry := randomHex(32), now.Add(sessionLifetime)
	s.sessions[id] = expiry
	s.mu.Unlock()

	s.opts.Logger.Info("UI login; the previous login URL no longer works")
	s.announce()
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]any{"session": id, "expiresAt": expiry})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	id, _ := bearerToken(r)
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != ""
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := bearerToken(r)
		s.mu.Lock()
		expiry, known := s.sessions[id]
		if known && time.Now().After(expiry) {
			delete(s.sessions, id)
			known = false
		}
		s.mu.Unlock()
		if !ok || !known {
			writeError(w, http.StatusUnauthorized, errors.New("not signed in"))
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type statusResponse struct {
	Version     string `json:"version"`
	ProxyListen string `json:"proxyListen"`
	UIListen    string `json:"uiListen"`
	ConfigPath  string `json:"configPath"`
	CAPath      string `json:"caPath"`
	Providers   int    `json:"providers"`
	Secrets     int    `json:"secrets"`
	Rules       int    `json:"rules"`
	Clients     int    `json:"clients"`
	// Warnings lists configuration that is valid but probably unintended.
	Warnings []string `json:"warnings"`
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	cfg := s.opts.App.Config()
	writeJSON(w, statusResponse{
		Version:     s.opts.Version,
		ProxyListen: s.opts.ProxyListen,
		UIListen:    s.opts.Listen,
		ConfigPath:  s.opts.App.Path(),
		CAPath:      s.opts.CA.CertPath(),
		Providers:   len(cfg.Providers),
		Secrets:     len(cfg.Secrets),
		Rules:       len(cfg.Rules),
		Clients:     len(cfg.Clients),
		Warnings:    append([]string{}, cfg.Warnings()...),
	})
}

func (s *Server) caCert(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="fullmakt-ca.pem"`)
	_, _ = w.Write(s.opts.CA.CertPEM())
}

func (s *Server) getConfig(w http.ResponseWriter, _ *http.Request) {
	cfg := s.opts.App.Config()
	writeJSON(w, app.Editable{Providers: cfg.Providers, Secrets: cfg.Secrets, Rules: cfg.Rules})
}

func (s *Server) putConfig(w http.ResponseWriter, r *http.Request) {
	var e app.Editable
	if err := decodeJSON(w, r, &e); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.opts.App.Apply(e); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.opts.Logger.Info("configuration updated from UI")
	s.getConfig(w, r)
}

func (s *Server) reload(w http.ResponseWriter, r *http.Request) {
	if err := s.opts.App.Reload(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.opts.Logger.Info("configuration reloaded from disk")
	s.getConfig(w, r)
}

type clientInfo struct {
	Name    string    `json:"name"`
	AddedAt time.Time `json:"addedAt"`
}

// listClients returns client names; token hashes stay on the server.
func (s *Server) listClients(w http.ResponseWriter, _ *http.Request) {
	out := []clientInfo{}
	for _, c := range s.opts.App.Config().Clients {
		out = append(out, clientInfo{Name: c.Name, AddedAt: c.AddedAt})
	}
	writeJSON(w, out)
}

// addClient creates a client and returns its token, which is shown once.
func (s *Server) addClient(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	token, err := s.opts.App.AddClient(body.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.opts.Logger.Info("proxy client added from UI", "client", body.Name)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, map[string]string{"name": body.Name, "token": token})
}

func (s *Server) deleteClient(w http.ResponseWriter, r *http.Request) {
	if err := s.opts.App.DeleteClient(r.PathValue("name")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.opts.Logger.Info("proxy client deleted from UI", "client", r.PathValue("name"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listSecrets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.opts.App.Runtime().Store.Statuses())
}

func (s *Server) checkSecret(w http.ResponseWriter, r *http.Request) {
	store := s.opts.App.Runtime().Store
	name := r.PathValue("name")
	if !store.Has(name) {
		writeError(w, http.StatusNotFound, fmt.Errorf("secret %q is not configured", name))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), checkTimeout)
	defer cancel()
	result := struct {
		OK    bool   `json:"ok"`
		Error string `json:"error,omitempty"`
	}{OK: true}
	if err := store.Check(ctx, name); err != nil {
		result.OK, result.Error = false, err.Error()
	}
	writeJSON(w, result)
}

// localProvider returns the named provider if it is a local file provider.
func (s *Server) localProvider(w http.ResponseWriter, r *http.Request) (*secrets.Local, bool) {
	name := r.PathValue("name")
	p, ok := s.opts.App.Runtime().Providers[name]
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("provider %q is not configured", name))
		return nil, false
	}
	local, ok := p.(*secrets.Local)
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Errorf("provider %q is not of type %s", name, config.ProviderLocal))
		return nil, false
	}
	return local, true
}

func (s *Server) listKeys(w http.ResponseWriter, r *http.Request) {
	local, ok := s.localProvider(w, r)
	if !ok {
		return
	}
	entries, err := local.Entries()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, entries)
}

// addKey stores a new local value. Existing values cannot be replaced or
// read; they can only be deleted.
func (s *Server) addKey(w http.ResponseWriter, r *http.Request) {
	local, ok := s.localProvider(w, r)
	if !ok {
		return
	}
	var body struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := local.Add(body.Name, body.Value); errors.Is(err, secrets.ErrExists) {
		writeError(w, http.StatusConflict, err)
		return
	} else if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.afterKeyChange(w, "added", r.PathValue("name"), body.Name)
}

func (s *Server) deleteKey(w http.ResponseWriter, r *http.Request) {
	local, ok := s.localProvider(w, r)
	if !ok {
		return
	}
	if err := local.Delete(r.PathValue("key")); err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	s.afterKeyChange(w, "deleted", r.PathValue("name"), r.PathValue("key"))
}

func (s *Server) afterKeyChange(w http.ResponseWriter, action, provider, key string) {
	// Drop cached values so the change takes effect immediately.
	if err := s.opts.App.ReloadSecrets(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.opts.Logger.Info("local secret "+action+" from UI", "provider", provider, "key", key)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) events(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.opts.Audit.Recent())
}

func (s *Server) eventStream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}
	events, unsubscribe := s.opts.Audit.Subscribe()
	defer unsubscribe()
	ticker := time.NewTicker(streamKeepWarm)
	defer ticker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
		case e := <-events:
			data, err := json.Marshal(e)
			if err != nil {
				continue
			}
			if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
				return
			}
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid request body: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeError returns {"errors": [...]}, one entry per line of err, so joined
// validation errors show up as a list.
func writeError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string][]string{"errors": strings.Split(err.Error(), "\n")})
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}
