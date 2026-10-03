// Package proxy implements the HTTP proxy that injects secrets into matching
// HTTPS requests and passes everything else through unchanged.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/waldemarsson/fullmakt/internal/audit"
	"github.com/waldemarsson/fullmakt/internal/ca"
	"github.com/waldemarsson/fullmakt/internal/rules"
)

const (
	dialTimeout      = 10 * time.Second
	handshakeTimeout = 10 * time.Second
)

// Options configures a Proxy.
type Options struct {
	Rules   *rules.Engine
	Secrets rules.Getter
	CA      *ca.Authority
	Logger  *slog.Logger
	// Audit receives every connection and request event. Optional.
	Audit func(audit.Event)
	// AllowLoopbackTargets permits connections to loopback, link-local and
	// unspecified addresses. Off by default so clients cannot use the proxy
	// to reach services on its host, such as the UI or a cloud metadata endpoint.
	AllowLoopbackTargets bool
	// UpstreamRootCAs replaces the system roots for upstream TLS. Tests use it.
	UpstreamRootCAs *x509.CertPool
}

// Proxy is an http.Handler for proxy requests: CONNECT tunnels and
// absolute-form plain HTTP requests.
type Proxy struct {
	state     atomic.Pointer[state]
	ca        *ca.Authority
	log       *slog.Logger
	audit     func(audit.Event)
	dialer    *net.Dialer
	transport *http.Transport
}

// state is replaced as a whole when the configuration is reloaded.
type state struct {
	rules   *rules.Engine
	secrets rules.Getter
}

// ErrForbiddenTarget is returned when a connection to a loopback,
// link-local or unspecified address is refused.
var ErrForbiddenTarget = errors.New("target address is not allowed")

// New returns a Proxy.
func New(o Options) *Proxy {
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	if !o.AllowLoopbackTargets {
		// Control sees the resolved address, so DNS names that resolve to
		// loopback are caught too.
		dialer.Control = func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip == nil || forbiddenIP(ip) {
				return fmt.Errorf("%w: %s", ErrForbiddenTarget, address)
			}
			return nil
		}
	}
	p := &Proxy{
		ca:     o.CA,
		log:    o.Logger,
		audit:  o.Audit,
		dialer: dialer,
		transport: &http.Transport{
			// Never chain to a proxy from the environment.
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.UpstreamRootCAs},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   handshakeTimeout,
			ExpectContinueTimeout: time.Second,
		},
	}
	p.Update(o.Rules, o.Secrets)
	return p
}

func forbiddenIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast()
}

// Update replaces the rules and secret source. Requests already in progress
// finish with the previous ones.
func (p *Proxy) Update(r *rules.Engine, secrets rules.Getter) {
	p.state.Store(&state{rules: r, secrets: secrets})
}

func (p *Proxy) record(e audit.Event) {
	e.Time = time.Now()
	p.log.Info(e.Kind, e.Attrs()...)
	if p.audit != nil {
		p.audit(e)
	}
}

// ServeHTTP dispatches proxy requests.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.handleConnect(w, r)
	case r.URL.IsAbs() && r.URL.Scheme == "http":
		p.forwardPlain(w, r)
	default:
		http.Error(w, "fullmakt: not a proxy request", http.StatusBadRequest)
	}
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "fullmakt: invalid CONNECT target", http.StatusBadRequest)
		return
	}
	host = rules.NormalizeHost(host)
	intercept := p.state.Load().rules.Intercepts(host, port)
	ev := audit.Event{Kind: "connect", Host: r.Host, Mode: "tunnel"}
	if intercept {
		ev.Mode = "intercept"
	}

	// Dial before answering, so failures surface as an HTTP status. For
	// intercepted hosts this also applies the target guard up front.
	upstream, err := p.dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		ev.Error = err.Error()
		status := http.StatusBadGateway
		if errors.Is(err, ErrForbiddenTarget) {
			ev.Rejected, status = "forbidden target", http.StatusForbidden
		}
		ev.Status = status
		p.record(ev)
		http.Error(w, "fullmakt: cannot connect to target", status)
		return
	}
	if intercept {
		// Requests inside the tunnel use the pooled transport instead.
		upstream.Close()
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		if !intercept {
			upstream.Close()
		}
		http.Error(w, "fullmakt: hijack not supported", http.StatusInternalServerError)
		return
	}
	// The server may have set deadlines while reading the CONNECT request.
	_ = conn.SetDeadline(time.Time{})
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		conn.Close()
		if !intercept {
			upstream.Close()
		}
		return
	}
	p.record(ev)
	client := &bufferedConn{Conn: conn, r: brw.Reader}
	if intercept {
		p.intercept(client, host, port)
		return
	}
	tunnel(client, upstream)
}

// intercept terminates TLS with a leaf certificate for host and serves the
// requests inside the tunnel.
func (p *Proxy) intercept(client net.Conn, host, port string) {
	tlsConn := tls.Server(client, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		// The certificate always names the CONNECT target, whatever SNI says.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return p.ca.Leaf(host)
		},
	})
	_ = tlsConn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		p.log.Warn("client TLS handshake failed", "host", host, "err", err)
		tlsConn.Close()
		return
	}
	_ = tlsConn.SetDeadline(time.Time{})

	srv := &http.Server{
		Handler:           p.interceptedHandler(host, port),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(p.log.Handler(), slog.LevelDebug),
	}
	_ = srv.Serve(newSingleConnListener(tlsConn))
}

func (p *Proxy) interceptedHandler(host, port string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		ev := audit.Event{Kind: "request", Mode: "intercept", Host: authority(host, port), Method: r.Method, Path: r.URL.Path}
		defer func() {
			ev.Status, ev.DurationMs = rec.status, time.Since(start).Milliseconds()
			p.record(ev)
		}()

		// The request must target the CONNECT host. Otherwise a shared front
		// end (CDN, load balancer) could route an injected secret to another
		// tenant based on the Host header.
		if !sameAuthority(r.Host, host, port) {
			ev.Rejected = "host header " + r.Host + " does not match CONNECT target"
			http.Error(rec, "fullmakt: Host header does not match CONNECT target", http.StatusMisdirectedRequest)
			return
		}

		st := p.state.Load()
		var inj *rules.Injection
		if rule := st.rules.Match(host, port, r.Method, r.URL); rule != nil {
			ev.Rule = rule.Name
			if isUpgrade(r) {
				ev.Rejected = "protocol upgrade"
				http.Error(rec, "fullmakt: protocol upgrades cannot receive secrets", http.StatusForbidden)
				return
			}
			var err error
			if inj, err = rule.Render(r.Context(), st.secrets); err != nil {
				ev.Error = err.Error()
				http.Error(rec, "fullmakt: secret unavailable", http.StatusBadGateway)
				return
			}
			ev.Secrets = inj.Secrets
		}

		rp := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Scheme = "https"
				pr.Out.URL.Host = net.JoinHostPort(host, port)
				pr.Out.Host = authority(host, port)
				if inj == nil {
					return
				}
				for _, h := range inj.Headers {
					pr.Out.Header.Set(h.Name, h.Value)
				}
				// Let the transport negotiate gzip and decode it, so the
				// response body is plain text that can be redacted.
				pr.Out.Header.Del("Accept-Encoding")
			},
			Transport:    p.transport,
			ErrorHandler: upstreamError(&ev),
		}
		if inj != nil {
			rp.ModifyResponse = func(resp *http.Response) error {
				return redactResponse(resp, inj.Redact)
			}
		}
		rp.ServeHTTP(rec, r)
	})
}

// forwardPlain relays plain HTTP requests. Secrets are never sent over plain
// HTTP, so no rules apply.
func (p *Proxy) forwardPlain(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	ev := audit.Event{Kind: "request", Mode: "plain", Host: r.URL.Host, Method: r.Method, Path: r.URL.Path}
	defer func() {
		ev.Status, ev.DurationMs = rec.status, time.Since(start).Milliseconds()
		p.record(ev)
	}()
	rp := &httputil.ReverseProxy{
		Rewrite:      func(*httputil.ProxyRequest) {},
		Transport:    p.transport,
		ErrorHandler: upstreamError(&ev),
	}
	rp.ServeHTTP(rec, r)
}

func upstreamError(ev *audit.Event) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, _ *http.Request, err error) {
		status := http.StatusBadGateway
		if errors.Is(err, ErrForbiddenTarget) {
			ev.Rejected, status = "forbidden target", http.StatusForbidden
		}
		if !errors.Is(err, context.Canceled) {
			ev.Error = err.Error()
		}
		http.Error(w, "fullmakt: upstream request failed", status)
	}
}

// sameAuthority reports whether a Host header names host:port.
func sameAuthority(hostHeader, host, port string) bool {
	h, p, err := net.SplitHostPort(hostHeader)
	if err != nil {
		h, p = strings.Trim(hostHeader, "[]"), "443"
	}
	return rules.NormalizeHost(h) == host && p == port
}

// authority formats the Host header value, omitting the default port.
func authority(host, port string) string {
	if port == "443" {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

func isUpgrade(r *http.Request) bool {
	for _, v := range r.Header.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return r.Header.Get("Upgrade") != ""
}

// redactResponse removes injected values from response headers and body.
func redactResponse(resp *http.Response, values []string) error {
	for _, vs := range resp.Header {
		for i, v := range vs {
			vs[i] = redactString(v, values)
		}
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return fmt.Errorf("cannot redact response with Content-Encoding %q", ce)
	}
	if resp.Request.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	resp.Body = newRedactor(resp.Body, values)
	resp.ContentLength = -1
	resp.Header.Del("Content-Length")
	return nil
}

// tunnel copies bytes in both directions until both sides finish.
func tunnel(client, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan struct{}, 2)
	relay := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		closeWrite(dst)
		done <- struct{}{}
	}
	go relay(upstream, client)
	go relay(client, upstream)
	<-done
	<-done
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	// Informational responses (100, 103) precede the final status.
	if !s.wrote && (code >= 200 || code == http.StatusSwitchingProtocols) {
		s.status, s.wrote = code, true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.wrote = true
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
}
