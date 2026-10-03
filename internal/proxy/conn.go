package proxy

import (
	"bufio"
	"net"
	"sync"
)

// bufferedConn reads first from the bufio.Reader returned by Hijack, which
// may hold bytes the client sent right after the CONNECT request.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *bufferedConn) CloseWrite() error {
	closeWrite(c.Conn)
	return nil
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// singleConnListener lets http.Server serve one existing connection. Accept
// returns the connection once, then blocks until it is closed.
type singleConnListener struct {
	mu   sync.Mutex
	conn net.Conn
	done chan struct{}
}

func newSingleConnListener(c net.Conn) *singleConnListener {
	return &singleConnListener{conn: c, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return &notifyConn{Conn: c, done: l.done}, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	return nil
}

func (l *singleConnListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

type notifyConn struct {
	net.Conn
	once sync.Once
	done chan struct{}
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
