package proxy

import (
	"bytes"
	"io"
	"strings"
)

const redacted = "[REDACTED]"

func redactString(s string, values []string) string {
	for _, v := range values {
		if v != "" {
			s = strings.ReplaceAll(s, v, redacted)
		}
	}
	return s
}

// redactor replaces secret values in a stream. It holds back a possible
// partial match at the end of each chunk until more input arrives.
type redactor struct {
	src     io.ReadCloser
	secrets [][]byte // longest first
	maxLen  int
	chunk   []byte
	buf     []byte // input not yet processed
	out     []byte // output not yet returned
	err     error
}

func newRedactor(src io.ReadCloser, values []string) *redactor {
	r := &redactor{src: src, chunk: make([]byte, 32*1024)}
	for _, v := range values {
		if v == "" {
			continue
		}
		r.secrets = append(r.secrets, []byte(v))
		r.maxLen = max(r.maxLen, len(v))
	}
	return r
}

func (r *redactor) Read(p []byte) (int, error) {
	for len(r.out) == 0 {
		if r.err != nil {
			return 0, r.err
		}
		n, err := r.src.Read(r.chunk)
		r.buf = append(r.buf, r.chunk[:n]...)
		switch {
		case err == io.EOF:
			r.err = err
			r.process(true)
		case err != nil:
			// Drop held-back bytes: they may be the start of a secret.
			r.err, r.buf = err, nil
		default:
			r.process(false)
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *redactor) Close() error {
	return r.src.Close()
}

func (r *redactor) process(final bool) {
	i, start := 0, 0
	for i < len(r.buf) {
		// Wait for more input while a longer secret could still match here.
		if !final && len(r.buf)-i < r.maxLen && r.partialAt(i) {
			break
		}
		if s := r.matchAt(i); s != nil {
			r.out = append(r.out, r.buf[start:i]...)
			r.out = append(r.out, redacted...)
			i += len(s)
			start = i
			continue
		}
		i++
	}
	r.out = append(r.out, r.buf[start:i]...)
	r.buf = append(r.buf[:0], r.buf[i:]...)
}

func (r *redactor) matchAt(i int) []byte {
	for _, s := range r.secrets {
		if bytes.HasPrefix(r.buf[i:], s) {
			return s
		}
	}
	return nil
}

func (r *redactor) partialAt(i int) bool {
	rest := r.buf[i:]
	for _, s := range r.secrets {
		if len(rest) < len(s) && bytes.HasPrefix(s, rest) {
			return true
		}
	}
	return false
}
