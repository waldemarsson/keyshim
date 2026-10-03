// Package audit records proxy activity in memory for the UI. Events never
// contain secret values.
package audit

import (
	"sync"
	"time"
)

// Event is one connection or request handled by the proxy.
type Event struct {
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"`           // connect or request
	Mode       string    `json:"mode,omitempty"` // intercept, tunnel or plain
	Client     string    `json:"client,omitempty"`
	Host       string    `json:"host"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	Secrets    []string  `json:"secrets,omitempty"`
	Status     int       `json:"status,omitempty"`
	DurationMs int64     `json:"durationMs,omitempty"`
	Rejected   string    `json:"rejected,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Attrs returns the event as slog key-value pairs.
func (e Event) Attrs() []any {
	attrs := []any{"kind", e.Kind, "host", e.Host}
	add := func(key string, value any, ok bool) {
		if ok {
			attrs = append(attrs, key, value)
		}
	}
	add("client", e.Client, e.Client != "")
	add("mode", e.Mode, e.Mode != "")
	add("method", e.Method, e.Method != "")
	add("path", e.Path, e.Path != "")
	add("rule", e.Rule, e.Rule != "")
	add("secrets", e.Secrets, len(e.Secrets) > 0)
	add("status", e.Status, e.Status != 0)
	add("duration_ms", e.DurationMs, e.Kind == "request")
	add("rejected", e.Rejected, e.Rejected != "")
	add("err", e.Error, e.Error != "")
	return attrs
}

// Log keeps the most recent events and fans new events out to subscribers.
type Log struct {
	mu     sync.Mutex
	events []Event
	next   int
	full   bool
	subs   map[chan Event]struct{}
}

// NewLog returns a Log that keeps up to capacity events.
func NewLog(capacity int) *Log {
	return &Log{events: make([]Event, capacity), subs: map[chan Event]struct{}{}}
}

// Add records an event. Slow subscribers miss events rather than block the proxy.
func (l *Log) Add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events[l.next] = e
	l.next = (l.next + 1) % len(l.events)
	if l.next == 0 {
		l.full = true
	}
	for ch := range l.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Recent returns stored events, oldest first.
func (l *Log) Recent() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.full {
		return append([]Event{}, l.events[:l.next]...)
	}
	return append(append([]Event{}, l.events[l.next:]...), l.events[:l.next]...)
}

// Subscribe returns a channel of new events and a function that ends the
// subscription.
func (l *Log) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		delete(l.subs, ch)
		l.mu.Unlock()
	}
}
