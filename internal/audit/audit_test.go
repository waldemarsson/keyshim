package audit

import (
	"testing"
	"time"
)

func TestLogKeepsMostRecent(t *testing.T) {
	l := NewLog(3)
	for i := range 5 {
		l.Add(Event{Status: i})
	}
	got := l.Recent()
	if len(got) != 3 || got[0].Status != 2 || got[2].Status != 4 {
		t.Errorf("Recent = %+v", got)
	}
}

func TestSubscribe(t *testing.T) {
	l := NewLog(3)
	ch, unsubscribe := l.Subscribe()
	l.Add(Event{Host: "a"})
	select {
	case e := <-ch:
		if e.Host != "a" {
			t.Errorf("event = %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("no event")
	}
	unsubscribe()
	l.Add(Event{Host: "b"})
	select {
	case e := <-ch:
		t.Errorf("event after unsubscribe: %+v", e)
	default:
	}
}
