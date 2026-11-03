package prewarm

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

func TestPlanSkipsWildcards(t *testing.T) {
	res, wc := Plan([]string{
		"wiki.example.internal", "*.corp.example.internal", "192.0.2.0/24", "10.1.1.1", "ipa.example.internal", "wiki.example.internal",
	})
	if !slices.Equal(res, []string{"wiki.example.internal", "ipa.example.internal"}) {
		t.Errorf("resolve=%v", res)
	}
	if !slices.Equal(wc, []string{"*.corp.example.internal"}) {
		t.Errorf("wildcards=%v", wc)
	}
}

type recorder struct {
	mu    sync.Mutex
	names []string
	ups   []string
}

func (r *recorder) resolve(_ context.Context, up, name string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names = append(r.names, name)
	r.ups = append(r.ups, up)
	if name == "bad.example.internal" {
		return nil, errors.New("SERVFAIL")
	}
	return []netip.Addr{netip.MustParseAddr("203.0.113.5")}, nil
}
func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.names)
}
func (r *recorder) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.names) }

func TestRunResolvesOnChangeAndRefresh(t *testing.T) {
	rec := &recorder{}
	pub := make(chan []Result, 16)
	w := &Warmer{
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Resolve: rec.resolve,
		Refresh: 150 * time.Millisecond, Publish: func(r []Result) { pub <- r },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	// Not connected: nothing resolved.
	w.Observe("10.99.1.5:53", []string{"wiki.example.internal"}, false)
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatal("resolved while NetBird was not connected")
	}

	w.Observe("10.99.1.5:53", []string{"wiki.example.internal", "*.corp.example.internal", "bad.example.internal", "192.0.2.0/24"}, true)
	// The retry loop for bad.* may publish before wiki.* has resolved; wait
	// for the snapshot the finished run publishes.
	var got []Result
	dl := time.After(2 * time.Second)
wait:
	for {
		select {
		case got = <-pub:
			for _, r := range got {
				if r.Domain == "wiki.example.internal" && len(r.Addrs) == 1 {
					break wait
				}
			}
		case <-dl:
			t.Fatal("no run after networks appeared")
		}
	}
	if names := rec.snapshot(); len(names) < 2 {
		t.Errorf("resolved %v, want the two non-wildcard names", names)
	}
	if slices.Contains(rec.snapshot(), "*.corp.example.internal") {
		t.Error("wildcard was resolved")
	}
	byName := map[string]Result{}
	for _, r := range got {
		byName[r.Domain] = r
	}
	if r := byName["wiki.example.internal"]; r.Err != "" || len(r.Addrs) != 1 {
		t.Errorf("wiki: %+v", r)
	}
	if r := byName["bad.example.internal"]; r.Err == "" {
		t.Errorf("bad: %+v", r)
	}
	if r := byName["*.corp.example.internal"]; !r.Wildcard || r.Addrs != nil {
		t.Errorf("wildcard: %+v", r)
	}
	rec.mu.Lock()
	ups := slices.Clone(rec.ups)
	rec.mu.Unlock()
	for _, u := range ups {
		if u != "10.99.1.5:53" {
			t.Errorf("queried %q", u)
		}
	}

	// Periodic refresh re-resolves without any change.
	select {
	case <-pub:
	case <-time.After(2 * time.Second):
		t.Fatal("no periodic refresh")
	}

	// Same list again: no extra trigger, only the timer runs.
	w.Observe("10.99.1.5:53", []string{"192.0.2.0/24", "bad.example.internal", "wiki.example.internal", "*.corp.example.internal"}, true)

	// List change triggers immediately (well inside the refresh period? use a new name).
	w.Observe("10.99.1.5:53", []string{"new.example.internal"}, true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rec.mu.Lock()
		found := slices.Contains(rec.names, "new.example.internal")
		rec.mu.Unlock()
		if found {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("new domain was not pre-warmed after the list changed")
}
