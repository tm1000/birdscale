package prewarm

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuf is a goroutine-safe log sink.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), sub)
}

// harness wires a Warmer to a fake resolver, a fake clock and a fake sleep.
type harness struct {
	t   *testing.T
	w   *Warmer
	log *syncBuf

	mu    sync.Mutex
	clock time.Time
	all   []time.Duration // every Sleep delay, in order
	calls map[string]int
	// answer decides each lookup; nil = success with one address.
	answer func(name string, call int, now time.Time) ([]netip.Addr, error)
	// gate, when set, makes Sleep block until a token arrives (or ctx ends).
	gate     chan struct{}
	sleeping chan struct{} // one token per Sleep entered (buffered)
}

var addr1 = []netip.Addr{netip.MustParseAddr("203.0.113.5")}

func newHarness(t *testing.T) *harness {
	h := &harness{t: t, log: &syncBuf{}, clock: time.Unix(1_700_000_000, 0), calls: map[string]int{},
		sleeping: make(chan struct{}, 1024)}
	h.w = &Warmer{
		Log:     slog.New(slog.NewTextHandler(h.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Resolve: h.resolve,
		Now:     func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.clock },
		Sleep:   h.sleep,
		Rand:    func() float64 { return 1 }, // no jitter: delays are exactly the backoff
	}
	return h
}

func (h *harness) resolve(_ context.Context, _, name string) ([]netip.Addr, error) {
	h.mu.Lock()
	h.calls[name]++
	n, now, f := h.calls[name], h.clock, h.answer
	h.mu.Unlock()
	if f == nil {
		return addr1, nil
	}
	return f(name, n, now)
}

func (h *harness) sleep(ctx context.Context, d time.Duration) error {
	h.mu.Lock()
	h.all = append(h.all, d)
	gate := h.gate
	h.mu.Unlock()
	h.sleeping <- struct{}{}
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	h.mu.Lock()
	h.clock = h.clock.Add(d)
	h.mu.Unlock()
	return nil
}

func (h *harness) callCount(name string) int { h.mu.Lock(); defer h.mu.Unlock(); return h.calls[name] }
func (h *harness) sleeps() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.all...)
}

func (h *harness) result(name string) Result {
	for _, r := range h.w.Results() {
		if r.Domain == name {
			return r
		}
	}
	h.t.Fatalf("no result for %s: %+v", name, h.w.Results())
	return Result{}
}

// waitSleeps waits for n Sleep calls to have started.
func (h *harness) waitSleeps(n int) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-h.sleeping:
		case <-time.After(2 * time.Second):
			h.t.Fatalf("timed out waiting for sleep %d/%d", i+1, n)
		}
	}
}

func (h *harness) waitRetriers() {
	h.t.Helper()
	done := make(chan struct{})
	go func() { h.w.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		h.t.Fatal("retry loops did not stop")
	}
}

var errTimeout = errors.New("read udp 100.64.0.1:51117->100.64.0.2:53: i/o timeout")

func TestBackoffGrowthAndCap(t *testing.T) {
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60, 60}
	for i, s := range want {
		if got := Backoff(i+1, 1); got != s*time.Second {
			t.Errorf("attempt %d: %v, want %v", i+1, got, s*time.Second)
		}
	}
	if got := Backoff(1000, 1); got != BackoffMax {
		t.Errorf("huge attempt: %v", got)
	}
	// Jitter stays within [d/2, d].
	for a := 1; a <= 8; a++ {
		hi := Backoff(a, 1)
		for _, r := range []float64{0, 0.25, 0.5, 1} {
			if d := Backoff(a, r); d < hi/2 || d > hi {
				t.Errorf("attempt %d rnd %v: %v outside [%v,%v]", a, r, d, hi/2, hi)
			}
		}
	}
}

func TestRecoveryAfterFailures(t *testing.T) {
	h := newHarness(t)
	h.answer = func(name string, call int, _ time.Time) ([]netip.Addr, error) {
		if name == "a.example.internal" && call <= 3 {
			return nil, errTimeout
		}
		return addr1, nil
	}
	published := 0
	h.w.Publish = func([]Result) { published++ }
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal", "b.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.w.runOnce(ctx)
	h.waitRetriers()

	r := h.result("a.example.internal")
	if r.State != StateResolved || r.Err != "" || r.Attempts != 0 || len(r.Addrs) != 1 {
		t.Errorf("a: %+v", r)
	}
	if h.callCount("a.example.internal") != 4 || h.callCount("b.example.internal") != 1 {
		t.Errorf("calls a=%d b=%d", h.callCount("a.example.internal"), h.callCount("b.example.internal"))
	}
	if got := h.sleeps(); len(got) != 3 || got[0] != 2*time.Second || got[1] != 4*time.Second || got[2] != 8*time.Second {
		t.Errorf("delays %v", got)
	}
	if h.log.count("level=WARN msg=\"prewarm: resolve failed, retrying with backoff\"") != 1 {
		t.Errorf("want exactly one first-failure WARN:\n%s", h.log.b.String())
	}
	if h.log.count("level=DEBUG msg=\"prewarm: resolve failed again\"") != 2 {
		t.Errorf("later failures must be DEBUG:\n%s", h.log.b.String())
	}
	if h.log.count("level=INFO msg=\"prewarm: resolved after 4 attempts\"") != 1 {
		t.Errorf("missing recovery INFO:\n%s", h.log.b.String())
	}
	if published < 2 {
		t.Errorf("published %d times", published)
	}
}

func TestRetryingStateVisible(t *testing.T) {
	h := newHarness(t)
	h.gate = make(chan struct{})
	h.answer = func(string, int, time.Time) ([]netip.Addr, error) { return nil, errTimeout }
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	h.w.runOnce(ctx)
	h.waitSleeps(1)
	r := h.result("a.example.internal")
	if r.State != StateRetrying || r.Attempts != 1 || r.Err == "" || !r.NextRetry.Equal(r.At.Add(2*time.Second)) {
		t.Errorf("retrying: %+v", r)
	}
	cancel()
	h.waitRetriers()
}

func TestBackoffCapsInLoop(t *testing.T) {
	h := newHarness(t)
	h.answer = func(_ string, call int, _ time.Time) ([]netip.Addr, error) {
		if call <= 10 {
			return nil, errors.New("SERVFAIL")
		}
		return addr1, nil
	}
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	h.w.runOnce(context.Background())
	h.waitRetriers()
	got := h.sleeps()
	want := []time.Duration{2, 4, 8, 16, 32, 60, 60, 60, 60, 60}
	if len(got) != len(want) {
		t.Fatalf("delays %v", got)
	}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Errorf("delay %d: %v", i, got[i])
		}
	}
}

func TestPersistentFailureWarnsAfterFiveMinutesThenHourly(t *testing.T) {
	h := newHarness(t)
	start := h.clock
	h.answer = func(_ string, _ int, now time.Time) ([]netip.Addr, error) {
		if now.Sub(start) < 130*time.Minute {
			return nil, errTimeout
		}
		return addr1, nil
	}
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	h.w.runOnce(context.Background())
	h.waitRetriers()
	if n := h.log.count("level=WARN msg=\"prewarm: resolve failed, retrying with backoff\""); n != 1 {
		t.Errorf("first-failure WARNs: %d", n)
	}
	// ~5m, ~65m and ~125m.
	if n := h.log.count("level=WARN msg=\"prewarm: still failing\""); n != 3 {
		t.Errorf("still-failing WARNs: %d\n%s", n, h.log.b.String())
	}
}

func TestNXDOMAINNotFastRetried(t *testing.T) {
	h := newHarness(t)
	h.answer = func(string, int, time.Time) ([]netip.Addr, error) { return nil, nil } // NXDOMAIN/NODATA
	h.w.Observe("10.99.1.5:53", []string{"gone.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.w.runOnce(ctx)
	h.waitRetriers()
	if r := h.result("gone.example.internal"); r.State != StateNoRecords || r.Err != "" {
		t.Errorf("state %+v", r)
	}
	if len(h.sleeps()) != 0 || h.callCount("gone.example.internal") != 1 {
		t.Errorf("fast-retried: sleeps=%v calls=%d", h.sleeps(), h.callCount("gone.example.internal"))
	}
	// The normal refresh re-checks it, without logging again.
	h.w.runOnce(ctx)
	if h.callCount("gone.example.internal") != 2 {
		t.Error("refresh did not re-check")
	}
	if n := h.log.count("NXDOMAIN or NODATA"); n != 1 {
		t.Errorf("NXDOMAIN logged %d times", n)
	}
}

func TestRefreshSkipsDomainsAlreadyRetrying(t *testing.T) {
	h := newHarness(t)
	h.gate = make(chan struct{})
	h.answer = func(name string, _ int, _ time.Time) ([]netip.Addr, error) {
		if name == "a.example.internal" {
			return nil, errTimeout
		}
		return addr1, nil
	}
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal", "b.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	h.w.runOnce(ctx)
	h.waitSleeps(1)
	h.w.runOnce(ctx) // normal refresh while a is retrying
	if h.callCount("a.example.internal") != 1 || h.callCount("b.example.internal") != 2 {
		t.Errorf("a=%d b=%d", h.callCount("a.example.internal"), h.callCount("b.example.internal"))
	}
	cancel()
	h.waitRetriers()
}

func TestRetriesCancelledOnDomainRemoval(t *testing.T) {
	h := newHarness(t)
	h.gate = make(chan struct{})
	h.answer = func(string, int, time.Time) ([]netip.Addr, error) { return nil, errTimeout }
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal", "b.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.w.runOnce(ctx)
	h.waitSleeps(2)

	h.w.Observe("10.99.1.5:53", []string{"b.example.internal"}, true)
	h.waitRetriers() // both loops stop; b is restarted by the next run
	aCalls := h.callCount("a.example.internal")
	h.w.runOnce(ctx)
	h.waitSleeps(1)
	if h.callCount("a.example.internal") != aCalls {
		t.Error("removed domain was queried again")
	}
	for _, r := range h.w.Results() {
		if r.Domain == "a.example.internal" {
			t.Errorf("removed domain still reported: %+v", r)
		}
	}
	h.gate <- struct{}{} // let b retry once, proving its loop is live
	h.waitSleeps(1)
	if h.callCount("a.example.internal") != aCalls {
		t.Error("removed domain retried")
	}
	cancel()
	h.waitRetriers()
}

func TestRetriesStopOnShutdown(t *testing.T) {
	h := newHarness(t)
	h.gate = make(chan struct{})
	h.answer = func(string, int, time.Time) ([]netip.Addr, error) { return nil, errTimeout }
	h.w.Log = slog.New(slog.NewTextHandler(h.log, nil))
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal", "b.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.w.Run(ctx); close(done) }()
	h.waitSleeps(2)
	cancel()
	select {
	case <-done: // Run waits for its retry loops
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
	calls := h.callCount("a.example.internal")
	if len(h.sleeps()) != 2 {
		t.Errorf("sleeps %v", h.sleeps())
	}
	time.Sleep(20 * time.Millisecond)
	if h.callCount("a.example.internal") != calls {
		t.Error("queried after shutdown")
	}
}

func TestBackoffResetOnListChange(t *testing.T) {
	h := newHarness(t)
	h.answer = func(name string, call int, _ time.Time) ([]netip.Addr, error) {
		if name == "a.example.internal" && call <= 4 {
			return nil, errTimeout
		}
		return addr1, nil
	}
	h.gate = make(chan struct{}, 8)
	h.gate <- struct{}{}
	h.gate <- struct{}{}
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.w.runOnce(ctx)
	h.waitSleeps(3) // delays 2s, 4s, then a third sleep that blocks
	if got := h.sleeps(); len(got) != 3 || got[2] != 8*time.Second {
		t.Fatalf("delays %v", got)
	}

	// A new list resets the backoff.
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal", "c.example.internal"}, true)
	h.waitRetriers()
	h.w.runOnce(ctx) // call 4 for a fails: first delay again
	h.waitSleeps(1)
	if got := h.sleeps(); got[len(got)-1] != 2*time.Second {
		t.Errorf("backoff not reset after list change: %v", got)
	}
}
