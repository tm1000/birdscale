package prewarm

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// probeLog is a fake Prober that fails the first n calls and records the
// order of probe and lookup events.
type probeLog struct {
	mu     sync.Mutex
	failN  int // fail the first failN probes (-1 = always)
	probes int
	events []string
}

func (p *probeLog) probe(_ context.Context, up, name string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probes++
	p.events = append(p.events, "probe:"+name)
	if p.failN < 0 || p.probes <= p.failN {
		return errors.New("i/o timeout")
	}
	return nil
}

func (p *probeLog) note(s string) { p.mu.Lock(); p.events = append(p.events, s); p.mu.Unlock() }
func (p *probeLog) count() int    { p.mu.Lock(); defer p.mu.Unlock(); return p.probes }

func withProbe(h *harness, failN int) *probeLog {
	p := &probeLog{failN: failN}
	h.w.Probe = p.probe
	inner := h.answer
	h.answer = func(name string, call int, now time.Time) ([]netip.Addr, error) {
		p.note("resolve:" + name)
		if inner != nil {
			return inner(name, call, now)
		}
		return addr1, nil
	}
	return p
}

func TestWaitsForResolverBeforeFirstLookup(t *testing.T) {
	h := newHarness(t)
	p := withProbe(h, 3)
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal", "b.example.internal"}, true)
	h.w.runOnce(context.Background())
	h.waitRetriers()

	// 3 failed probes, 4th succeeds, only then the lookups.
	if p.events[0] != "probe:a.example.internal" || p.count() != 4 {
		t.Fatalf("events %v", p.events)
	}
	for _, e := range p.events[:4] {
		if e != "probe:a.example.internal" {
			t.Fatalf("lookup before the resolver was ready: %v", p.events)
		}
	}
	got := h.sleeps()
	want := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond, time.Second}
	if len(got) != len(want) {
		t.Fatalf("delays %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("probe delay %d: %v want %v", i, got[i], want[i])
		}
	}
	for _, d := range []string{"a.example.internal", "b.example.internal"} {
		if r := h.result(d); r.State != StateResolved {
			t.Errorf("%s: %+v", d, r)
		}
	}
	if n := h.log.count("level=WARN"); n != 0 {
		t.Errorf("no WARN expected:\n%s", h.log.b.String())
	}
	if h.log.count("level=INFO msg=\"prewarm: resolver is answering\"") != 1 {
		t.Errorf("missing ready INFO:\n%s", h.log.b.String())
	}
}

func TestProbeBackoffCapsAndTimesOut(t *testing.T) {
	h := newHarness(t)
	p := withProbe(h, -1) // never answers
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	h.w.runOnce(context.Background())
	h.waitRetriers()

	// Delays double up to the cap, then stay there.
	got := h.sleeps()
	if len(got) < 10 || got[0] != ProbeStart || got[1] != 2*ProbeStart || got[len(got)-1] != ProbeMax {
		t.Fatalf("probe delays %v", got)
	}
	var total time.Duration
	for _, d := range got {
		total += d
		if d > ProbeMax {
			t.Fatalf("delay %v above cap", d)
		}
	}
	if total > DefaultReadyTimeout || total < DefaultReadyTimeout-ProbeMax {
		t.Errorf("waited %v in total, want about %v", total, DefaultReadyTimeout)
	}
	// It then proceeds anyway: the lookup ran after the last probe.
	last := p.events[len(p.events)-1]
	if last != "resolve:a.example.internal" {
		t.Errorf("did not proceed after the timeout: last event %q", last)
	}
	if n := h.log.count("level=WARN msg=\"prewarm: resolver did not answer in time; pre-warming anyway\""); n != 1 {
		t.Errorf("want one WARN for a resolver that never became ready, got %d:\n%s", n, h.log.b.String())
	}
}

func TestFailuresInsideGraceAreQuiet(t *testing.T) {
	h := newHarness(t)
	h.answer = func(_ string, call int, _ time.Time) ([]netip.Addr, error) {
		if call <= 2 {
			return nil, errTimeout
		}
		return addr1, nil
	}
	withProbe(h, 2)
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	h.w.runOnce(context.Background())
	h.waitRetriers()
	if n := h.log.count("level=WARN"); n != 0 {
		t.Errorf("failures inside the grace window must not WARN:\n%s", h.log.b.String())
	}
	if h.log.count("level=DEBUG msg=\"prewarm: resolve failed again\"")+h.log.count("level=DEBUG msg=\"prewarm: resolve failed, retrying") == 0 {
		t.Errorf("expected DEBUG lines for the quiet failures:\n%s", h.log.b.String())
	}
	if h.log.count("level=INFO msg=\"prewarm: resolved after 3 attempts\"") != 1 {
		t.Errorf("missing recovery INFO:\n%s", h.log.b.String())
	}
}

func TestFailureAfterGraceWarns(t *testing.T) {
	h := newHarness(t)
	h.gate = make(chan struct{})
	h.answer = func(string, int, time.Time) ([]netip.Addr, error) { return nil, errTimeout }
	withProbe(h, 0)
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { h.w.runOnce(ctx) }()
	// Probe answers at once; first lookup fails in grace (DEBUG), the retry loop sleeps.
	h.waitSleeps(1)
	if n := h.log.count("level=WARN"); n != 0 {
		t.Fatalf("WARN inside grace:\n%s", h.log.b.String())
	}
	// Jump the clock past the grace window, then let the loop retry and fail again.
	h.mu.Lock()
	h.clock = h.clock.Add(DefaultGrace + time.Second)
	h.mu.Unlock()
	h.gate <- struct{}{}
	h.waitSleeps(1)
	if n := h.log.count("level=WARN msg=\"prewarm: resolve failed, retrying with backoff\""); n != 1 {
		t.Errorf("want one WARN once the grace window is over, got %d:\n%s", n, h.log.b.String())
	}
	cancel()
	h.waitRetriers()
}

func TestNoReprobeOnRefreshButOnResolverChange(t *testing.T) {
	h := newHarness(t)
	p := withProbe(h, 0)
	nets := []string{"a.example.internal"}
	h.w.Observe("10.99.1.5:53", nets, true)
	ctx := context.Background()
	h.w.runOnce(ctx)
	h.w.runOnce(ctx) // periodic refresh, same resolver
	if p.count() != 1 {
		t.Fatalf("refresh re-probed: %d probes", p.count())
	}
	// Same resolver, new domain: still no probe.
	h.w.Observe("10.99.1.5:53", append(nets, "b.example.internal"), true)
	h.w.runOnce(ctx)
	if p.count() != 1 {
		t.Fatalf("list change re-probed: %d probes", p.count())
	}
	// Resolver address change: probe again.
	h.w.Observe("10.99.1.9:53", nets, true)
	h.w.runOnce(ctx)
	if p.count() != 2 {
		t.Fatalf("resolver change must re-probe: %d probes", p.count())
	}
	// Disconnect and reconnect to the same address: probe again.
	h.w.Observe("", nets, false)
	h.w.Observe("10.99.1.9:53", nets, true)
	h.w.runOnce(ctx)
	if p.count() != 3 {
		t.Fatalf("reconnect must re-probe: %d probes", p.count())
	}
}

func TestResolverChangeAbortsWait(t *testing.T) {
	h := newHarness(t)
	h.gate = make(chan struct{})
	p := withProbe(h, -1)
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	done := make(chan struct{})
	go func() { h.w.runOnce(context.Background()); close(done) }()
	h.waitSleeps(1)
	h.w.Observe("10.99.1.9:53", []string{"a.example.internal"}, true)
	h.gate <- struct{}{}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runOnce kept waiting on the stale resolver")
	}
	for _, e := range p.events {
		if e == "resolve:a.example.internal" {
			t.Fatalf("looked up against the stale resolver: %v", p.events)
		}
	}
}

func TestCounters(t *testing.T) {
	h := newHarness(t)
	h.answer = func(_ string, call int, _ time.Time) ([]netip.Addr, error) {
		if call == 1 {
			return nil, errTimeout
		}
		return addr1, nil
	}
	h.w.Observe("10.99.1.5:53", []string{"a.example.internal"}, true)
	h.w.runOnce(context.Background())
	h.waitRetriers()
	if c := h.w.Counters(); c.Attempts != 2 || c.Failures != 1 {
		t.Errorf("counters %+v", c)
	}
}
