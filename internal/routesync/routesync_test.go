package routesync

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

	"github.com/tm1000/birdscale/internal/routes"
)

var pfx = netip.MustParsePrefix

type fakeAdv struct {
	mu    sync.Mutex
	cur   []netip.Prefix
	sets  [][]netip.Prefix
	fail  error
	readE error
}

func (f *fakeAdv) AdvertisedRoutes(context.Context) ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.cur), f.readE
}
func (f *fakeAdv) SetRoutes(_ context.Context, p []netip.Prefix) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	f.cur = slices.Clone(p)
	f.sets = append(f.sets, slices.Clone(p))
	return nil
}
func (f *fakeAdv) nsets() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sets) }
func (f *fakeAdv) current() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return routes.Strings(f.cur)
}

type fakeTable struct {
	mu  sync.Mutex
	r   []netip.Prefix
	err error
}

func (f *fakeTable) HostRoutes() ([]netip.Prefix, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.r), f.err
}
func (f *fakeTable) set(r ...netip.Prefix) { f.mu.Lock(); f.r = r; f.mu.Unlock() }

func newSyncer(adv Advertiser, tab *fakeTable) *Syncer {
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), adv, tab)
	s.Debounce, s.MaxDelay, s.Urgent, s.Resync = 80*time.Millisecond, 400*time.Millisecond, 10*time.Millisecond, time.Hour
	return s
}

func run(t *testing.T, s *Syncer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func obs(networks ...string) Observation {
	return Observation{NBConnected: true, NetBirdIP: "10.99.1.5/23", Networks: networks, TSRunning: true}
}

func TestAddPruneAndDebounce(t *testing.T) {
	adv, tab := &fakeAdv{}, &fakeTable{}
	s := newSyncer(adv, tab)
	run(t, s)

	s.Observe(obs("192.0.2.0/24", "wiki.example.internal"))
	eventually(t, "initial advertisement", func() bool {
		return slices.Equal(adv.current(), []string{"10.99.0.0/23", "192.0.2.0/24"})
	})
	base := adv.nsets()

	// A burst of table events: three /32s appear within the debounce window.
	tab.set(pfx("203.0.113.1/32"))
	s.Kick()
	time.Sleep(10 * time.Millisecond)
	tab.set(pfx("203.0.113.1/32"), pfx("203.0.113.2/32"))
	s.Kick()
	time.Sleep(10 * time.Millisecond)
	tab.set(pfx("203.0.113.1/32"), pfx("203.0.113.2/32"), pfx("2001:db8::7/128"))
	s.Kick()
	eventually(t, "domain /32s advertised", func() bool { return len(adv.current()) == 5 })
	time.Sleep(200 * time.Millisecond) // nothing further may trickle in
	if n := adv.nsets() - base; n != 1 {
		t.Errorf("burst caused %d EditPrefs calls, want 1", n)
	}
	want := []string{"10.99.0.0/23", "192.0.2.0/24", "203.0.113.1/32", "203.0.113.2/32", "2001:db8::7/128"}
	if got := adv.current(); !slices.Equal(got, want) {
		t.Errorf("advertised %v want %v", got, want)
	}

	// NetBird drops two of them: they must be pruned.
	tab.set(pfx("203.0.113.2/32"))
	s.Kick()
	eventually(t, "prune", func() bool {
		return slices.Equal(adv.current(), []string{"10.99.0.0/23", "192.0.2.0/24", "203.0.113.2/32"})
	})
	st := s.State()
	if !st.Computed || st.Changes < 3 || len(st.Learned) != 1 {
		t.Errorf("state: %+v", st)
	}
	if st.Added != 5 || st.Removed != 2 {
		t.Errorf("cumulative adds/removes = %d/%d, want 5/2", st.Added, st.Removed)
	}
	origin := map[string]routes.Origin{}
	for _, e := range st.Entries {
		origin[e.Prefix.String()] = e.Origin
	}
	if origin["203.0.113.2/32"] != routes.OriginDomain || origin["192.0.2.0/24"] != routes.OriginCIDR {
		t.Errorf("origins: %v", origin)
	}
}

func TestNoChurnWhenEqual(t *testing.T) {
	adv, tab := &fakeAdv{}, &fakeTable{}
	s := newSyncer(adv, tab)
	run(t, s)
	s.Observe(obs("192.0.2.0/24"))
	eventually(t, "first apply", func() bool { return adv.nsets() == 1 })
	for i := 0; i < 5; i++ {
		s.Kick()
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if adv.nsets() != 1 {
		t.Errorf("unchanged set was re-applied: %d", adv.nsets())
	}
}

func TestHoldsWhenNetBirdDisconnected(t *testing.T) {
	adv, tab := &fakeAdv{}, &fakeTable{}
	s := newSyncer(adv, tab)
	run(t, s)
	s.Observe(obs("192.0.2.0/24"))
	eventually(t, "first apply", func() bool { return adv.nsets() == 1 })
	o := obs()
	o.NBConnected = false
	s.Observe(o)
	time.Sleep(300 * time.Millisecond)
	if got := adv.current(); !slices.Equal(got, []string{"10.99.0.0/23", "192.0.2.0/24"}) {
		t.Errorf("routes were pruned while NetBird was down: %v", got)
	}
}

func TestReappliesAfterTailscaleDrift(t *testing.T) {
	adv, tab := &fakeAdv{}, &fakeTable{}
	s := newSyncer(adv, tab)
	run(t, s)
	s.Observe(obs("192.0.2.0/24"))
	eventually(t, "first apply", func() bool { return adv.nsets() == 1 })
	adv.mu.Lock()
	adv.cur = nil // `tailscale up --reset` cleared them
	adv.mu.Unlock()
	o := obs("192.0.2.0/24")
	o.Advertised = nil
	s.Observe(o)
	eventually(t, "re-apply", func() bool { return adv.nsets() == 2 })
}

func TestOverrideAndFailure(t *testing.T) {
	adv, tab := &fakeAdv{fail: errors.New("boom")}, &fakeTable{}
	tab.set(pfx("203.0.113.1/32"))
	s := newSyncer(adv, tab)
	s.Override = []netip.Prefix{pfx("198.51.100.0/24")}
	run(t, s)
	s.Observe(obs("192.0.2.0/24"))
	eventually(t, "error recorded", func() bool { return s.State().Err != "" })
	adv.mu.Lock()
	adv.fail = nil
	adv.mu.Unlock()
	s.Kick()
	eventually(t, "override applied", func() bool { return slices.Equal(adv.current(), []string{"198.51.100.0/24"}) })
}

func TestWaitCovered(t *testing.T) {
	adv, tab := &fakeAdv{}, &fakeTable{}
	s := newSyncer(adv, tab)
	s.Debounce, s.MaxDelay = 5*time.Second, 10*time.Second // the urgent path must beat this
	run(t, s)
	s.Observe(obs())
	eventually(t, "first apply", func() bool { return adv.nsets() == 1 })

	a := netip.MustParseAddr("203.0.113.5")
	// Not advertised and never will be: times out.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if s.WaitCovered(ctx, []netip.Addr{a}) {
		t.Error("covered without a route")
	}
	// The route appears in NetBird's table while the waiter is blocked; the
	// urgent path must apply it well inside the (long) debounce.
	tab.set(pfx("203.0.113.5/32"))
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	start := time.Now()
	if !s.WaitCovered(ctx2, []netip.Addr{a}) {
		t.Fatal("route never advertised")
	}
	if time.Since(start) > time.Second {
		t.Errorf("urgent path too slow: %v", time.Since(start))
	}
	if !s.Covered([]netip.Addr{a, netip.MustParseAddr("10.99.0.9")}) {
		t.Error("Covered should be true for advertised and peer-network addresses")
	}
}
