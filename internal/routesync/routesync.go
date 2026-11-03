// Package routesync keeps Tailscale's advertised routes equal to the desired
// set (routes.Compute over NetBird's status plus the host routes in NetBird's
// routing table). Changes are debounced so a burst of DNS lookups causes one
// EditPrefs call, and routes NetBird removes are pruned.
package routesync

import (
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tm1000/birdscale/internal/routes"
	"github.com/tm1000/birdscale/internal/rtwatch"
)

// Advertiser reads and applies the advertised route set (tailscale.Client).
type Advertiser interface {
	AdvertisedRoutes(ctx context.Context) ([]netip.Prefix, error)
	SetRoutes(ctx context.Context, p []netip.Prefix) error
}

// Observation is what the poll loop knows about the world.
type Observation struct {
	NBConnected bool
	NetBirdIP   string
	NetBirdIPv6 string
	Networks    []string
	// TSRunning is true when tailscaled is Running and Advertised is valid.
	TSRunning  bool
	Advertised []netip.Prefix // current tailscale AdvertiseRoutes
}

// State is published after every reconcile for the status page.
type State struct {
	Computed   bool // true once NetBird has connected and a set was computed
	Entries    []routes.Entry
	Desired    []netip.Prefix
	Skipped    []string
	Warnings   []string
	Learned    []netip.Prefix // host routes read from the NetBird table
	LastSync   time.Time      // last reconcile run (any outcome)
	LastChange time.Time      // last time EditPrefs changed the advertised set
	Syncs      int
	Changes    int
	Added      uint64 // prefixes added to the advertised set, cumulative
	Removed    uint64 // prefixes removed from it, cumulative
	Err        string
}

// Syncer is the reconciler. Create with New, feed it with Observe/Kick, run Run.
type Syncer struct {
	Log      *slog.Logger
	Adv      Advertiser
	Table    rtwatch.Source // nil = no table (tests, non-linux)
	Override []netip.Prefix
	ExitNode bool
	Publish  func(State)

	Debounce time.Duration // default 2s: quiet period before applying
	MaxDelay time.Duration // default 10s: a constant burst still applies by then
	Urgent   time.Duration // default 150ms: delay when a DNS client is waiting
	Resync   time.Duration // default 30s: periodic full re-read of the table
	Now      func() time.Time

	kick   chan struct{}
	urgent chan struct{}

	mu         sync.Mutex
	obs        Observation
	haveObs    bool
	desired    []netip.Prefix // last computed (post-hold)
	advertised []netip.Prefix
	changed    chan struct{} // closed and replaced whenever advertised changes
	st         State
	lastWarn   string
	lastTable  []netip.Prefix
}

// New returns a Syncer with defaults filled in.
func New(log *slog.Logger, adv Advertiser, table rtwatch.Source) *Syncer {
	return &Syncer{
		Log: log, Adv: adv, Table: table,
		Debounce: 2 * time.Second, MaxDelay: 10 * time.Second,
		Urgent: 150 * time.Millisecond, Resync: 30 * time.Second,
		Now:     time.Now,
		kick:    make(chan struct{}, 1),
		urgent:  make(chan struct{}, 1),
		changed: make(chan struct{}),
	}
}

// Kick asks for a reconcile (debounced). Safe from any goroutine; never blocks.
func (s *Syncer) Kick() {
	select {
	case s.kick <- struct{}{}:
	default:
	}
}

// Observe records the latest world state. It kicks only when something that
// matters changed: the NetBird inputs, tailscale readiness, or drift between
// the advertised routes and the last desired set.
func (s *Syncer) Observe(o Observation) {
	s.mu.Lock()
	prev, had := s.obs, s.haveObs
	s.obs, s.haveObs = o, true
	// o.Advertised may be a poll old; it only decides whether to look closer.
	drift := s.desired != nil && o.TSRunning && !routes.Equal(o.Advertised, s.desired)
	s.mu.Unlock()

	if !had || drift || prev.NBConnected != o.NBConnected || prev.NetBirdIP != o.NetBirdIP || prev.NetBirdIPv6 != o.NetBirdIPv6 ||
		prev.TSRunning != o.TSRunning || !slices.Equal(prev.Networks, o.Networks) {
		s.Kick()
	}
}

// setAdvertisedLocked records the advertised set and wakes route waiters.
func (s *Syncer) setAdvertisedLocked(p []netip.Prefix) {
	s.advertised = slices.Clone(p)
	close(s.changed)
	s.changed = make(chan struct{})
}

// Covered reports whether every address falls inside an advertised route.
func (s *Syncer) Covered(addrs []netip.Addr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return coveredLocked(s.advertised, addrs)
}

func coveredLocked(adv []netip.Prefix, addrs []netip.Addr) bool {
	for _, a := range addrs {
		a = a.Unmap()
		ok := false
		for _, p := range adv {
			if p.Contains(a) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// WaitCovered waits until every address is inside an advertised route or ctx
// ends, and reports which. It asks the loop to hurry (short debounce) because a
// DNS client is waiting. This is the dnsfwd.RouteWaiter implementation.
func (s *Syncer) WaitCovered(ctx context.Context, addrs []netip.Addr) bool {
	first := true
	for {
		s.mu.Lock()
		if coveredLocked(s.advertised, addrs) {
			s.mu.Unlock()
			return true
		}
		ch := s.changed
		s.mu.Unlock()
		if first {
			first = false
			select {
			case s.urgent <- struct{}{}:
			default:
			}
			s.Kick()
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return false
		}
	}
}

// Last returns the most recent observation.
func (s *Syncer) Last() Observation {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.obs
}

// State returns the last published state.
func (s *Syncer) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// Run reconciles until ctx ends.
func (s *Syncer) Run(ctx context.Context) {
	resync := time.NewTicker(s.Resync)
	defer resync.Stop()
	var (
		timer  *time.Timer
		timerC <-chan time.Time
		first  time.Time
	)
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer, timerC, first = nil, nil, time.Time{}
	}
	defer stopTimer()
	arm := func(urgent bool) {
		now := s.Now()
		if first.IsZero() {
			first = now
		}
		d := s.Debounce
		if urgent {
			d = s.Urgent
		}
		if left := first.Add(s.MaxDelay).Sub(now); left < d {
			d = max(left, 0)
		}
		if timer != nil {
			timer.Stop()
		}
		timer = time.NewTimer(d)
		timerC = timer.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.kick:
			s.mu.Lock()
			firstRun := !s.st.Computed
			s.mu.Unlock()
			// The very first reconcile does not wait: nothing is advertised yet.
			arm(firstRun || s.takeUrgent())
		case <-resync.C:
			stopTimer()
			s.reconcile(ctx, true)
		case <-timerC:
			stopTimer()
			s.reconcile(ctx, true)
		}
	}
}

func (s *Syncer) takeUrgent() bool {
	select {
	case <-s.urgent:
		return true
	default:
		return false
	}
}

// reconcile computes the desired set and applies it if it differs.
func (s *Syncer) reconcile(ctx context.Context, readTable bool) {
	s.mu.Lock()
	obs, have := s.obs, s.haveObs
	s.mu.Unlock()
	if !have || ctx.Err() != nil {
		return
	}
	now := s.Now()
	var errMsg string

	// Hold the previous set while NetBird is not connected: a transient
	// status failure must not prune every route.
	if obs.NBConnected {
		learned := s.lastTable
		if readTable && s.Table != nil {
			l, err := s.Table.HostRoutes()
			if err != nil {
				errMsg = "read netbird route table: " + err.Error()
				s.Log.Warn("routes: " + errMsg)
			} else {
				learned = l
			}
		}
		s.lastTable = learned
		res := routes.Compute(routes.Input{
			NetBirdIP: obs.NetBirdIP, NetBirdIPv6: obs.NetBirdIPv6, Networks: obs.Networks,
			Override: s.Override, ExitNode: s.ExitNode, Learned: learned,
		})
		warn := strings.Join(res.Warnings, "\n")
		if warn != s.lastWarn {
			for _, w := range res.Warnings {
				s.Log.Warn("routes: " + w)
			}
			s.lastWarn = warn
		}
		s.mu.Lock()
		if !routes.Equal(s.desired, res.Prefixes) || !s.st.Computed {
			s.Log.Info("routes: desired set", "routes", routes.Strings(res.Prefixes), "override", len(s.Override) > 0,
				"exit_node", s.ExitNode, "learned_host_routes", len(learned))
		}
		s.desired = res.Prefixes
		s.st.Computed = true
		s.st.Entries, s.st.Desired = res.Entries, res.Prefixes
		s.st.Skipped, s.st.Warnings = res.Skipped, res.Warnings
		s.st.Learned = learned
		s.mu.Unlock()
	}

	s.mu.Lock()
	desired := s.desired
	entries := s.st.Entries
	s.mu.Unlock()

	var adv []netip.Prefix
	if desired != nil && obs.TSRunning {
		// Authoritative read: the poll's copy may predate our last change.
		cur, err := s.Adv.AdvertisedRoutes(ctx)
		if err != nil {
			errMsg = "reading advertised routes: " + err.Error()
			s.Log.Warn("routes: " + errMsg)
			desired = nil
		} else {
			adv = cur
			s.mu.Lock()
			if !routes.Equal(s.advertised, cur) {
				s.setAdvertisedLocked(cur)
			}
			s.mu.Unlock()
		}
	}
	if desired != nil && obs.TSRunning && !routes.Equal(adv, desired) {
		add, rm := routes.Diff(adv, desired)
		origin := map[netip.Prefix]routes.Origin{}
		for _, e := range entries {
			origin[e.Prefix] = e.Origin
		}
		if err := s.Adv.SetRoutes(ctx, desired); err != nil {
			errMsg = "applying routes to tailscale: " + err.Error()
			s.Log.Warn("routes: " + errMsg)
		} else {
			for _, p := range add {
				s.Log.Info("routes: add", "route", p.String(), "origin", string(origin[p]))
			}
			for _, p := range rm {
				s.Log.Info("routes: remove", "route", p.String())
			}
			s.Log.Info("routes: advertised to tailnet", "routes", routes.Strings(desired), "added", len(add), "removed", len(rm))
			s.mu.Lock()
			s.setAdvertisedLocked(desired)
			s.st.LastChange = now
			s.st.Changes++
			s.st.Added += uint64(len(add))
			s.st.Removed += uint64(len(rm))
			s.mu.Unlock()
		}
	}

	s.mu.Lock()
	s.st.LastSync, s.st.Err = now, errMsg
	s.st.Syncs++
	st := s.st
	s.mu.Unlock()
	if s.Publish != nil {
		s.Publish(st)
	}
}
