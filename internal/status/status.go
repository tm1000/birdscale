// Package status holds the shared, periodically refreshed view of the bridge
// that health checks and the web page read.
package status

import (
	"net/netip"
	"sync"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"github.com/tm1000/birdscale/internal/dnsfwd"
	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/nft"
	"github.com/tm1000/birdscale/internal/prewarm"
	"github.com/tm1000/birdscale/internal/routesync"
	"github.com/tm1000/birdscale/internal/tailscale"
)

// Snapshot is one consistent observation. Treat it as read-only.
type Snapshot struct {
	StartedAt time.Time
	UpdatedAt time.Time

	TSStatus   *ipnstate.Status
	TSPrefs    *ipn.Prefs
	TSErr      string
	TSLogin    tailscale.LoginState
	TSApproved map[netip.Prefix]bool
	TSLoginURL string
	NBStatus   *netbird.Status
	NBErr      string
	NBLogin    netbird.LoginState

	// Routes. RoutesComputed is false until NetBird has connected once.
	RoutesComputed bool
	RoutesDesired  []netip.Prefix
	RoutesSkipped  []string
	RoutesWarnings []string
	RoutesOverride bool
	ExitNode       bool
	// RouteSync is the continuous reconciler's last published state
	// (entries with origins, learned host routes, last sync/change times).
	RouteSync routesync.State

	// DNS forwarder (BS_DNS). Listening is empty while Tailscale has no IP.
	DNSEnabled   bool
	DNSListening []string
	DNSUpstream  string
	DNSDomains   []string
	DNSRouteWait time.Duration
	DNS          dnsfwd.Stats

	// Prewarm holds the latest domain-resource pre-warm results.
	Prewarm       []prewarm.Result
	PrewarmCount  prewarm.Counters
	DomainRefresh time.Duration

	// Overlaps are human-readable tailnet/route overlap warnings.
	Overlaps []string

	// SessionWarn is BS_SESSION_WARN.
	SessionWarn time.Duration

	// ReloginAttempts counts NetBird re-login requests from the status page.
	ReloginAttempts uint64

	NFTPresent  bool
	NFTCounters []nft.RuleCounter
	NFTErr      string

	Healthy     bool
	LastHealthy time.Time
}

// Store is a mutex-guarded Snapshot.
type Store struct {
	mu sync.RWMutex
	s  Snapshot
}

// NewStore returns a Store whose StartedAt is now.
func NewStore() *Store { return &Store{s: Snapshot{StartedAt: time.Now()}} }

// Get returns a copy of the current snapshot.
func (st *Store) Get() Snapshot {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.s
}

// Update mutates the snapshot under the lock.
func (st *Store) Update(f func(*Snapshot)) {
	st.mu.Lock()
	f(&st.s)
	st.s.UpdatedAt = time.Now()
	st.mu.Unlock()
}
