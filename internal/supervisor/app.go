package supervisor

import (
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tm1000/birdscale/internal/config"
	"github.com/tm1000/birdscale/internal/dnsfwd"
	"github.com/tm1000/birdscale/internal/health"
	"github.com/tm1000/birdscale/internal/metrics"
	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/nft"
	"github.com/tm1000/birdscale/internal/overlap"
	"github.com/tm1000/birdscale/internal/prewarm"
	"github.com/tm1000/birdscale/internal/routesync"
	"github.com/tm1000/birdscale/internal/rtwatch"
	"github.com/tm1000/birdscale/internal/status"
	"github.com/tm1000/birdscale/internal/tailscale"
	"github.com/tm1000/birdscale/internal/version"
	"github.com/tm1000/birdscale/internal/web"
)

const (
	pollInterval = 3 * time.Second
	stopGrace    = 15 * time.Second
	// peerCheckEvery bounds how often the full tailnet peer list is fetched
	// for the overlap check.
	peerCheckEvery = 30 * time.Second
	// sessionLogEvery repeats the session-expiry WARN while it stays true.
	sessionLogEvery = time.Hour
)

// App wires everything together.
type App struct {
	Cfg *config.Config
	Log *slog.Logger

	store *status.Store
	ts    *tailscale.Client
	tsLog *tailscale.Login
	nb    *netbird.Client
	nbLog *netbird.Login
	nft   *nft.Manager
	web   *web.Server
	sync  *routesync.Syncer
	warm  *prewarm.Warmer
	fwd   *dnsfwd.Forwarder // nil when BS_DNS=false
	table *rtwatch.Netlink

	tsd, nbd *Proc

	// runCtx outlives HTTP requests; the re-login command is tied to it.
	runCtx context.Context

	// transition logging
	lastTS, lastNB string

	// overlap check state (tick goroutine only)
	peerAddrs       []netip.Addr
	peersAt         time.Time
	lastOverlapKey  string
	lastOverlapMsgs []string

	// session warning state (tick goroutine only)
	sessGate sessionGate
}

// New builds an App.
func New(cfg *config.Config, log *slog.Logger) *App {
	a := &App{Cfg: cfg, Log: log, store: status.NewStore()}
	a.ts = tailscale.New(tailscale.DefaultSocket)
	a.tsLog = &tailscale.Login{Log: log, Cfg: tailscale.LoginConfig{
		AuthKey: cfg.TSAuthKey, Hostname: cfg.TSHostname, Tags: cfg.TSTags,
		LoginServer: cfg.TSLoginServer, NetfilterMode: cfg.TSNetfilterMode, Socket: tailscale.DefaultSocket,
	}}
	a.nb = &netbird.Client{}
	a.nbLog = &netbird.Login{Log: log, Cfg: netbird.LoginConfig{
		ManagementURL: cfg.NBManagementURL, SetupKey: cfg.NBSetupKey, Hostname: cfg.NBHostname, WireGuardPort: cfg.NBPort,
	}}
	a.nft = nft.New(nft.Params{TSIface: config.TSIface, NBIface: config.NBIface, WebPort: cfg.WebUIPort, DNS: cfg.DNSEnabled})

	a.table = &rtwatch.Netlink{Table: rtwatch.NetBirdTable, Iface: config.NBIface, Log: log}
	a.sync = routesync.New(log, a.ts, a.table)
	a.sync.Override, a.sync.ExitNode = cfg.Routes, cfg.AdvertiseExitNode
	a.sync.Publish = func(st routesync.State) {
		a.store.Update(func(s *status.Snapshot) {
			s.RouteSync = st
			s.RoutesComputed, s.RoutesDesired = st.Computed, st.Desired
			s.RoutesSkipped, s.RoutesWarnings = st.Skipped, st.Warnings
		})
	}
	a.warm = &prewarm.Warmer{Log: log, Resolve: dnsfwd.Lookup, Probe: dnsfwd.Probe, Refresh: cfg.DomainRefresh,
		Publish: func(r []prewarm.Result) { a.store.Update(func(s *status.Snapshot) { s.Prewarm = r }) }}
	if cfg.DNSEnabled {
		a.fwd = &dnsfwd.Forwarder{Log: log, Port: 53, Suffixes: cfg.DNSDomains, RouteWait: cfg.DNSRouteWait, Waiter: a.sync}
	}
	if cfg.WebUIPort > 0 {
		a.web = &web.Server{Who: a.ts, Store: a.store, Allow: cfg.WebUIAllow, Port: cfg.WebUIPort, Log: log, Relogin: a,
			Metrics: metrics.New(a.store, version.Version).Handler()}
	}
	return a
}

// Run starts everything and blocks until ctx is cancelled (clean, returns nil)
// or a daemon exits (returns an error; the caller exits non-zero so Docker
// restarts the container). Cleanup always runs.
func (a *App) Run(ctx context.Context) error {
	defer a.cleanup()
	a.runCtx = ctx

	if err := a.nft.Apply(ctx); err != nil {
		return fmt.Errorf("install nftables rules: %w", err)
	}
	a.Log.Info("nftables: table inet birdscale installed", "forward", config.TSIface+" -> "+config.NBIface,
		"input_filtered", config.TSIface+","+config.NBIface, "web_port", a.Cfg.WebUIPort, "dns", a.Cfg.DNSEnabled)
	if b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil && strings.TrimSpace(string(b)) != "1" {
		a.Log.Warn("net.ipv4.ip_forward is 0: forwarding will not work (set sysctls in compose)")
	}

	var err error
	a.tsd, err = StartProc("tailscaled", "tailscaled", []string{
		"--tun=" + config.TSIface,
		"--statedir=/var/lib/tailscale",
		"--socket=" + tailscale.DefaultSocket,
		"--port=" + strconv.Itoa(a.Cfg.TSPort),
	}, EnvWithout(os.Environ(), "TS_AUTHKEY"))
	if err != nil {
		return fmt.Errorf("start tailscaled: %w", err)
	}
	a.nbd, err = StartProc("netbird", "netbird", []string{"service", "run"},
		EnvWithout(os.Environ(), "NB_SETUP_KEY", "NB_PORT"))
	if err != nil {
		return fmt.Errorf("start netbird: %w", err)
	}
	a.Log.Info("daemons started", "tailscaled_port", a.Cfg.TSPort, "netbird_state_dir", os.Getenv("NB_STATE_DIR"))

	hctx, hcancel := context.WithCancel(ctx)
	defer hcancel()
	var hwg sync.WaitGroup
	hwg.Add(1)
	go func() {
		defer hwg.Done()
		if err := health.Serve(hctx, a.Cfg.HealthPort, a.store); err != nil {
			a.Log.Error("health server stopped", "err", err)
		}
	}()
	for _, f := range []func(){
		func() { a.sync.Run(hctx) },
		func() { a.warm.Run(hctx) },
		func() { a.table.Watch(hctx, a.sync.Kick) },
	} {
		hwg.Add(1)
		go func() { defer hwg.Done(); f() }()
	}
	defer hwg.Wait()
	defer hcancel()

	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	a.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			a.Log.Info("shutting down")
			return nil
		case <-a.tsd.Done():
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("tailscaled exited: %v", a.tsd.Err())
		case <-a.nbd.Done():
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("netbird exited: %v", a.nbd.Err())
		case <-tick.C:
			a.tick(ctx)
		}
	}
}

func (a *App) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a.nbLog.Stop()
	a.tsLog.Stop()
	if a.web != nil {
		a.web.Close()
	}
	if a.fwd != nil {
		a.fwd.Close()
	}
	if err := a.nft.Remove(ctx); err != nil {
		a.Log.Error("nftables: remove failed", "err", err)
	} else {
		a.Log.Info("nftables: table inet birdscale removed")
	}
	var wg sync.WaitGroup
	for _, p := range []*Proc{a.nbd, a.tsd} {
		if p == nil {
			continue
		}
		wg.Add(1)
		go func() { defer wg.Done(); p.Stop(stopGrace) }()
	}
	wg.Wait()
	a.Log.Info("daemons stopped")
}

// tick polls both daemons, drives logins, applies routes and refreshes the
// shared snapshot.
func (a *App) tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// --- Tailscale
	tsSt, tsErr := a.ts.Status(pctx)
	var prefs *ipn.Prefs
	if tsErr == nil {
		if p, err := a.ts.Prefs(pctx); err == nil {
			prefs = p
		}
		a.logTS(tsSt.BackendState)
		a.tsLog.Ensure(ctx, tsSt.BackendState, tsSt.AuthURL)
		if tsSt.BackendState == tailscale.StateRunning {
			fixed, err := a.ts.EnsurePrefs(pctx, tailscale.PrefsWanted{
				Hostname: a.Cfg.TSHostname, Tags: a.Cfg.TSTags, NetfilterMode: a.Cfg.TSNetfilterMode,
			})
			switch {
			case err != nil:
				a.Log.Warn("tailscale: enforcing prefs failed", "err", err)
			case len(fixed) > 0:
				a.Log.Warn("tailscale: corrected drifted prefs", "fields", fixed)
				prefs, _ = a.ts.Prefs(pctx)
			}
			if a.web != nil {
				a.web.SetAddrs(tsSt.TailscaleIPs)
			}
			if a.fwd != nil {
				a.fwd.SetAddrs(tsSt.TailscaleIPs)
			}
		} else {
			if a.web != nil {
				a.web.SetAddrs(nil)
			}
			if a.fwd != nil {
				a.fwd.SetAddrs(nil)
			}
		}
	}

	// --- NetBird
	nbSt, nbErr := a.nb.Status(pctx)
	if nbErr == nil {
		a.logNB(nbSt)
	}
	a.nbLog.Ensure(ctx, nbSt)

	// --- nftables (self-heal if the table vanished)
	present := a.nft.Present(pctx)
	var nftErr string
	if !present {
		a.Log.Warn("nftables: table missing, reinstalling")
		if err := a.nft.Apply(pctx); err != nil {
			nftErr = err.Error()
			a.Log.Error("nftables: reinstall failed", "err", err)
		} else {
			present = true
		}
	}
	var counters []nft.RuleCounter
	if present {
		counters, _ = a.nft.Counters(pctx)
	}

	// --- Routes, pre-warm, DNS upstream
	a.observe(tsSt, prefs, nbSt)

	// --- Overlap and session warnings
	overlaps := a.checkOverlap(pctx, tsSt)
	a.checkSession(nbSt, time.Now())

	var dnsStats dnsfwd.Stats
	var dnsListening []string
	var dnsUpstream string
	if a.fwd != nil {
		dnsStats, dnsListening, dnsUpstream = a.fwd.Stats(), a.fwd.Listening(), a.fwd.Upstream()
	}

	a.store.Update(func(s *status.Snapshot) {
		s.DNSEnabled, s.DNSListening, s.DNSUpstream = a.fwd != nil, dnsListening, dnsUpstream
		s.DNSDomains, s.DNSRouteWait, s.DNS = a.Cfg.DNSDomains, a.Cfg.DNSRouteWait, dnsStats
		s.DomainRefresh, s.SessionWarn, s.Overlaps = a.Cfg.DomainRefresh, a.Cfg.SessionWarn, overlaps
		s.TSStatus, s.TSPrefs, s.TSLogin = tsSt, prefs, a.tsLog.State()
		s.TSErr = errStr(tsErr)
		s.TSApproved = tailscale.ApprovedRoutes(tsSt)
		s.NBStatus, s.NBErr, s.NBLogin = nbSt, errStr(nbErr), a.nbLog.State()
		s.NFTPresent, s.NFTCounters, s.NFTErr = present, counters, nftErr
		s.PrewarmCount = a.warm.Counters()
		s.RoutesOverride, s.ExitNode = len(a.Cfg.Routes) > 0, a.Cfg.AdvertiseExitNode
		rep := health.Evaluate(*s)
		s.Healthy = rep.Healthy
		if rep.Healthy {
			s.LastHealthy = time.Now()
		}
	})
}

// observe feeds the latest NetBird/Tailscale state to the route syncer (which
// reconciles continuously, debounced), the pre-warm and the DNS forwarder.
func (a *App) observe(tsSt *ipnstate.Status, prefs *ipn.Prefs, nbSt *netbird.Status) {
	o := routesync.Observation{TSRunning: tsSt != nil && tsSt.BackendState == tailscale.StateRunning && prefs != nil}
	if o.TSRunning {
		o.Advertised = prefs.AdvertiseRoutes
	}
	if nbSt == nil {
		// Status failed this poll: keep the last known inputs rather than
		// pruning everything on a transient error.
		a.sync.Observe(a.lastObservation(o))
		return
	}
	o.NBConnected, o.NetBirdIP, o.NetBirdIPv6, o.Networks = nbSt.Connected(), nbSt.NetbirdIP, nbSt.NetbirdIPv6, nbSt.Networks()
	a.sync.Observe(o)
	up := ""
	if nbSt.Connected() {
		up = nbSt.ResolverAddr()
	}
	a.warm.Observe(up, o.Networks, nbSt.Connected())
	if a.fwd != nil {
		a.fwd.SetUpstream(up)
		a.fwd.SetResources(o.Networks)
	}
}

// lastObservation keeps the NetBird half of the previous observation.
func (a *App) lastObservation(o routesync.Observation) routesync.Observation {
	prev := a.sync.Last()
	o.NBConnected, o.NetBirdIP, o.NetBirdIPv6, o.Networks = prev.NBConnected, prev.NetBirdIP, prev.NetBirdIPv6, prev.Networks
	return o
}

// checkOverlap warns when a tailnet address falls inside a prefix the bridge
// advertises. The full peer list is fetched at most every peerCheckEvery.
func (a *App) checkOverlap(ctx context.Context, tsSt *ipnstate.Status) []string {
	entries := a.sync.State().Entries
	if tsSt == nil || tsSt.BackendState != tailscale.StateRunning {
		return a.lastOverlapMsgs
	}
	if time.Since(a.peersAt) >= peerCheckEvery {
		if addrs, err := a.ts.PeerAddrs(ctx); err == nil {
			a.peerAddrs, a.peersAt = addrs, time.Now()
		} else {
			a.Log.Debug("overlap: listing tailnet peers failed", "err", err)
			return a.lastOverlapMsgs
		}
	}
	hits := overlap.Detect(a.peerAddrs, entries)
	if key := overlap.Key(hits); key != a.lastOverlapKey {
		a.lastOverlapKey = key
		a.lastOverlapMsgs = overlap.Messages(hits)
		if len(hits) == 0 {
			a.Log.Info("overlap: no tailnet address falls inside an advertised route")
		}
		for _, m := range a.lastOverlapMsgs {
			a.Log.Warn("overlap: " + m)
		}
	}
	return a.lastOverlapMsgs
}

// checkSession logs a WARN while the SSO session is within BS_SESSION_WARN of
// expiring (or expired), on each state change and then hourly.
func (a *App) checkSession(nbSt *netbird.Status, now time.Time) {
	if nbSt == nil {
		return
	}
	state, left := nbSt.Session(now, a.Cfg.SessionWarn)
	if !a.sessGate.Due(state, now) {
		return
	}
	switch state {
	case netbird.SessionExpiring:
		a.Log.Warn("netbird: SSO session expires soon; use the status page button or `netbird login --extend` to renew",
			"expires_in", left.Round(time.Minute).String())
	case netbird.SessionExpired:
		a.Log.Warn("netbird: SSO session expired; a new login is required", "expired_ago", (-left).Round(time.Minute).String())
	}
}

// sessionGate decides when to repeat the session warning.
type sessionGate struct {
	state netbird.SessionState
	last  time.Time
}

// Due reports whether to log now: on entering a warning state, then hourly.
func (g *sessionGate) Due(state netbird.SessionState, now time.Time) bool {
	if state != netbird.SessionExpiring && state != netbird.SessionExpired {
		g.state, g.last = state, time.Time{}
		return false
	}
	if state != g.state || now.Sub(g.last) >= sessionLogEvery {
		g.state, g.last = state, now
		return true
	}
	return false
}

// Relogin implements web.Reloginer: it starts the NetBird flow that renews the
// SSO session (connected: `netbird login --extend`) or recovers it (expired:
// `netbird up`), then waits briefly for the login URL so the redirected page shows it.
func (a *App) Relogin(_ context.Context) (netbird.Mode, error) {
	a.store.Update(func(s *status.Snapshot) { s.ReloginAttempts++ })
	ctx := a.runCtx
	if ctx == nil || ctx.Err() != nil {
		return "", fmt.Errorf("shutting down")
	}
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	st, err := a.nb.Status(sctx)
	if err != nil {
		return "", err
	}
	mode, err := a.nbLog.Renew(ctx, st)
	if err != nil {
		return "", err
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if s := a.nbLog.State(); s.URL != "" || !s.Running {
			break
		}
	}
	a.store.Update(func(s *status.Snapshot) { s.NBLogin = a.nbLog.State() })
	return mode, nil
}

func (a *App) logTS(state string) {
	if state == a.lastTS {
		return
	}
	a.lastTS = state
	switch state {
	case tailscale.StateNeedsLogin:
		if a.Cfg.TSAuthKey == "" {
			a.Log.Warn("tailscale: needs login and no TS_AUTHKEY is set; an interactive login URL will be logged")
		} else {
			a.Log.Warn("tailscale: needs login; using TS_AUTHKEY")
		}
	case tailscale.StateNeedsMachineAuth:
		a.Log.Warn("tailscale: NeedsMachineAuth. This tailnet requires device approval; approve the device in the admin console. Waiting.")
	default:
		a.Log.Info("tailscale: state changed", "state", state)
	}
}

func (a *App) logNB(st *netbird.Status) {
	key := st.DaemonStatus
	if key == a.lastNB {
		return
	}
	a.lastNB = key
	switch {
	case st.NeedsLogin():
		if a.Cfg.NBSetupKey == "" {
			a.Log.Warn("netbird: needs login (" + st.DaemonStatus + "); an SSO login URL will be logged")
		} else {
			a.Log.Warn("netbird: needs login (" + st.DaemonStatus + "); logging in with NB_SETUP_KEY")
		}
	default:
		a.Log.Info("netbird: state changed", "state", st.DaemonStatus, "ip", st.NetbirdIP)
	}
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
