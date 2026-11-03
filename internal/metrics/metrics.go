// Package metrics exposes the bridge's state as Prometheus metrics.
//
// A single collector reads the shared status snapshot at scrape time, so the
// metrics can never drift from the status page or /healthz. Counters are
// emitted as const metrics from cumulative values kept elsewhere (the DNS
// forwarder, the route syncer, the pre-warm). Nothing here uses the global
// default registry. Labels are bounded: no client addresses, no query names.
package metrics

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tm1000/birdscale/internal/health"
	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/prewarm"
	"github.com/tm1000/birdscale/internal/routes"
	"github.com/tm1000/birdscale/internal/status"
	"github.com/tm1000/birdscale/internal/tailscale"
)

// Known state values, so every state is always present (0 or 1) and an alert
// can use a plain `== 0`.
var (
	tsStates = []string{tailscale.StateRunning, tailscale.StateNeedsLogin, tailscale.StateNeedsMachineAuth,
		tailscale.StateStopped, tailscale.StateStarting, tailscale.StateNoState}
	nbStates = []string{netbird.DaemonConnected, netbird.DaemonConnecting, netbird.DaemonIdle,
		netbird.DaemonNeedsLogin, netbird.DaemonLoginFailed, netbird.DaemonSessionExpired}
	prewarmStates = []string{string(prewarm.StateResolved), string(prewarm.StateRetrying),
		string(prewarm.StateNoRecords), "wildcard", "pending"}
	routeOrigins = []routes.Origin{routes.OriginOverride, routes.OriginPeerNetwork, routes.OriginCIDR,
		routes.OriginExitNode, routes.OriginDomain}
	healthChecks = []string{"tailscale", "netbird", "routes", "nftables"}
)

func originLabel(o routes.Origin) string {
	switch o {
	case routes.OriginPeerNetwork:
		return "peer_network"
	case routes.OriginExitNode:
		return "exit_node"
	case routes.OriginDomain:
		return "domain_resource"
	case "":
		return "other"
	}
	return string(o)
}

var (
	dBuild = prometheus.NewDesc("birdscale_build_info",
		"Constant 1, labelled with the birdscale, Tailscale and NetBird versions (empty until known).",
		[]string{"version", "tailscale_version", "netbird_version"}, nil)
	dHealthy = prometheus.NewDesc("birdscale_healthy",
		"1 if the bridge is healthy overall (same definition as /healthz), else 0.", nil, nil)
	dCheck = prometheus.NewDesc("birdscale_health_check",
		"1 if the named health check passes, else 0.", []string{"check"}, nil)
	dLastHealthy = prometheus.NewDesc("birdscale_last_healthy_timestamp_seconds",
		"Unix time the bridge was last healthy; absent if it has not been.", nil, nil)
	dTS = prometheus.NewDesc("birdscale_tailscale_backend_state",
		"1 for the current Tailscale backend state, 0 for the other known states.", []string{"state"}, nil)
	dNB = prometheus.NewDesc("birdscale_netbird_daemon_state",
		"1 for the current NetBird daemon state, 0 for the other known states.", []string{"state"}, nil)
	dNBConn = prometheus.NewDesc("birdscale_netbird_connected",
		"1 if the NetBird management or signal server is connected, else 0.", []string{"service"}, nil)
	dPeersConn = prometheus.NewDesc("birdscale_netbird_peers_connected",
		"NetBird peers currently connected.", nil, nil)
	dPeersTotal = prometheus.NewDesc("birdscale_netbird_peers_total",
		"NetBird peers known to this peer.", nil, nil)
	dSession = prometheus.NewDesc("birdscale_netbird_session_expiry_timestamp_seconds",
		"Unix time the NetBird SSO session expires. Absent for setup-key peers and when unknown.", nil, nil)
	dRoutes = prometheus.NewDesc("birdscale_routes",
		"Routes by state (desired: computed from NetBird; advertised: set in Tailscale; approved: accepted by the control server) and origin.",
		[]string{"state", "origin"}, nil)
	dRouteChanges = prometheus.NewDesc("birdscale_route_sync_changes_total",
		"Prefixes added to or removed from the advertised set by the route sync.", []string{"direction"}, nil)
	dRouteSync = prometheus.NewDesc("birdscale_route_sync_last_timestamp_seconds",
		"Unix time of the last route reconcile; absent before the first.", nil, nil)
	dPrewarm = prometheus.NewDesc("birdscale_prewarm_domains",
		"Domain-resource pre-warm entries by state.", []string{"state"}, nil)
	dPrewarmRes = prometheus.NewDesc("birdscale_prewarm_resolutions_total",
		"Pre-warm lookups made through NetBird's resolver.", nil, nil)
	dPrewarmFail = prometheus.NewDesc("birdscale_prewarm_resolution_failures_total",
		"Pre-warm lookups that failed (timeout, SERVFAIL, network).", nil, nil)
	dDNSQ = prometheus.NewDesc("birdscale_dns_queries_total",
		"DNS forwarder queries received, by client transport.", []string{"transport"}, nil)
	dDNSFwd = prometheus.NewDesc("birdscale_dns_forwarded_total",
		"DNS queries answered by NetBird's resolver.", nil, nil)
	dDNSRef = prometheus.NewDesc("birdscale_dns_refused_total",
		"DNS queries refused because the name is outside BS_DNS_DOMAINS.", nil, nil)
	dDNSFail = prometheus.NewDesc("birdscale_dns_servfail_total",
		"DNS queries answered SERVFAIL (upstream unreachable or unknown).", nil, nil)
	dDNSMal = prometheus.NewDesc("birdscale_dns_malformed_total",
		"DNS queries answered FORMERR or NOTIMP.", nil, nil)
	dDNSTrunc = prometheus.NewDesc("birdscale_dns_truncated_total",
		"DNS replies sent with the TC bit set.", nil, nil)
	dDNSWait = prometheus.NewDesc("birdscale_dns_route_wait_total",
		"Answers for domain resources held until the route was advertised, by result.", []string{"result"}, nil)
	dNFTPkts = prometheus.NewDesc("birdscale_nft_rule_packets_total",
		"Packets matched by an nftables rule of table inet birdscale (resets if the table is reinstalled).",
		[]string{"chain", "comment"}, nil)
	dNFTBytes = prometheus.NewDesc("birdscale_nft_rule_bytes_total",
		"Bytes matched by an nftables rule of table inet birdscale (resets if the table is reinstalled).",
		[]string{"chain", "comment"}, nil)
	dOverlap = prometheus.NewDesc("birdscale_address_overlaps",
		"Advertised prefixes that contain tailnet addresses (see the 100.64.0.0/10 caveat).", nil, nil)
	dRelogin = prometheus.NewDesc("birdscale_netbird_relogin_attempts_total",
		"NetBird re-login requests made from the status page.", nil, nil)
)

var allDescs = []*prometheus.Desc{dBuild, dHealthy, dCheck, dLastHealthy, dTS, dNB, dNBConn, dPeersConn,
	dPeersTotal, dSession, dRoutes, dRouteChanges, dRouteSync, dPrewarm, dPrewarmRes, dPrewarmFail,
	dDNSQ, dDNSFwd, dDNSRef, dDNSFail, dDNSMal, dDNSTrunc, dDNSWait, dNFTPkts, dNFTBytes, dOverlap, dRelogin}

// Collector turns a status snapshot into metrics.
type Collector struct {
	Store   *status.Store
	Version string
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range allDescs {
		ch <- d
	}
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) { Emit(ch, c.Store.Get(), c.Version) }

// Emit sends all metrics for s. It is a pure function of its input.
func Emit(ch chan<- prometheus.Metric, s status.Snapshot, version string) {
	gauge := func(d *prometheus.Desc, v float64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, v, lv...)
	}
	counter := func(d *prometheus.Desc, v uint64, lv ...string) {
		ch <- prometheus.MustNewConstMetric(d, prometheus.CounterValue, float64(v), lv...)
	}
	b2f := func(b bool) float64 {
		if b {
			return 1
		}
		return 0
	}

	tsVer, nbVer := "", ""
	if s.TSStatus != nil {
		tsVer = s.TSStatus.Version
	}
	if s.NBStatus != nil {
		nbVer = s.NBStatus.DaemonVer
	}
	gauge(dBuild, 1, version, tsVer, nbVer)

	rep := health.Evaluate(s)
	gauge(dHealthy, b2f(rep.Healthy))
	seen := map[string]bool{}
	for _, chk := range rep.Checks {
		seen[chk.Name] = true
		gauge(dCheck, b2f(chk.OK), chk.Name)
	}
	for _, n := range healthChecks {
		if !seen[n] {
			gauge(dCheck, 0, n)
		}
	}
	if !s.LastHealthy.IsZero() {
		gauge(dLastHealthy, unix(s.LastHealthy))
	}

	tsState := ""
	if s.TSStatus != nil {
		tsState = s.TSStatus.BackendState
	}
	stateGauges(gauge, dTS, tsStates, tsState)
	nbState := ""
	if s.NBStatus != nil {
		nbState = s.NBStatus.DaemonStatus
	}
	stateGauges(gauge, dNB, nbStates, nbState)

	if nb := s.NBStatus; nb != nil {
		gauge(dNBConn, b2f(nb.Management.Connected), "management")
		gauge(dNBConn, b2f(nb.Signal.Connected), "signal")
		gauge(dPeersConn, float64(nb.Peers.Connected))
		gauge(dPeersTotal, float64(nb.Peers.Total))
		if ex, ok := nb.SessionExpiry(); ok {
			gauge(dSession, unix(ex))
		}
	} else {
		gauge(dNBConn, 0, "management")
		gauge(dNBConn, 0, "signal")
	}

	emitRoutes(gauge, s)
	counter(dRouteChanges, s.RouteSync.Added, "add")
	counter(dRouteChanges, s.RouteSync.Removed, "remove")
	if !s.RouteSync.LastSync.IsZero() {
		gauge(dRouteSync, unix(s.RouteSync.LastSync))
	}

	byState := map[string]int{}
	for _, r := range s.Prewarm {
		st := string(r.State)
		switch {
		case r.Wildcard:
			st = "wildcard"
		case st == "":
			st = "pending"
		}
		byState[st]++
	}
	for _, st := range prewarmStates {
		gauge(dPrewarm, float64(byState[st]), st)
	}
	counter(dPrewarmRes, s.PrewarmCount.Attempts)
	counter(dPrewarmFail, s.PrewarmCount.Failures)

	if s.DNSEnabled {
		counter(dDNSQ, s.DNS.UDP, "udp")
		counter(dDNSQ, s.DNS.TCP, "tcp")
		counter(dDNSFwd, s.DNS.Forwarded)
		counter(dDNSRef, s.DNS.Refused)
		counter(dDNSFail, s.DNS.Failed)
		counter(dDNSMal, s.DNS.Malformed)
		counter(dDNSTrunc, s.DNS.Truncated)
		counter(dDNSWait, s.DNS.RouteWaitOK, "ok")
		counter(dDNSWait, s.DNS.RouteWaitTimeout, "timeout")
	}

	for _, rc := range s.NFTCounters {
		counter(dNFTPkts, rc.Packets, rc.Chain, rc.Comment)
		counter(dNFTBytes, rc.Bytes, rc.Chain, rc.Comment)
	}
	gauge(dOverlap, float64(len(s.Overlaps)))
	counter(dRelogin, s.ReloginAttempts)
}

func unix(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// stateGauges emits 1 for the current state and 0 for the other known ones. A
// state outside the known list is emitted too (value 1).
func stateGauges(gauge func(*prometheus.Desc, float64, ...string), d *prometheus.Desc, known []string, cur string) {
	found := false
	for _, k := range known {
		v := 0.0
		if k == cur {
			v, found = 1, true
		}
		gauge(d, v, k)
	}
	if cur != "" && !found {
		gauge(d, 1, cur)
	}
}

func emitRoutes(gauge func(*prometheus.Desc, float64, ...string), s status.Snapshot) {
	origin := map[netip.Prefix]routes.Origin{}
	for _, e := range s.RouteSync.Entries {
		origin[e.Prefix] = e.Origin
	}
	count := func(ps []netip.Prefix, keep func(netip.Prefix) bool) map[string]float64 {
		m := map[string]float64{}
		for _, p := range ps {
			if keep == nil || keep(p) {
				m[originLabel(origin[p.Masked()])]++
			}
		}
		return m
	}
	var advertised []netip.Prefix
	if s.TSPrefs != nil {
		advertised = s.TSPrefs.AdvertiseRoutes
	}
	sets := []struct {
		state string
		m     map[string]float64
	}{
		{"desired", count(s.RoutesDesired, nil)},
		{"advertised", count(advertised, nil)},
		{"approved", count(advertised, func(p netip.Prefix) bool { return s.TSApproved[p] })},
	}
	for _, set := range sets {
		for _, o := range routeOrigins {
			l := originLabel(o)
			gauge(dRoutes, set.m[l], set.state, l)
		}
		// Prefixes with no known origin (e.g. advertised but no longer desired).
		gauge(dRoutes, set.m["other"], set.state, "other")
	}
}

// Metrics owns the private registry.
type Metrics struct {
	reg *prometheus.Registry
}

// New builds a private registry with the birdscale collector plus the Go
// runtime and process collectors.
func New(store *status.Store, version string) *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		&Collector{Store: store, Version: version},
	)
	return &Metrics{reg: reg}
}

// Registry returns the private registry.
func (m *Metrics) Registry() *prometheus.Registry { return m.reg }

// Handler serves the registry in the Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
