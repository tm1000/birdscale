package metrics

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"github.com/tm1000/birdscale/internal/dnsfwd"
	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/nft"
	"github.com/tm1000/birdscale/internal/prewarm"
	"github.com/tm1000/birdscale/internal/routes"
	"github.com/tm1000/birdscale/internal/routesync"
	"github.com/tm1000/birdscale/internal/status"
)

func mp(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// fullSnapshot is a healthy bridge with a little of everything.
func fullSnapshot() status.Snapshot {
	nb := &netbird.Status{DaemonStatus: "Connected", DaemonVer: "0.82.0", NetbirdIP: "10.99.1.5/23",
		SessionExpiresAt: "2026-11-09T12:00:00Z"}
	nb.Management.Connected, nb.Signal.Connected = true, true
	nb.Peers.Total, nb.Peers.Connected = 7, 5
	adv := []netip.Prefix{mp("10.99.0.0/23"), mp("10.20.0.0/16"), mp("203.0.113.5/32"), mp("192.0.2.0/24")}
	return status.Snapshot{
		TSStatus: &ipnstate.Status{BackendState: "Running", Version: "1.104.4-t0"},
		TSPrefs:  &ipn.Prefs{AdvertiseRoutes: adv},
		NBStatus: nb,

		RoutesComputed: true,
		RoutesDesired:  adv[:3],
		RouteSync: routesync.State{
			Entries: []routes.Entry{
				{Prefix: adv[0], Origin: routes.OriginPeerNetwork},
				{Prefix: adv[1], Origin: routes.OriginCIDR},
				{Prefix: adv[2], Origin: routes.OriginDomain},
			},
			Added: 4, Removed: 1, LastSync: time.Unix(1_700_000_000, 0),
		},
		TSApproved: map[netip.Prefix]bool{adv[0]: true, adv[1]: true},

		DNSEnabled: true,
		DNS: dnsfwd.Stats{Queries: 10, UDP: 8, TCP: 2, Forwarded: 7, Refused: 1, Failed: 2,
			Malformed: 3, Truncated: 4, RouteWaitOK: 5, RouteWaitTimeout: 6},
		Prewarm: []prewarm.Result{
			{Domain: "a.example.internal", State: prewarm.StateResolved},
			{Domain: "b.example.internal", State: prewarm.StateResolved},
			{Domain: "c.example.internal", State: prewarm.StateRetrying},
			{Domain: "*.example.internal", Wildcard: true},
		},
		PrewarmCount:    prewarm.Counters{Attempts: 9, Failures: 3},
		NFTPresent:      true,
		NFTCounters:     []nft.RuleCounter{{Chain: "forward", Comment: "tailnet -> netbird", Packets: 100, Bytes: 6400}},
		Overlaps:        []string{"x"},
		ReloginAttempts: 2,
		LastHealthy:     time.Unix(1_700_000_100, 0),
	}
}

func collect(t *testing.T, s status.Snapshot, expected string, names ...string) {
	t.Helper()
	store := status.NewStore()
	store.Update(func(d *status.Snapshot) { *d = s })
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(&Collector{Store: store, Version: "1.2.3"})
	if err := testutil.GatherAndCompare(reg, strings.NewReader(expected), names...); err != nil {
		t.Error(err)
	}
}

func TestBuildInfoAndHealth(t *testing.T) {
	collect(t, fullSnapshot(), `
# HELP birdscale_build_info Constant 1, labelled with the birdscale, Tailscale and NetBird versions (empty until known).
# TYPE birdscale_build_info gauge
birdscale_build_info{netbird_version="0.82.0",tailscale_version="1.104.4-t0",version="1.2.3"} 1
# HELP birdscale_health_check 1 if the named health check passes, else 0.
# TYPE birdscale_health_check gauge
birdscale_health_check{check="netbird"} 1
birdscale_health_check{check="nftables"} 1
birdscale_health_check{check="routes"} 0
birdscale_health_check{check="tailscale"} 1
# HELP birdscale_healthy 1 if the bridge is healthy overall (same definition as /healthz), else 0.
# TYPE birdscale_healthy gauge
birdscale_healthy 0
`, "birdscale_build_info", "birdscale_health_check", "birdscale_healthy")
}

func TestHealthyWhenRoutesMatch(t *testing.T) {
	s := fullSnapshot()
	s.TSPrefs.AdvertiseRoutes = s.RoutesDesired
	collect(t, s, `
# HELP birdscale_healthy 1 if the bridge is healthy overall (same definition as /healthz), else 0.
# TYPE birdscale_healthy gauge
birdscale_healthy 1
`, "birdscale_healthy")
}

func TestStatesAndNetBird(t *testing.T) {
	collect(t, fullSnapshot(), `
# HELP birdscale_tailscale_backend_state 1 for the current Tailscale backend state, 0 for the other known states.
# TYPE birdscale_tailscale_backend_state gauge
birdscale_tailscale_backend_state{state="NeedsLogin"} 0
birdscale_tailscale_backend_state{state="NeedsMachineAuth"} 0
birdscale_tailscale_backend_state{state="NoState"} 0
birdscale_tailscale_backend_state{state="Running"} 1
birdscale_tailscale_backend_state{state="Starting"} 0
birdscale_tailscale_backend_state{state="Stopped"} 0
# HELP birdscale_netbird_connected 1 if the NetBird management or signal server is connected, else 0.
# TYPE birdscale_netbird_connected gauge
birdscale_netbird_connected{service="management"} 1
birdscale_netbird_connected{service="signal"} 1
# HELP birdscale_netbird_peers_connected NetBird peers currently connected.
# TYPE birdscale_netbird_peers_connected gauge
birdscale_netbird_peers_connected 5
# HELP birdscale_netbird_peers_total NetBird peers known to this peer.
# TYPE birdscale_netbird_peers_total gauge
birdscale_netbird_peers_total 7
# HELP birdscale_netbird_session_expiry_timestamp_seconds Unix time the NetBird SSO session expires. Absent for setup-key peers and when unknown.
# TYPE birdscale_netbird_session_expiry_timestamp_seconds gauge
birdscale_netbird_session_expiry_timestamp_seconds 1.7942256e+09
`, "birdscale_tailscale_backend_state", "birdscale_netbird_connected", "birdscale_netbird_peers_connected",
		"birdscale_netbird_peers_total", "birdscale_netbird_session_expiry_timestamp_seconds")

	// Daemon state: exactly one 1, an unknown state is emitted as its own series.
	s := fullSnapshot()
	s.NBStatus.DaemonStatus = "SomethingNew"
	if n := testutil.CollectAndCount(&Collector{Store: storeOf(s)}, "birdscale_netbird_daemon_state"); n != len(nbStates)+1 {
		t.Errorf("daemon state series: %d", n)
	}
}

func storeOf(s status.Snapshot) *status.Store {
	st := status.NewStore()
	st.Update(func(d *status.Snapshot) { *d = s })
	return st
}

func TestSessionExpiryAbsentForSetupKey(t *testing.T) {
	s := fullSnapshot()
	s.NBStatus.SessionExpiresAt = ""
	if n := testutil.CollectAndCount(&Collector{Store: storeOf(s)}, "birdscale_netbird_session_expiry_timestamp_seconds"); n != 0 {
		t.Errorf("expiry series for a setup-key peer: %d", n)
	}
}

func TestRoutesByOrigin(t *testing.T) {
	m := map[string]float64{}
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(&Collector{Store: storeOf(fullSnapshot()), Version: "x"})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() != "birdscale_routes" {
			continue
		}
		for _, mm := range mf.Metric {
			var st, or string
			for _, l := range mm.Label {
				switch l.GetName() {
				case "state":
					st = l.GetValue()
				case "origin":
					or = l.GetValue()
				}
			}
			m[st+"/"+or] = mm.GetGauge().GetValue()
		}
	}
	want := map[string]float64{
		"desired/peer_network": 1, "desired/cidr": 1, "desired/domain_resource": 1, "desired/other": 0,
		"advertised/peer_network": 1, "advertised/cidr": 1, "advertised/domain_resource": 1,
		"advertised/other":      1, // 192.0.2.0/24: advertised but no longer desired
		"approved/peer_network": 1, "approved/cidr": 1, "approved/domain_resource": 0,
		"approved/exit_node": 0,
	}
	for k, v := range want {
		if got, ok := m[k]; !ok || got != v {
			t.Errorf("%s = %v (present %v), want %v", k, got, ok, v)
		}
	}
}

func TestCounters(t *testing.T) {
	collect(t, fullSnapshot(), `
# HELP birdscale_route_sync_changes_total Prefixes added to or removed from the advertised set by the route sync.
# TYPE birdscale_route_sync_changes_total counter
birdscale_route_sync_changes_total{direction="add"} 4
birdscale_route_sync_changes_total{direction="remove"} 1
# HELP birdscale_prewarm_domains Domain-resource pre-warm entries by state.
# TYPE birdscale_prewarm_domains gauge
birdscale_prewarm_domains{state="no-records"} 0
birdscale_prewarm_domains{state="pending"} 0
birdscale_prewarm_domains{state="resolved"} 2
birdscale_prewarm_domains{state="retrying"} 1
birdscale_prewarm_domains{state="wildcard"} 1
# HELP birdscale_prewarm_resolutions_total Pre-warm lookups made through NetBird's resolver.
# TYPE birdscale_prewarm_resolutions_total counter
birdscale_prewarm_resolutions_total 9
# HELP birdscale_prewarm_resolution_failures_total Pre-warm lookups that failed (timeout, SERVFAIL, network).
# TYPE birdscale_prewarm_resolution_failures_total counter
birdscale_prewarm_resolution_failures_total 3
# HELP birdscale_dns_queries_total DNS forwarder queries received, by client transport.
# TYPE birdscale_dns_queries_total counter
birdscale_dns_queries_total{transport="tcp"} 2
birdscale_dns_queries_total{transport="udp"} 8
# HELP birdscale_dns_forwarded_total DNS queries answered by NetBird's resolver.
# TYPE birdscale_dns_forwarded_total counter
birdscale_dns_forwarded_total 7
# HELP birdscale_dns_refused_total DNS queries refused because the name is outside BS_DNS_DOMAINS.
# TYPE birdscale_dns_refused_total counter
birdscale_dns_refused_total 1
# HELP birdscale_dns_servfail_total DNS queries answered SERVFAIL (upstream unreachable or unknown).
# TYPE birdscale_dns_servfail_total counter
birdscale_dns_servfail_total 2
# HELP birdscale_dns_malformed_total DNS queries answered FORMERR or NOTIMP.
# TYPE birdscale_dns_malformed_total counter
birdscale_dns_malformed_total 3
# HELP birdscale_dns_truncated_total DNS replies sent with the TC bit set.
# TYPE birdscale_dns_truncated_total counter
birdscale_dns_truncated_total 4
# HELP birdscale_dns_route_wait_total Answers for domain resources held until the route was advertised, by result.
# TYPE birdscale_dns_route_wait_total counter
birdscale_dns_route_wait_total{result="ok"} 5
birdscale_dns_route_wait_total{result="timeout"} 6
# HELP birdscale_nft_rule_packets_total Packets matched by an nftables rule of table inet birdscale (resets if the table is reinstalled).
# TYPE birdscale_nft_rule_packets_total counter
birdscale_nft_rule_packets_total{chain="forward",comment="tailnet -> netbird"} 100
# HELP birdscale_nft_rule_bytes_total Bytes matched by an nftables rule of table inet birdscale (resets if the table is reinstalled).
# TYPE birdscale_nft_rule_bytes_total counter
birdscale_nft_rule_bytes_total{chain="forward",comment="tailnet -> netbird"} 6400
# HELP birdscale_address_overlaps Advertised prefixes that contain tailnet addresses (see the 100.64.0.0/10 caveat).
# TYPE birdscale_address_overlaps gauge
birdscale_address_overlaps 1
# HELP birdscale_netbird_relogin_attempts_total NetBird re-login requests made from the status page.
# TYPE birdscale_netbird_relogin_attempts_total counter
birdscale_netbird_relogin_attempts_total 2
`, "birdscale_route_sync_changes_total", "birdscale_prewarm_domains", "birdscale_prewarm_resolutions_total",
		"birdscale_prewarm_resolution_failures_total", "birdscale_dns_queries_total", "birdscale_dns_forwarded_total",
		"birdscale_dns_refused_total", "birdscale_dns_servfail_total", "birdscale_dns_malformed_total",
		"birdscale_dns_truncated_total", "birdscale_dns_route_wait_total", "birdscale_nft_rule_packets_total",
		"birdscale_nft_rule_bytes_total", "birdscale_address_overlaps", "birdscale_netbird_relogin_attempts_total")
}

func TestDNSOmittedWhenDisabled(t *testing.T) {
	s := fullSnapshot()
	s.DNSEnabled = false
	if n := testutil.CollectAndCount(&Collector{Store: storeOf(s)}, "birdscale_dns_queries_total", "birdscale_dns_forwarded_total"); n != 0 {
		t.Errorf("dns series with BS_DNS=false: %d", n)
	}
}

func TestEmptySnapshotRenders(t *testing.T) {
	// Before anything is up: no panics, no NaN, valid exposition.
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(&Collector{Store: status.NewStore(), Version: "dev"})
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, mf := range mfs {
		got[mf.GetName()] = true
	}
	for _, n := range []string{"birdscale_build_info", "birdscale_healthy", "birdscale_health_check"} {
		if !got[n] {
			t.Errorf("missing %s", n)
		}
	}
	if got["birdscale_netbird_session_expiry_timestamp_seconds"] || got["birdscale_last_healthy_timestamp_seconds"] {
		t.Error("timestamp metrics must be absent while unknown")
	}
}

func TestRegistryHasGoAndProcessAndLintsClean(t *testing.T) {
	m := New(status.NewStore(), "1.2.3")
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, mf := range mfs {
		names[mf.GetName()] = true
	}
	for _, n := range []string{"go_goroutines", "process_open_fds", "birdscale_build_info"} {
		if !names[n] {
			t.Errorf("registry lacks %s", n)
		}
	}
	// Every birdscale_ metric has the prefix and HELP text; promlint is happy.
	for _, mf := range mfs {
		if strings.HasPrefix(mf.GetName(), "birdscale_") && mf.GetHelp() == "" {
			t.Errorf("%s has no HELP", mf.GetName())
		}
	}
	// Not the global registry.
	if gm, _ := prometheus.DefaultGatherer.Gather(); len(gm) > 0 {
		for _, mf := range gm {
			if strings.HasPrefix(mf.GetName(), "birdscale_") {
				t.Errorf("birdscale metric on the default registry: %s", mf.GetName())
			}
		}
	}
}

func TestHandlerServesText(t *testing.T) {
	m := New(storeOf(fullSnapshot()), "1.2.3")
	rec := newRecorder()
	m.Handler().ServeHTTP(rec, newGet("/metrics"))
	body := rec.Body.String()
	if rec.Code != 200 || !strings.Contains(body, "birdscale_build_info{") || !strings.Contains(body, "go_goroutines") {
		t.Errorf("%d\n%.400s", rec.Code, body)
	}
}
