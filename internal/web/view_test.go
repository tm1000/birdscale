package web

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/prewarm"
	"github.com/tm1000/birdscale/internal/routes"
	"github.com/tm1000/birdscale/internal/routesync"
	"github.com/tm1000/birdscale/internal/status"
)

func TestBuildView(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	nb, err := netbird.ParseStatus([]byte(`{"daemonStatus":"NeedsLogin","management":{"connected":false,"error":"dial failed"},
	 "peers":{"total":1,"connected":0,"details":[{"fqdn":"p.example.internal","netbirdIp":"10.99.0.7","status":"Idle","networks":["192.0.2.0/24","wiki.example.internal"]}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	r := netip.MustParsePrefix("10.99.0.0/23")
	s := status.Snapshot{
		StartedAt:  now.Add(-time.Hour),
		TSStatus:   &ipnstate.Status{BackendState: "NeedsLogin", AuthURL: "https://login.example.internal/a/abc"},
		TSPrefs:    &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{r}},
		TSApproved: map[netip.Prefix]bool{r: true},
		NBStatus:   nb,
		NBLogin:    netbird.LoginState{URL: "https://nb.example.internal/oauth2/device?user_code=AAAA-BBBB"},
	}
	v := buildView(s, "alice@example.internal", "tok", now)
	if v.Healthy || v.Uptime != "1h0m0s" {
		t.Errorf("bad header: %+v", v)
	}
	if v.NB.LoginURL == "" || v.TS.AuthURL == "" {
		t.Error("login URLs should be shown while logged out")
	}
	if len(v.TS.Routes) != 1 || !v.TS.Routes[0].Approved {
		t.Errorf("routes: %+v", v.TS.Routes)
	}
	if len(v.NB.Networks) != 2 || v.NB.Networks[0].Kind != "cidr" || v.NB.Networks[1].Kind != "domain" {
		t.Errorf("networks: %+v", v.NB.Networks)
	}
	if v.NB.Mgmt.OK || v.NB.Mgmt.Text != "disconnected: dial failed" {
		t.Errorf("mgmt: %+v", v.NB.Mgmt)
	}
}

func TestBuildViewPhase23(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	nb, err := netbird.ParseStatus([]byte(`{"daemonStatus":"Connected","management":{"connected":true},"netbirdIp":"10.99.1.5/23",
	 "sessionExpiresAt":"2026-01-02T10:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix
	s := status.Snapshot{
		StartedAt: now.Add(-time.Hour),
		NBStatus:  nb,
		TSPrefs:   &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{p("10.99.0.0/23"), p("203.0.113.1/32")}},
		RouteSync: routesync.State{
			Computed: true,
			Entries: []routes.Entry{
				{Prefix: p("10.99.0.0/23"), Origin: routes.OriginPeerNetwork},
				{Prefix: p("203.0.113.2/32"), Origin: routes.OriginDomain},
			},
			Learned: []netip.Prefix{p("203.0.113.2/32")}, Syncs: 4, Changes: 2,
			LastSync: now.Add(-5 * time.Second),
		},
		SessionWarn: 24 * time.Hour,
		Overlaps:    []string{"tailnet address(es) 100.90.1.1 fall inside route 10.99.0.0/23"},
		DNSEnabled:  true, DNSDomains: []string{"example.internal"},
		Prewarm: []prewarm.Result{
			{Domain: "wiki.example.internal", Addrs: []netip.Addr{netip.MustParseAddr("203.0.113.2")}, At: now.Add(-time.Minute)},
			{Domain: "*.corp.example.internal", Wildcard: true},
			{Domain: "slow.example.internal", State: prewarm.StateRetrying, Attempts: 3, Err: "i/o timeout", NextRetry: now.Add(8 * time.Second), At: now},
			{Domain: "gone.example.internal", State: prewarm.StateNoRecords},
		},
	}
	v := buildView(s, "alice@example.internal", "tok", now)
	if len(v.Sync.Rows) != 3 || v.Sync.Pending != 1 || v.Sync.Stale != 1 {
		t.Fatalf("sync: %+v", v.Sync)
	}
	if !v.Sync.Rows[0].Advertised || v.Sync.Rows[1].Advertised || !v.Sync.Rows[2].Stale || v.Sync.Rows[1].Origin != "domain resource" {
		t.Errorf("rows: %+v", v.Sync.Rows)
	}
	if v.SessionBanner == "" || v.SessionBad {
		t.Errorf("banner: %q bad=%v", v.SessionBanner, v.SessionBad)
	}
	if v.NB.ReloginLabel != "Renew SSO session" {
		t.Errorf("relogin label %q", v.NB.ReloginLabel)
	}
	if len(v.Overlaps) != 1 || len(v.Prewarm) != 4 || !v.Prewarm[1].Skipped || !v.Prewarm[0].OK {
		t.Errorf("overlaps/prewarm: %+v %+v", v.Overlaps, v.Prewarm)
	}
	if r := v.Prewarm[2]; r.Class != "bad" || r.Err != "i/o timeout" || r.Result != "retrying (attempt 3 failed, next retry in 8s)" {
		t.Errorf("retrying row: %+v", r)
	}
	if r := v.Prewarm[3]; r.Class != "warn" || r.OK || !strings.Contains(r.Result, "NXDOMAIN") {
		t.Errorf("nxdomain row: %+v", r)
	}
	if v.DNS.Filter == "everything" {
		t.Error("dns filter text")
	}

	// Expired and logged out: bad banner, login button.
	s.NBStatus, _ = netbird.ParseStatus([]byte(`{"daemonStatus":"SessionExpired","sessionExpiresAt":"2026-01-01T00:00:00Z"}`))
	v = buildView(s, "alice@example.internal", "tok", now)
	if !v.SessionBad || v.NB.ReloginLabel != "Start NetBird login" {
		t.Errorf("expired: bad=%v label=%q", v.SessionBad, v.NB.ReloginLabel)
	}
	// While a flow runs the button is hidden.
	s.NBLogin = netbird.LoginState{Running: true, Mode: netbird.ModeUp}
	if v = buildView(s, "a", "t", now); v.NB.ReloginLabel != "" || v.NB.LoginProgress == "" {
		t.Errorf("running: %+v", v.NB)
	}
}
