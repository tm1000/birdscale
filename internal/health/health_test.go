package health

import (
	"net/netip"
	"strings"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"

	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/status"
)

func healthy() status.Snapshot {
	p := netip.MustParsePrefix("10.99.0.0/23")
	nb := &netbird.Status{DaemonStatus: "Connected"}
	nb.Management.Connected = true
	return status.Snapshot{
		TSStatus:       &ipnstate.Status{BackendState: "Running"},
		TSPrefs:        &ipn.Prefs{AdvertiseRoutes: []netip.Prefix{p}},
		NBStatus:       nb,
		RoutesComputed: true,
		RoutesDesired:  []netip.Prefix{p},
		NFTPresent:     true,
	}
}

func TestHealthy(t *testing.T) {
	if r := Evaluate(healthy()); !r.Healthy {
		t.Errorf("expected healthy: %+v", r)
	}
}

func TestUnhealthyReasons(t *testing.T) {
	cases := map[string]func(*status.Snapshot){
		"needs login":                  func(s *status.Snapshot) { s.TSStatus.BackendState = "NeedsLogin" },
		"device approval":              func(s *status.Snapshot) { s.TSStatus.BackendState = "NeedsMachineAuth" },
		"not reachable":                func(s *status.Snapshot) { s.TSStatus = nil; s.TSErr = "dial" },
		"SessionExpired":               func(s *status.Snapshot) { s.NBStatus.DaemonStatus = "SessionExpired" },
		"not computed":                 func(s *status.Snapshot) { s.RoutesComputed = false },
		"advertised []":                func(s *status.Snapshot) { s.TSPrefs.AdvertiseRoutes = nil },
		"table inet birdscale missing": func(s *status.Snapshot) { s.NFTPresent = false },
		"management not connected":     func(s *status.Snapshot) { s.NBStatus.Management.Connected = false },
	}
	for want, mut := range cases {
		s := healthy()
		mut(&s)
		r := Evaluate(s)
		if r.Healthy {
			t.Errorf("%s: should be unhealthy", want)
			continue
		}
		found := false
		for _, c := range r.Checks {
			if !c.OK && strings.Contains(c.Reason, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: reason not found in %+v", want, r.Checks)
		}
	}
}
