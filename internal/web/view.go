package web

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/tm1000/birdscale/internal/health"
	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/prewarm"
	"github.com/tm1000/birdscale/internal/routes"
	"github.com/tm1000/birdscale/internal/status"
	"github.com/tm1000/birdscale/internal/version"
)

type routeView struct {
	Prefix   string
	Approved bool
}

type tsView struct {
	State, Hostname, DNSName, KeyExpiry, AuthURL, Err string
	IPs, Tags                                         []string
	AcceptRoutes                                      string
	Routes                                            []routeView
}

type connView struct {
	OK   bool
	Text string
}

type peerView struct{ FQDN, IP, Status, Path, Handshake string }

type networkView struct{ Value, Kind string }

type nbView struct {
	State, Err, LoginURL, IP, Interface, SessionExpiry, RelaySummary string
	// Re-login action. ReloginLabel is empty when no flow applies.
	ReloginLabel, ReloginHelp, LoginProgress, LoginResult string
	Connected                                             bool
	Mgmt, Signal                                          connView
	PeersTotal, PeersConnected                            int
	Peers                                                 []peerView
	Networks                                              []networkView
}

type syncRow struct {
	Prefix, Origin       string
	Advertised, Approved bool
	Stale                bool // advertised but no longer desired: about to be pruned
}

type syncView struct {
	Rows                 []syncRow
	LastSync, LastChange string
	Syncs, Changes       int
	Learned              int
	Err                  string
	Pending              int // desired but not yet advertised
	Stale                int
}

type dnsView struct {
	Enabled                                                             bool
	Listening                                                           string
	Upstream                                                            string
	Filter                                                              string
	RouteWait                                                           string
	Queries, UDP, TCP, Forwarded, Refused, Failed, Malformed, Truncated uint64
	RouteWaits, RouteWaitOK, RouteWaitTimeout                           uint64
}

type prewarmView struct {
	Domain, Result, Addrs, Age, Err, Class string
	OK, Skipped                            bool
}

type pageView struct {
	CSS                                    any
	Version                                string
	Caller                                 string
	CSRF                                   string
	Healthy                                bool
	Checks                                 []health.Check
	Uptime, LastHealthy                    string
	RoutesComputed, RoutesOverride         bool
	Desired, Advertised, Skipped, Warnings []string
	NFTPresent                             bool
	NFTCounters                            any
	TS                                     tsView
	NB                                     nbView
	Sync                                   syncView
	DNS                                    dnsView
	Prewarm                                []prewarmView
	DomainRefresh                          string
	Overlaps                               []string
	SessionBanner                          string
	SessionBad                             bool
}

func buildView(s status.Snapshot, caller, csrfToken string, now time.Time) pageView {
	rep := health.Evaluate(s)
	v := pageView{
		Version: version.Version,
		Caller:  caller, CSRF: csrfToken, Overlaps: s.Overlaps, Healthy: rep.Healthy, Checks: rep.Checks,
		Uptime:         now.Sub(s.StartedAt).Round(time.Second).String(),
		LastHealthy:    "never",
		RoutesComputed: s.RoutesComputed, RoutesOverride: s.RoutesOverride,
		Desired: routes.Strings(s.RoutesDesired), Skipped: s.RoutesSkipped, Warnings: s.RoutesWarnings,
		NFTPresent: s.NFTPresent, NFTCounters: s.NFTCounters,
	}
	if rep.Healthy {
		v.LastHealthy = "now"
	} else if !s.LastHealthy.IsZero() {
		v.LastHealthy = fmt.Sprintf("%s (%s ago)", s.LastHealthy.UTC().Format(time.RFC3339), now.Sub(s.LastHealthy).Round(time.Second))
	}
	if s.TSPrefs != nil {
		v.Advertised = routes.Strings(s.TSPrefs.AdvertiseRoutes)
	}

	// Tailscale.
	t := tsView{State: "unreachable", Err: s.TSErr, AcceptRoutes: "unknown", KeyExpiry: "n/a"}
	if st := s.TSStatus; st != nil {
		t.State, t.AuthURL = st.BackendState, st.AuthURL
		for _, ip := range st.TailscaleIPs {
			t.IPs = append(t.IPs, ip.String())
		}
		if st.Self != nil {
			t.Hostname, t.DNSName = st.Self.HostName, st.Self.DNSName
			if st.Self.Tags != nil {
				t.Tags = st.Self.Tags.AsSlice()
			}
			if st.Self.KeyExpiry != nil {
				t.KeyExpiry = fmt.Sprintf("%s (in %s)", st.Self.KeyExpiry.UTC().Format(time.RFC3339), until(now, *st.Self.KeyExpiry))
			}
		}
	}
	if s.TSPrefs != nil {
		t.AcceptRoutes = fmt.Sprint(s.TSPrefs.RouteAll)
		for _, p := range s.TSPrefs.AdvertiseRoutes {
			t.Routes = append(t.Routes, routeView{p.String(), approved(s.TSApproved, p)})
		}
	}
	v.TS = t

	// NetBird.
	n := nbView{State: "unreachable", Err: s.NBErr, SessionExpiry: "n/a (setup key or unknown)", Interface: "n/a"}
	if st := s.NBStatus; st != nil {
		n.State, n.Connected, n.IP = st.DaemonStatus, st.Connected(), st.NetbirdIP
		n.Mgmt = conn(st.Management)
		n.Signal = conn(st.Signal)
		n.RelaySummary = fmt.Sprintf("%d of %d available", st.Relays.Available, st.Relays.Total)
		if st.NetbirdIP != "" {
			if st.Kernel {
				n.Interface = "kernel WireGuard (wt0)"
			} else {
				n.Interface = "userspace WireGuard"
			}
		}
		if ex, ok := st.SessionExpiry(); ok {
			n.SessionExpiry = fmt.Sprintf("%s (in %s)", ex.UTC().Format(time.RFC3339), until(now, ex))
		}
		n.PeersTotal, n.PeersConnected = st.Peers.Total, st.Peers.Connected
		for _, p := range st.Peers.Details {
			path := p.ConnectionType
			if path == "" {
				path = "n/a"
			}
			hs := p.LastWireguardHandshake
			if tm, err := time.Parse(time.RFC3339, hs); err != nil || tm.Year() < 2000 {
				hs = "never"
			} else {
				hs = now.Sub(tm).Round(time.Second).String() + " ago"
			}
			n.Peers = append(n.Peers, peerView{p.FQDN, p.NetbirdIP, p.Status, path, hs})
		}
		for _, net := range st.Networks() {
			kind := "domain"
			if _, ok := routes.ParseNetwork(net); ok {
				kind = "cidr"
			}
			n.Networks = append(n.Networks, networkView{net, kind})
		}
	}
	// Show the SSO URL whenever the daemon is not logged in.
	if s.NBStatus == nil || !s.NBStatus.Connected() {
		n.LoginURL = s.NBLogin.URL
	}
	// Relogin action and progress.
	n.LoginResult = s.NBLogin.LastResult
	if s.NBLogin.Running {
		n.LoginProgress = "NetBird login in progress"
		if s.NBLogin.Mode == netbird.ModeExtend {
			n.LoginProgress = "SSO session renewal in progress"
		}
		if s.NBLogin.URL == "" {
			n.LoginProgress += " (waiting for the login URL)"
		}
		if s.NBLogin.Mode == netbird.ModeExtend && s.NBLogin.URL != "" {
			n.LoginURL = s.NBLogin.URL
		}
	} else if s.NBLogin.LastErr != "" && s.NBStatus != nil && s.NBStatus.Connected() {
		n.Err = s.NBLogin.LastErr
	}
	if st := s.NBStatus; st != nil && !s.NBLogin.Running {
		switch {
		case st.Connected():
			if _, ok := st.SessionExpiry(); ok {
				n.ReloginLabel = "Renew SSO session"
				n.ReloginHelp = "Runs netbird login --extend: you approve a login URL, the tunnel stays up."
			}
		case st.NeedsLogin():
			n.ReloginLabel = "Start NetBird login"
			n.ReloginHelp = "Runs netbird up: shows a fresh login URL to approve."
		}
	}
	if st := s.NBStatus; st != nil {
		state, left := st.Session(now, s.SessionWarn)
		switch state {
		case netbird.SessionExpiring:
			v.SessionBanner = fmt.Sprintf("NetBird SSO session expires in %s. Renew it before then or the bridge will stop forwarding.", left.Round(time.Minute))
		case netbird.SessionExpired:
			v.SessionBanner = fmt.Sprintf("NetBird SSO session expired %s ago. The bridge cannot reach NetBird until you log in again.", (-left).Round(time.Minute))
			v.SessionBad = true
		}
	}
	v.NB = n

	// Route sync.
	v.Sync = buildSync(s, now)

	// DNS forwarder.
	d := dnsView{
		Enabled: s.DNSEnabled, Listening: strings.Join(s.DNSListening, ", "), Upstream: s.DNSUpstream,
		Filter: "everything", RouteWait: s.DNSRouteWait.String(),
		Queries: s.DNS.Queries, UDP: s.DNS.UDP, TCP: s.DNS.TCP, Forwarded: s.DNS.Forwarded, Refused: s.DNS.Refused,
		Failed: s.DNS.Failed, Malformed: s.DNS.Malformed, Truncated: s.DNS.Truncated,
		RouteWaits: s.DNS.RouteWaits, RouteWaitOK: s.DNS.RouteWaitOK, RouteWaitTimeout: s.DNS.RouteWaitTimeout,
	}
	if len(s.DNSDomains) > 0 {
		d.Filter = strings.Join(s.DNSDomains, ", ") + " (others get REFUSED)"
	}
	if d.Listening == "" {
		d.Listening = "none (waiting for a Tailscale IP)"
	}
	if d.Upstream == "" {
		d.Upstream = "unknown (NetBird has no address yet)"
	}
	v.DNS = d

	// Pre-warm.
	v.DomainRefresh = "off (only at start and when the list changes)"
	if s.DomainRefresh > 0 {
		v.DomainRefresh = "every " + s.DomainRefresh.String()
	}
	for _, r := range s.Prewarm {
		pv := prewarmView{Domain: r.Domain}
		switch {
		case r.Wildcard:
			pv.Skipped, pv.Result = true, "skipped: wildcard (learned from real queries via the DNS forwarder)"
		case r.State == prewarm.StateRetrying:
			pv.Class, pv.Err = "bad", r.Err
			pv.Result = fmt.Sprintf("retrying (attempt %d failed", r.Attempts)
			if !r.NextRetry.IsZero() {
				pv.Result += ", next retry in " + max(r.NextRetry.Sub(now), 0).Round(time.Second).String()
			}
			pv.Result += ")"
		case r.State == prewarm.StateNoRecords:
			pv.Class = "warn"
			pv.Result = "NXDOMAIN / no A/AAAA records (re-checked on the normal refresh)"
		case r.Err != "":
			pv.Class, pv.Err = "bad", r.Err
			pv.Result = "failed"
		default:
			pv.OK, pv.Class = true, "ok"
			pv.Result = "resolved"
			if len(r.Addrs) == 0 {
				pv.Result = "resolved, no A/AAAA records"
			}
		}
		for i, a := range r.Addrs {
			if i > 0 {
				pv.Addrs += " "
			}
			pv.Addrs += a.String()
		}
		if !r.At.IsZero() {
			pv.Age = now.Sub(r.At).Round(time.Second).String() + " ago"
		}
		v.Prewarm = append(v.Prewarm, pv)
	}
	return v
}

func buildSync(s status.Snapshot, now time.Time) syncView {
	sv := syncView{
		Syncs: s.RouteSync.Syncs, Changes: s.RouteSync.Changes, Learned: len(s.RouteSync.Learned),
		Err: s.RouteSync.Err, LastSync: "never", LastChange: "never",
	}
	if !s.RouteSync.LastSync.IsZero() {
		sv.LastSync = now.Sub(s.RouteSync.LastSync).Round(time.Second).String() + " ago"
	}
	if !s.RouteSync.LastChange.IsZero() {
		sv.LastChange = now.Sub(s.RouteSync.LastChange).Round(time.Second).String() + " ago"
	}
	var adv []netip.Prefix
	if s.TSPrefs != nil {
		adv = s.TSPrefs.AdvertiseRoutes
	}
	isAdv := map[netip.Prefix]bool{}
	for _, p := range adv {
		isAdv[p.Masked()] = true
	}
	desired := map[netip.Prefix]bool{}
	for _, e := range s.RouteSync.Entries {
		desired[e.Prefix] = true
		row := syncRow{Prefix: e.Prefix.String(), Origin: string(e.Origin), Advertised: isAdv[e.Prefix], Approved: approved(s.TSApproved, e.Prefix)}
		if !row.Advertised {
			sv.Pending++
		}
		sv.Rows = append(sv.Rows, row)
	}
	var stale []netip.Prefix
	for p := range isAdv {
		if !desired[p] && s.RouteSync.Computed {
			stale = append(stale, p)
		}
	}
	slices.SortFunc(stale, routes.ComparePrefix)
	for _, p := range stale {
		sv.Stale++
		sv.Rows = append(sv.Rows, syncRow{Prefix: p.String(), Origin: "no longer desired (pruning)", Advertised: true, Approved: approved(s.TSApproved, p), Stale: true})
	}
	return sv
}

func conn(c netbird.Conn) connView {
	if c.Connected {
		return connView{true, "connected"}
	}
	if c.Error != "" {
		return connView{false, "disconnected: " + c.Error}
	}
	return connView{false, "disconnected"}
}

func approved(m map[netip.Prefix]bool, p netip.Prefix) bool { return m[p] }

func until(now, t time.Time) string {
	d := t.Sub(now)
	if d < 0 {
		return "expired " + (-d).Round(time.Minute).String() + " ago"
	}
	return d.Round(time.Minute).String()
}
