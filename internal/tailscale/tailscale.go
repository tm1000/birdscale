// Package tailscale talks to tailscaled: LocalAPI (status, prefs, WhoIs) via
// tailscale.com/client/local, and the `tailscale up` CLI for the login itself.
package tailscale

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/preftype"
)

// DefaultSocket is tailscaled's LocalAPI unix socket.
const DefaultSocket = "/var/run/tailscale/tailscaled.sock"

// Backend states (ipnstate.Status.BackendState).
const (
	StateRunning          = "Running"
	StateNeedsLogin       = "NeedsLogin"
	StateNeedsMachineAuth = "NeedsMachineAuth"
	StateStopped          = "Stopped"
	StateStarting         = "Starting"
	StateNoState          = "NoState"
)

// Client wraps the LocalAPI.
type Client struct {
	LC *local.Client
}

// New returns a Client for the given LocalAPI socket.
func New(socket string) *Client {
	return &Client{LC: &local.Client{Socket: socket, UseSocketOnly: true}}
}

// Status returns the current status (peers omitted).
func (c *Client) Status(ctx context.Context) (*ipnstate.Status, error) {
	return c.LC.StatusWithoutPeers(ctx)
}

// Prefs returns the current prefs.
func (c *Client) Prefs(ctx context.Context) (*ipn.Prefs, error) { return c.LC.GetPrefs(ctx) }

// AdvertisedRoutes returns the currently advertised routes.
func (c *Client) AdvertisedRoutes(ctx context.Context) ([]netip.Prefix, error) {
	p, err := c.Prefs(ctx)
	if err != nil {
		return nil, err
	}
	return p.AdvertiseRoutes, nil
}

// PeerAddrs returns this node's and every peer's Tailscale IPs (full status,
// so call it sparingly on big tailnets).
func (c *Client) PeerAddrs(ctx context.Context) ([]netip.Addr, error) {
	st, err := c.LC.Status(ctx)
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	out = append(out, st.TailscaleIPs...)
	for _, p := range st.Peer {
		out = append(out, p.TailscaleIPs...)
	}
	return out, nil
}

// WhoIs identifies the tailnet caller behind remoteAddr.
func (c *Client) WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error) {
	return c.LC.WhoIs(ctx, remoteAddr)
}

// PrefsWanted are the prefs birdscale enforces once the node is Running.
type PrefsWanted struct {
	Hostname      string
	Tags          []string
	NetfilterMode string
}

// NetfilterMode converts the config string to the pref value.
func NetfilterMode(s string) (preftype.NetfilterMode, error) {
	switch s {
	case "off":
		return preftype.NetfilterOff, nil
	case "nodivert":
		return preftype.NetfilterNoDivert, nil
	case "on":
		return preftype.NetfilterOn, nil
	}
	return 0, fmt.Errorf("invalid netfilter mode %q", s)
}

// Drift lists the pref fields in p that differ from want. The bridge must
// never accept routes or DNS (see AGENTS.md invariants: otherwise another subnet router could pull
// NetBird-bound traffic back into the tailnet).
func Drift(p *ipn.Prefs, want PrefsWanted) []string {
	var d []string
	if p.RouteAll {
		d = append(d, "RouteAll")
	}
	if p.CorpDNS {
		d = append(d, "CorpDNS")
	}
	if m, err := NetfilterMode(want.NetfilterMode); err == nil && p.NetfilterMode != m {
		d = append(d, "NetfilterMode")
	}
	if want.Hostname != "" && p.Hostname != want.Hostname {
		d = append(d, "Hostname")
	}
	if len(want.Tags) > 0 && !slices.Equal(sorted(p.AdvertiseTags), sorted(want.Tags)) {
		d = append(d, "AdvertiseTags")
	}
	return d
}

func sorted(s []string) []string {
	c := slices.Clone(s)
	slices.Sort(c)
	return c
}

// EnsurePrefs corrects drifted prefs via EditPrefs and returns what it fixed.
func (c *Client) EnsurePrefs(ctx context.Context, want PrefsWanted) ([]string, error) {
	cur, err := c.Prefs(ctx)
	if err != nil {
		return nil, err
	}
	drift := Drift(cur, want)
	if len(drift) == 0 {
		return nil, nil
	}
	mode, _ := NetfilterMode(want.NetfilterMode)
	mp := &ipn.MaskedPrefs{}
	for _, f := range drift {
		switch f {
		case "RouteAll":
			mp.RouteAll, mp.RouteAllSet = false, true
		case "CorpDNS":
			mp.CorpDNS, mp.CorpDNSSet = false, true
		case "NetfilterMode":
			mp.NetfilterMode, mp.NetfilterModeSet = mode, true
		case "Hostname":
			mp.Hostname, mp.HostnameSet = want.Hostname, true
		case "AdvertiseTags":
			mp.AdvertiseTags, mp.AdvertiseTagsSet = want.Tags, true
		}
	}
	_, err = c.LC.EditPrefs(ctx, mp)
	return drift, err
}

// SetRoutes sets the advertised routes (equivalent of `tailscale set --advertise-routes`).
// Advertising 0.0.0.0/0 and ::/0 is what makes the node an exit node.
func (c *Client) SetRoutes(ctx context.Context, routes []netip.Prefix) error {
	if routes == nil {
		routes = []netip.Prefix{}
	}
	_, err := c.LC.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:              ipn.Prefs{AdvertiseRoutes: routes},
		AdvertiseRoutesSet: true,
	})
	return err
}

// ApprovedRoutes returns the routes control has approved for this node
// (Self.PrimaryRoutes plus any non-address AllowedIPs).
func ApprovedRoutes(st *ipnstate.Status) map[netip.Prefix]bool {
	out := map[netip.Prefix]bool{}
	if st == nil || st.Self == nil {
		return out
	}
	if st.Self.PrimaryRoutes != nil {
		for _, p := range st.Self.PrimaryRoutes.All() {
			out[p] = true
		}
	}
	if st.Self.AllowedIPs != nil {
		for _, p := range st.Self.AllowedIPs.All() {
			if p.IsSingleIP() && slices.Contains(st.Self.TailscaleIPs, p.Addr()) {
				continue
			}
			out[p] = true
		}
	}
	return out
}
