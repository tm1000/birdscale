// Package overlap detects tailnet addresses that sit inside a prefix the
// bridge advertises (the 100.64.0.0/10 overlap case). Such a device would have its own traffic
// captured by, or collide with, the NetBird-bound route.
package overlap

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/tm1000/birdscale/internal/routes"
)

// Hit is one tailnet address inside one advertised prefix.
type Hit struct {
	Addr   netip.Addr
	Prefix netip.Prefix
	Origin routes.Origin
}

// Detect returns every (addr, prefix) overlap, sorted. Default routes
// (exit node) are ignored: they contain everything by design. The bridge's
// own Tailscale IPs are fine to pass in: they overlap the same way.
func Detect(tailnet []netip.Addr, advertised []routes.Entry) []Hit {
	var hits []Hit
	seen := map[Hit]bool{}
	for _, e := range advertised {
		if e.Prefix.Bits() == 0 {
			continue
		}
		for _, a := range tailnet {
			a = a.Unmap()
			if e.Prefix.Contains(a) {
				h := Hit{a, e.Prefix, e.Origin}
				if !seen[h] {
					seen[h] = true
					hits = append(hits, h)
				}
			}
		}
	}
	slices.SortFunc(hits, func(x, y Hit) int {
		if c := x.Addr.Compare(y.Addr); c != 0 {
			return c
		}
		return routes.ComparePrefix(x.Prefix, y.Prefix)
	})
	return hits
}

// Messages renders one line per advertised prefix that is overlapped, with its addresses.
func Messages(hits []Hit) []string {
	by := map[netip.Prefix][]string{}
	var order []netip.Prefix
	origin := map[netip.Prefix]routes.Origin{}
	for _, h := range hits {
		if _, ok := by[h.Prefix]; !ok {
			order = append(order, h.Prefix)
			origin[h.Prefix] = h.Origin
		}
		by[h.Prefix] = append(by[h.Prefix], h.Addr.String())
	}
	var out []string
	for _, p := range order {
		a := by[p]
		shown := a
		more := ""
		if len(a) > 5 {
			shown, more = a[:5], fmt.Sprintf(" and %d more", len(a)-5)
		}
		out = append(out, fmt.Sprintf("tailnet address(es) %s%s fall inside the advertised %s route %s; "+
			"those devices cannot reach each other correctly through the bridge. Re-address them or restrict the tailnet with ipPool.",
			strings.Join(shown, ", "), more, origin[p], p))
	}
	return out
}

// Key is a stable fingerprint for change detection.
func Key(hits []Hit) string {
	var b strings.Builder
	for _, h := range hits {
		fmt.Fprintf(&b, "%s>%s;", h.Addr, h.Prefix)
	}
	return b.String()
}
