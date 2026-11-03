// Package routes computes the set of prefixes birdscale advertises into the tailnet.
//
// Compute is a pure function. The route syncer calls it on every change with
// the current NetBird status plus the host routes learned from NetBird's
// routing table (domain resources).
package routes

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

// Input is everything Compute needs.
type Input struct {
	// NetBirdIP is the "netbirdIp" status field, normally with a prefix length
	// ("10.99.1.5/23"). The advertised peer network is the masked prefix.
	NetBirdIP string
	// NetBirdIPv6 is the "netbirdIpv6" status field, present only when the
	// NetBird account gives peers IPv6 addresses. Handled like NetBirdIP.
	NetBirdIPv6 string
	// Networks are all peers.details[].networks entries: CIDRs, bare IPs or
	// domain names (the latter are skipped).
	Networks []string
	// Override, when non-empty, replaces the computed set (BS_ROUTES).
	Override []netip.Prefix
	// ExitNode adds 0.0.0.0/0 and ::/0 and lets default routes from NetBird through.
	ExitNode bool
	// Learned are the /32 and /128 routes NetBird installed in its routing
	// table on demand (domain resources). Anything that is not a host route,
	// and anything already covered by a broader desired prefix, is ignored.
	// Ignored when Override is set: the override is the whole answer.
	Learned []netip.Prefix
}

// Origin says why a prefix is in the advertised set.
type Origin string

// Origins, in precedence order (a prefix with several reasons shows the first).
const (
	OriginOverride    Origin = "override"
	OriginPeerNetwork Origin = "peer network"
	OriginCIDR        Origin = "cidr"
	OriginExitNode    Origin = "exit node"
	OriginDomain      Origin = "domain resource"
)

// Entry is one desired prefix and its origin.
type Entry struct {
	Prefix netip.Prefix
	Origin Origin
}

// Result is the computed advertised set.
type Result struct {
	Prefixes []netip.Prefix // deduped, sorted (v4 before v6, then by address, then length)
	Entries  []Entry        // same order as Prefixes, with origins
	Skipped  []string       // entries ignored (domains, default routes, unparsable)
	Warnings []string
}

// Compute builds the advertised set.
func Compute(in Input) Result {
	var res Result
	set := map[netip.Prefix]Origin{}
	add := func(p netip.Prefix, o Origin) {
		if _, ok := set[p]; !ok {
			set[p] = o
		}
	}

	if len(in.Override) > 0 {
		for _, p := range in.Override {
			add(p.Masked(), OriginOverride)
		}
	} else {
		if p, warn, err := peerNetwork(in.NetBirdIP); err != nil {
			res.Warnings = append(res.Warnings, err.Error())
		} else {
			if warn != "" {
				res.Warnings = append(res.Warnings, warn)
			}
			add(p, OriginPeerNetwork)
		}
		if in.NetBirdIPv6 != "" {
			if p, warn, err := peerNetwork(in.NetBirdIPv6); err != nil {
				res.Warnings = append(res.Warnings, err.Error())
			} else if p.Addr().Is4() {
				res.Warnings = append(res.Warnings, fmt.Sprintf("netbirdIpv6 %q is not an IPv6 address; ignored", in.NetBirdIPv6))
			} else {
				if warn != "" {
					res.Warnings = append(res.Warnings, warn)
				}
				add(p, OriginPeerNetwork)
			}
		}
		for _, n := range in.Networks {
			n = strings.TrimSpace(n)
			p, ok := ParseNetwork(n)
			switch {
			case !ok:
				res.Skipped = append(res.Skipped, n) // domain or garbage
			case p.Bits() == 0 && !in.ExitNode:
				res.Skipped = append(res.Skipped, n)
			default:
				add(p, OriginCIDR)
			}
		}
	}
	if in.ExitNode {
		add(netip.MustParsePrefix("0.0.0.0/0"), OriginExitNode)
		add(netip.MustParsePrefix("::/0"), OriginExitNode)
	}
	if len(in.Override) == 0 {
		// Host routes are judged against the non-host prefixes only, so two
		// learned /32s never hide each other.
		var wide []netip.Prefix
		for p := range set {
			if !p.IsSingleIP() {
				wide = append(wide, p)
			}
		}
		for _, l := range in.Learned {
			l = l.Masked()
			if !l.IsValid() || !l.IsSingleIP() || coveredBy(l, wide) {
				continue
			}
			add(l, OriginDomain)
		}
	}

	for p := range set {
		res.Prefixes = append(res.Prefixes, p)
	}
	slices.SortFunc(res.Prefixes, ComparePrefix)
	for _, p := range res.Prefixes {
		res.Entries = append(res.Entries, Entry{p, set[p]})
	}
	slices.Sort(res.Skipped)
	res.Skipped = slices.Compact(res.Skipped)
	return res
}

func coveredBy(p netip.Prefix, wide []netip.Prefix) bool {
	for _, w := range wide {
		if w.Addr().Is4() == p.Addr().Is4() && w.Bits() <= p.Bits() && w.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// Diff returns the prefixes in want that are not in have (add) and those in
// have that are not in want (remove), both sorted.
func Diff(have, want []netip.Prefix) (add, remove []netip.Prefix) {
	h := map[netip.Prefix]bool{}
	for _, p := range have {
		h[p.Masked()] = true
	}
	w := map[netip.Prefix]bool{}
	for _, p := range want {
		p = p.Masked()
		if w[p] {
			continue
		}
		w[p] = true
		if !h[p] {
			add = append(add, p)
		}
	}
	for p := range h {
		if !w[p] {
			remove = append(remove, p)
		}
	}
	slices.SortFunc(add, ComparePrefix)
	slices.SortFunc(remove, ComparePrefix)
	return add, remove
}

// ComparePrefix orders v4 before v6, then by address, then by length.
func ComparePrefix(a, b netip.Prefix) int {
	if a.Addr().Is4() != b.Addr().Is4() {
		if a.Addr().Is4() {
			return -1
		}
		return 1
	}
	if c := a.Addr().Compare(b.Addr()); c != 0 {
		return c
	}
	return a.Bits() - b.Bits()
}

// Equal reports whether two prefix lists hold the same set.
func Equal(a, b []netip.Prefix) bool {
	norm := func(in []netip.Prefix) []netip.Prefix {
		out := make([]netip.Prefix, 0, len(in))
		for _, p := range in {
			out = append(out, p.Masked())
		}
		slices.SortFunc(out, ComparePrefix)
		return slices.Compact(out)
	}
	return slices.Equal(norm(a), norm(b))
}

// peerNetwork derives the NetBird peer network from netbirdIp. Without a prefix
// length the network is unknown: fall back to the single address and warn
// rather than guessing a /16.
func peerNetwork(s string) (netip.Prefix, string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Prefix{}, "", fmt.Errorf("no netbirdIp: cannot derive the NetBird peer network")
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, "", fmt.Errorf("netbirdIp %q is not valid: %v", s, err)
		}
		return p.Masked(), "", nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, "", fmt.Errorf("netbirdIp %q is not valid: %v", s, err)
	}
	a = a.Unmap()
	p := netip.PrefixFrom(a, a.BitLen())
	return p, fmt.Sprintf("netbirdIp %q has no prefix length; advertising only %s (set BS_ROUTES to cover the whole NetBird network)", s, p), nil
}

// ParseNetwork accepts a CIDR or a bare IP; anything else (a domain) is not ok.
func ParseNetwork(s string) (netip.Prefix, bool) {
	if s == "" {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

// Strings renders prefixes for logs and display.
func Strings(ps []netip.Prefix) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.String()
	}
	return out
}
