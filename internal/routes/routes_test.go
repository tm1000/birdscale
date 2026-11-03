package routes

import (
	"net/netip"
	"slices"
	"testing"
)

func strs(r Result) []string { return Strings(r.Prefixes) }

func TestComputeBasic(t *testing.T) {
	r := Compute(Input{
		NetBirdIP: "10.99.1.5/23",
		Networks: []string{
			"192.0.2.0/24", "wiki.example.internal", "10.99.0.0/23", // peer net duplicate
			"192.0.2.0/24", "198.51.100.7", "2001:db8::/32", "2001:db8::1",
			"*.example.internal", "0.0.0.0/0", "::/0", "", "garbage/xx",
		},
	})
	want := []string{"10.99.0.0/23", "192.0.2.0/24", "198.51.100.7/32", "2001:db8::/32", "2001:db8::1/128"}
	if got := strs(r); !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	for _, s := range []string{"wiki.example.internal", "*.example.internal", "0.0.0.0/0", "::/0", "garbage/xx"} {
		if !slices.Contains(r.Skipped, s) {
			t.Errorf("%q should be skipped, skipped=%v", s, r.Skipped)
		}
	}
	if len(r.Warnings) != 0 {
		t.Errorf("warnings: %v", r.Warnings)
	}
}

func TestPeerNetworkUsesRealPrefix(t *testing.T) {
	for in, want := range map[string]string{
		"10.99.1.5/23":    "10.99.0.0/23",
		"100.90.200.3/16": "100.90.0.0/16",
		"100.90.200.3/24": "100.90.200.0/24",
		"fd00:1234::5/64": "fd00:1234::/64",
	} {
		r := Compute(Input{NetBirdIP: in})
		if got := strs(r); len(got) != 1 || got[0] != want {
			t.Errorf("%s: got %v want %s", in, got, want)
		}
	}
}

func TestNoPrefixFallsBackToHostAndWarns(t *testing.T) {
	r := Compute(Input{NetBirdIP: "10.99.1.5"})
	if got := strs(r); !slices.Equal(got, []string{"10.99.1.5/32"}) || len(r.Warnings) != 1 {
		t.Errorf("got %v warnings %v", got, r.Warnings)
	}
}

func TestMissingIP(t *testing.T) {
	r := Compute(Input{Networks: []string{"192.0.2.0/24"}})
	if len(r.Warnings) != 1 || !slices.Equal(strs(r), []string{"192.0.2.0/24"}) {
		t.Errorf("got %v %v", strs(r), r.Warnings)
	}
}

func TestExitNode(t *testing.T) {
	r := Compute(Input{NetBirdIP: "10.99.1.5/23", Networks: []string{"0.0.0.0/0", "::/0"}, ExitNode: true})
	want := []string{"0.0.0.0/0", "10.99.0.0/23", "::/0"}
	if got := strs(r); !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	// Exit node enabled even if NetBird pushes no default route.
	r = Compute(Input{NetBirdIP: "10.99.1.5/23", ExitNode: true})
	if got := strs(r); !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestOverrideReplaces(t *testing.T) {
	r := Compute(Input{
		NetBirdIP: "10.99.1.5/23",
		Networks:  []string{"192.0.2.0/24"},
		Override:  []netip.Prefix{netip.MustParsePrefix("203.0.113.9/24"), netip.MustParsePrefix("203.0.113.0/24")},
	})
	if got := strs(r); !slices.Equal(got, []string{"203.0.113.0/24"}) {
		t.Errorf("got %v", got)
	}
}

func TestEqual(t *testing.T) {
	a := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24")}
	b := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8")}
	if !Equal(a, b) || Equal(a, a[:1]) {
		t.Error("Equal misbehaves")
	}
}

func TestComputeLearnedAndOrigins(t *testing.T) {
	pfx := netip.MustParsePrefix
	r := Compute(Input{
		NetBirdIP: "10.99.1.5/23",
		Networks:  []string{"192.0.2.0/24", "wiki.example.internal"},
		Learned: []netip.Prefix{
			pfx("203.0.113.9/32"),  // domain resource
			pfx("192.0.2.77/32"),   // covered by 192.0.2.0/24
			pfx("10.99.0.4/32"),    // covered by the peer network
			pfx("2001:db8::9/128"), // v6 domain resource
			pfx("198.51.100.0/24"), // not a host route: ignored
			pfx("203.0.113.9/32"),  // duplicate
		},
	})
	want := []string{"10.99.0.0/23", "192.0.2.0/24", "203.0.113.9/32", "2001:db8::9/128"}
	if got := strs(r); !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	origins := map[string]Origin{}
	for _, e := range r.Entries {
		origins[e.Prefix.String()] = e.Origin
	}
	for p, o := range map[string]Origin{
		"10.99.0.0/23": OriginPeerNetwork, "192.0.2.0/24": OriginCIDR,
		"203.0.113.9/32": OriginDomain, "2001:db8::9/128": OriginDomain,
	} {
		if origins[p] != o {
			t.Errorf("%s origin %q want %q", p, origins[p], o)
		}
	}
}

func TestComputeOverrideIgnoresLearned(t *testing.T) {
	r := Compute(Input{
		NetBirdIP: "10.99.1.5/23",
		Override:  []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		Learned:   []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32")},
	})
	if got := strs(r); !slices.Equal(got, []string{"192.0.2.0/24"}) || r.Entries[0].Origin != OriginOverride {
		t.Errorf("got %v %+v", got, r.Entries)
	}
}

func TestComputeExitNodeCoversLearnedV4(t *testing.T) {
	r := Compute(Input{
		NetBirdIP: "10.99.1.5/23", ExitNode: true,
		Learned: []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32"), netip.MustParsePrefix("2001:db8::9/128")},
	})
	want := []string{"0.0.0.0/0", "10.99.0.0/23", "::/0"}
	if got := strs(r); !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestDiff(t *testing.T) {
	pfx := netip.MustParsePrefix
	add, rm := Diff(
		[]netip.Prefix{pfx("10.0.0.0/24"), pfx("203.0.113.1/32")},
		[]netip.Prefix{pfx("10.0.0.0/24"), pfx("203.0.113.2/32"), pfx("203.0.113.2/32")},
	)
	if len(add) != 1 || add[0] != pfx("203.0.113.2/32") || len(rm) != 1 || rm[0] != pfx("203.0.113.1/32") {
		t.Errorf("add=%v rm=%v", add, rm)
	}
}

func TestDomainEntries(t *testing.T) {
	exact, wild := DomainEntries([]string{
		"Wiki.Example.Internal.", "*.corp.example.internal", "192.0.2.0/24", "10.1.1.1", "", "bad name", "wiki.example.internal", "*.",
	})
	if !slices.Equal(exact, []string{"wiki.example.internal"}) || !slices.Equal(wild, []string{"corp.example.internal"}) {
		t.Errorf("exact=%v wild=%v", exact, wild)
	}
	for name, want := range map[string]bool{
		"wiki.example.internal.":     true,
		"WIKI.example.internal":      true,
		"x.wiki.example.internal":    false,
		"a.corp.example.internal":    true,
		"a.b.corp.example.internal.": true,
		"corp.example.internal":      false, // wildcard does not cover the apex
		"notcorp.example.internal":   false,
		"example.com":                false,
	} {
		if got := MatchDomain(name, exact, wild); got != want {
			t.Errorf("MatchDomain(%q)=%v want %v", name, got, want)
		}
	}
}

func TestIPv6PeerNetworkAndResources(t *testing.T) {
	// Synthetic dual-stack NetBird account: v4 and v6 peer addresses, a v6
	// route, a v6 domain-resource host route and a v6 default route.
	r := Compute(Input{
		NetBirdIP:   "10.99.1.5/23",
		NetBirdIPv6: "fd99:1234:5678:9abc::5/64",
		Networks:    []string{"2001:db8:10::/48", "::/0", "wiki.example.internal"},
		Learned:     []netip.Prefix{netip.MustParsePrefix("2001:db8:10::7/128"), netip.MustParsePrefix("2001:db8:20::7/128")},
	})
	want := []string{"10.99.0.0/23", "2001:db8:10::/48", "2001:db8:20::7/128", "fd99:1234:5678:9abc::/64"}
	if got := strs(r); !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	origin := map[string]Origin{}
	for _, e := range r.Entries {
		origin[e.Prefix.String()] = e.Origin
	}
	if origin["fd99:1234:5678:9abc::/64"] != OriginPeerNetwork || origin["2001:db8:20::7/128"] != OriginDomain {
		t.Errorf("origins %v", origin)
	}
	if len(r.Warnings) != 0 {
		t.Errorf("warnings %v", r.Warnings)
	}
	// ::/0 is only taken with the exit-node option.
	if slices.Contains(strs(r), "::/0") {
		t.Error("default v6 route advertised without BS_ADVERTISE_EXIT_NODE")
	}
}

func TestIPv6PeerAddressEdgeCases(t *testing.T) {
	// No prefix length: advertise the single address and warn.
	r := Compute(Input{NetBirdIP: "10.99.1.5/23", NetBirdIPv6: "fd99::5"})
	if got := strs(r); !slices.Contains(got, "fd99::5/128") || len(r.Warnings) != 1 {
		t.Errorf("got %v warnings %v", got, r.Warnings)
	}
	// A v4 address in the v6 field is ignored with a warning.
	r = Compute(Input{NetBirdIP: "10.99.1.5/23", NetBirdIPv6: "10.1.1.1/24"})
	if got := strs(r); !slices.Equal(got, []string{"10.99.0.0/23"}) || len(r.Warnings) != 1 {
		t.Errorf("got %v warnings %v", got, r.Warnings)
	}
	// BS_ROUTES override is the whole answer, v6 included.
	r = Compute(Input{NetBirdIP: "10.99.1.5/23", NetBirdIPv6: "fd99::5/64", Override: []netip.Prefix{netip.MustParsePrefix("2001:db8::1/32")}})
	if got := strs(r); !slices.Equal(got, []string{"2001:db8::/32"}) {
		t.Errorf("override: %v", got)
	}
}
