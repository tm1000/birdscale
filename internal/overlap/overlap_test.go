package overlap

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/tm1000/birdscale/internal/routes"
)

func TestDetect(t *testing.T) {
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	adv := []routes.Entry{
		{Prefix: p("100.90.0.0/16"), Origin: routes.OriginPeerNetwork},
		{Prefix: p("192.0.2.0/24"), Origin: routes.OriginCIDR},
		{Prefix: p("100.64.7.9/32"), Origin: routes.OriginDomain},
		{Prefix: p("0.0.0.0/0"), Origin: routes.OriginExitNode},
		{Prefix: p("::/0"), Origin: routes.OriginExitNode},
	}
	tailnet := []netip.Addr{a("100.64.1.1"), a("100.90.3.4"), a("100.90.200.1"), a("100.64.7.9"), a("fd7a:115c:a1e0::1"), a("::ffff:100.90.9.9")}
	hits := Detect(tailnet, adv)
	if len(hits) != 4 {
		t.Fatalf("hits: %+v", hits)
	}
	if hits[0].Addr != a("100.64.7.9") || hits[0].Origin != routes.OriginDomain {
		t.Errorf("first: %+v", hits[0])
	}
	msgs := Messages(hits)
	if len(msgs) != 2 || !strings.Contains(strings.Join(msgs, "|"), "100.90.3.4, 100.90.9.9, 100.90.200.1") {
		t.Errorf("messages: %v", msgs)
	}
	if Key(hits) == "" || Key(hits) != Key(Detect(tailnet, adv)) {
		t.Error("key must be stable and non-empty")
	}
}

func TestDetectNone(t *testing.T) {
	adv := []routes.Entry{{Prefix: netip.MustParsePrefix("10.99.0.0/23"), Origin: routes.OriginPeerNetwork}}
	if h := Detect([]netip.Addr{netip.MustParseAddr("100.64.1.1")}, adv); len(h) != 0 || Key(h) != "" {
		t.Errorf("unexpected hits %v", h)
	}
}

func TestDetectIPv6TailnetULA(t *testing.T) {
	p, a := netip.MustParsePrefix, netip.MustParseAddr
	// Tailscale's IPv6 range is fd7a:115c:a1e0::/48. A NetBird v6 route that
	// covers it (or sits inside it) overlaps.
	adv := []routes.Entry{
		{Prefix: p("fd00::/8"), Origin: routes.OriginCIDR},
		{Prefix: p("fd7a:115c:a1e0:ab12::/64"), Origin: routes.OriginPeerNetwork},
		{Prefix: p("2001:db8::/32"), Origin: routes.OriginCIDR},
		{Prefix: p("::/0"), Origin: routes.OriginExitNode},
	}
	tailnet := []netip.Addr{a("fd7a:115c:a1e0::1"), a("fd7a:115c:a1e0:ab12::7"), a("100.64.1.1"), a("2600:db8::1")}
	hits := Detect(tailnet, adv)
	if len(hits) != 3 {
		t.Fatalf("hits: %+v", hits)
	}
	msgs := strings.Join(Messages(hits), "|")
	for _, want := range []string{"fd7a:115c:a1e0::1", "fd7a:115c:a1e0:ab12::7", "fd00::/8", "fd7a:115c:a1e0:ab12::/64"} {
		if !strings.Contains(msgs, want) {
			t.Errorf("messages lack %q: %s", want, msgs)
		}
	}
	// A route outside the tailnet ULA does not overlap.
	if h := Detect(tailnet, adv[2:3]); len(h) != 0 {
		t.Errorf("unexpected hits %v", h)
	}
}
