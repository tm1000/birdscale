package rtwatch

import (
	"net/netip"
	"slices"
	"testing"
)

func TestHostRoutes(t *testing.T) {
	p := netip.MustParsePrefix
	got := HostRoutes([]Route{
		{p("203.0.113.9/32"), 7120, "wt0"},
		{p("203.0.113.9/32"), 7120, "wt0"}, // dup
		{p("2001:db8::9/128"), 7120, "wt0"},
		{p("192.0.2.0/24"), 7120, "wt0"},     // not a host route
		{p("203.0.113.10/32"), 254, "wt0"},   // wrong table
		{p("203.0.113.11/32"), 7120, "eth0"}, // wrong interface
		{netip.Prefix{}, 7120, "wt0"},        // invalid
		{p("198.51.100.4/32"), 7120, "wt0"},
	}, 7120, "wt0")
	want := []netip.Prefix{p("198.51.100.4/32"), p("203.0.113.9/32"), p("2001:db8::9/128")}
	if !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
}
