package tailscale

import (
	"slices"
	"testing"

	"tailscale.com/ipn"
	"tailscale.com/types/preftype"
)

func TestDrift(t *testing.T) {
	want := PrefsWanted{Hostname: "birdscale", Tags: []string{"tag:b", "tag:a"}, NetfilterMode: "off"}
	ok := &ipn.Prefs{Hostname: "birdscale", AdvertiseTags: []string{"tag:a", "tag:b"}, NetfilterMode: preftype.NetfilterOff}
	if d := Drift(ok, want); len(d) != 0 {
		t.Errorf("unexpected drift %v", d)
	}
	bad := &ipn.Prefs{RouteAll: true, CorpDNS: true, Hostname: "x", NetfilterMode: preftype.NetfilterOn}
	d := Drift(bad, want)
	for _, f := range []string{"RouteAll", "CorpDNS", "NetfilterMode", "Hostname", "AdvertiseTags"} {
		if !slices.Contains(d, f) {
			t.Errorf("missing drift %s in %v", f, d)
		}
	}
}

func TestNetfilterMode(t *testing.T) {
	if m, err := NetfilterMode("nodivert"); err != nil || m != preftype.NetfilterNoDivert {
		t.Error("nodivert")
	}
	if _, err := NetfilterMode("bogus"); err == nil {
		t.Error("bogus accepted")
	}
}
