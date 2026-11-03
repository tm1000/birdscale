package nft

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	s, err := Render(Params{TSIface: "tailscale0", NBIface: "wt0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"add table inet birdscale\ndelete table inet birdscale\ntable inet birdscale {",
		"type filter hook forward priority filter; policy accept;",
		"ct state invalid drop",
		`iifname "tailscale0" oifname "wt0" counter accept comment "tailnet -> netbird"`,
		`iifname "wt0" oifname "tailscale0" ct state established,related counter accept`,
		`iifname { "tailscale0", "wt0" } oifname { "tailscale0", "wt0" } counter drop`,
		"type nat hook postrouting priority srcnat; policy accept;",
		`oifname "wt0" counter masquerade`,
		"type filter hook forward priority mangle; policy accept;",
		"tcp flags & (syn | rst) == syn counter tcp option maxseg size set rt mtu",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered ruleset missing %q\n%s", want, s)
		}
	}
}

func TestRenderRejectsBadNames(t *testing.T) {
	for _, n := range []string{"", `wt0"; drop`, "waytoolonginterfacename", "a b"} {
		if _, err := Render(Params{TSIface: "tailscale0", NBIface: n}); err == nil {
			t.Errorf("name %q accepted", n)
		}
	}
}

func TestApplyAndRemove(t *testing.T) {
	var calls [][]string
	var stdins []string
	present := true
	m := &Manager{P: Params{TSIface: "tailscale0", NBIface: "wt0", Table: Table}, Run: func(_ context.Context, in string, a ...string) ([]byte, error) {
		calls = append(calls, a)
		stdins = append(stdins, in)
		if a[0] == "list" && !present {
			return nil, errors.New("no such table")
		}
		return nil, nil
	}}
	if err := m.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(calls[0], " ") != "-f -" || !strings.Contains(stdins[0], "masquerade") {
		t.Errorf("apply call wrong: %v", calls)
	}
	if err := m.Remove(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := strings.Join(calls[len(calls)-1], " "); last != "delete table inet birdscale" {
		t.Errorf("last call %q", last)
	}
	present = false
	n := len(calls)
	if err := m.Remove(context.Background()); err != nil || len(calls) != n+1 {
		t.Errorf("remove of missing table should only probe: err=%v calls=%v", err, calls[n:])
	}
}

func TestParseCounters(t *testing.T) {
	js := `{"nftables":[{"metainfo":{"version":"1.1.3"}},{"table":{"family":"inet","name":"birdscale"}},
	{"rule":{"family":"inet","table":"birdscale","chain":"forward","expr":[{"match":{}},{"counter":{"packets":12,"bytes":3400}},{"accept":null}],"comment":"tailnet -> netbird"}},
	{"rule":{"family":"inet","table":"birdscale","chain":"forward","expr":[{"match":{}},{"drop":null}]}}]}`
	rc, err := ParseCounters([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(rc) != 1 || rc[0].Packets != 12 || rc[0].Bytes != 3400 || rc[0].Comment != "tailnet -> netbird" || rc[0].Chain != "forward" {
		t.Errorf("got %+v", rc)
	}
}

func TestRenderInputChain(t *testing.T) {
	s, err := Render(Params{TSIface: "tailscale0", NBIface: "wt0", WebPort: 8080, DNS: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"chain input {\n    type filter hook input priority filter; policy accept;",
		`iifname { "tailscale0", "wt0" } ct state established,related counter accept`,
		`iifname { "tailscale0", "wt0" } ct state invalid counter drop`,
		`iifname { "tailscale0", "wt0" } meta l4proto { icmp, ipv6-icmp } counter accept`,
		`iifname "tailscale0" tcp dport 8080 ct state new counter accept`,
		`iifname "tailscale0" udp dport 53 counter accept`,
		`iifname "tailscale0" tcp dport 53 ct state new counter accept`,
		`iifname { "tailscale0", "wt0" } counter drop comment "input: drop other new inbound"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q\n%s", want, s)
		}
	}
	in := inputChain(t, s)
	// Every rule in the input chain must be scoped to the tunnel interfaces.
	for _, line := range strings.Split(in, "\n")[2:] {
		line = strings.TrimSpace(line)
		if line == "" || line == "}" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "iifname ") {
			t.Errorf("input rule without iifname scope: %q", line)
		}
		if strings.Contains(line, "eth0") || strings.Contains(line, `"lo"`) {
			t.Errorf("input rule names another interface: %q", line)
		}
	}
	// wt0 never gets the service accepts.
	for _, line := range strings.Split(in, "\n") {
		if strings.Contains(line, "dport") && !strings.Contains(line, `iifname "tailscale0"`) {
			t.Errorf("service port accepted on a non-tailscale interface: %q", line)
		}
	}
	// The drop is the last rule.
	lines := strings.Split(strings.TrimSpace(in), "\n")
	if !strings.Contains(lines[len(lines)-2], "counter drop") {
		t.Errorf("last input rule is not the drop: %q", lines[len(lines)-2])
	}
}

func TestRenderInputChainOptional(t *testing.T) {
	s, err := Render(Params{TSIface: "tailscale0", NBIface: "wt0"})
	if err != nil {
		t.Fatal(err)
	}
	in := inputChain(t, s)
	if strings.Contains(in, "dport") {
		t.Errorf("no service ports expected when web and DNS are off:\n%s", in)
	}
	if !strings.Contains(in, "drop other new inbound") {
		t.Error("default drop missing")
	}
	s, _ = Render(Params{TSIface: "tailscale0", NBIface: "wt0", WebPort: 9000})
	in = inputChain(t, s)
	if !strings.Contains(in, "tcp dport 9000") || strings.Contains(in, "dport 53") {
		t.Errorf("web-only chain wrong:\n%s", in)
	}
}

func inputChain(t *testing.T, s string) string {
	t.Helper()
	i := strings.Index(s, "  chain input {")
	j := strings.Index(s, "  chain postrouting {")
	if i < 0 || j < i {
		t.Fatalf("no input chain:\n%s", s)
	}
	return s[i:j]
}

// The table is family inet and no rule is IPv4-specific, so the same forward,
// SNAT, MSS and input rules apply to IPv6 when NetBird provides it.
func TestRulesAreFamilyAgnostic(t *testing.T) {
	s, err := Render(Params{TSIface: "tailscale0", NBIface: "wt0", WebPort: 8080, DNS: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, "table inet birdscale") {
		t.Error("table must be family inet")
	}
	for _, line := range strings.Split(s, "\n") {
		for _, bad := range []string{"ip saddr", "ip daddr", "ip protocol", "ip6 ", "icmpv6 type", "nfproto"} {
			if strings.Contains(line, bad) {
				t.Errorf("family-specific match %q in: %s", bad, line)
			}
		}
	}
	for _, want := range []string{
		`oifname "wt0" counter masquerade`,
		"tcp option maxseg size set rt mtu",
		"ipv6-icmp", // ND and PMTUD must pass on the tunnel interfaces
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
}
