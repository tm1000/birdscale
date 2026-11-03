// Package nft owns birdscale's nftables table, `inet birdscale`.
//
// The ruleset is a port of the Phase 0 spike's forward.sh plus an input chain that
// is scoped to the tailscale and netbird interfaces only. Rules match on
// interface names (iifname/oifname), so the table loads fine while wt0 does not
// exist yet (NetBird logged out). NetBird's own iptables rules are left alone.
package nft

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"text/template"
)

// Table is the nftables table name (family inet).
const Table = "birdscale"

// Params selects the interface names used in the ruleset.
type Params struct {
	TSIface string
	NBIface string
	Table   string
	// WebPort, when non-zero, is accepted on TSIface (the status page).
	WebPort int
	// DNS accepts DNS (53 udp/tcp) on TSIface (the forwarder).
	DNS bool
}

var ruleset = template.Must(template.New("nft").Parse(`# add + delete + re-create in ONE transaction: idempotent and atomic.
add table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct state invalid drop
    iifname "{{.TSIface}}" oifname "{{.NBIface}}" counter accept comment "tailnet -> netbird"
    iifname "{{.NBIface}}" oifname "{{.TSIface}}" ct state established,related counter accept comment "replies only"
    iifname { "{{.TSIface}}", "{{.NBIface}}" } oifname { "{{.TSIface}}", "{{.NBIface}}" } counter drop comment "everything else between the two"
  }
  # INPUT: only traffic arriving on the two tunnel interfaces is filtered.
  # eth0, lo and everything else fall through untouched (policy accept, and no
  # rule here matches them), so the daemons' own UDP ports on the host side
  # and the container's loopback health check are unaffected.
  chain input {
    type filter hook input priority filter; policy accept;
    iifname { "{{.TSIface}}", "{{.NBIface}}" } ct state established,related counter accept comment "input: established"
    iifname { "{{.TSIface}}", "{{.NBIface}}" } ct state invalid counter drop comment "input: invalid"
    iifname { "{{.TSIface}}", "{{.NBIface}}" } meta l4proto { icmp, ipv6-icmp } counter accept comment "input: icmp"
{{- if .WebPort}}
    iifname "{{.TSIface}}" tcp dport {{.WebPort}} ct state new counter accept comment "input: status page"
{{- end}}
{{- if .DNS}}
    iifname "{{.TSIface}}" udp dport 53 counter accept comment "input: dns udp"
    iifname "{{.TSIface}}" tcp dport 53 ct state new counter accept comment "input: dns tcp"
{{- end}}
    iifname { "{{.TSIface}}", "{{.NBIface}}" } counter drop comment "input: drop other new inbound"
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "{{.NBIface}}" counter masquerade comment "SNAT to the bridge's netbird IP"
  }
  chain mss {
    type filter hook forward priority mangle; policy accept;
    oifname { "{{.TSIface}}", "{{.NBIface}}" } tcp flags & (syn | rst) == syn counter tcp option maxseg size set rt mtu comment "clamp MSS to PMTU"
  }
}
`))

// Render returns the nft script for p. Interface names are validated, since
// they are interpolated into the script.
func Render(p Params) (string, error) {
	if p.Table == "" {
		p.Table = Table
	}
	for _, n := range []string{p.TSIface, p.NBIface, p.Table} {
		if !validName(n) {
			return "", fmt.Errorf("invalid nft name %q", n)
		}
	}
	if p.WebPort < 0 || p.WebPort > 65535 {
		return "", fmt.Errorf("invalid web port %d", p.WebPort)
	}
	var b bytes.Buffer
	if err := ruleset.Execute(&b, p); err != nil {
		return "", err
	}
	return b.String(), nil
}

func validName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

// Runner executes `nft args...` with stdin and returns stdout. Replaceable in tests.
type Runner func(ctx context.Context, stdin string, args ...string) ([]byte, error)

func execRunner(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "nft", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return out.Bytes(), nil
}

// Manager applies, inspects and removes the table.
type Manager struct {
	P   Params
	Run Runner
}

// New returns a Manager that shells out to nft.
func New(p Params) *Manager {
	if p.Table == "" {
		p.Table = Table
	}
	return &Manager{P: p, Run: execRunner}
}

// Apply atomically (re)installs the table.
func (m *Manager) Apply(ctx context.Context) error {
	s, err := Render(m.P)
	if err != nil {
		return err
	}
	_, err = m.Run(ctx, s, "-f", "-")
	return err
}

// Present reports whether the table exists.
func (m *Manager) Present(ctx context.Context) bool {
	_, err := m.Run(ctx, "", "list", "table", "inet", m.P.Table)
	return err == nil
}

// Remove deletes the table; a missing table is not an error.
func (m *Manager) Remove(ctx context.Context) error {
	if !m.Present(ctx) {
		return nil
	}
	_, err := m.Run(ctx, "", "delete", "table", "inet", m.P.Table)
	return err
}

// RuleCounter is one rule's comment and packet/byte counters.
type RuleCounter struct {
	Chain   string `json:"chain"`
	Comment string `json:"comment"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Counters returns the counters of every rule that has a counter expression.
func (m *Manager) Counters(ctx context.Context) ([]RuleCounter, error) {
	out, err := m.Run(ctx, "", "-j", "list", "table", "inet", m.P.Table)
	if err != nil {
		return nil, err
	}
	return ParseCounters(out)
}

// ParseCounters extracts rule counters from `nft -j list table` output.
func ParseCounters(js []byte) ([]RuleCounter, error) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Chain   string `json:"chain"`
				Comment string `json:"comment"`
				Expr    []struct {
					Counter *struct {
						Packets uint64 `json:"packets"`
						Bytes   uint64 `json:"bytes"`
					} `json:"counter"`
				} `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	var rc []RuleCounter
	for _, item := range doc.Nftables {
		if item.Rule == nil {
			continue
		}
		for _, e := range item.Rule.Expr {
			if e.Counter != nil {
				rc = append(rc, RuleCounter{Chain: item.Rule.Chain, Comment: item.Rule.Comment, Packets: e.Counter.Packets, Bytes: e.Counter.Bytes})
				break
			}
		}
	}
	return rc, nil
}
