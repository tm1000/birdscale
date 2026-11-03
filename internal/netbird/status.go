// Package netbird wraps the netbird CLI: status parsing and the login flow.
// It shells out to the CLI rather than importing the netbird module, which
// keeps the dependency tree small.
package netbird

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// Daemon status values reported by `netbird status --json` ("daemonStatus").
const (
	DaemonConnected      = "Connected"
	DaemonConnecting     = "Connecting"
	DaemonIdle           = "Idle"
	DaemonNeedsLogin     = "NeedsLogin"
	DaemonLoginFailed    = "LoginFailed"
	DaemonSessionExpired = "SessionExpired"
)

// Status is the subset of `netbird status --json` birdscale uses.
type Status struct {
	DaemonStatus string `json:"daemonStatus"`
	DaemonVer    string `json:"daemonVersion"`
	NetbirdIP    string `json:"netbirdIp"` // with prefix, e.g. 10.99.1.5/23
	// NetbirdIPv6 is only present when the NetBird account assigns IPv6 addresses.
	NetbirdIPv6 string `json:"netbirdIpv6"`
	FQDN        string `json:"fqdn"`
	Kernel      bool   `json:"usesKernelInterface"`
	WGPort      int    `json:"wireguardPort"`
	// SessionExpiresAt is the SSO session expiry (RFC 3339). It is only
	// present for SSO logins; setup-key peers have none.
	SessionExpiresAt string `json:"sessionExpiresAt"`

	Management Conn `json:"management"`
	Signal     Conn `json:"signal"`
	Relays     struct {
		Total     int `json:"total"`
		Available int `json:"available"`
		Details   []struct {
			URI       string `json:"uri"`
			Available bool   `json:"available"`
			Error     string `json:"error"`
		} `json:"details"`
	} `json:"relays"`
	Peers struct {
		Total     int    `json:"total"`
		Connected int    `json:"connected"`
		Details   []Peer `json:"details"`
	} `json:"peers"`
}

// Conn is a management or signal connection.
type Conn struct {
	URL       string `json:"url"`
	Connected bool   `json:"connected"`
	Error     string `json:"error"`
}

// Peer is one entry of peers.details.
type Peer struct {
	FQDN                   string   `json:"fqdn"`
	NetbirdIP              string   `json:"netbirdIp"`
	Status                 string   `json:"status"`
	ConnectionType         string   `json:"connectionType"` // P2P | Relayed
	RelayAddress           string   `json:"relayAddress"`
	LastWireguardHandshake string   `json:"lastWireguardHandshake"`
	Latency                int64    `json:"latency"` // nanoseconds
	TransferReceived       int64    `json:"transferReceived"`
	TransferSent           int64    `json:"transferSent"`
	Networks               []string `json:"networks"`
}

// ParseStatus decodes `netbird status --json` output. The CLI may print
// trailing text after the JSON document; only the first value is decoded.
func ParseStatus(b []byte) (*Status, error) {
	var s Status
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&s); err != nil {
		return nil, fmt.Errorf("parse netbird status: %w", err)
	}
	return &s, nil
}

// Networks returns every received network string from all peers (CIDRs, bare
// IPs and domain names alike), in order.
func (s *Status) Networks() []string {
	var out []string
	for _, p := range s.Peers.Details {
		out = append(out, p.Networks...)
	}
	return out
}

// Connected reports whether the daemon is logged in and management is up.
func (s *Status) Connected() bool {
	return s.DaemonStatus == DaemonConnected && s.Management.Connected
}

// NeedsLogin reports whether the daemon is waiting for a (re)login.
func (s *Status) NeedsLogin() bool {
	switch s.DaemonStatus {
	case DaemonNeedsLogin, DaemonLoginFailed, DaemonSessionExpired, DaemonIdle:
		return true
	}
	return false
}

// SessionExpiry returns the SSO session expiry, if known.
func (s *Status) SessionExpiry() (time.Time, bool) {
	if s.SessionExpiresAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s.SessionExpiresAt)
	if err != nil || t.IsZero() || t.Year() < 2000 {
		return time.Time{}, false
	}
	return t, true
}

// SessionState describes the SSO session relative to a warning window.
type SessionState int

// SessionState values.
const (
	SessionUnknown SessionState = iota // no expiry reported (setup key, or expiry disabled)
	SessionOK
	SessionExpiring // expires within the warning window
	SessionExpired  // expiry has passed
)

// Session reports the SSO session state at now. warn <= 0 never reports SessionExpiring.
func (s *Status) Session(now time.Time, warn time.Duration) (SessionState, time.Duration) {
	ex, ok := s.SessionExpiry()
	if !ok {
		return SessionUnknown, 0
	}
	left := ex.Sub(now)
	switch {
	case left <= 0:
		return SessionExpired, left
	case warn > 0 && left <= warn:
		return SessionExpiring, left
	}
	return SessionOK, left
}

// ResolverAddr is NetBird's own resolver: the peer's NetBird IP, port 53.
// Empty when the peer has no address yet.
func (s *Status) ResolverAddr() string {
	// IPv4 first (NetBird's resolver listens on it); an IPv6-only peer uses its v6 address.
	for _, ip := range []string{s.NetbirdIP, s.NetbirdIPv6} {
		ip = strings.TrimSpace(ip)
		if i := strings.IndexByte(ip, '/'); i >= 0 {
			ip = ip[:i]
		}
		if a, err := netip.ParseAddr(ip); err == nil {
			return net.JoinHostPort(a.Unmap().String(), "53")
		}
	}
	return ""
}

// Client runs the netbird CLI.
type Client struct {
	Bin string // default "netbird"
}

func (c *Client) bin() string {
	if c.Bin == "" {
		return "netbird"
	}
	return c.Bin
}

// Status runs `netbird status --json`.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.bin(), "status", "--json")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("netbird status: %w: %s", err, strings.TrimSpace(errb.String()))
	}
	return ParseStatus(out.Bytes())
}
