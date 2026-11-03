// Package config loads and validates birdscaled's environment configuration.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Fixed interface names. The nftables rules, the tailscaled flags and the
// NetBird client all agree on these.
const (
	TSIface = "tailscale0"
	NBIface = "wt0"
)

// DefaultHealthPort is the loopback port for /healthz when BS_HEALTH_PORT is unset.
const DefaultHealthPort = 9180

// Config is the validated process configuration. Never log it with %v; use
// Redacted for a loggable form.
type Config struct {
	// Tailscale.
	TSAuthKey       string // secret
	TSHostname      string
	TSTags          []string
	TSLoginServer   string
	TSPort          int
	TSNetfilterMode string // off | nodivert | on

	// NetBird.
	NBManagementURL string
	NBSetupKey      string // secret
	NBHostname      string
	NBPort          int

	// Bridge.
	Routes            []netip.Prefix // BS_ROUTES override; nil = compute from NetBird
	AdvertiseExitNode bool
	WebUIPort         int // 0 = disabled
	WebUIAllow        []string
	HealthPort        int
	LogLevel          slog.Level

	// DNS forwarder (BS_DNS*). Binds port 53 on the bridge's Tailscale IPs.
	DNSEnabled   bool
	DNSDomains   []string      // normalized suffixes; empty = forward everything
	DNSRouteWait time.Duration // max wait for a route before replying; 0 = no wait

	// DomainRefresh is how often domain resources are re-resolved (0 = only at
	// startup and when the list changes).
	DomainRefresh time.Duration
	// SessionWarn warns when the NetBird SSO session expires within this long (0 = never).
	SessionWarn time.Duration
}

// Load reads configuration from getenv (os.Getenv in production) and returns
// every validation problem at once.
func Load(getenv func(string) string) (*Config, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }

	c := &Config{
		TSAuthKey:       get("TS_AUTHKEY"),
		TSHostname:      get("TS_HOSTNAME"),
		TSLoginServer:   get("TS_LOGIN_SERVER"),
		TSNetfilterMode: strings.ToLower(get("TS_NETFILTER_MODE")),
		NBManagementURL: get("NB_MANAGEMENT_URL"),
		NBSetupKey:      get("NB_SETUP_KEY"),
		NBHostname:      get("NB_HOSTNAME"),
	}
	if c.TSHostname == "" {
		c.TSHostname = "birdscale"
	}
	if c.TSNetfilterMode == "" {
		c.TSNetfilterMode = "off"
	}
	switch c.TSNetfilterMode {
	case "off", "nodivert", "on":
	default:
		bad("TS_NETFILTER_MODE=%q: must be off, nodivert or on", c.TSNetfilterMode)
	}

	for _, t := range splitList(get("TS_TAGS")) {
		if !strings.HasPrefix(t, "tag:") || len(t) <= len("tag:") {
			bad("TS_TAGS: %q is not of the form tag:name", t)
			continue
		}
		c.TSTags = append(c.TSTags, t)
	}
	if strings.HasPrefix(c.TSAuthKey, "tskey-client-") && len(c.TSTags) == 0 {
		// `tailscale up` exchanges an OAuth client secret for an auth key and
		// refuses to do so without --advertise-tags.
		bad("TS_AUTHKEY is an OAuth client secret (tskey-client-...), which requires TS_TAGS (e.g. tag:birdscale)")
	}
	if c.TSLoginServer != "" {
		if err := checkURL(c.TSLoginServer); err != nil {
			bad("TS_LOGIN_SERVER: %v", err)
		}
	}

	if c.NBManagementURL == "" {
		bad("NB_MANAGEMENT_URL is required (e.g. https://api.netbird.io:443)")
	} else if err := checkURL(c.NBManagementURL); err != nil {
		bad("NB_MANAGEMENT_URL: %v", err)
	}

	var err error
	if c.TSPort, err = port(get("TS_PORT"), 41641, false); err != nil {
		bad("TS_PORT: %v", err)
	}
	if c.NBPort, err = port(get("NB_PORT"), 51820, false); err != nil {
		bad("NB_PORT: %v", err)
	}
	if c.WebUIPort, err = port(get("BS_WEBUI_PORT"), 0, true); err != nil {
		bad("BS_WEBUI_PORT: %v", err)
	}
	if c.HealthPort, err = port(get("BS_HEALTH_PORT"), DefaultHealthPort, false); err != nil {
		bad("BS_HEALTH_PORT: %v", err)
	}

	if v := get("BS_ADVERTISE_EXIT_NODE"); v != "" {
		if c.AdvertiseExitNode, err = strconv.ParseBool(v); err != nil {
			bad("BS_ADVERTISE_EXIT_NODE=%q: not a boolean", v)
		}
	}

	for _, r := range splitList(get("BS_ROUTES")) {
		p, err := ParsePrefix(r)
		if err != nil {
			bad("BS_ROUTES: %v", err)
			continue
		}
		c.Routes = append(c.Routes, p)
	}

	c.WebUIAllow = splitList(get("BS_WEBUI_ALLOW"))
	if c.WebUIPort == 0 && len(c.WebUIAllow) > 0 {
		bad("BS_WEBUI_ALLOW is set but BS_WEBUI_PORT is not: the web page is disabled")
	}

	c.DNSEnabled = true
	if v := get("BS_DNS"); v != "" {
		if c.DNSEnabled, err = strconv.ParseBool(v); err != nil {
			bad("BS_DNS=%q: not a boolean", v)
		}
	}
	for _, d := range splitList(get("BS_DNS_DOMAINS")) {
		n, err := dnsSuffix(d)
		if err != nil {
			bad("BS_DNS_DOMAINS: %v", err)
			continue
		}
		c.DNSDomains = append(c.DNSDomains, n)
	}
	if len(c.DNSDomains) > 0 && !c.DNSEnabled {
		bad("BS_DNS_DOMAINS is set but BS_DNS is false: the DNS forwarder is disabled")
	}
	if c.DNSRouteWait, err = duration(get("BS_DNS_ROUTE_WAIT"), 1500*time.Millisecond, 0, 30*time.Second); err != nil {
		bad("BS_DNS_ROUTE_WAIT: %v", err)
	}
	if c.DomainRefresh, err = duration(get("BS_DOMAIN_REFRESH"), 5*time.Minute, 0, 24*time.Hour); err != nil {
		bad("BS_DOMAIN_REFRESH: %v", err)
	} else if c.DomainRefresh > 0 && c.DomainRefresh < 10*time.Second {
		bad("BS_DOMAIN_REFRESH=%s: must be 0 (off) or at least 10s", c.DomainRefresh)
	}
	if c.SessionWarn, err = duration(get("BS_SESSION_WARN"), 24*time.Hour, 0, 90*24*time.Hour); err != nil {
		bad("BS_SESSION_WARN: %v", err)
	}

	c.LogLevel = slog.LevelInfo
	if v := strings.ToLower(get("BS_LOG_LEVEL")); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			bad("BS_LOG_LEVEL=%q: must be debug, info, warn or error", v)
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// Redacted returns key=value pairs safe to log: secrets appear only as set/unset.
func (c *Config) Redacted() []any {
	set := func(s string) string {
		if s == "" {
			return "unset"
		}
		return "set"
	}
	return []any{
		"ts_authkey", set(c.TSAuthKey),
		"ts_hostname", c.TSHostname,
		"ts_tags", strings.Join(c.TSTags, ","),
		"ts_login_server", c.TSLoginServer,
		"ts_port", c.TSPort,
		"ts_netfilter_mode", c.TSNetfilterMode,
		"nb_management_url", c.NBManagementURL,
		"nb_setup_key", set(c.NBSetupKey),
		"nb_hostname", c.NBHostname,
		"nb_port", c.NBPort,
		"bs_routes_override", len(c.Routes),
		"bs_advertise_exit_node", c.AdvertiseExitNode,
		"bs_webui_port", c.WebUIPort,
		"bs_webui_allow", strings.Join(c.WebUIAllow, ","),
		"bs_health_port", c.HealthPort,
		"bs_log_level", c.LogLevel.String(),
		"bs_dns", c.DNSEnabled,
		"bs_dns_domains", strings.Join(c.DNSDomains, ","),
		"bs_dns_route_wait", c.DNSRouteWait.String(),
		"bs_domain_refresh", c.DomainRefresh.String(),
		"bs_session_warn", c.SessionWarn.String(),
	}
}

// ParsePrefix parses a CIDR or a bare IP (/32 or /128) and masks host bits.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q is not a valid CIDR or IP", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func port(s string, def int, allowZero bool) (int, error) {
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > 65535 || n < 0 || (n == 0 && !allowZero) {
		return 0, fmt.Errorf("%q is not a valid port (1-65535)", s)
	}
	return n, nil
}

func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%q must be an http(s) URL with a host", s)
	}
	return nil
}

// dnsSuffix validates and normalizes one BS_DNS_DOMAINS entry: lower-case, no
// trailing dot, a leading "." or "*." is accepted and dropped.
func dnsSuffix(s string) (string, error) {
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	n = strings.TrimPrefix(strings.TrimPrefix(n, "*"), ".")
	if n == "" || len(n) > 253 || strings.Contains(n, "..") {
		return "", fmt.Errorf("%q is not a valid domain suffix", s)
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return "", fmt.Errorf("%q is not a valid domain suffix", s)
		}
	}
	return n, nil
}

// duration parses a Go duration ("1500ms", "5m"); a bare "0" is allowed.
func duration(s string, def, lo, hi time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a duration (e.g. 1500ms, 5m, 24h)", s)
	}
	if d < lo || d > hi {
		return 0, fmt.Errorf("%q is out of range (%s to %s)", s, lo, hi)
	}
	return d, nil
}
