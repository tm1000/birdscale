package config

import (
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := Load(env(map[string]string{"NB_MANAGEMENT_URL": "https://nb.example.internal:443"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.TSHostname != "birdscale" || c.TSPort != 41641 || c.NBPort != 51820 || c.TSNetfilterMode != "off" {
		t.Errorf("bad defaults: %+v", c)
	}
	if c.WebUIPort != 0 || c.AdvertiseExitNode || c.LogLevel != slog.LevelInfo || c.HealthPort != DefaultHealthPort {
		t.Errorf("bad defaults: %+v", c)
	}
}

func TestFull(t *testing.T) {
	c, err := Load(env(map[string]string{
		"NB_MANAGEMENT_URL":      "https://nb.example.internal",
		"TS_TAGS":                "tag:birdscale, tag:other",
		"TS_NETFILTER_MODE":      "NODIVERT",
		"BS_ROUTES":              "10.99.0.0/23, 192.0.2.7, 10.99.0.5/23",
		"BS_ADVERTISE_EXIT_NODE": "true",
		"BS_WEBUI_PORT":          "8080",
		"BS_WEBUI_ALLOW":         "alice@example.internal,tag:admin",
		"BS_LOG_LEVEL":           "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TSTags) != 2 || c.TSNetfilterMode != "nodivert" || !c.AdvertiseExitNode || c.WebUIPort != 8080 || c.LogLevel != slog.LevelDebug {
		t.Errorf("unexpected: %+v", c)
	}
	want := []string{"10.99.0.0/23", "192.0.2.7/32", "10.99.0.0/23"}
	for i, p := range c.Routes {
		if p.String() != want[i] {
			t.Errorf("route %d = %s, want %s", i, p, want[i])
		}
	}
}

func TestInvalid(t *testing.T) {
	_, err := Load(env(map[string]string{
		"TS_TAGS":                "birdscale",
		"TS_NETFILTER_MODE":      "maybe",
		"TS_PORT":                "70000",
		"NB_PORT":                "abc",
		"BS_ROUTES":              "nonsense",
		"BS_ADVERTISE_EXIT_NODE": "perhaps",
		"BS_WEBUI_ALLOW":         "bob",
		"BS_LOG_LEVEL":           "loud",
	}))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, s := range []string{"NB_MANAGEMENT_URL is required", "TS_TAGS", "TS_NETFILTER_MODE", "TS_PORT", "NB_PORT", "BS_ROUTES", "BS_ADVERTISE_EXIT_NODE", "BS_WEBUI_ALLOW", "BS_LOG_LEVEL"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error missing %q:\n%v", s, err)
		}
	}
}

func TestBadURL(t *testing.T) {
	if _, err := Load(env(map[string]string{"NB_MANAGEMENT_URL": "nb.example.internal"})); err == nil {
		t.Fatal("expected error for URL without scheme")
	}
}

func TestRedactedHidesSecrets(t *testing.T) {
	c, err := Load(env(map[string]string{
		"NB_MANAGEMENT_URL": "https://nb.example.internal",
		"TS_AUTHKEY":        "tskey-auth-SECRET",
		"NB_SETUP_KEY":      "SETUPSECRET",
	}))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(func() (o []string) {
		for _, v := range c.Redacted() {
			o = append(o, strings.TrimSpace(fmtAny(v)))
		}
		return
	}(), " ")
	if strings.Contains(s, "SECRET") {
		t.Errorf("secret leaked: %s", s)
	}
}

func fmtAny(v any) string {
	switch x := v.(type) {
	case string:
		return x
	default:
		return ""
	}
}

func TestPhase23Defaults(t *testing.T) {
	c, err := Load(env(map[string]string{"NB_MANAGEMENT_URL": "https://nb.example.internal:443"}))
	if err != nil {
		t.Fatal(err)
	}
	if !c.DNSEnabled || len(c.DNSDomains) != 0 || c.DNSRouteWait != 1500*time.Millisecond ||
		c.DomainRefresh != 5*time.Minute || c.SessionWarn != 24*time.Hour {
		t.Errorf("defaults: %+v", c)
	}
}

func TestPhase23Values(t *testing.T) {
	c, err := Load(env(map[string]string{
		"NB_MANAGEMENT_URL": "https://nb.example.internal:443",
		"BS_DNS":            "true",
		"BS_DNS_DOMAINS":    "Example.Internal., .corp.test, *.lab.test",
		"BS_DNS_ROUTE_WAIT": "0",
		"BS_DOMAIN_REFRESH": "30s",
		"BS_SESSION_WARN":   "48h",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.DNSDomains, []string{"example.internal", "corp.test", "lab.test"}) ||
		c.DNSRouteWait != 0 || c.DomainRefresh != 30*time.Second || c.SessionWarn != 48*time.Hour {
		t.Errorf("values: %+v", c)
	}
}

func TestPhase23Invalid(t *testing.T) {
	base := map[string]string{"NB_MANAGEMENT_URL": "https://nb.example.internal:443"}
	for name, kv := range map[string][2]string{
		"BS_DNS":            {"BS_DNS", "maybe"},
		"BS_DNS_DOMAINS":    {"BS_DNS_DOMAINS", "bad domain!"},
		"BS_DNS_ROUTE_WAIT": {"BS_DNS_ROUTE_WAIT", "5"},
		"route wait range":  {"BS_DNS_ROUTE_WAIT", "5m"},
		"BS_DOMAIN_REFRESH": {"BS_DOMAIN_REFRESH", "1s"},
		"BS_SESSION_WARN":   {"BS_SESSION_WARN", "-1h"},
	} {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		m[kv[0]] = kv[1]
		if _, err := Load(env(m)); err == nil {
			t.Errorf("%s: %s=%q accepted", name, kv[0], kv[1])
		}
	}
	_, err := Load(env(map[string]string{"NB_MANAGEMENT_URL": "https://nb.example.internal:443", "BS_DNS": "false", "BS_DNS_DOMAINS": "example.internal"}))
	if err == nil || !strings.Contains(err.Error(), "BS_DNS_DOMAINS") {
		t.Errorf("BS_DNS_DOMAINS with BS_DNS=false: %v", err)
	}
}

func TestOAuthSecretNeedsTags(t *testing.T) {
	base := map[string]string{"NB_MANAGEMENT_URL": "https://nb.example.internal", "TS_AUTHKEY": "tskey-client-XXXX?ephemeral=false&preauthorized=true"}
	_, err := Load(env(base))
	if err == nil || !strings.Contains(err.Error(), "requires TS_TAGS") {
		t.Fatalf("want a TS_TAGS error, got %v", err)
	}
	if strings.Contains(err.Error(), "XXXX") {
		t.Errorf("secret leaked in error: %v", err)
	}
	base["TS_TAGS"] = "tag:birdscale"
	c, err := Load(env(base))
	if err != nil {
		t.Fatal(err)
	}
	if c.TSAuthKey != base["TS_AUTHKEY"] {
		t.Errorf("query parameters must be kept intact: %q", c.TSAuthKey)
	}
}
