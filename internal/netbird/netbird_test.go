package netbird

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sample = `{"peers":{"total":2,"connected":1,"details":[
 {"fqdn":"peer1.example.internal","netbirdIp":"10.99.0.7","status":"Connected","connectionType":"P2P","lastWireguardHandshake":"2026-01-01T00:00:00Z","networks":["192.0.2.0/24","wiki.example.internal"]},
 {"fqdn":"peer2.example.internal","netbirdIp":"10.99.0.8","status":"Idle","connectionType":"Relayed","networks":null}]},
 "daemonStatus":"Connected","management":{"url":"https://nb.example.internal:443","connected":true,"error":""},
 "signal":{"url":"https://nb.example.internal:443","connected":true},"relays":{"total":1,"available":1,"details":[{"uri":"rels://relay.example.internal:443","available":true}]},
 "netbirdIp":"10.99.1.5/23","usesKernelInterface":true,"sessionExpiresAt":"2026-01-08T00:00:00Z"}
trailing text`

func TestParseStatus(t *testing.T) {
	s, err := ParseStatus([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Connected() || s.NetbirdIP != "10.99.1.5/23" || !s.Kernel || s.NeedsLogin() {
		t.Errorf("unexpected: %+v", s)
	}
	if n := s.Networks(); len(n) != 2 || n[1] != "wiki.example.internal" {
		t.Errorf("networks: %v", n)
	}
	if ex, ok := s.SessionExpiry(); !ok || ex.Year() != 2026 {
		t.Errorf("expiry: %v %v", ex, ok)
	}
}

func TestNeedsLogin(t *testing.T) {
	s, _ := ParseStatus([]byte(`{"daemonStatus":"NeedsLogin","management":{"connected":false},"sessionExpiresAt":"0001-01-01T00:00:00Z"}`))
	if !s.NeedsLogin() || s.Connected() {
		t.Error("should need login")
	}
	if _, ok := s.SessionExpiry(); ok {
		t.Error("zero time must count as unknown")
	}
}

func TestExtractURL(t *testing.T) {
	u, ok := ExtractURL("https://nb.example.internal/oauth2/device?user_code=ABCD-EFGH ")
	if !ok || u != "https://nb.example.internal/oauth2/device?user_code=ABCD-EFGH" {
		t.Errorf("got %q %v", u, ok)
	}
	if _, ok := ExtractURL("Use this URL to log in:"); ok {
		t.Error("no URL expected")
	}
}

func TestSessionAndResolver(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	mk := func(exp string) *Status {
		return &Status{NetbirdIP: "10.99.1.5/23", SessionExpiresAt: exp}
	}
	cases := []struct {
		exp  string
		warn time.Duration
		want SessionState
	}{
		{"", time.Hour, SessionUnknown},
		{"0001-01-01T00:00:00Z", time.Hour, SessionUnknown},
		{"2026-01-08T12:00:00Z", 24 * time.Hour, SessionOK},
		{"2026-01-02T11:00:00Z", 24 * time.Hour, SessionExpiring},
		{"2026-01-02T11:00:00Z", 0, SessionOK}, // warning disabled
		{"2026-01-01T11:00:00Z", 24 * time.Hour, SessionExpired},
	}
	for _, c := range cases {
		if got, _ := mk(c.exp).Session(now, c.warn); got != c.want {
			t.Errorf("exp=%q warn=%v: got %v want %v", c.exp, c.warn, got, c.want)
		}
	}
	// IPv6-only peer falls back to its v6 address; v4 wins when both exist.
	if got := (&Status{NetbirdIPv6: "fd99::5/64"}).ResolverAddr(); got != "[fd99::5]:53" {
		t.Errorf("v6 fallback: %q", got)
	}
	if got := (&Status{NetbirdIP: "10.99.1.5/23", NetbirdIPv6: "fd99::5/64"}).ResolverAddr(); got != "10.99.1.5:53" {
		t.Errorf("v4 first: %q", got)
	}
	if st, err := ParseStatus([]byte(`{"daemonStatus":"Connected","netbirdIp":"10.99.1.5/23","netbirdIpv6":"fd99::5/64"}`)); err != nil || st.NetbirdIPv6 != "fd99::5/64" {
		t.Errorf("netbirdIpv6 parse: %+v %v", st, err)
	}
	for ip, want := range map[string]string{"10.99.1.5/23": "10.99.1.5:53", "10.99.1.5": "10.99.1.5:53", "fd00::5/64": "[fd00::5]:53", "": "", "junk": ""} {
		if got := (&Status{NetbirdIP: ip}).ResolverAddr(); got != want {
			t.Errorf("ResolverAddr(%q)=%q want %q", ip, got, want)
		}
	}
}

// fakeBin writes a stand-in for the netbird CLI that records its argv and
// prints a device-flow URL, then (for `login --extend`) a result line.
func fakeBin(t *testing.T) (bin, argsFile string) {
	t.Helper()
	dir := t.TempDir()
	argsFile = filepath.Join(dir, "args")
	bin = filepath.Join(dir, "netbird")
	script := "#!/bin/sh\necho \"$@\" >> " + argsFile + "\n" +
		"echo 'Use this URL to log in:'\necho\necho 'https://nb.example.internal/device?code=ABCD-1234 '\n" +
		"if [ \"$1\" = login ]; then echo 'Session extended. New expiry: 2026-01-09 00:00:00 UTC'; fi\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, argsFile
}

func waitNotRunning(t *testing.T, l *Login) LoginState {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st := l.State(); !st.Running {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("login helper still running")
	return LoginState{}
}

func TestRenewChoosesFlow(t *testing.T) {
	bin, argsFile := fakeBin(t)
	l := &Login{Bin: bin, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Cfg: LoginConfig{ManagementURL: "https://nb.example.internal:443"}}
	ctx := context.Background()

	if _, err := l.Renew(ctx, nil); err == nil {
		t.Error("nil status accepted")
	}
	// Connected without an expiry (setup key): nothing to renew.
	setup := &Status{DaemonStatus: DaemonConnected, Management: Conn{Connected: true}}
	if _, err := l.Renew(ctx, setup); err == nil {
		t.Error("renewing a setup-key peer should fail")
	}
	// Connecting: neither flow applies.
	if _, err := l.Renew(ctx, &Status{DaemonStatus: DaemonConnecting}); err == nil {
		t.Error("renew while connecting should fail")
	}

	// Connected SSO peer: extend, tunnel untouched.
	sso := &Status{DaemonStatus: DaemonConnected, Management: Conn{Connected: true}, SessionExpiresAt: "2026-01-08T00:00:00Z"}
	mode, err := l.Renew(ctx, sso)
	if err != nil || mode != ModeExtend {
		t.Fatalf("mode=%q err=%v", mode, err)
	}
	// While extending on a live tunnel, Ensure must not cancel it or clear its URL.
	deadline := time.Now().Add(3 * time.Second)
	for l.State().URL == "" && l.State().Running && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	l.Ensure(ctx, sso)
	st := waitNotRunning(t, l)
	if st.LastErr != "" || st.LastResult != "Session extended. New expiry: 2026-01-09 00:00:00 UTC" || st.URL != "" {
		t.Errorf("after extend: %+v", st)
	}

	// Expired: recover with `up`, URL captured and kept.
	exp := &Status{DaemonStatus: DaemonSessionExpired}
	mode, err = l.Renew(ctx, exp)
	if err != nil || mode != ModeUp {
		t.Fatalf("mode=%q err=%v", mode, err)
	}
	waitNotRunning(t, l)
	if got := l.State().URL; got != "https://nb.example.internal/device?code=ABCD-1234" {
		t.Errorf("url %q", got)
	}

	b, _ := os.ReadFile(argsFile)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 || lines[0] != "login --extend --no-browser" ||
		!strings.HasPrefix(lines[1], "up --management-url https://nb.example.internal:443 --no-browser") {
		t.Errorf("argv: %q", lines)
	}
}
