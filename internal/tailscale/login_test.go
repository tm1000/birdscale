package tailscale

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

// An OAuth client secret with ?query parameters must reach `tailscale up`
// byte for byte through the "file:" auth-key file (tailscale resolves file:
// before it exchanges tskey-client- secrets), and never appear in argv.
func TestLoginPassesOAuthSecretViaFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "got")
	argv := filepath.Join(dir, "argv")
	fake := filepath.Join(dir, "tailscale")
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > " + argv + "\n" +
		"for a in \"$@\"; do case \"$a\" in --auth-key=file:*) cp \"${a#--auth-key=file:}\" " + out + " ;; esac; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	const secret = "tskey-client-XXXX?ephemeral=false&preauthorized=true"
	l := &Login{
		Cfg: LoginConfig{AuthKey: secret, Hostname: "birdscale", Tags: []string{"tag:birdscale"}, NetfilterMode: "off", Socket: "/nonexistent"},
		Bin: fake, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	l.start(context.Background())
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && l.State().Running {
		time.Sleep(10 * time.Millisecond)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret {
		t.Errorf("file holds %q, want the full secret with its query", got)
	}
	args, _ := os.ReadFile(argv)
	if strings.Contains(string(args), "tskey-client") {
		t.Errorf("secret leaked into argv:\n%s", args)
	}
	if !strings.Contains(string(args), "--advertise-tags=tag:birdscale") {
		t.Errorf("tags missing from argv:\n%s", args)
	}
}
