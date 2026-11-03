package tailscale

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// LoginConfig holds the `tailscale up` inputs.
type LoginConfig struct {
	AuthKey       string // secret; passed via a 0600 temp file ("file:"), never argv
	Hostname      string
	Tags          []string
	LoginServer   string
	NetfilterMode string
	Socket        string
}

// Login runs `tailscale up` in the background when the node needs a login.
// Interactive logins (no auth key) get their URL from LocalAPI status.AuthURL.
//
// Why the CLI: `tailscale up --reset` is the exact behaviour proven in the Phase 0 spike and
// applies the full pref set (including auth key handling and re-auth) the same
// way tailscale itself does; status/prefs/routes still use LocalAPI.
type Login struct {
	Cfg LoginConfig
	Bin string
	Log *slog.Logger

	mu          sync.Mutex
	running     bool
	stop        context.CancelFunc
	fail        int
	next        time.Time
	lastErr     string
	lastMachine time.Time
	lastURL     string
}

// LoginState is the user-visible login state.
type LoginState struct {
	Running bool
	LastErr string
}

// State returns a snapshot.
func (l *Login) State() LoginState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return LoginState{Running: l.running, LastErr: l.lastErr}
}

// Ensure is called on every poll with the latest backend state and AuthURL.
func (l *Login) Ensure(ctx context.Context, backendState, authURL string) {
	switch backendState {
	case StateRunning:
		l.mu.Lock()
		stop := l.stop
		l.fail, l.lastErr = 0, ""
		running := l.running
		l.mu.Unlock()
		if running && stop != nil {
			stop()
		}
	case StateNeedsMachineAuth:
		// Device approval is on: nothing to do but wait for an admin.
		l.mu.Lock()
		due := time.Since(l.lastMachine) > 5*time.Minute
		if due {
			l.lastMachine = time.Now()
		}
		l.mu.Unlock()
		if due {
			l.Log.Warn("TAILSCALE: device is waiting for approval (NeedsMachineAuth). Approve it in the admin console (Machines); birdscale will continue automatically.")
		}
	case StateNeedsLogin, StateStopped:
		l.mu.Lock()
		skip := l.running || time.Now().Before(l.next)
		l.mu.Unlock()
		if skip {
			if authURL != "" {
				l.logURL(authURL)
			}
			return
		}
		l.start(ctx)
	}
}

func (l *Login) logURL(u string) {
	l.mu.Lock()
	changed := l.lastURL != u
	l.lastURL = u
	l.mu.Unlock()
	if changed {
		l.Log.Warn("TAILSCALE LOGIN REQUIRED: open this URL in a browser to authenticate", "url", u)
	}
}

func (l *Login) start(ctx context.Context) {
	args := []string{
		"--socket=" + l.Cfg.Socket,
		"up", "--reset", "--timeout=0",
		"--hostname=" + l.Cfg.Hostname,
		"--accept-dns=false", "--accept-routes=false",
		"--netfilter-mode=" + l.Cfg.NetfilterMode,
	}
	if l.Cfg.LoginServer != "" {
		args = append(args, "--login-server="+l.Cfg.LoginServer)
	}
	if len(l.Cfg.Tags) > 0 {
		args = append(args, "--advertise-tags="+strings.Join(l.Cfg.Tags, ","))
	}
	keyFile := ""
	if l.Cfg.AuthKey != "" {
		f, err := os.CreateTemp("", "ts-authkey-*")
		if err != nil {
			l.fail1(err)
			return
		}
		keyFile = f.Name()
		_, werr := f.WriteString(l.Cfg.AuthKey)
		f.Close()
		if werr != nil {
			os.Remove(keyFile)
			l.fail1(werr)
			return
		}
		args = append(args, "--auth-key=file:"+keyFile)
		l.Log.Info("tailscale: logging in with auth key")
	} else {
		l.Log.Info("tailscale: no TS_AUTHKEY; starting interactive login (URL will be logged)")
	}
	bin := l.Bin
	if bin == "" {
		bin = "tailscale"
	}
	cctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(cctx, bin, args...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		cancel()
		pw.Close()
		if keyFile != "" {
			os.Remove(keyFile)
		}
		l.fail1(err)
		return
	}
	l.mu.Lock()
	l.running, l.stop = true, cancel
	l.mu.Unlock()
	go func() {
		sc := bufio.NewScanner(pr)
		for sc.Scan() {
			if t := strings.TrimSpace(sc.Text()); t != "" {
				l.Log.Debug("tailscale up", "out", t)
			}
		}
	}()
	go func() {
		err := cmd.Wait()
		pw.Close()
		cancel()
		if keyFile != "" {
			os.Remove(keyFile)
		}
		l.mu.Lock()
		l.running = false
		l.mu.Unlock()
		if err != nil && cctx.Err() == nil {
			l.fail1(err)
		}
	}()
}

func (l *Login) fail1(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail++
	backoff := time.Duration(min(l.fail, 6)) * 5 * time.Second
	l.next = time.Now().Add(backoff)
	l.lastErr = err.Error()
	l.Log.Warn("tailscale: login command failed; will retry", "err", fmt.Sprint(err), "retry_in", backoff.String())
}

// Stop cancels a running login command.
func (l *Login) Stop() {
	l.mu.Lock()
	stop := l.stop
	l.mu.Unlock()
	if stop != nil {
		stop()
	}
}
