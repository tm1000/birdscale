package netbird

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// LoginConfig is what `netbird up` needs.
type LoginConfig struct {
	ManagementURL string
	SetupKey      string // secret; passed via environment, never argv
	Hostname      string
	WireGuardPort int
}

// LoginState is the user-visible state of the login helper.
type LoginState struct {
	Running bool      // a `netbird up` or `netbird login --extend` is currently running
	Mode    Mode      // which of the two, while Running
	URL     string    // SSO device-flow URL, if one was printed
	Since   time.Time // when URL was captured
	LastErr string
	// LastResult is the last line a finished --extend printed (new expiry).
	LastResult string
}

// Mode is which NetBird flow the helper is running.
type Mode string

// Modes.
const (
	ModeUp     Mode = "up"     // `netbird up --no-browser`: recover after expiry / first login
	ModeExtend Mode = "extend" // `netbird login --extend --no-browser`: renew before expiry, tunnel stays up
)

// extendTimeout bounds one --extend run (the device code expires well before).
const extendTimeout = 15 * time.Minute

// Login drives `netbird up` until the daemon is connected, restarting it when
// the device code expires or the command fails (with backoff, never exiting).
type Login struct {
	Cfg      LoginConfig
	Bin      string
	Log      *slog.Logger
	mu       sync.Mutex
	st       LoginState
	stop     context.CancelFunc
	done     chan struct{}
	fail     int
	next     time.Time // do not start before this (backoff)
	lastLine string
}

// State returns a copy of the current login state.
func (l *Login) State() LoginState {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.st
}

func (l *Login) update(f func(*LoginState)) {
	l.mu.Lock()
	f(&l.st)
	l.mu.Unlock()
}

// Ensure is called on every poll with the latest daemon status. It starts a
// background `netbird up` if a login is needed and none is running, and
// cancels a running one once the daemon is connected.
func (l *Login) Ensure(ctx context.Context, st *Status) {
	l.mu.Lock()
	running, stop, next, mode := l.st.Running, l.stop, l.next, l.st.Mode
	if st != nil && st.Connected() {
		if running && mode == ModeExtend {
			// A renewal is in progress on a live tunnel: leave it (and its URL) alone.
			l.mu.Unlock()
			return
		}
		l.st.URL, l.st.LastErr, l.fail = "", "", 0
		l.mu.Unlock()
		if running && stop != nil {
			stop()
		}
		return
	}
	l.mu.Unlock()
	if running || st == nil || !st.NeedsLogin() || time.Now().Before(next) {
		return
	}
	l.start(ctx, ModeUp)
}

// Renew starts the NetBird flow that extends or recovers the SSO session,
// chosen from the daemon status:
//
//   - connected with a known session expiry: `netbird login --extend`
//     (RequestExtendAuthSession/WaitExtendAuthSession; tunnel stays up).
//   - needs login (expired, never logged in): `netbird up` (Login +
//     WaitSSOLogin + Up), the same flow Ensure runs, started now without backoff.
//
// It returns which flow was started, or an error if nothing sensible can be
// started. ctx bounds the lifetime of the spawned command, not the HTTP request.
func (l *Login) Renew(ctx context.Context, st *Status) (Mode, error) {
	if st == nil {
		return "", fmt.Errorf("netbird status is unavailable")
	}
	l.mu.Lock()
	if l.st.Running {
		mode := l.st.Mode
		l.mu.Unlock()
		return mode, nil // already in progress; the page shows its URL
	}
	l.mu.Unlock()
	switch {
	case st.Connected():
		if _, ok := st.SessionExpiry(); !ok {
			return "", fmt.Errorf("no SSO session to renew (peer uses a setup key, or login expiry is disabled)")
		}
		l.start(ctx, ModeExtend)
		return ModeExtend, nil
	case st.NeedsLogin():
		l.mu.Lock()
		l.fail, l.next = 0, time.Time{}
		l.mu.Unlock()
		l.start(ctx, ModeUp)
		return ModeUp, nil
	}
	return "", fmt.Errorf("netbird is %s; try again once it is connected or asks for login", st.DaemonStatus)
}

func (l *Login) start(ctx context.Context, mode Mode) {
	var cctx context.Context
	var cancel context.CancelFunc
	if mode == ModeExtend {
		cctx, cancel = context.WithTimeout(ctx, extendTimeout)
	} else {
		cctx, cancel = context.WithCancel(ctx)
	}
	l.mu.Lock()
	l.stop = cancel
	l.done = make(chan struct{})
	l.st.Running, l.st.Mode, l.st.URL, l.lastLine = true, mode, "", ""
	l.st.LastResult = ""
	l.mu.Unlock()

	var args []string
	switch mode {
	case ModeExtend:
		args = []string{"login", "--extend", "--no-browser"}
	default:
		args = []string{"up", "--management-url", l.Cfg.ManagementURL, "--no-browser"}
		if l.Cfg.Hostname != "" {
			args = append(args, "--hostname", l.Cfg.Hostname)
		}
		if l.Cfg.WireGuardPort != 0 {
			args = append(args, "--wireguard-port", fmt.Sprint(l.Cfg.WireGuardPort))
		}
	}
	bin := l.Bin
	if bin == "" {
		bin = "netbird"
	}
	keyFile := ""
	if l.Cfg.SetupKey != "" && mode == ModeUp {
		// A 0600 temp file keeps the key out of argv and `ps`.
		f, err := os.CreateTemp("", "nb-setupkey-*")
		if err == nil {
			keyFile = f.Name()
			_, err = f.WriteString(l.Cfg.SetupKey)
			f.Close()
		}
		if err != nil {
			cancel()
			if keyFile != "" {
				os.Remove(keyFile)
			}
			l.finish(err, mode)
			return
		}
		args = append(args, "--setup-key-file", keyFile)
	}
	cmd := exec.CommandContext(cctx, bin, args...)
	cmd.Env = childEnv()
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	sso := l.Cfg.SetupKey == "" || mode == ModeExtend

	if mode == ModeExtend {
		l.Log.Info("netbird: starting SSO session renewal (netbird login --extend)")
	} else if sso {
		l.Log.Info("netbird: starting SSO login (device flow)")
	} else {
		l.Log.Info("netbird: logging in with setup key")
	}
	if err := cmd.Start(); err != nil {
		pw.Close()
		if keyFile != "" {
			os.Remove(keyFile)
		}
		l.finish(err, mode)
		return
	}
	scanned := make(chan struct{})
	go func() { defer close(scanned); l.scan(pr, sso, mode) }()
	go func() {
		err := cmd.Wait()
		if cctx.Err() != nil {
			err = nil // cancelled on purpose (connected or shutting down)
		}
		pw.Close()
		<-scanned // lastLine must be final before finish reads it
		if keyFile != "" {
			os.Remove(keyFile)
		}
		l.finish(err, mode)
	}()
}

func (l *Login) finish(err error, mode Mode) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.st.Running = false
	if l.done != nil {
		close(l.done)
		l.done = nil
	}
	if mode == ModeExtend {
		// A renewal is user-initiated: report the outcome, never retry or back off.
		l.st.URL = ""
		if err != nil {
			l.st.LastErr = "session renewal failed: " + err.Error()
			if l.lastLine != "" {
				l.st.LastErr += ": " + l.lastLine
			}
			l.Log.Warn("netbird: session renewal failed", "err", l.st.LastErr)
			return
		}
		l.st.LastErr, l.st.LastResult = "", l.lastLine
		l.Log.Info("netbird: session renewal finished", "result", l.lastLine)
		return
	}
	if err != nil {
		l.fail++
		backoff := time.Duration(min(l.fail, 6)) * 5 * time.Second // 5s .. 30s
		l.next = time.Now().Add(backoff)
		l.st.LastErr = err.Error()
		if l.lastLine != "" {
			l.st.LastErr += ": " + l.lastLine
		}
		l.Log.Warn("netbird: login command failed; will retry", "err", l.st.LastErr, "retry_in", backoff.String())
		return
	}
	// A clean exit means connected (or the code was consumed); the next poll confirms.
	l.fail = 0
	l.next = time.Time{}
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// ExtractURL returns the first URL in a line of `netbird up` output.
func ExtractURL(line string) (string, bool) {
	u := urlRe.FindString(line)
	return strings.TrimRight(u, ".,;)"), u != ""
}

func (l *Login) scan(r io.Reader, sso bool, mode Mode) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		l.Log.Debug("netbird up", "out", redact(line, l.Cfg.SetupKey))
		l.mu.Lock()
		l.lastLine = redact(line, l.Cfg.SetupKey)
		if len(l.lastLine) > 200 {
			l.lastLine = l.lastLine[:200]
		}
		l.mu.Unlock()
		if !sso {
			continue
		}
		if u, ok := ExtractURL(line); ok {
			l.update(func(s *LoginState) { s.URL, s.Since = u, time.Now() })
			if mode == ModeExtend {
				l.Log.Warn("NETBIRD SESSION RENEWAL: open this URL in a browser to extend the SSO session", "url", u)
			} else {
				l.Log.Warn("NETBIRD LOGIN REQUIRED: open this URL in a browser to authorise this peer", "url", u)
			}
		}
	}
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "<redacted>")
}

// Stop cancels a running login and waits briefly for it.
func (l *Login) Stop() {
	l.mu.Lock()
	stop, done := l.stop, l.done
	l.mu.Unlock()
	if stop != nil {
		stop()
	}
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
}

// childEnv is the environment for `netbird up`: the process environment minus
// the setup key (passed by file) and NB_PORT (not a netbird setting).
func childEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "NB_SETUP_KEY=") || strings.HasPrefix(kv, "NB_PORT=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}
