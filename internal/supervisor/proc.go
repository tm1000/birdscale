// Package supervisor starts and watches tailscaled and the NetBird daemon and
// drives login, route advertisement and firewall setup.
package supervisor

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

var outMu sync.Mutex

// prefixWriter writes complete lines to w as "[prefix] line".
type prefixWriter struct {
	prefix string
	w      io.Writer
}

func (p prefixWriter) Write(b []byte) (int, error) {
	outMu.Lock()
	defer outMu.Unlock()
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if _, err := io.WriteString(p.w, "["+p.prefix+"] "+sc.Text()+"\n"); err != nil {
			return 0, err
		}
	}
	return len(b), nil
}

// Proc is a supervised child process.
type Proc struct {
	Name string
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

// StartProc launches bin with args and env, forwarding output to stdout with a
// "[name]" line prefix.
func StartProc(name, bin string, args, env []string) (*Proc, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	w := prefixWriter{prefix: name, w: os.Stdout}
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	p := &Proc{Name: name, cmd: cmd, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// Done is closed when the process has exited.
func (p *Proc) Done() <-chan struct{} { return p.done }

// Err is the Wait result; valid after Done is closed.
func (p *Proc) Err() error { return p.err }

// Stop sends SIGTERM and, after grace, SIGKILL.
func (p *Proc) Stop(grace time.Duration) {
	select {
	case <-p.done:
		return
	default:
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
	case <-time.After(grace):
		_ = p.cmd.Process.Kill()
		<-p.done
	}
}

// EnvWithout returns env minus the named variables.
func EnvWithout(env []string, names ...string) []string {
	var out []string
outer:
	for _, kv := range env {
		for _, n := range names {
			if strings.HasPrefix(kv, n+"=") {
				continue outer
			}
		}
		out = append(out, kv)
	}
	return out
}
