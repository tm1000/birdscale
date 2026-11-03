// Command birdscaled supervises tailscaled and the NetBird client and bridges
// the tailnet to the NetBird network. `birdscaled health` is the Docker
// HEALTHCHECK probe.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/tm1000/birdscale/internal/config"
	"github.com/tm1000/birdscale/internal/health"
	"github.com/tm1000/birdscale/internal/supervisor"
	"github.com/tm1000/birdscale/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "health":
			os.Exit(healthCmd())
		case "run":
		default:
			fmt.Fprintf(os.Stderr, "usage: %s [run|health]\n", os.Args[0])
			os.Exit(2)
		}
	}
	os.Exit(run())
}

func healthCmd() int {
	port := config.DefaultHealthPort
	if v := os.Getenv("BS_HEALTH_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			fmt.Fprintln(os.Stderr, "BS_HEALTH_PORT:", err)
			return 2
		}
		port = n
	}
	ok, report, err := health.Probe(port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy: cannot query /healthz:", err)
		return 1
	}
	fmt.Println(report)
	if !ok {
		return 1
	}
	return 0
}

func run() int {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "birdscaled: invalid configuration:\n%v\n", err)
		return 2
	}
	// Secrets are held in cfg only; do not let any child process inherit them.
	os.Unsetenv("TS_AUTHKEY")
	os.Unsetenv("NB_SETUP_KEY")
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: cfg.LogLevel}))
	log.Info("birdscaled starting", append([]any{"version", version.Version}, cfg.Redacted()...)...)

	// Defaults shared by the netbird daemon and the CLI invocations (status/up).
	for k, v := range map[string]string{
		"NB_STATE_DIR":   "/etc/netbird",
		"NB_LOG_FILE":    "console",
		"NB_DAEMON_ADDR": "unix:///var/run/netbird.sock",
	} {
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if err := supervisor.New(cfg, log).Run(ctx); err != nil {
		log.Error("birdscaled exiting", "err", err)
		return 1
	}
	log.Info("birdscaled stopped cleanly")
	return 0
}
