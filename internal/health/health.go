// Package health evaluates the bridge's health from a status snapshot and
// serves it as JSON on loopback.
package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/tm1000/birdscale/internal/routes"
	"github.com/tm1000/birdscale/internal/status"
	"github.com/tm1000/birdscale/internal/tailscale"
)

// Check is one named health condition.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

// Report is the overall result.
type Report struct {
	Healthy bool    `json:"healthy"`
	Checks  []Check `json:"checks"`
}

// Evaluate applies the Phase 1 definition of healthy: tailscale Running,
// NetBird logged in with management connected, routes advertised (prefs match
// the computed set), and the nft table present.
func Evaluate(s status.Snapshot) Report {
	r := Report{Healthy: true}
	add := func(name string, ok bool, reason string) {
		r.Checks = append(r.Checks, Check{name, ok, reason})
		if !ok {
			r.Healthy = false
		}
	}

	switch {
	case s.TSStatus == nil:
		add("tailscale", false, "tailscaled not reachable: "+orUnknown(s.TSErr))
	case s.TSStatus.BackendState == tailscale.StateRunning:
		add("tailscale", true, "backend Running")
	case s.TSStatus.BackendState == tailscale.StateNeedsLogin:
		add("tailscale", false, "needs login (no usable auth key; see the login URL in the logs or status page)")
	case s.TSStatus.BackendState == tailscale.StateNeedsMachineAuth:
		add("tailscale", false, "waiting for device approval (NeedsMachineAuth)")
	default:
		add("tailscale", false, "backend state "+s.TSStatus.BackendState)
	}

	switch {
	case s.NBStatus == nil:
		add("netbird", false, "netbird daemon not reachable: "+orUnknown(s.NBErr))
	case s.NBStatus.Connected():
		add("netbird", true, "logged in, management connected")
	case s.NBStatus.NeedsLogin():
		add("netbird", false, "needs login ("+s.NBStatus.DaemonStatus+")")
	case !s.NBStatus.Management.Connected:
		add("netbird", false, "management not connected (daemon "+s.NBStatus.DaemonStatus+")")
	default:
		add("netbird", false, "daemon status "+s.NBStatus.DaemonStatus)
	}

	switch {
	case !s.RoutesComputed:
		add("routes", false, "routes not computed yet (NetBird has not connected)")
	case s.TSPrefs == nil:
		add("routes", false, "tailscale prefs unavailable")
	case !routes.Equal(s.TSPrefs.AdvertiseRoutes, s.RoutesDesired):
		add("routes", false, fmt.Sprintf("advertised %v, want %v", routes.Strings(s.TSPrefs.AdvertiseRoutes), routes.Strings(s.RoutesDesired)))
	default:
		add("routes", true, fmt.Sprintf("%d route(s) advertised", len(s.RoutesDesired)))
	}

	if s.NFTPresent {
		add("nftables", true, "table inet birdscale present")
	} else {
		add("nftables", false, "table inet birdscale missing: "+orUnknown(s.NFTErr))
	}
	return r
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Serve serves /healthz on 127.0.0.1:port until ctx ends.
func Serve(ctx context.Context, port int, store *status.Store) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		rep := Evaluate(store.Get())
		w.Header().Set("Content-Type", "application/json")
		if !rep.Healthy {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(rep)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		sctx, c := context.WithTimeout(context.Background(), 2*time.Second)
		defer c()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.Serve(ln); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// Probe is the `birdscaled health` client: it prints the report and returns
// whether the bridge is healthy.
func Probe(port int) (bool, string, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(port)) + "/healthz")
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	var rep Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return false, "", err
	}
	out, _ := json.MarshalIndent(rep, "", "  ")
	return resp.StatusCode == http.StatusOK && rep.Healthy, string(out), nil
}
