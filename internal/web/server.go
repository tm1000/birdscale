package web

import (
	"context"
	"embed"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"

	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/status"
)

//go:embed assets/index.html.tmpl assets/style.css
var assets embed.FS

var (
	pageTmpl = template.Must(template.ParseFS(assets, "assets/index.html.tmpl"))
	css      = func() template.CSS { b, _ := assets.ReadFile("assets/style.css"); return template.CSS(b) }()
)

// WhoIser resolves a tailnet caller. *local.Client satisfies it through tailscale.Client.
type WhoIser interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// Reloginer starts the NetBird flow that renews or recovers the SSO session.
// It must not tie the started command to the HTTP request's context.
type Reloginer interface {
	Relogin(ctx context.Context) (netbird.Mode, error)
}

// metricsPath serves Prometheus metrics (only when Server.Metrics is set).
const metricsPath = "/metrics"

// reloginPath is the page's only state-changing endpoint.
const reloginPath = "/netbird/relogin"

// Server is the status page: read-only except for the NetBird re-login POST.
type Server struct {
	Who     WhoIser
	Store   *status.Store
	Allow   []string
	Port    int
	Log     *slog.Logger
	Relogin Reloginer // nil disables the re-login endpoint
	// Metrics, when set, is served at GET /metrics behind the same rate
	// limit and WhoIs allow-list as the page.
	Metrics http.Handler

	lim  *limiter
	csrf *csrf
	mu   sync.Mutex
	addr []netip.Addr
	srvs []*http.Server
}

// Handler returns the page handler: rate limit, WhoIs authorisation, then
// either render the page (GET /) or handle the re-login POST.
func (s *Server) Handler() http.Handler {
	if s.lim == nil {
		s.lim = newLimiter()
	}
	if s.csrf == nil {
		s.csrf = newCSRF()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isPost := r.Method == http.MethodPost && r.URL.Path == reloginPath
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !isPost {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		if !s.lim.allow(host) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		who, err := s.Who.WhoIs(ctx, r.RemoteAddr)
		if err != nil || who == nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		login := ""
		if who.UserProfile != nil {
			login = who.UserProfile.LoginName
		}
		var tags []string
		if who.Node != nil {
			tags = who.Node.Tags
		}
		if !Allowed(s.Allow, login, tags) {
			s.Log.Info("web: denied", "login", login, "remote", host)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		subject := login + "|" + host
		if isPost {
			s.handleRelogin(w, r, login, host, subject)
			return
		}
		if r.URL.Path == metricsPath && s.Metrics != nil {
			w.Header().Set("Cache-Control", "no-store")
			s.Metrics.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		caller := login
		if len(tags) > 0 {
			caller = login + " " + tags[0]
		}
		v := buildView(s.Store.Get(), caller, s.csrf.Issue(subject), time.Now())
		v.CSS = css
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if err := pageTmpl.Execute(w, v); err != nil {
			s.Log.Error("web: render", "err", err)
		}
	})
}

// handleRelogin is the one state-changing endpoint. The caller already passed
// the rate limit and the WhoIs allow-list; here the CSRF token (issued when
// the page was rendered, bound to this caller) and same-origin are checked.
func (s *Server) handleRelogin(w http.ResponseWriter, r *http.Request, login, host, subject string) {
	if s.Relogin == nil {
		http.NotFound(w, r)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
		s.Log.Warn("web: relogin rejected (cross-site)", "login", login, "remote", host)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			s.Log.Warn("web: relogin rejected (origin mismatch)", "login", login, "remote", host)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !s.csrf.Verify(subject, r.PostForm.Get("csrf")) {
		s.Log.Warn("web: relogin rejected (bad CSRF token)", "login", login, "remote", host)
		http.Error(w, "forbidden: missing or stale CSRF token; reload the page and try again", http.StatusForbidden)
		return
	}
	mode, err := s.Relogin.Relogin(r.Context())
	if err != nil {
		s.Log.Warn("web: netbird relogin refused", "login", login, "err", err)
		http.Error(w, "cannot start NetBird login: "+err.Error(), http.StatusConflict)
		return
	}
	s.Log.Warn("web: netbird relogin started", "login", login, "remote", host, "flow", string(mode))
	http.Redirect(w, r, "/#netbird", http.StatusSeeOther)
}

// SetAddrs (re)binds listeners to exactly the given Tailscale IPs. The page is
// never served on any other address. Calling it with the same set is a no-op.
func (s *Server) SetAddrs(addrs []netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	addrs = slices.Clone(addrs)
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	if slices.Equal(addrs, s.addr) {
		return
	}
	s.closeLocked()
	s.addr = addrs
	h := s.Handler()
	for _, a := range addrs {
		ln, err := net.Listen("tcp", net.JoinHostPort(a.String(), strconv.Itoa(s.Port)))
		if err != nil {
			s.Log.Warn("web: listen failed", "addr", a, "err", err)
			continue
		}
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
		s.srvs = append(s.srvs, srv)
		go srv.Serve(ln)
		s.Log.Info("web: status page listening", "addr", ln.Addr().String())
	}
}

// Close stops all listeners.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	s.addr = nil
}

func (s *Server) closeLocked() {
	for _, srv := range s.srvs {
		ctx, c := context.WithTimeout(context.Background(), time.Second)
		_ = srv.Shutdown(ctx)
		c()
	}
	s.srvs = nil
}
