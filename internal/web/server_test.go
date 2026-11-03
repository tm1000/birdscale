package web

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"

	"github.com/tm1000/birdscale/internal/netbird"
	"github.com/tm1000/birdscale/internal/status"
)

type fakeWho struct {
	resp *apitype.WhoIsResponse
	err  error
}

func (f fakeWho) WhoIs(context.Context, string) (*apitype.WhoIsResponse, error) { return f.resp, f.err }

func serve(t *testing.T, w WhoIser, allow []string) *httptest.ResponseRecorder {
	t.Helper()
	s := &Server{Who: w, Store: status.NewStore(), Allow: allow, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "100.64.0.9:5555"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func resp(login string, tags ...string) *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{UserProfile: &tailcfg.UserProfile{LoginName: login}, Node: &tailcfg.Node{Tags: tags}}
}

func TestHandlerAuth(t *testing.T) {
	if rec := serve(t, fakeWho{err: errors.New("not a tailnet peer")}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("unresolvable caller: %d", rec.Code)
	}
	if rec := serve(t, fakeWho{resp: resp("bob@example.internal")}, []string{"alice@example.internal"}); rec.Code != http.StatusForbidden {
		t.Errorf("disallowed: %d", rec.Code)
	}
	rec := serve(t, fakeWho{resp: resp("alice@example.internal")}, []string{"alice@example.internal"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "birdscale") || !strings.Contains(rec.Body.String(), "unreachable") {
		t.Errorf("allowed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := serve(t, fakeWho{resp: resp("tagged-devices", "tag:admin")}, []string{"tag:admin"}); rec.Code != 200 {
		t.Errorf("tag allowed: %d", rec.Code)
	}
}

type fakeRelogin struct {
	calls int
	mode  netbird.Mode
	err   error
}

func (f *fakeRelogin) Relogin(context.Context) (netbird.Mode, error) {
	f.calls++
	return f.mode, f.err
}

func newPostServer(t *testing.T, who WhoIser, allow []string, rl Reloginer) *Server {
	t.Helper()
	st := status.NewStore()
	st.Update(func(s *status.Snapshot) {
		s.NBStatus = &netbird.Status{DaemonStatus: netbird.DaemonConnected, Management: netbird.Conn{Connected: true}, SessionExpiresAt: "2099-01-01T00:00:00Z"}
	})
	srv := &Server{Who: who, Store: st, Allow: allow, Relogin: rl, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	// A clock that moves 2s per request keeps the rate limiter out of these tests.
	srv.lim = newLimiter()
	tick := time.Unix(1000, 0)
	srv.lim.now = func() time.Time { tick = tick.Add(2 * time.Second); return tick }
	return srv
}

func do(s *Server, method, path, remote string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, path, body)
	req.RemoteAddr = remote
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func pageToken(t *testing.T, s *Server, remote string) string {
	t.Helper()
	rec := do(s, "GET", "/", remote, nil, nil)
	m := csrfRe.FindStringSubmatch(rec.Body.String())
	if rec.Code != 200 || m == nil {
		t.Fatalf("page %d has no CSRF form:\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "form-action 'self'") {
		t.Error("CSP must allow same-origin form posts")
	}
	return m[1]
}

func TestReloginPost(t *testing.T) {
	rl := &fakeRelogin{mode: netbird.ModeExtend}
	s := newPostServer(t, fakeWho{resp: resp("alice@example.internal")}, []string{"alice@example.internal"}, rl)
	const remote = "100.64.0.9:5555"
	tok := pageToken(t, s, remote)

	// Valid token: flow started, redirect back to the page.
	rec := do(s, "POST", "/netbird/relogin", remote, url.Values{"csrf": {tok}}, map[string]string{"Origin": "http://example.com"})
	if rec.Code != http.StatusSeeOther || rl.calls != 1 {
		t.Fatalf("valid post: code=%d calls=%d body=%s", rec.Code, rl.calls, rec.Body.String())
	}

	bad := map[string]url.Values{
		"missing token": {},
		"garbage token": {"csrf": {"nonsense"}},
		"tampered mac":  {"csrf": {tok[:len(tok)-1] + "0"}},
		"other subject": {"csrf": {s.csrf.Issue("bob@example.internal|100.64.0.9")}},
	}
	for name, form := range bad {
		if rec := do(s, "POST", "/netbird/relogin", remote, form, nil); rec.Code != http.StatusForbidden {
			t.Errorf("%s: code %d", name, rec.Code)
		}
	}
	// Stale token.
	old := s.csrf.now
	s.csrf.now = func() time.Time { return old().Add(2 * time.Hour) }
	if rec := do(s, "POST", "/netbird/relogin", remote, url.Values{"csrf": {tok}}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("stale token: %d", rec.Code)
	}
	s.csrf.now = old
	// Cross-site.
	if rec := do(s, "POST", "/netbird/relogin", remote, url.Values{"csrf": {tok}}, map[string]string{"Origin": "https://evil.test"}); rec.Code != http.StatusForbidden {
		t.Errorf("foreign Origin: %d", rec.Code)
	}
	if rec := do(s, "POST", "/netbird/relogin", remote, url.Values{"csrf": {tok}}, map[string]string{"Sec-Fetch-Site": "cross-site"}); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site fetch: %d", rec.Code)
	}
	if rl.calls != 1 {
		t.Errorf("rejected requests started the flow: calls=%d", rl.calls)
	}
}

func TestReloginPostAllowListAndMethods(t *testing.T) {
	rl := &fakeRelogin{mode: netbird.ModeUp}
	// A disallowed caller cannot POST even with a token minted for them.
	s := newPostServer(t, fakeWho{resp: resp("bob@example.internal")}, []string{"alice@example.internal"}, rl)
	tok := s.csrfFor().Issue("bob@example.internal|100.64.0.9")
	if rec := do(s, "POST", "/netbird/relogin", "100.64.0.9:1", url.Values{"csrf": {tok}}, nil); rec.Code != http.StatusForbidden || rl.calls != 0 {
		t.Errorf("disallowed caller: code=%d calls=%d", rec.Code, rl.calls)
	}
	// Unresolvable caller.
	s2 := newPostServer(t, fakeWho{err: errors.New("not a tailnet peer")}, nil, rl)
	if rec := do(s2, "POST", "/netbird/relogin", "203.0.113.9:1", url.Values{"csrf": {"x"}}, nil); rec.Code != http.StatusForbidden {
		t.Errorf("non-tailnet caller: %d", rec.Code)
	}
	// Every other write is rejected; GET on the action path is not an action.
	s3 := newPostServer(t, fakeWho{resp: resp("alice@example.internal")}, nil, rl)
	for _, c := range [][2]string{{"POST", "/"}, {"PUT", "/netbird/relogin"}, {"DELETE", "/"}, {"POST", "/other"}} {
		if rec := do(s3, c[0], c[1], "100.64.0.9:1", url.Values{"csrf": {"x"}}, nil); rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: %d", c[0], c[1], rec.Code)
		}
	}
	if rec := do(s3, "GET", "/netbird/relogin", "100.64.0.9:1", nil, nil); rec.Code != http.StatusNotFound || rl.calls != 0 {
		t.Errorf("GET on action path: %d calls=%d", rec.Code, rl.calls)
	}
}

func TestReloginRefusedAndDisabled(t *testing.T) {
	rl := &fakeRelogin{err: errors.New("no SSO session to renew")}
	s := newPostServer(t, fakeWho{resp: resp("alice@example.internal")}, nil, rl)
	tok := pageToken(t, s, "100.64.0.9:1")
	rec := do(s, "POST", "/netbird/relogin", "100.64.0.9:1", url.Values{"csrf": {tok}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no SSO session") {
		t.Errorf("refused: %d %s", rec.Code, rec.Body.String())
	}
	s2 := newPostServer(t, fakeWho{resp: resp("alice@example.internal")}, nil, nil)
	if rec := do(s2, "POST", "/netbird/relogin", "100.64.0.9:1", url.Values{"csrf": {"x"}}, nil); rec.Code != http.StatusNotFound {
		t.Errorf("disabled endpoint: %d", rec.Code)
	}
}

func TestCSRFRoundTrip(t *testing.T) {
	c := newCSRF()
	tok := c.Issue("alice|100.64.0.9")
	if !c.Verify("alice|100.64.0.9", tok) || c.Verify("alice|100.64.0.10", tok) || c.Verify("alice|100.64.0.9", "") {
		t.Error("csrf verify")
	}
	if newCSRF().Verify("alice|100.64.0.9", tok) {
		t.Error("tokens must not survive a different key (restart)")
	}
}

// csrfFor returns the server's CSRF issuer, creating it the way Handler does.
func (s *Server) csrfFor() *csrf {
	s.Handler()
	return s.csrf
}

func TestMetricsEndpoint(t *testing.T) {
	get := func(s *Server, w WhoIser) *httptest.ResponseRecorder {
		s.Who = w
		req := httptest.NewRequest("GET", "/metrics", nil)
		req.RemoteAddr = "100.64.0.9:5555"
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "birdscale_build_info 1\n") })
	newSrv := func(m http.Handler) *Server {
		return &Server{Store: status.NewStore(), Allow: []string{"tag:prometheus"}, Metrics: m,
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	}

	// Same allow-list as the page: an allowed tag scrapes, anyone else is 403.
	if rec := get(newSrv(h), fakeWho{resp: resp("tagged-devices", "tag:prometheus")}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "birdscale_build_info") {
		t.Errorf("allowed scrape: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(newSrv(h), fakeWho{resp: resp("bob@example.internal")}); rec.Code != http.StatusForbidden {
		t.Errorf("disallowed scrape: %d", rec.Code)
	}
	if rec := get(newSrv(h), fakeWho{err: errors.New("not a tailnet peer")}); rec.Code != http.StatusForbidden {
		t.Errorf("unidentified scrape: %d", rec.Code)
	}
	// No metrics handler configured: the path does not exist.
	if rec := get(newSrv(nil), fakeWho{resp: resp("tagged-devices", "tag:prometheus")}); rec.Code != http.StatusNotFound {
		t.Errorf("metrics disabled: %d", rec.Code)
	}
	// Read-only: POST /metrics is not allowed.
	s := newSrv(h)
	s.Who = fakeWho{resp: resp("tagged-devices", "tag:prometheus")}
	req := httptest.NewRequest("POST", "/metrics", nil)
	req.RemoteAddr = "100.64.0.9:5555"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics: %d", rec.Code)
	}
}
