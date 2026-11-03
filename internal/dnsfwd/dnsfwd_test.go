package dnsfwd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// freePort finds a port that is free for both UDP and TCP on 127.0.0.1.
func freePort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 50; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		pc.Close()
		if err == nil {
			ln.Close()
			return port
		}
	}
	t.Fatal("no free port")
	return 0
}

type upstreamCounts struct{ udp, tcp atomic.Int64 }

// startUpstream runs a fake resolver (UDP+TCP). wiki.example.internal ->
// 203.0.113.5; big.example.internal -> TC over UDP, 40 A records over TCP;
// everything else NXDOMAIN.
func startUpstream(t *testing.T) (string, *upstreamCounts) {
	t.Helper()
	port := freePort(t)
	addr := "127.0.0.1:" + strconv.Itoa(port)
	cnt := &upstreamCounts{}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		_, isTCP := w.RemoteAddr().(*net.TCPAddr)
		if isTCP {
			cnt.tcp.Add(1)
		} else {
			cnt.udp.Add(1)
		}
		m := new(dns.Msg)
		m.SetReply(r)
		q := r.Question[0]
		switch strings.ToLower(q.Name) {
		case "wiki.example.internal.":
			if q.Qtype == dns.TypeA {
				m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.5")})
			}
		case "big.example.internal.":
			if !isTCP {
				m.Truncated = true
			} else {
				for i := 0; i < 40; i++ {
					m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(198, 51, 100, byte(i+1))})
				}
			}
		case "plain.other.test.":
			m.Answer = append(m.Answer, &dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("203.0.113.77")})
		default:
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})
	for _, srv := range []*dns.Server{
		{Addr: addr, Net: "udp", Handler: h},
		{Addr: addr, Net: "tcp", Handler: h},
	} {
		started := make(chan struct{})
		srv.NotifyStartedFunc = func() { close(started) }
		go func() { _ = srv.ListenAndServe() }()
		<-started
		t.Cleanup(func() { _ = srv.Shutdown() })
	}
	return addr, cnt
}

func newFwd(t *testing.T, upstream string, opts ...func(*Forwarder)) (*Forwarder, string) {
	t.Helper()
	f := &Forwarder{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Port: freePort(t)}
	for _, o := range opts {
		o(f) // settings are fixed before the listeners start, as in production
	}
	f.SetUpstream(upstream)
	f.SetAddrs([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	t.Cleanup(f.Close)
	return f, "127.0.0.1:" + strconv.Itoa(f.Port)
}

func ask(t *testing.T, network, addr, name string, qt uint16) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, qt)
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		t.Fatalf("%s query %s: %v", network, name, err)
	}
	return r
}

func TestForwardUDPAndTCP(t *testing.T) {
	up, cnt := startUpstream(t)
	f, addr := newFwd(t, up)
	for _, nw := range []string{"udp", "tcp"} {
		r := ask(t, nw, addr, "wiki.example.internal.", dns.TypeA)
		if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "203.0.113.5" {
			t.Errorf("%s: %v", nw, r)
		}
	}
	if r := ask(t, "udp", addr, "nope.example.internal.", dns.TypeA); r.Rcode != dns.RcodeNameError {
		t.Errorf("NXDOMAIN not passed through: %v", r)
	}
	if cnt.udp.Load() != 2 || cnt.tcp.Load() != 1 {
		t.Errorf("upstream transports: udp=%d tcp=%d (client transport must be preserved)", cnt.udp.Load(), cnt.tcp.Load())
	}
	st := f.Stats()
	if st.Queries != 3 || st.Forwarded != 3 || st.UDP != 2 || st.TCP != 1 {
		t.Errorf("stats: %+v", st)
	}
}

func TestRefusedOutsideSuffixes(t *testing.T) {
	up, cnt := startUpstream(t)
	f, addr := newFwd(t, up, func(f *Forwarder) { f.Suffixes = []string{"example.internal", "corp.test"} })
	for _, nw := range []string{"udp", "tcp"} {
		if r := ask(t, nw, addr, "plain.other.test.", dns.TypeA); r.Rcode != dns.RcodeRefused {
			t.Errorf("%s: want REFUSED, got %s", nw, dns.RcodeToString[r.Rcode])
		}
	}
	if r := ask(t, "udp", addr, "notexample.internal.", dns.TypeA); r.Rcode != dns.RcodeRefused {
		t.Error("suffix match must be label-aligned")
	}
	if r := ask(t, "udp", addr, "WIKI.Example.Internal.", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Errorf("allowed name (case-insensitive) failed: %v", r)
	}
	if cnt.udp.Load()+cnt.tcp.Load() != 1 { // only the allowed WIKI query
		t.Errorf("refused queries reached the upstream: %d", cnt.udp.Load()+cnt.tcp.Load())
	}
	if st := f.Stats(); st.Refused != 3 {
		t.Errorf("refused counter %d", st.Refused)
	}
	// Empty list forwards everything.
	_, addr2 := newFwd(t, up)
	if r := ask(t, "udp", addr2, "plain.other.test.", dns.TypeA); r.Rcode != dns.RcodeSuccess {
		t.Errorf("empty list should forward: %v", r)
	}
}

func TestTruncationAndTCPFallback(t *testing.T) {
	up, _ := startUpstream(t)
	f, addr := newFwd(t, up)
	r := ask(t, "udp", addr, "big.example.internal.", dns.TypeA)
	if !r.Truncated {
		t.Fatalf("TC must be passed through to UDP clients: %v", r)
	}
	r = ask(t, "tcp", addr, "big.example.internal.", dns.TypeA)
	if r.Truncated || len(r.Answer) != 40 {
		t.Errorf("TCP retry: truncated=%v answers=%d", r.Truncated, len(r.Answer))
	}
	if f.Stats().Truncated != 1 {
		t.Errorf("truncated counter %d", f.Stats().Truncated)
	}
}

func TestServfailWithoutUpstreamAndIdleWithoutAddrs(t *testing.T) {
	f, addr := newFwd(t, "", func(f *Forwarder) { f.Timeout = 300 * time.Millisecond })
	if r := ask(t, "udp", addr, "wiki.example.internal.", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("want SERVFAIL, got %s", dns.RcodeToString[r.Rcode])
	}
	// Dead upstream: SERVFAIL after the timeout, not a hang.
	f.SetUpstream("127.0.0.1:" + strconv.Itoa(freePort(t)))
	start := time.Now()
	if r := ask(t, "tcp", addr, "wiki.example.internal.", dns.TypeA); r.Rcode != dns.RcodeServerFailure {
		t.Errorf("dead upstream: %s", dns.RcodeToString[r.Rcode])
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("dead upstream took %v", time.Since(start))
	}
	// No Tailscale IP yet: idle, no panic, nothing listening.
	f.SetAddrs(nil)
	f.SetAddrs(nil)
	if len(f.Listening()) != 0 {
		t.Errorf("listening: %v", f.Listening())
	}
	c := &dns.Client{Net: "udp", Timeout: 300 * time.Millisecond}
	m := new(dns.Msg)
	m.SetQuestion("x.test.", dns.TypeA)
	if _, _, err := c.Exchange(m, addr); err == nil {
		t.Error("forwarder still answering with no addresses")
	}
	// Rebind when the address comes back.
	f.SetAddrs([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	if len(f.Listening()) != 1 {
		t.Errorf("listening after rebind: %v", f.Listening())
	}
}

type fakeWaiter struct {
	delay time.Duration // 0 = block until ctx ends (route never appears)
	calls atomic.Int64
	got   atomic.Value
}

func (w *fakeWaiter) WaitCovered(ctx context.Context, addrs []netip.Addr) bool {
	w.calls.Add(1)
	w.got.Store(addrs)
	if w.delay == 0 {
		<-ctx.Done()
		return false
	}
	select {
	case <-time.After(w.delay):
		return true
	case <-ctx.Done():
		return false
	}
}

func TestRouteWait(t *testing.T) {
	up, _ := startUpstream(t)
	w := &fakeWaiter{delay: 150 * time.Millisecond}
	f, addr := newFwd(t, up, func(f *Forwarder) { f.Waiter, f.RouteWait = w, 2*time.Second })
	f.SetResources([]string{"wiki.example.internal", "192.0.2.0/24"})

	// A domain-resource answer is held until the route is advertised.
	start := time.Now()
	r := ask(t, "udp", addr, "wiki.example.internal.", dns.TypeA)
	el := time.Since(start)
	if r.Rcode != dns.RcodeSuccess || len(r.Answer) != 1 {
		t.Fatalf("answer: %v", r)
	}
	if el < 140*time.Millisecond || el > 1500*time.Millisecond {
		t.Errorf("held for %v, want about 150ms", el)
	}
	if got := w.got.Load().([]netip.Addr); len(got) != 1 || got[0].String() != "203.0.113.5" {
		t.Errorf("waited on %v", got)
	}

	// A name that is not a domain resource is not held.
	start = time.Now()
	ask(t, "udp", addr, "plain.other.test.", dns.TypeA)
	if time.Since(start) > 100*time.Millisecond || w.calls.Load() != 1 {
		t.Errorf("non-resource answer was delayed or waited (%v, calls=%d)", time.Since(start), w.calls.Load())
	}

	// The route never appears: give up after RouteWait and still answer.
	w2 := &fakeWaiter{}
	f2, addr2 := newFwd(t, up, func(f *Forwarder) { f.Waiter, f.RouteWait = w2, 300*time.Millisecond })
	f2.SetResources([]string{"wiki.example.internal"})
	start = time.Now()
	r = ask(t, "tcp", addr2, "wiki.example.internal.", dns.TypeA)
	el = time.Since(start)
	if len(r.Answer) != 1 {
		t.Errorf("no answer after route-wait timeout: %v", r)
	}
	if el < 290*time.Millisecond || el > 1500*time.Millisecond {
		t.Errorf("timeout path took %v, want about 300ms", el)
	}
	if st := f.Stats(); st.RouteWaits != 1 || st.RouteWaitOK != 1 || st.RouteWaitTimeout != 0 {
		t.Errorf("route wait stats: %+v", st)
	}
	if st := f2.Stats(); st.RouteWaits != 1 || st.RouteWaitOK != 0 || st.RouteWaitTimeout != 1 {
		t.Errorf("route wait timeout stats: %+v", st)
	}

	// RouteWait=0 disables the wait entirely.
	w3 := &fakeWaiter{}
	f3, addr3 := newFwd(t, up, func(f *Forwarder) { f.Waiter, f.RouteWait = w3, 0 })
	f3.SetResources([]string{"wiki.example.internal"})
	start = time.Now()
	ask(t, "udp", addr3, "wiki.example.internal.", dns.TypeA)
	if time.Since(start) > 100*time.Millisecond || w3.calls.Load() != 0 {
		t.Error("RouteWait=0 still waited")
	}
}

func TestSuffixAllowed(t *testing.T) {
	s := []string{"example.internal"}
	for name, want := range map[string]bool{
		"example.internal.": true, "a.example.internal": true, "A.B.EXAMPLE.INTERNAL.": true,
		"xexample.internal": false, "example.internal.evil.test": false, "": false,
	} {
		if got := SuffixAllowed(s, name); got != want {
			t.Errorf("SuffixAllowed(%q)=%v want %v", name, got, want)
		}
	}
	if !SuffixAllowed(nil, "anything.test") {
		t.Error("empty list must allow everything")
	}
}

func TestLookup(t *testing.T) {
	up, _ := startUpstream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := Lookup(ctx, up, "wiki.example.internal")
	if err != nil || len(got) != 1 || got[0].String() != "203.0.113.5" {
		t.Errorf("got %v err %v", got, err)
	}
	got, err = Lookup(ctx, up, "nope.example.internal")
	if err != nil || len(got) != 0 {
		t.Errorf("NXDOMAIN: got %v err %v", got, err)
	}
	if _, err := Lookup(ctx, "127.0.0.1:"+strconv.Itoa(freePort(t)), "x.test"); err == nil {
		t.Error("dead upstream should error")
	}
}

func TestProbe(t *testing.T) {
	up, _ := startUpstream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// NXDOMAIN is still an answer.
	if err := Probe(ctx, up, "nothing.example.internal"); err != nil {
		t.Fatalf("answering resolver: %v", err)
	}

	// REFUSED (listening, no handler) counts as up.
	port := freePort(t)
	refused := "127.0.0.1:" + strconv.Itoa(port)
	srv := &dns.Server{Addr: refused, Net: "udp", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ListenAndServe() }()
	<-started
	defer srv.Shutdown()
	if err := Probe(ctx, refused, "wiki.example.internal"); err != nil {
		t.Fatalf("REFUSED resolver must count as up: %v", err)
	}

	// Nothing listening: an error.
	dead := "127.0.0.1:" + strconv.Itoa(freePort(t))
	if err := Probe(ctx, dead, "wiki.example.internal"); err == nil {
		t.Fatal("dead resolver reported as up")
	}
}

func TestForwarderBindsIPv6Address(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback in this environment")
	}
	ln.Close()
	up, _ := startUpstream(t)
	port := freePort(t)
	f := &Forwarder{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Port: port}
	f.SetUpstream(up)
	f.SetAddrs([]netip.Addr{netip.MustParseAddr("::1")})
	defer f.Close()
	want := "[::1]:" + strconv.Itoa(port)
	if got := f.Listening(); len(got) != 1 || got[0] != want {
		t.Fatalf("Listening() = %v, want [%s]", got, want)
	}
	for _, network := range []string{"udp", "tcp"} {
		m := new(dns.Msg)
		m.SetQuestion("wiki.example.internal.", dns.TypeA)
		c := &dns.Client{Net: network, Timeout: 2 * time.Second}
		resp, _, err := c.Exchange(m, want)
		if err != nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Errorf("%s over IPv6: %v %+v", network, err, resp)
		}
	}
}
