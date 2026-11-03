// Package dnsfwd is the DNS forwarder: it listens on the bridge's Tailscale
// IPs (UDP and TCP port 53) and forwards queries to NetBird's resolver, so
// tailnet clients can use Tailscale split DNS for NetBird-only domains.
//
// For answers that fall under a NetBird domain resource the reply is held for
// a moment until the resolved address is advertised to the tailnet (the
// route syncer sees the /32 NetBird installs and advertises it). That gives the
// local advertisement a head start over the client's first connection.
package dnsfwd

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/tm1000/birdscale/internal/routes"
)

// RouteWaiter blocks until every address is covered by an advertised route
// or ctx ends, and reports whether they are covered.
type RouteWaiter interface {
	WaitCovered(ctx context.Context, addrs []netip.Addr) bool
}

// Stats are the forwarder's counters since start.
type Stats struct {
	Queries          uint64 // every query received
	UDP, TCP         uint64 // by client transport
	Forwarded        uint64 // answered from upstream
	Refused          uint64 // outside BS_DNS_DOMAINS
	Failed           uint64 // upstream unreachable/unknown -> SERVFAIL
	Malformed        uint64 // FORMERR / NOTIMP
	Truncated        uint64 // replies sent with TC set
	RouteWaits       uint64 // answers held for a route (domain resources)
	RouteWaitOK      uint64 // ... route was advertised in time
	RouteWaitTimeout uint64 // ... gave up after BS_DNS_ROUTE_WAIT
}

// Forwarder implements dns.Handler and manages the listeners.
type Forwarder struct {
	Log       *slog.Logger
	Port      int           // 53 in production
	Suffixes  []string      // BS_DNS_DOMAINS, normalized; empty = forward everything
	RouteWait time.Duration // 0 disables the wait
	Waiter    RouteWaiter   // nil disables the wait
	Timeout   time.Duration // upstream timeout, default 4s

	mu       sync.Mutex
	addrs    []netip.Addr
	servers  []*dns.Server
	upstream string
	exact    []string
	wild     []string

	queries, udp, tcp, forwarded, refused, failed, malformed, truncated atomic.Uint64
	waits, waitOK, waitTimeout                                          atomic.Uint64
}

// Stats returns a copy of the counters.
func (f *Forwarder) Stats() Stats {
	return Stats{
		Queries: f.queries.Load(), UDP: f.udp.Load(), TCP: f.tcp.Load(),
		Forwarded: f.forwarded.Load(), Refused: f.refused.Load(), Failed: f.failed.Load(),
		Malformed: f.malformed.Load(), Truncated: f.truncated.Load(),
		RouteWaits: f.waits.Load(), RouteWaitOK: f.waitOK.Load(), RouteWaitTimeout: f.waitTimeout.Load(),
	}
}

// SetUpstream sets NetBird's resolver as "ip:port"; "" means unknown (queries get SERVFAIL).
func (f *Forwarder) SetUpstream(addr string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if addr != f.upstream {
		if f.Log != nil {
			f.Log.Info("dns: upstream resolver", "addr", addr)
		}
		f.upstream = addr
	}
}

// Upstream returns the current upstream.
func (f *Forwarder) Upstream() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.upstream
}

// SetResources sets the NetBird networks list; its domain entries decide when
// an answer is held for a route.
func (f *Forwarder) SetResources(networks []string) {
	exact, wild := routes.DomainEntries(networks)
	f.mu.Lock()
	f.exact, f.wild = exact, wild
	f.mu.Unlock()
}

// Listening returns the addresses currently bound (host:port).
func (f *Forwarder) Listening() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, a := range f.addrs {
		out = append(out, net.JoinHostPort(a.String(), strconv.Itoa(f.Port)))
	}
	return out
}

// SetAddrs (re)binds UDP and TCP listeners to exactly the given Tailscale IPs
// and never to anything else. Calling it with the same set is a no-op. With no
// addresses (Tailscale not up) the forwarder idles.
func (f *Forwarder) SetAddrs(addrs []netip.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	addrs = slices.Clone(addrs)
	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
	if slices.Equal(addrs, f.addrs) {
		return
	}
	f.closeLocked()
	f.addrs = addrs
	for _, a := range addrs {
		hp := net.JoinHostPort(a.String(), strconv.Itoa(f.Port))
		pc, err := net.ListenPacket("udp", hp)
		if err != nil {
			f.warn("dns: listen udp failed", "addr", hp, "err", err)
			continue
		}
		ln, err := net.Listen("tcp", hp)
		if err != nil {
			pc.Close()
			f.warn("dns: listen tcp failed", "addr", hp, "err", err)
			continue
		}
		for _, srv := range []*dns.Server{
			{PacketConn: pc, Handler: f},
			{Listener: ln, Handler: f},
		} {
			started := make(chan struct{})
			srv.NotifyStartedFunc = func() { close(started) }
			f.servers = append(f.servers, srv)
			go func() { _ = srv.ActivateAndServe() }()
			select {
			case <-started:
			case <-time.After(2 * time.Second):
			}
		}
		if f.Log != nil {
			f.Log.Info("dns: forwarder listening (udp+tcp)", "addr", hp)
		}
	}
}

func (f *Forwarder) warn(msg string, args ...any) {
	if f.Log != nil {
		f.Log.Warn(msg, args...)
	}
}

// Close stops all listeners.
func (f *Forwarder) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closeLocked()
	f.addrs = nil
}

func (f *Forwarder) closeLocked() {
	for _, s := range f.servers {
		_ = s.Shutdown()
	}
	f.servers = nil
}

// SuffixAllowed reports whether name may be forwarded. An empty suffix list
// allows everything; otherwise name must equal a suffix or be below it.
func SuffixAllowed(suffixes []string, name string) bool {
	if len(suffixes) == 0 {
		return true
	}
	name = routes.NormalizeName(name)
	for _, s := range suffixes {
		if name == s || strings.HasSuffix(name, "."+s) {
			return true
		}
	}
	return false
}

// ServeDNS implements dns.Handler.
func (f *Forwarder) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	f.queries.Add(1)
	isTCP := false
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		isTCP = true
		f.tcp.Add(1)
	} else {
		f.udp.Add(1)
	}
	reply := func(m *dns.Msg) {
		if !isTCP {
			size := dns.MinMsgSize
			if opt := r.IsEdns0(); opt != nil && int(opt.UDPSize()) > size {
				size = int(opt.UDPSize())
			}
			m.Truncate(size)
		}
		if m.Truncated {
			f.truncated.Add(1)
		}
		_ = w.WriteMsg(m)
	}
	fail := func(code int, counter *atomic.Uint64) {
		counter.Add(1)
		m := new(dns.Msg)
		m.SetRcode(r, code)
		reply(m)
	}

	if r.Opcode != dns.OpcodeQuery {
		fail(dns.RcodeNotImplemented, &f.malformed)
		return
	}
	if len(r.Question) != 1 {
		fail(dns.RcodeFormatError, &f.malformed)
		return
	}
	q := r.Question[0]
	if !SuffixAllowed(f.Suffixes, q.Name) {
		fail(dns.RcodeRefused, &f.refused)
		return
	}
	f.mu.Lock()
	up := f.upstream
	exact, wild := f.exact, f.wild
	f.mu.Unlock()
	if up == "" {
		fail(dns.RcodeServerFailure, &f.failed)
		return
	}

	timeout := f.Timeout
	if timeout == 0 {
		timeout = 4 * time.Second
	}
	network := "udp"
	if isTCP {
		network = "tcp"
	}
	// A truncated UDP answer is passed to the client with TC set; the client
	// then retries over TCP to us, and that retry goes to the upstream over TCP.
	c := &dns.Client{Net: network, Timeout: timeout}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, _, err := c.ExchangeContext(ctx, r.Copy(), up)
	if resp == nil || (err != nil && !resp.Truncated) {
		if f.Log != nil {
			f.Log.Debug("dns: upstream exchange failed", "err", err)
		}
		fail(dns.RcodeServerFailure, &f.failed)
		return
	}
	resp.Id = r.Id
	f.forwarded.Add(1)

	if f.Waiter != nil && f.RouteWait > 0 && resp.Rcode == dns.RcodeSuccess && !resp.Truncated {
		if addrs := resourceAddrs(resp, exact, wild); len(addrs) > 0 {
			f.waits.Add(1)
			wctx, wcancel := context.WithTimeout(context.Background(), f.RouteWait)
			ok := f.Waiter.WaitCovered(wctx, addrs)
			wcancel()
			if ok {
				f.waitOK.Add(1)
			} else {
				f.waitTimeout.Add(1)
				if f.Log != nil {
					f.Log.Debug("dns: route not advertised in time; replying anyway", "name", q.Name, "wait", f.RouteWait.String())
				}
			}
		}
	}
	reply(resp)
}

// resourceAddrs returns the A/AAAA addresses of resp when the question or any
// answer owner name (a CNAME chain) falls under a domain resource.
func resourceAddrs(resp *dns.Msg, exact, wild []string) []netip.Addr {
	if len(exact) == 0 && len(wild) == 0 {
		return nil
	}
	match := false
	for _, q := range resp.Question {
		match = match || routes.MatchDomain(q.Name, exact, wild)
	}
	var addrs []netip.Addr
	for _, rr := range resp.Answer {
		match = match || routes.MatchDomain(rr.Header().Name, exact, wild)
		switch v := rr.(type) {
		case *dns.A:
			if a, ok := netip.AddrFromSlice(v.A); ok {
				addrs = append(addrs, a.Unmap())
			}
		case *dns.AAAA:
			if a, ok := netip.AddrFromSlice(v.AAAA); ok {
				addrs = append(addrs, a.Unmap())
			}
		}
	}
	if !match {
		return nil
	}
	return addrs
}

// Lookup resolves name (A and AAAA) through the resolver at upstream over UDP,
// falling back to TCP on truncation. It is used by the domain pre-warm.
func Lookup(ctx context.Context, upstream, name string) ([]netip.Addr, error) {
	var out []netip.Addr
	var firstErr error
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(name), qt)
		m.RecursionDesired = true
		c := &dns.Client{Net: "udp", Timeout: 4 * time.Second}
		resp, _, err := c.ExchangeContext(ctx, m, upstream)
		if resp != nil && resp.Truncated {
			c.Net = "tcp"
			resp, _, err = c.ExchangeContext(ctx, m, upstream)
		}
		if err != nil || resp == nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
			if firstErr == nil {
				firstErr = errors.New(dns.RcodeToString[resp.Rcode])
			}
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				if a, ok := netip.AddrFromSlice(v.A); ok {
					out = append(out, a.Unmap())
				}
			case *dns.AAAA:
				if a, ok := netip.AddrFromSlice(v.AAAA); ok {
					out = append(out, a.Unmap())
				}
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// Probe sends one cheap A query for name to the resolver at upstream over UDP
// and returns nil if any DNS response comes back, whatever its rcode. NetBird's
// resolver answers REFUSED when it is listening but has no handler for a name,
// so any reply proves it is up; a timeout or a refused connection means it is
// not (yet). Use a name the pre-warm will look up anyway.
func Probe(ctx context.Context, upstream, name string) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true
	c := &dns.Client{Net: "udp", Timeout: time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, upstream)
	if resp != nil {
		return nil
	}
	if err == nil {
		err = errors.New("no response")
	}
	return err
}
