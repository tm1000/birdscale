// Package prewarm resolves NetBird domain resources through NetBird's own
// resolver. Doing that makes NetBird install the /32 route for each name, so the
// route is already advertised to the tailnet by the time a client asks.
package prewarm

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tm1000/birdscale/internal/routes"
)

// Resolver resolves name through the resolver at upstream ("ip:53").
type Resolver func(ctx context.Context, upstream, name string) ([]netip.Addr, error)

// State is where one domain is in the pre-warm life cycle.
type State string

const (
	// StateResolved: the last lookup returned addresses (the zero value of
	// State is treated the same unless Err is set).
	StateResolved State = "resolved"
	// StateRetrying: the last lookup failed (timeout, SERVFAIL, network) and
	// a fast retry with backoff is scheduled.
	StateRetrying State = "retrying"
	// StateNoRecords: NXDOMAIN or NODATA. A valid answer, only re-checked on
	// the normal refresh.
	StateNoRecords State = "no-records"
)

// Result is the outcome for one domain entry.
type Result struct {
	Domain    string // as listed, e.g. "wiki.example.internal" or "*.example.internal"
	Wildcard  bool   // not resolvable ahead of time
	State     State
	Addrs     []netip.Addr
	Err       string    // last error, kept while retrying
	At        time.Time // last lookup attempt
	Attempts  int       // consecutive failed attempts while retrying
	NextRetry time.Time // when the next fast retry fires (StateRetrying only)
}

// Backoff timing for failed lookups.
const (
	BackoffStart = 2 * time.Second
	BackoffMax   = 60 * time.Second
	// firstWarnAfter and warnEvery rate-limit the WARN for a domain that keeps failing.
	firstWarnAfter = 5 * time.Minute
	warnEvery      = time.Hour
)

// Resolver-readiness probe and start-up grace window.
const (
	// ProbeStart and ProbeMax bound the delay between readiness probes.
	ProbeStart = 250 * time.Millisecond
	ProbeMax   = 2 * time.Second
	// DefaultReadyTimeout is how long to wait for the resolver before the
	// pre-warm proceeds anyway.
	DefaultReadyTimeout = 30 * time.Second
	// DefaultGrace is the start-up grace window that begins once the resolver
	// answered a probe. Failures inside it are logged at DEBUG, not WARN.
	DefaultGrace = 30 * time.Second
	probeTimeout = time.Second
)

// Backoff returns the delay before retry number attempt (1 = after the first
// failure): BackoffStart doubling up to BackoffMax, with "equal jitter" so the
// result lies in [d/2, d]. rnd must be in [0,1]; rnd=1 gives the unjittered value.
func Backoff(attempt int, rnd float64) time.Duration {
	d := BackoffMax
	if attempt < 1 {
		attempt = 1
	}
	if attempt <= 6 { // 2s<<5 = 64s is already past the cap
		if v := BackoffStart << (attempt - 1); v < d {
			d = v
		}
	}
	return d/2 + time.Duration(float64(d/2)*rnd)
}

// Plan splits the networks list into names to resolve and wildcards to skip.
func Plan(networks []string) (resolve, wildcards []string) {
	exact, wild := routes.DomainEntries(networks)
	for _, w := range wild {
		wildcards = append(wildcards, "*."+w)
	}
	return exact, wildcards
}

// Prober asks the resolver at upstream ("ip:53") for name and returns nil as
// soon as it answers with any DNS response (even REFUSED or NXDOMAIN): that
// proves the resolver is listening. It returns an error on timeout or a
// network failure. It must honour ctx.
type Prober func(ctx context.Context, upstream, name string) error

// Counters are cumulative since start.
type Counters struct {
	Attempts uint64 // domain lookups made (refresh and retry; not readiness probes)
	Failures uint64 // ... that returned an error
}

// Warmer runs the pre-warm at startup, on list changes and on a timer. A
// domain whose lookup fails with a retryable error (timeout, SERVFAIL, network)
// is retried individually with exponential backoff until it succeeds; the
// periodic refresh keeps re-checking the others. NXDOMAIN/NODATA (a nil error
// with no addresses) is a valid answer and is only re-checked on the refresh.
type Warmer struct {
	Log     *slog.Logger
	Resolve Resolver
	Refresh time.Duration // 0 disables the periodic refresh
	Publish func([]Result)
	Timeout time.Duration // per query, default 2s

	// Probe, when set, is used to wait for NetBird's resolver to answer before
	// the first pre-warm after (re)connect or a resolver address change.
	// NetBird reports Connected a few seconds before its resolver answers.
	// nil skips the wait (and the grace window).
	Probe Prober
	// ReadyTimeout bounds that wait (default 30s); the pre-warm then proceeds anyway.
	ReadyTimeout time.Duration
	// Grace is the start-up grace window after the resolver became ready
	// (default 30s). Lookup failures inside it log at DEBUG, outside at WARN.
	Grace time.Duration

	// Test hooks; nil uses the real clock, timers and math/rand.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	Rand  func() float64

	trigger chan struct{}
	once    sync.Once
	pubMu   sync.Mutex // orders Publish calls

	mu       sync.Mutex
	upstream string
	networks []string
	states   map[string]Result
	retriers map[string]*retrier
	loggedWC string
	wg       sync.WaitGroup // running retriers

	readyFor   string    // upstream the readiness wait already ran for ("" = none)
	graceUntil time.Time // failures before this are start-up noise

	attempts, failures atomic.Uint64
}

// Counters returns the cumulative lookup counters.
func (w *Warmer) Counters() Counters {
	return Counters{Attempts: w.attempts.Load(), Failures: w.failures.Load()}
}

// retrier is one domain's fast-retry loop; its identity guards against a
// cancelled loop writing over its replacement.
type retrier struct{ cancel context.CancelFunc }

func (w *Warmer) init() {
	w.once.Do(func() {
		w.trigger = make(chan struct{}, 1)
		w.states = map[string]Result{}
		w.retriers = map[string]*retrier{}
	})
}

func (w *Warmer) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *Warmer) rnd() float64 {
	if w.Rand != nil {
		return w.Rand()
	}
	return rand.Float64()
}

func (w *Warmer) sleep(ctx context.Context, d time.Duration) error {
	if w.Sleep != nil {
		return w.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Observe records the latest NetBird state. A change of the domain list, the
// resolver address or the connected flag stops every pending retry (resetting
// the backoff) and triggers a run.
func (w *Warmer) Observe(upstream string, networks []string, connected bool) {
	w.init()
	if !connected {
		upstream = ""
	}
	res, wc := Plan(networks)
	key := append(slices.Clone(res), wc...)
	slices.Sort(key)
	w.mu.Lock()
	prevUp := w.upstream
	changed := upstream != w.upstream || !slices.Equal(key, w.networks)
	w.upstream, w.networks = upstream, key
	if changed {
		w.cancelRetriersLocked()
	}
	if upstream != prevUp {
		w.readyFor, w.graceUntil = "", time.Time{} // new or lost resolver: probe again
	}
	w.mu.Unlock()
	if changed && upstream != "" {
		select {
		case w.trigger <- struct{}{}:
		default:
		}
	}
}

func (w *Warmer) cancelRetriersLocked() {
	for d, r := range w.retriers {
		r.cancel()
		delete(w.retriers, d)
	}
}

// Results returns the latest results: resolvable domains in list order, then wildcards.
func (w *Warmer) Results() []Result {
	w.init()
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.resultsLocked()
}

func (w *Warmer) resultsLocked() []Result {
	var out, wild []Result
	for _, n := range w.networks {
		r, ok := w.states[n]
		if !ok {
			continue
		}
		if r.Wildcard {
			wild = append(wild, r)
		} else {
			out = append(out, r)
		}
	}
	return append(out, wild...)
}

// publish sends a snapshot to Publish, keeping snapshots in order.
func (w *Warmer) publish() {
	if w.Publish == nil {
		return
	}
	w.pubMu.Lock()
	defer w.pubMu.Unlock()
	w.Publish(w.Results())
}

// Run blocks until ctx ends, then waits for the retry loops to stop.
func (w *Warmer) Run(ctx context.Context) {
	w.init()
	defer w.wg.Wait()
	var tick <-chan time.Time
	if w.Refresh > 0 {
		t := time.NewTicker(w.Refresh)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-ctx.Done():
			w.mu.Lock()
			w.cancelRetriersLocked()
			w.mu.Unlock()
			return
		case <-w.trigger:
		case <-tick:
		}
		w.runOnce(ctx)
	}
}

func (w *Warmer) timeout() time.Duration {
	if w.Timeout > 0 {
		return w.Timeout
	}
	return 2 * time.Second
}

func (w *Warmer) query(ctx context.Context, up, name string) ([]netip.Addr, error) {
	qctx, cancel := context.WithTimeout(ctx, w.timeout())
	defer cancel()
	w.attempts.Add(1)
	addrs, err := w.Resolve(qctx, up, name)
	if err != nil && ctx.Err() == nil {
		w.failures.Add(1)
	}
	return addrs, err
}

func (w *Warmer) inGrace(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return now.Before(w.graceUntil)
}

// waitReady blocks until the resolver at up answers a probe for name, backing
// off from ProbeStart to ProbeMax, for at most ReadyTimeout. It returns false
// if ctx ended or the resolver address changed meanwhile (a new run follows).
// On success it opens the grace window; if the resolver never answered it logs
// one WARN and returns true without a grace window, so later failures warn.
func (w *Warmer) waitReady(ctx context.Context, up, name string) bool {
	timeout := w.ReadyTimeout
	if timeout <= 0 {
		timeout = DefaultReadyTimeout
	}
	grace := w.Grace
	if grace <= 0 {
		grace = DefaultGrace
	}
	start := w.now()
	deadline := start.Add(timeout)
	delay := ProbeStart
	for attempt := 1; ; attempt++ {
		pctx, cancel := context.WithTimeout(ctx, probeTimeout)
		err := w.Probe(pctx, up, name)
		cancel()
		if ctx.Err() != nil {
			return false
		}
		w.mu.Lock()
		same := w.upstream == up
		w.mu.Unlock()
		if !same {
			return false
		}
		now := w.now()
		if err == nil {
			w.mu.Lock()
			w.readyFor, w.graceUntil = up, now.Add(grace)
			w.mu.Unlock()
			w.Log.Info("prewarm: resolver is answering", "upstream", up, "probes", attempt, "waited", now.Sub(start).Round(time.Millisecond))
			return true
		}
		if !now.Add(delay).Before(deadline) {
			w.mu.Lock()
			w.readyFor, w.graceUntil = up, time.Time{}
			w.mu.Unlock()
			w.Log.Warn("prewarm: resolver did not answer in time; pre-warming anyway", "upstream", up, "probes", attempt,
				"waited", now.Sub(start).Round(time.Millisecond), "err", err)
			return true
		}
		w.Log.Debug("prewarm: resolver not answering yet", "upstream", up, "probes", attempt, "err", err, "retry_in", delay)
		if w.sleep(ctx, delay) != nil {
			return false
		}
		delay = min(delay*2, ProbeMax)
	}
}

// runOnce is a full refresh: every non-wildcard domain is looked up (in
// parallel, so one hung query does not stall the rest), except those with a
// retry loop already running.
func (w *Warmer) runOnce(ctx context.Context) {
	w.mu.Lock()
	up, nets := w.upstream, slices.Clone(w.networks)
	w.mu.Unlock()
	if up == "" {
		return
	}
	var res, wc []string
	for _, n := range nets {
		if strings.HasPrefix(n, "*.") {
			wc = append(wc, n)
		} else {
			res = append(res, n)
		}
	}
	if joined := strings.Join(wc, ","); joined != "" {
		w.mu.Lock()
		first := joined != w.loggedWC
		w.loggedWC = joined
		w.mu.Unlock()
		if first {
			w.Log.Info("prewarm: skipping wildcard domain resources (learned only from real queries through the DNS forwarder)", "wildcards", wc)
		}
	}

	// Wait for the resolver once per (re)connect or resolver change.
	if w.Probe != nil && len(res) > 0 {
		w.mu.Lock()
		need := w.readyFor != up
		w.mu.Unlock()
		if need && !w.waitReady(ctx, up, res[0]) {
			return
		}
	}

	// Forget domains that left the list; record the wildcards.
	w.mu.Lock()
	for d := range w.states {
		if !slices.Contains(nets, d) {
			delete(w.states, d)
		}
	}
	for d, r := range w.retriers {
		if !slices.Contains(res, d) {
			r.cancel()
			delete(w.retriers, d)
		}
	}
	for _, d := range wc {
		w.states[d] = Result{Domain: d, Wildcard: true}
	}
	var todo []string
	for _, d := range res {
		if w.retriers[d] == nil {
			todo = append(todo, d)
		}
	}
	w.mu.Unlock()

	var wg sync.WaitGroup
	for _, d := range todo {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addrs, err := w.query(ctx, up, d)
			if ctx.Err() != nil {
				return
			}
			w.record(ctx, up, d, addrs, err)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}

	w.mu.Lock()
	ok, retrying, nodata := 0, 0, 0
	for _, d := range res {
		switch w.states[d].State {
		case StateResolved:
			ok++
		case StateRetrying:
			retrying++
		case StateNoRecords:
			nodata++
		}
	}
	w.mu.Unlock()
	w.Log.Info("prewarm: done", "resolved", ok, "retrying", retrying, "no_records", nodata,
		"domains", len(res), "wildcards_skipped", len(wc))
	w.publish()
}

// record stores the outcome of a refresh lookup and starts a retry loop on a
// retryable failure.
func (w *Warmer) record(ctx context.Context, up, d string, addrs []netip.Addr, err error) {
	now := w.now()
	w.mu.Lock()
	if w.upstream != up || !slices.Contains(w.networks, d) {
		w.mu.Unlock() // list or resolver changed meanwhile; a new run is coming
		return
	}
	prev := w.states[d]
	r := Result{Domain: d, At: now}
	switch {
	case err != nil:
		r.State, r.Err, r.Attempts, r.Addrs = StateRetrying, err.Error(), 1, prev.Addrs
	case len(addrs) == 0:
		r.State = StateNoRecords
	default:
		r.State, r.Addrs = StateResolved, addrs
	}
	var rt *retrier
	var rctx context.Context
	if err != nil {
		rctx, rt = w.newRetrierLocked(ctx, d)
	}
	w.states[d] = r
	w.mu.Unlock()

	switch r.State {
	case StateResolved:
		w.Log.Debug("prewarm: resolved", "domain", d, "addrs", len(addrs))
	case StateNoRecords:
		if prev.State != StateNoRecords {
			w.Log.Warn("prewarm: no A/AAAA records (NXDOMAIN or NODATA); not retrying until the next refresh", "domain", d)
		}
	case StateRetrying:
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			w.retryLoop(rctx, rt, up, d, err, now)
		}()
	}
}

func (w *Warmer) newRetrierLocked(ctx context.Context, d string) (context.Context, *retrier) {
	rctx, cancel := context.WithCancel(ctx)
	rt := &retrier{cancel: cancel}
	w.retriers[d] = rt
	return rctx, rt
}

// retryLoop retries d with exponential backoff until it gets an answer (an
// address list or NXDOMAIN/NODATA), the loop is cancelled (domain removed,
// state reset, shutdown) or superseded.
func (w *Warmer) retryLoop(ctx context.Context, rt *retrier, up, d string, err error, first time.Time) {
	defer rt.cancel()
	attempts := 1
	nextWarn := first.Add(firstWarnAfter)
	warned := false
	for {
		delay := Backoff(attempts, w.rnd())
		now := w.now()
		if !w.update(rt, d, func(r *Result) {
			r.State, r.Err, r.Attempts, r.NextRetry = StateRetrying, err.Error(), attempts, now.Add(delay)
		}) {
			return
		}
		w.publish()
		switch {
		case !warned && !w.inGrace(now):
			// The first failure outside the start-up grace window.
			warned = true
			w.Log.Warn("prewarm: resolve failed, retrying with backoff", "domain", d, "err", err, "retry_in", delay.Round(time.Millisecond))
		case warned && !now.Before(nextWarn):
			nextWarn = now.Add(warnEvery)
			w.Log.Warn("prewarm: still failing", "domain", d, "err", err, "attempts", attempts, "failing_for", now.Sub(first).Round(time.Second), "retry_in", delay.Round(time.Millisecond))
		default:
			w.Log.Debug("prewarm: resolve failed again", "domain", d, "err", err, "attempts", attempts, "retry_in", delay.Round(time.Millisecond))
		}
		if w.sleep(ctx, delay) != nil {
			return
		}
		addrs, qerr := w.query(ctx, up, d)
		if ctx.Err() != nil {
			return
		}
		attempts++
		if qerr != nil {
			err = qerr
			if !w.update(rt, d, func(r *Result) { r.At = w.now() }) {
				return
			}
			continue
		}
		done := w.update(rt, d, func(r *Result) {
			*r = Result{Domain: d, At: w.now(), State: StateResolved, Addrs: addrs}
			if len(addrs) == 0 {
				r.State = StateNoRecords
			}
		})
		if !done {
			return
		}
		w.mu.Lock()
		if w.retriers[d] == rt {
			delete(w.retriers, d)
		}
		w.mu.Unlock()
		if len(addrs) == 0 {
			w.Log.Warn("prewarm: no A/AAAA records (NXDOMAIN or NODATA); not retrying until the next refresh", "domain", d, "attempts", attempts)
		} else {
			w.Log.Info("prewarm: resolved after "+strconv.Itoa(attempts)+" attempts", "domain", d, "addrs", len(addrs), "failing_for", w.now().Sub(first).Round(time.Second))
		}
		w.publish()
		return
	}
}

// update applies f to d's state unless rt has been cancelled or replaced.
func (w *Warmer) update(rt *retrier, d string, f func(*Result)) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.retriers[d] != rt {
		return false
	}
	r := w.states[d]
	f(&r)
	w.states[d] = r
	return true
}
