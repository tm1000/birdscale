// Package web serves the status page on the bridge's Tailscale IPs. It is
// read-only except for one POST: the NetBird re-login action.
package web

import (
	"strings"
	"sync"
	"time"
)

// Allowed reports whether a caller may view the page. allow is the
// BS_WEBUI_ALLOW list: user login names and/or "tag:" values. An empty list
// allows every caller that WhoIs resolved. A caller matches if their login
// name equals a user entry (case-insensitive) or any of their tags equals a
// tag entry.
func Allowed(allow []string, login string, tags []string) bool {
	if len(allow) == 0 {
		return true
	}
	for _, a := range allow {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, "tag:") {
			for _, t := range tags {
				if t == a {
					return true
				}
			}
			continue
		}
		if login != "" && strings.EqualFold(a, login) {
			return true
		}
	}
	return false
}

// limiter is a per-client token bucket (1 request per second, burst 3).
type limiter struct {
	mu      sync.Mutex
	clients map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter() *limiter { return &limiter{clients: map[string]*bucket{}, now: time.Now} }

func (l *limiter) allow(key string) bool {
	const rate, burst = 1.0, 3.0
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b := l.clients[key]
	if b == nil {
		if len(l.clients) > 1024 { // bound memory: forget idle clients
			for k, v := range l.clients {
				if now.Sub(v.last) > time.Minute {
					delete(l.clients, k)
				}
			}
		}
		b = &bucket{tokens: burst, last: now}
		l.clients[key] = b
	}
	b.tokens = min(burst, b.tokens+now.Sub(b.last).Seconds()*rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
