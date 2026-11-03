package web

import (
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	cases := []struct {
		name  string
		allow []string
		login string
		tags  []string
		want  bool
	}{
		{"empty allows any resolved caller", nil, "bob@example.internal", nil, true},
		{"user match", []string{"alice@example.internal"}, "alice@example.internal", nil, true},
		{"user match case-insensitive", []string{"Alice@Example.internal"}, "alice@example.internal", nil, true},
		{"user mismatch", []string{"alice@example.internal"}, "bob@example.internal", nil, false},
		{"tag match", []string{"tag:admin"}, "tagged-devices", []string{"tag:web", "tag:admin"}, true},
		{"tag mismatch", []string{"tag:admin"}, "tagged-devices", []string{"tag:web"}, false},
		{"tag entry never matches a login", []string{"tag:admin"}, "tag:admin", nil, false},
		{"mixed list", []string{"alice@example.internal", "tag:admin"}, "bob@example.internal", []string{"tag:admin"}, true},
		{"blank entries ignored", []string{" ", ""}, "bob@example.internal", nil, false},
	}
	for _, c := range cases {
		if got := Allowed(c.allow, c.login, c.tags); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := newLimiter()
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	n := 0
	for i := 0; i < 10; i++ {
		if l.allow("a") {
			n++
		}
	}
	if n != 3 {
		t.Errorf("burst allowed %d, want 3", n)
	}
	if !l.allow("b") {
		t.Error("other client must have its own bucket")
	}
	now = now.Add(1100 * time.Millisecond)
	if !l.allow("a") || l.allow("a") {
		t.Error("expected exactly one token after ~1s")
	}
}
