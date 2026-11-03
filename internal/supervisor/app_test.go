package supervisor

import (
	"testing"
	"time"

	"github.com/tm1000/birdscale/internal/netbird"
)

func TestSessionGate(t *testing.T) {
	var g sessionGate
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if g.Due(netbird.SessionOK, t0) || g.Due(netbird.SessionUnknown, t0) {
		t.Error("no warning expected outside the window")
	}
	if !g.Due(netbird.SessionExpiring, t0) {
		t.Error("first expiring state must log")
	}
	if g.Due(netbird.SessionExpiring, t0.Add(10*time.Minute)) {
		t.Error("repeat inside the hour")
	}
	if !g.Due(netbird.SessionExpiring, t0.Add(61*time.Minute)) {
		t.Error("hourly repeat")
	}
	if !g.Due(netbird.SessionExpired, t0.Add(62*time.Minute)) {
		t.Error("state change must log")
	}
	g.Due(netbird.SessionOK, t0.Add(63*time.Minute)) // renewed
	if !g.Due(netbird.SessionExpiring, t0.Add(64*time.Minute)) {
		t.Error("warning after renewal and a new window must log again")
	}
}
