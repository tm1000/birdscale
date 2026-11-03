//go:build linux

package rtwatch

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// TestNetlinkLive changes real network state (a dummy "wt0" and routes), so it
// only runs when BS_LIVE_NETLINK=1, inside a throwaway container with
// CAP_NET_ADMIN:
//
//	docker run --rm --cap-add NET_ADMIN -v "$PWD":/src -w /src golang:1.27.3-trixie \
//	    env BS_LIVE_NETLINK=1 go test -run Live -v ./internal/rtwatch
func TestNetlinkLive(t *testing.T) {
	if os.Getenv("BS_LIVE_NETLINK") != "1" {
		t.Skip("set BS_LIVE_NETLINK=1 (in a disposable network namespace) to run")
	}
	la := netlink.NewLinkAttrs()
	la.Name = "wt0"
	if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: la}); err != nil {
		t.Skip("cannot add dummy link:", err)
	}
	link, _ := netlink.LinkByName("wt0")
	_ = netlink.LinkSetUp(link)

	add := func(cidr string, table int) *netlink.Route {
		_, dst, _ := net.ParseCIDR(cidr)
		r := &netlink.Route{LinkIndex: link.Attrs().Index, Dst: dst, Table: table, Scope: netlink.SCOPE_LINK}
		if err := netlink.RouteAdd(r); err != nil {
			t.Fatalf("route add %s: %v", cidr, err)
		}
		return r
	}
	n := &Netlink{Table: NetBirdTable, Iface: "wt0"}
	add("198.51.100.0/24", NetBirdTable)
	add("203.0.113.9/32", NetBirdTable)
	add("203.0.113.10/32", 254) // other table
	add("2001:db8::9/128", NetBirdTable)

	got, err := n.HostRoutes()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.9/32"), netip.MustParsePrefix("2001:db8::9/128")}
	if !slices.Equal(got, want) {
		t.Fatalf("HostRoutes=%v want %v", got, want)
	}

	// Subscription sees adds and removals in the table.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kicks := make(chan struct{}, 16)
	go n.Watch(ctx, func() {
		select {
		case kicks <- struct{}{}:
		default:
		}
	})
	time.Sleep(300 * time.Millisecond) // let the subscription start
	r := add("203.0.113.11/32", NetBirdTable)
	select {
	case <-kicks:
	case <-time.After(3 * time.Second):
		t.Fatal("no kick after route add")
	}
	if got, _ = n.HostRoutes(); len(got) != 3 {
		t.Errorf("after add: %v", got)
	}
	// Removal is visible too (pruning relies on it).
	for len(kicks) > 0 {
		<-kicks
	}
	if err := netlink.RouteDel(r); err != nil {
		t.Fatal(err)
	}
	select {
	case <-kicks:
	case <-time.After(3 * time.Second):
		t.Fatal("no kick after route delete")
	}
	if got, _ = n.HostRoutes(); len(got) != 2 {
		t.Errorf("after delete: %v", got)
	}
	// Events in other tables must not kick.
	for len(kicks) > 0 {
		<-kicks
	}
	add("203.0.113.12/32", 254)
	select {
	case <-kicks:
		t.Error("kick for a route in another table")
	case <-time.After(500 * time.Millisecond):
	}
}
