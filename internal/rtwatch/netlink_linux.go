//go:build linux

package rtwatch

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// Netlink reads table Table on interface Iface through rtnetlink.
type Netlink struct {
	Table int
	Iface string
	Log   *slog.Logger
}

func toRoute(r netlink.Route, ifaceName string) (Route, bool) {
	if r.Dst == nil {
		return Route{}, false
	}
	a, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		return Route{}, false
	}
	ones, _ := r.Dst.Mask.Size()
	a = a.Unmap()
	return Route{Dst: netip.PrefixFrom(a, ones), Table: r.Table, Iface: ifaceName}, true
}

// HostRoutes lists both families of the table and filters to host routes on the interface.
func (n *Netlink) HostRoutes() ([]netip.Prefix, error) {
	link, err := netlink.LinkByName(n.Iface)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil, nil // NetBird interface not up yet: no routes
		}
		return nil, fmt.Errorf("link %s: %w", n.Iface, err)
	}
	var rs []Route
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		list, err := netlink.RouteListFiltered(fam, &netlink.Route{Table: n.Table, LinkIndex: link.Attrs().Index},
			netlink.RT_FILTER_TABLE|netlink.RT_FILTER_OIF)
		if err != nil {
			return nil, fmt.Errorf("list routes (family %d): %w", fam, err)
		}
		for _, r := range list {
			if rt, ok := toRoute(r, n.Iface); ok {
				rs = append(rs, rt)
			}
		}
	}
	return HostRoutes(rs, n.Table, n.Iface), nil
}

// Watch calls kick whenever a route in the table is added or removed, until ctx
// ends. It resubscribes after errors. kick must not block (it is called inline).
func (n *Netlink) Watch(ctx context.Context, kick func()) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := n.subscribeOnce(ctx, kick)
		if ctx.Err() != nil {
			return
		}
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		if n.Log != nil {
			n.Log.Warn("rtwatch: route subscription ended; retrying", "err", err, "in", backoff.String())
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
		kick() // we may have missed events while unsubscribed
	}
}

func (n *Netlink) subscribeOnce(ctx context.Context, kick func()) error {
	ch := make(chan netlink.RouteUpdate, 256)
	done := make(chan struct{})
	defer close(done)
	errc := make(chan error, 1)
	err := netlink.RouteSubscribeWithOptions(ch, done, netlink.RouteSubscribeOptions{
		ErrorCallback: func(err error) {
			select {
			case errc <- err:
			default:
			}
		},
	})
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errc:
			return err
		case u, ok := <-ch:
			if !ok {
				return fmt.Errorf("route update channel closed")
			}
			if u.Type != unix.RTM_NEWROUTE && u.Type != unix.RTM_DELROUTE {
				continue
			}
			if u.Table == n.Table || u.Route.Table == n.Table {
				kick()
			}
		}
	}
}
