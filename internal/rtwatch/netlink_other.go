//go:build !linux

package rtwatch

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
)

// Netlink is only functional on Linux.
type Netlink struct {
	Table int
	Iface string
	Log   *slog.Logger
}

// HostRoutes always fails off Linux.
func (n *Netlink) HostRoutes() ([]netip.Prefix, error) {
	return nil, errors.New("rtwatch: netlink is only available on linux")
}

// Watch does nothing off Linux.
func (n *Netlink) Watch(ctx context.Context, kick func()) { <-ctx.Done() }
