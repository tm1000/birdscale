// Package rtwatch reads and watches NetBird's routing table. NetBird (kernel
// interface mode) installs routes in table 7120 (0x1bd0, systemops_linux.go
// NetbirdVPNTableID); domain resources show up there as host routes
// (/32, /128) on dev wt0 once something resolves them through NetBird's DNS.
package rtwatch

import (
	"net/netip"
	"slices"

	"github.com/tm1000/birdscale/internal/routes"
)

// NetBirdTable is NetBird's policy routing table (NetbirdVPNTableID = 0x1BD0).
const NetBirdTable = 7120

// Route is the part of a kernel route the filter needs.
type Route struct {
	Dst   netip.Prefix
	Table int
	Iface string
}

// HostRoutes returns the sorted, de-duplicated host routes (/32, /128) of
// table on iface. This is the "domain resource" signal.
func HostRoutes(rs []Route, table int, iface string) []netip.Prefix {
	var out []netip.Prefix
	for _, r := range rs {
		if r.Table != table || r.Iface != iface || !r.Dst.IsValid() || !r.Dst.IsSingleIP() {
			continue
		}
		out = append(out, r.Dst.Masked())
	}
	slices.SortFunc(out, routes.ComparePrefix)
	return slices.Compact(out)
}

// Source reads the current host routes.
type Source interface {
	HostRoutes() ([]netip.Prefix, error)
}
